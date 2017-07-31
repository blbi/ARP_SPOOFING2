#include <pcap/pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h> // for strncpy
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <net/ethernet.h>


#define strerr 2
#define ETHER_ARP 0x0806

int main(int argc, char *argv[]){

	char *interface=argv[1];
	
	//set sender_ip, target_ip
	struct sockaddr_in sender_ip;
	struct sockaddr_in target_ip;

	inet_aton(argv[2], &sender_ip.sin_addr); 
	inet_aton(argv[3], &target_ip.sin_addr);

	
	pcap_t *pcd;
	char *dev;
	char errbuf[PCAP_ERRBUF_SIZE];
	u_char *packet=malloc(42);


	int fd;
	struct ifreq ifr;
	struct ether_header *ETH;
	struct ether_arp arph;	

//=====================get my address====================
	fd = socket(AF_INET, SOCK_DGRAM, 0);

	//to get an IPv4 IP and MAC address attached to interface
	ifr.ifr_addr.sa_family = AF_INET;
	strncpy(ifr.ifr_name, interface, IFNAMSIZ-1);

//==============get ip=======
	ioctl(fd, SIOCGIFADDR, &ifr);  //ip address

	struct in_addr my_ip = ((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr;

//=================get mac============
	ioctl(fd, SIOCGIFHWADDR, &ifr); //mac address

	u_int8_t my_mac[ETH_ALEN];
	memcpy(my_mac, ifr.ifr_hwaddr.sa_data, ETH_ALEN);

	
	close(fd);


 //=====================================================


	if((dev = pcap_lookupdev(errbuf))==NULL){
		fprintf(stderr,"Couldn't find default device\n");
		return 2;
	}

	if((pcd = pcap_open_live(dev, BUFSIZ, 1, 1000,errbuf))==NULL){
		fprintf(strerr, "Device open failed\n");
		return 2;
	}
//====================================================

	//set ether header
	memcpy(ETH->ether_dhost,"\xff\xff\xff\xff\xff\xff",6);
	memcpy(ETH->ether_shost,my_mac,6);
	ETH->ether_type = ntohs(ETHER_ARP);

	//set arp header
	u_int8_t broadcast[ETH_ALEN] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
	
	arph.arp_hrd = htons(ARPHRD_ETHER);
	arph.arp_pro = htons(ETH_P_IP);
	arph.arp_hln = 0x06;
	arph.arp_pln = 0x04;
	arph.arp_op = htons(ARPOP_REQUEST);
	memcpy(arph.arp_sha, my_mac, ETH_ALEN);
	memcpy(arph.arp_spa, &sender_ip.sin_addr, 4);
	memcpy(arph.arp_tha, broadcast, ETH_ALEN);
	memcpy(arph.arp_tpa, &target_ip.sin_addr, 4);
 
	//set packet
	memcpy(packet,ETH,sizeof(struct ether_header));
	memcpy(packet+14, &arph, sizeof(struct ether_arp));


	pcap_sendpacket(pcd, packet, 42);


	return 0;
}
