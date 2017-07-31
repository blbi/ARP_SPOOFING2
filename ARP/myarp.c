#include <pcap/pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h> /* for strncpy */
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

typedef struct arp{
    unsigned short htype;
    unsigned short ptype;
    char hs;
    char ps;
    unsigned short opc;
    unsigned char smac[6];
    unsigned char sip[4];
    unsigned char tmac[6];
    unsigned char tip[4];
    

}ARP;   

/*typedef struct eth{
    u_char dest_addr[6];
    u_char src_addr[6];
    u_short type;
    ARP arph;
}ETH;*/

int main(int argc, char *argv[]){
//int main(char interface[], char sender_ip[], char target_ip[]){
	
	char *interface=argv[1];
	
	struct sockaddr_in sender_ip;
	struct sockaddr_in target_ip;
//char *sender_ip=argv[2];
	//char *target_ip = argv[3];

	pcap_t *pcd;
	
	char *dev;
	char errbuf[PCAP_ERRBUF_SIZE];

	int fd;
	struct ifreq ifr;
	struct ether_header *ETH;
	
	u_char *packet=malloc(42);
	ETH = (struct ether_header*)(packet);
	

//=====================get my address====================
	fd = socket(AF_INET, SOCK_DGRAM, 0);

	//to get an IPv4 IP address 
	ifr.ifr_addr.sa_family = AF_INET;

	//to get IP and MAC address attached to "eth0" 
	strncpy(ifr.ifr_name, interface, IFNAMSIZ-1);

//==============get ip=======
	ioctl(fd, SIOCGIFADDR, &ifr);  //ip address

	struct in_addr my_ip = ((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr;

//=================get mac============
	ioctl(fd, SIOCGIFHWADDR, &ifr); //mac address

	u_int8_t my_mac[ETH_ALEN];
	memcpy(my_mac, ifr.ifr_hwaddr.sa_data, ETH_ALEN);

	

/*
	char my_mac[]={0,};

	int i,j;
	for(i=0, j=0; i < 6 ; i++, j+=2)
	{ 
     	sprintf((char*)my_mac + j, "%02X", ((unsigned char*)ifr.ifr_hwaddr.sa_data)[i]);
	}
*/
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

//	ethh->dest_addr = malloc
	memcpy(ETH->ether_dhost,"\xff\xff\xff\xff\xff\xff",6);
	memcpy(ETH->ether_shost,my_mac,6);

//	ethh->dest_addr = "\xff\xff\xff\xff\xff\xff";				
//	ethh->src_addr = my_mac;

printf("%s", my_mac);

	char myipaddr[INET_ADDRSTRLEN];
	u_int8_t mac[ETH_ALEN];
	u_int8_t broadcast[ETH_ALEN] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
	struct ether_arp arph;

	ETH->ether_type = ntohs(ETHER_ARP);
	
	inet_aton(argv[2], &sender_ip.sin_addr); inet_aton(argv[3], &target_ip.sin_addr);



	arph.arp_hrd = htons(ARPHRD_ETHER);
	arph.arp_pro = htons(ETH_P_IP);
	arph.arp_hln = 0x06;
	arph.arp_pln = 0x04;
	arph.arp_op = htons(ARPOP_REQUEST);
	memcpy(arph.arp_sha, my_mac, ETH_ALEN);
	memcpy(arph.arp_spa, &sender_ip.sin_addr, 4);
	memcpy(arph.arp_tha, broadcast, ETH_ALEN);
	memcpy(arph.arp_tpa, &target_ip.sin_addr, 4);
 
	memcpy(packet,ETH,sizeof(ETH));
	memcpy(packet+14, &arph, sizeof(struct ether_arp));



	pcap_sendpacket(pcd, packet, 42);
//=====================================================
	/* Supposing to be on ethernet, set mac destination to 1:1:1:1:1:1 */
//=====================================================



	return 0;
}
