#include <pcap.h>
#include <time.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>

struct ether_header
{
	unsigned char ether_dhost[6];	//dst_MAC
	unsigned char ether_shost[6];	//src_MAC
	unsigned short ether_type;		//Ethernet type
};
int IP_count = 0;
int TCP_count = 0;
int UDP_count = 0;
	//time
	//MAC_Src MAC_Dst Ethernet type
	//IP->IP_Src IP_dst
	//TCP/UDP->Src_port Dst_port
void getpacket(u_char * arg, const struct pcap_pkthdr* packet_header, const u_char * packet_content){
	printf("----------------------------------------------------\n");
	//time
	printf("%s\n", ctime((time_t *)&(packet_header->ts.tv_sec)));
	struct ether_header *ethernet_content = (struct ether_header *)packet_content;
	unsigned short ethernet_type;
	//MAC_Dst(packet_content[0~5])
	printf("MAC Dst Address:");
	for(int i = 0; i < 6; i++){
		printf("%02x ",ethernet_content->ether_dhost[i]);
	}
	printf("\n");
	//MAC_Src(packet_content[6~11])
	printf("MAC Src Address:");
	for(int i = 0; i < 6; i++){
		printf("%02x ",ethernet_content->ether_shost[i]);
	}
	printf("\n");
	//Ethernet type
	ethernet_type = ntohs(ethernet_content->ether_type);//Get Ethernet type
	printf("Ethernet type is :%04x\n",ethernet_type);
	//IP
	if(ethernet_type == 0x0800){
		IP_count++;
		printf("Type:IP\n");
		//IP_Src(packet_content[26~29])
		printf("Src IP Address: ");
		for(int i=26;i<29;i++){
			printf("%d.",packet_content[i]);
		}
		printf("%d\n",packet_content[29]);
		//IP_Dst(packet_content[30~33])
		printf("Dst IP Address: ");
		for(int i=30;i<33;i++){
			printf("%d.",packet_content[i]);
		}
		printf("%d\n",packet_content[33]);
		//check packet_content[23] for Protocal type
		//TCP
		if(packet_content[23]==6){
			TCP_count++;
			printf("Protocal type: TCP\n");
			printf("Src port: %d\n",packet_content[34]*256+packet_content[35]);
			printf("Dst port: %d\n",packet_content[36]*256+packet_content[37]);
		}//UDP
		else if(packet_content[23]==17){
			UDP_count++;
			printf("Protocal type: UDP\n");
			printf("Src port: %d\n",packet_content[34]*256+packet_content[35]);
			printf("Dst port: %d\n",packet_content[36]*256+packet_content[37]);
		}
	}
}

int main(int argc ,char *argv[]){
    char* DevStr;
	char err_content[PCAP_ERRBUF_SIZE] = {0};
	char* Dev;
	int packet_num = -1;
	char filename[100];
	printf("How many packet do you want to get?(Input -1 as infinity)\n");
	scanf("%d",&packet_num);
    Dev = pcap_lookupdev(err_content);
	if(Dev){
		printf("success: device: %s\n", Dev);
	}
	else{
		printf("error: %s\n", err_content);
		exit(1);
	}
	pcap_t * pcap_handle = pcap_open_live(Dev,65535,1,0,err_content);
	if(argc==3)
	{
		if(strcmp(argv[1],"-r")==0)
		{
			strcpy(filename,argv[2]);
			pcap_handle = pcap_open_offline(filename, err_content);
			if(!pcap_handle) {
				fprintf(stderr, "pcap_open_offline(): %s\n", err_content);
				exit(1);
			}
			printf("Open: %s\n", filename);
		}
	}
	if(pcap_handle == NULL){
		printf("error: %s\n", err_content);
		exit(1);
	}  
	//let user can change packet_num from command line
	if(pcap_loop(pcap_handle,packet_num,getpacket,NULL)<0){
		perror("pcap_loop");
	}
	printf("Total IP packet num %d\nTCP packet num %d\nUDP packet num %d\n",IP_count,TCP_count,UDP_count);
	pcap_close(pcap_handle);
    return 0;
}