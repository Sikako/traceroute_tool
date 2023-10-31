#include <netinet/if_ether.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netpacket/packet.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <netinet/ip_icmp.h>
#include <netdb.h>
#include <time.h>

#define IP_HDRLEN 20
#define ICMP_HDRLEN 8
#define Ether_HDRLEN 14
#define Packet_Len Ether_HDRLEN + IP_HDRLEN + ICMP_HDRLEN
#define IP_ADDR_LEN 4
#define DEVICE_NAME "ens33"

# define DEBUG 1


unsigned short checksum(unsigned short *addr,int len){
    int nleft = len;
    int sum = 0;
    unsigned short *w = addr;
    unsigned short result = 0;

    while(nleft>1){
        sum += *w++;
        nleft-=2;
    }

    if(nleft == 1){
        *(unsigned *)(&result) = *(unsigned char *)w;
        sum+=result;
    }
    sum =(sum >> 16)+(sum & 0xffff);
    sum += (sum >> 16);
    result = ~sum;

    return result;
}

// header seting
void set_ip_h(struct ip* ip_hdr,struct sockaddr src,char *dst ,int ttl){
    //struct hostent *src_hp,*dst_hp;
    struct in_addr dst_ip,src_ip;
    //src_ip = ((struct sockaddr_in *)&src)->sin_addr;
    //ip_hdr->ip_src = src_ip;
    inet_pton(AF_INET,dst,&dst_ip);
    ip_hdr->ip_dst = dst_ip;
    //ip_hdr->ip_src.s_addr = (struct in_addr_t)src_inaddr;
    //ip_hdr->ip_dst.s_addr = dst_inaddr;
    ip_hdr->ip_v = 4;
    ip_hdr->ip_hl = 5;
    ip_hdr->ip_len = IP_HDRLEN+ICMP_HDRLEN; //not sure
    ip_hdr->ip_id = rand()%256;
    ip_hdr->ip_off = htons(0);
    ip_hdr->ip_ttl = (unsigned char)ttl;
    ip_hdr->ip_p = IPPROTO_ICMP;
    ip_hdr->ip_sum = 0;
}
void set_icmp_h(struct icmp* icmp_hdr, int16_t seq){

    icmp_hdr->icmp_type = ICMP_ECHO;
    icmp_hdr->icmp_code = 0;
    icmp_hdr->icmp_id = rand()%256;
    icmp_hdr->icmp_seq = htons(seq);
}

// Endianness conversion
uint16_t Reverse16(uint16_t value)
{
    return (((value & 0x00FF) << 8) |
            ((value & 0xFF00) >> 8));
}

int main(int argc ,char* argv[]){
    srand( time(NULL) );
    int sockfd_send = 0, sockfd_recv = 0;
    int ttl = 0;
    int send_result=0,recv_result=0;

    char send_buf[84],recv_buf[100];
    struct ip *ip_hdr;
    struct icmp *icmp_hdr;
    struct sockaddr_in sa;
    struct in_addr dst,*src;
    struct ifreq req;

    char src_ip[15];
    char *my_ip, *obj_ip=argv[2];

    //check if root
	if(geteuid() != 0){
		printf("%s\n","ERROR: You must be root to use this tool!");
		exit(1);
	}

    // 判斷格式正確
    if(argc!=3){
        printf("usage : ./ers <max_hop> <destination_ip>\n");
        exit(1);
    }
    
    if((sockfd_send = socket(AF_INET, SOCK_RAW ,IPPROTO_RAW)) < 0)
	{
		perror("Socket Error\n");
		exit(sockfd_send);
	}
    if((sockfd_recv = socket(PF_PACKET, SOCK_RAW ,htons(ETH_P_ALL))) < 0)
	{
		perror("Recv Socket Error\n");
		exit(sockfd_recv);
	}

    memset(&sa,'\0',sizeof(sa));
    memset(send_buf,'\0',sizeof(send_buf));
    memset(&req,'\0',sizeof(req));

    // Get IP from interface name
	strncpy(req.ifr_name, DEVICE_NAME,IF_NAMESIZE-1);
	if(ioctl(sockfd_send,SIOCGIFADDR,&req) < 0){
		perror("ioctl\n");
	}

    // Get source IP
    my_ip = inet_ntoa(((struct sockaddr_in *)&(req.ifr_addr))->sin_addr);
    inet_pton(AF_INET, obj_ip, &dst);
    if(DEBUG){
        printf("src IP: %s\n", my_ip);
        printf("obj IP: %s\n", obj_ip);
    }

    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = inet_addr(obj_ip);
    char *p;
    ttl = strtol(argv[1],&p,10);// change number string to int 
    struct sockaddr from;
    int from_addr_len = sizeof(from);
    
    printf("ERS to %s\n", obj_ip);
    for(int i=1;i<=ttl;i++){
        ip_hdr =(struct ip *)send_buf;
        icmp_hdr =(struct icmp *) (send_buf+IP_HDRLEN);
        // fill packet
        set_ip_h(ip_hdr,req.ifr_addr,obj_ip,i);
        ip_hdr->ip_sum = checksum((unsigned short *)send_buf, ip_hdr->ip_hl);
        set_icmp_h(icmp_hdr, i);
        icmp_hdr->icmp_cksum = checksum((unsigned short *)icmp_hdr,sizeof(send_buf)-sizeof(struct ip));

        printf("header length : %d\n",ip_hdr->ip_hl);
        // send 
        if(send_result = sendto(sockfd_send,send_buf,sizeof(send_buf),0,(struct sockaddr *)&sa,sizeof(struct sockaddr_in))<0){
            perror("send packet failed\n");
        }
        int count = 0;
        while(1){
            memset(recv_buf,'\0',sizeof(recv_buf));
            //printf("%d \n",count);
            recvfrom(sockfd_recv, recv_buf, sizeof(recv_buf), 0, &from, (socklen_t *) from_addr_len);
            ip_hdr =(struct ip *)(recv_buf + Ether_HDRLEN);
            struct in_addr inaddr = ip_hdr->ip_src;
            inet_ntop(AF_INET,&inaddr,src_ip,INET_ADDRSTRLEN);
            if(count >60){
                printf("%d hop request time out\n",i);
                break;
            }
            if(ip_hdr->ip_p==IPPROTO_ICMP && strcmp(src_ip,my_ip)!=0){ //icmp packet
                icmp_hdr = (struct icmp *)(recv_buf + Ether_HDRLEN + IP_HDRLEN);
                if(icmp_hdr->icmp_type==ICMP_TIMXCEED){ // if icmp packet is time exceed
                    printf("%d hop Src ip : %s  (time exceed)\n",i,src_ip);
                    break;
                }else if(icmp_hdr->icmp_type==ICMP_ECHOREPLY){ // if icmp packet is reply echo
                    printf("%d hop Src ip : %s  (icmp reply)\n",i,src_ip);
                    return 0;
                }else{
                    printf("unhandle icmp type :%d code :%d by %s  \n",icmp_hdr->icmp_type,icmp_hdr->icmp_code,src_ip);
                    break;
                }
            }
            count++; //for timeout
        }
    }

    return 0;
}