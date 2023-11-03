#include <netinet/if_ether.h>
#include <netinet/ip_icmp.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netpacket/packet.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <netdb.h>
#include <time.h>

#define IP_HDRLEN 20
#define ICMP_HDRLEN 8
#define Ether_HDRLEN 14
#define IP_ADDR_LEN 4
#define Packet_Len Ether_HDRLEN + IP_HDRLEN + ICMP_HDRLEN

#define BUFFER_SIZE 512
#define DEVICE_NAME "ens33"
#define DEBUG 0 




uint16_t checksum(uint16_t *,int);
void set_ip_hdr(struct ip*,char *,int);
void set_icmp_hdr(struct icmp*, int16_t);
void print_buffer(u_int8_t *);


int main(int argc ,char** argv){
    srand( time(NULL) );
    int sockfd_send = 0, sockfd_recv = 0;
    int ttl = 0;
    int result_send = 0,result_recv = 0;
    int setsockopt_ret;

    uint8_t buf_send[BUFFER_SIZE],buf_recv[BUFFER_SIZE];

    char src_ip[16];    // icmp reply 的 來源IP
    char *my_ip, *obj_ip=argv[2];

    struct ip *ip_hdr;
    struct icmp *icmp_hdr;
    struct sockaddr_in sa;
    struct in_addr dst,*src;
    struct ifreq ifr;

    if(DEBUG){
        // printf("address of ip_hdr: %p\n", ip_hdr);
        printf("address of icmp_hdr: %p\n", icmp_hdr);
        printf("address of buffer_send: %p\n", buf_send);
    }


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
    
    if((sockfd_send = socket(AF_INET, SOCK_RAW ,IPPROTO_ICMP)) < 0)
	{
		perror("sockfd_send\n");
		exit(1);
	}

    if((sockfd_recv = socket(AF_INET, SOCK_RAW ,IPPROTO_ICMP)) < 0)
	{
		perror("sockfd_recv\n");
		exit(1);
	}


    memset(&sa,'\0',sizeof(sa));
    memset(buf_send,'\0',sizeof(buf_send));
    memset(&ifr,'\0',sizeof(ifr));

    // Get IP from interface name
	// strncpy(ifr.ifr_name, DEVICE_NAME,IF_NAMESIZE);
    
    // if(ioctl(sockfd, SIOCGIFINDEX, &ifr) == -1){
	// 	perror("SIOCGIFINDEX");
	// 	exit(-1);
	// }

    // if(ioctl(sockfd, SIOCGIFHWADDR, &ifr) == -1){
	// 	perror("SIOCGIFHWADDR");
	// 	exit(-1);
	// }

	// if(ioctl(sockfd, SIOCGIFADDR, &ifr) == -1){
	// 	perror("ioctl\n");
	// }

    // Get source IP
    my_ip = inet_ntoa(((struct sockaddr_in *)&(ifr.ifr_addr))->sin_addr);
    inet_pton(AF_INET, obj_ip, &dst);
    if(DEBUG){
        printf("src IP: %s\n", my_ip);
        printf("obj IP: %s\n", obj_ip);
    }

    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = inet_addr(obj_ip);
    // char *p;
    // ttl = strtol(argv[1],&p,10);// change number string to int 
    ttl = atoi(argv[1]);
    
    printf("traceroute to %s, %s hops max, 84 byte packets\n", obj_ip, argv[1]);
    for(int i=1;i<=ttl;i++){
        memset(buf_send,'\0',sizeof(buf_send));
        if(DEBUG){
	    printf("init buf_send\n"); 
  	    print_buffer(buf_send);
	}
        icmp_hdr = (struct icmp *)buf_send;
        // fill packet
        // set_ip_hdr(ip_hdr, obj_ip, i);
        // ip_hdr->ip_sum = checksum((uint16_t *)ip_hdr, IP_HDRLEN);
        set_icmp_hdr(icmp_hdr, i);
        icmp_hdr->icmp_cksum = checksum((uint16_t *)icmp_hdr, ICMP_HDRLEN);

        // printf("IP header length : %ld\n",sizeof(ip_hdr));

        if ((setsockopt_ret = setsockopt(sockfd_send, IPPROTO_IP, IP_TTL, (char *)&i, sizeof(int))) != 0) {
            perror("setsockopt");
            exit(1);
        }

        if ((setsockopt_ret = setsockopt(sockfd_recv, IPPROTO_IP, IP_TTL, (char *)&i, sizeof(int))) != 0) {
            perror("setsockopt");
            exit(1);
        }

        if((result_send = sendto(sockfd_send, buf_send, 8, 0, (struct sockaddr *)&sa, sizeof(sa))) < 0){
            perror("send packet failed");
        }
        if(DEBUG){
	    printf("seted buf_send\n");
	    print_buffer(buf_send);
	}

        int count = 0;

        // recv
        while(1){
            memset(buf_recv,'\0',sizeof(buf_recv));
	    if(DEBUG){
		printf("init buf_recv:\n");
		print_buffer(buf_recv);
	    }

            if((result_recv = recv(sockfd_recv, buf_recv, sizeof(buf_recv), 0)) <= 0){
                perror("recvfrom");
                exit(1);
           }


            ip_hdr = (struct ip *)(buf_recv);
            struct in_addr inaddr = ip_hdr->ip_src;
            inet_ntop(AF_INET,&inaddr,src_ip,INET_ADDRSTRLEN);
            // if(count >10){
            //     printf("%d\t...\n",i);
            //     break;
            // }
	    if(DEBUG){
		printf("src_ip: %s\n", src_ip);
		printf("seted buf_recv:\n");
	        print_buffer(buf_recv);
                printf("%d\n", ip_hdr->ip_p);
	    }

            if(ip_hdr->ip_p == IPPROTO_ICMP && strcmp(src_ip,my_ip) != 0){
                icmp_hdr = (struct icmp *)(buf_recv + IP_HDRLEN);
                // time exceed
                if(icmp_hdr->icmp_type == ICMP_TIMXCEED){
                    printf("%d\t%s  (ttl exceeded)\n",i,src_ip);
                    break;
                // echo reply
                }else if(icmp_hdr->icmp_type == ICMP_ECHOREPLY){
                    printf("%d\t%s  (icmp reply)\n",i,src_ip);
                    return 0;
                }else{
                    printf("%d\t...\n",i);
                    // printf("type :%d code :%d from %s  \n",icmp_hdr->icmp_type,icmp_hdr->icmp_code,src_ip);
                    break;
                }
            }
            count++; //for timeout
        }
    }

    return 0;
}

uint16_t checksum(uint16_t *addr, int len) {
    unsigned long sum = 0;

    for (int i = 0; i < len / 2; i++) {
        sum += addr[i];
    }

    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    return (uint16_t)~sum;
}

// unsigned short checksum(unsigned short *addr,int len){
//     int nleft = len;
//     int sum = 0;
//     unsigned short *w = addr;
//     unsigned short result = 0;

//     while(nleft>1){
//         sum += *w++;
//         nleft-=2;
//     }

//     if(nleft == 1){
//         *(unsigned *)(&result) = *(unsigned char *)w;
//         sum+=result;
//     }
//     sum =(sum >> 16)+(sum & 0xffff);
//     sum += (sum >> 16);
//     result = ~sum;

//     return result;
// }

// header seting
void set_ip_hdr(struct ip* ip_hdr,char *dst ,int ttl){
    struct in_addr dst_ip,src_ip;
    inet_pton(AF_INET,dst,&dst_ip);
    ip_hdr->ip_dst = dst_ip;
    ip_hdr->ip_v = 4;
    ip_hdr->ip_hl = 5;
    ip_hdr->ip_len = IP_HDRLEN+ICMP_HDRLEN;
    ip_hdr->ip_id = rand()%256;
    ip_hdr->ip_off = htons(0);
    ip_hdr->ip_ttl = (unsigned char)ttl;
    ip_hdr->ip_p = IPPROTO_ICMP;
}
void set_icmp_hdr(struct icmp* icmp_hdr, int16_t seq){

    icmp_hdr->icmp_type = ICMP_ECHO;
    icmp_hdr->icmp_code = 0;
    icmp_hdr->icmp_id = rand()%256;
    icmp_hdr->icmp_seq = htons(seq);
}

void print_buffer(u_int8_t *buffer){
	for(int i=0; i<60; i++){
		printf("%02X ", buffer[i]);
		if ((i+1) % 16 == 0 && i != 0)
			printf("\n");
	}
	printf("\n");
}
