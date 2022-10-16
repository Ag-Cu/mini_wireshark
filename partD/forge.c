//
// Created by yt on 10/15/22.
//
#include<stdio.h>
#include<string.h>
#include<malloc.h>
#include<errno.h>
#include<sys/socket.h>
#include<sys/ioctl.h>
#include<net/if.h>
#include<netinet/in.h>
#include<netinet/if_ether.h>
#include<linux/if_packet.h>
#include "tcp_forge.h"
#include "arp_forge.h"
#include "icmp_forge.h"

// 主机对应网卡的MAC地址
#define DESTMAC0	0x00
#define DESTMAC1	0x50
#define DESTMAC2	0x56
#define DESTMAC3	0xc0
#define DESTMAC4	0x00
#define DESTMAC5	0x08

struct ifreq ifreq_i, ifreq_c, ifreq_ip, ifreq_arp;
int sock_raw;
unsigned char *sendbuff;
int total_len=0,send_len;

void get_eth_index();
void get_mac(int signal);

int main(){
    sock_raw=socket(AF_PACKET,SOCK_RAW,ETH_P_IP);
    if(sock_raw == -1)
        printf("error in socket");

    sendbuff=(unsigned char*)malloc(64); // increase in case of large data.
    memset(sendbuff,0,64);
    printf("请选择要伪造的协议类型：\n\t0 -> TCP\n\t1 -> ARP\n\t2 -> ICMP\n\t");
    int prot_type;                           // 标记MAC层封装协议类型
    scanf("%d", &prot_type);

    if (prot_type == 0) {           // TCP
        get_eth_index();  // interface number
        get_mac(prot_type);
        get_ip_tcp();
    } else if (prot_type == 1) {    // ARP
        get_eth_index();
        get_mac(prot_type);
        get_arp();
    } else {                        // ICMP
        get_eth_index();  // interface number
        get_mac(prot_type);
        get_ip_icmp();
    }

    struct sockaddr_ll sadr_ll;                     // 目的socket地址
    sadr_ll.sll_ifindex = ifreq_i.ifr_ifindex;      // interface索引
    sadr_ll.sll_halen   = ETH_ALEN;         // MAC地址长度
    sadr_ll.sll_addr[0]  = DESTMAC0;
    sadr_ll.sll_addr[1]  = DESTMAC1;
    sadr_ll.sll_addr[2]  = DESTMAC2;
    sadr_ll.sll_addr[3]  = DESTMAC3;
    sadr_ll.sll_addr[4]  = DESTMAC4;
    sadr_ll.sll_addr[5]  = DESTMAC5;

    printf("sending...\n");
    int i = 0;
    while(1){
        send_len = sendto(sock_raw,sendbuff,64,0,(const struct sockaddr*)&sadr_ll,sizeof(struct sockaddr_ll));
        if(send_len<0){
            printf("error in sending....sendlen=%d....errno=%d\n",send_len,errno);
            return -1;
        }
        i++;
        if (i > 20) {
            return 0;
        }
    }
}


// function definition
void get_eth_index(){
    memset(&ifreq_i,0,sizeof(ifreq_i));
    strncpy(ifreq_i.ifr_name,"ens33",IFNAMSIZ-1);

    if((ioctl(sock_raw,SIOCGIFINDEX,&ifreq_i))<0)
        printf("error in index ioctl reading");

    printf("index=%d\n",ifreq_i.ifr_ifindex);
}

// 获取MAC帧首部
void get_mac(int signal){
    memset(&ifreq_c,0,sizeof(ifreq_c));
    strncpy(ifreq_c.ifr_name,"ens33",IFNAMSIZ-1);

    if((ioctl(sock_raw,SIOCGIFHWADDR,&ifreq_c))<0)
        printf("error in SIOCGIFHWADDR ioctl reading");

    printf("Mac= %.2X-%.2X-%.2X-%.2X-%.2X-%.2X\n",
           (unsigned char)(ifreq_c.ifr_hwaddr.sa_data[0]),
           (unsigned char)(ifreq_c.ifr_hwaddr.sa_data[1]),
           (unsigned char)(ifreq_c.ifr_hwaddr.sa_data[2]),
           (unsigned char)(ifreq_c.ifr_hwaddr.sa_data[3]),
           (unsigned char)(ifreq_c.ifr_hwaddr.sa_data[4]),
           (unsigned char)(ifreq_c.ifr_hwaddr.sa_data[5]));

    printf("ethernet packaging start ... \n");

    struct ethhdr *eth = (struct ethhdr *)(sendbuff);
    eth->h_source[0] = (unsigned char)(ifreq_c.ifr_hwaddr.sa_data[0]);
    eth->h_source[1] = (unsigned char)(ifreq_c.ifr_hwaddr.sa_data[1]);
    eth->h_source[2] = (unsigned char)(ifreq_c.ifr_hwaddr.sa_data[2]);
    eth->h_source[3] = (unsigned char)(ifreq_c.ifr_hwaddr.sa_data[3]);
    eth->h_source[4] = (unsigned char)(ifreq_c.ifr_hwaddr.sa_data[4]);
    eth->h_source[5] = (unsigned char)(ifreq_c.ifr_hwaddr.sa_data[5]);

    if (signal == 0 || signal == 2) {
        eth->h_dest[0]    =  DESTMAC0;
        eth->h_dest[1]    =  DESTMAC1;
        eth->h_dest[2]    =  DESTMAC2;
        eth->h_dest[3]    =  DESTMAC3;
        eth->h_dest[4]    =  DESTMAC4;
        eth->h_dest[5]    =  DESTMAC5;

        eth->h_proto = htons(ETH_P_IP);   //0x0800
    } else {
        eth->h_dest[0]    =  0xff;
        eth->h_dest[1]    =  0xff;
        eth->h_dest[2]    =  0xff;
        eth->h_dest[3]    =  0xff;
        eth->h_dest[4]    =  0xff;
        eth->h_dest[5]    =  0xff;

        eth->h_proto = htons(ETH_P_ARP);
    }
    printf("ethernet packaging done.\n");
    total_len+=sizeof(struct ethhdr);
}

