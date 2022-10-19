//
// Created by yt on 10/15/22.
//

#include "arp_forge.h"
#include<stdio.h>
#include<string.h>
#include<sys/ioctl.h>
#include<net/if.h>
#include<netinet/in.h>
#include<netinet/if_ether.h>
#include<netinet/udp.h>
#include<arpa/inet.h>

#pragma pack(1)      // 强制结构体紧凑分配

#define TARGET_IP "192.168.163.1"          // target IP address

extern struct ifreq ifreq_arp, ifreq_ip;
extern int sock_raw;
extern unsigned char *sendbuff;
extern int total_len;

struct arp_body {
    unsigned char	S_H_addr[6];
    uint32_t	    S_P_addr;
    unsigned char	T_H_addr[6];
    uint32_t	    T_P_addr;
};

void get_arp(){
    memset(&ifreq_arp,0,sizeof(ifreq_arp));
    strncpy(ifreq_arp.ifr_name,"ens33",IFNAMSIZ-1);
    if(ioctl(sock_raw,SIOCGIFADDR,&ifreq_arp)<0){
        printf("error in SIOCGIFADDR \n");
    }

    printf("%s\n",inet_ntoa((((struct sockaddr_in*)&(ifreq_arp.ifr_addr))->sin_addr)));

    struct arphdr *arph = (struct arphdr*)(sendbuff + sizeof (struct ethhdr));
    arph->ar_hrd = htons(1);
    arph->ar_pro = htons(2048);
    arph->ar_hln = 6;
    arph->ar_pln = 4;
    arph->ar_op = htons(1);

    struct arp_body *arpb = (struct arp_body*)(sendbuff + sizeof (struct ethhdr) + sizeof (struct arphdr));
    struct ethhdr *eth = (struct ethhdr *)(sendbuff);
    arpb->S_H_addr[0] = eth->h_source[0];
    arpb->S_H_addr[1] = eth->h_source[1];
    arpb->S_H_addr[2] = eth->h_source[2];
    arpb->S_H_addr[3] = eth->h_source[3];
    arpb->S_H_addr[4] = eth->h_source[4];
    arpb->S_H_addr[5] = eth->h_source[5];

    arpb->S_P_addr = inet_addr(inet_ntoa((((struct sockaddr_in*)&(ifreq_arp.ifr_addr))->sin_addr)));

    arpb->T_H_addr[0] = 0x00;
    arpb->T_H_addr[1] = 0x00;
    arpb->T_H_addr[2] = 0x00;
    arpb->T_H_addr[3] = 0x00;
    arpb->T_H_addr[4] = 0x00;
    arpb->T_H_addr[5] = 0x00;

    arpb->T_P_addr = inet_addr(TARGET_IP); // put target IP address
}
