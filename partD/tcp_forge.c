//
// Created by yt on 10/15/22.
//

// an syn packet to "35.224.170.84"
#include<stdio.h>
#include<string.h>
#include<sys/ioctl.h>
#include<net/if.h>
#include<netinet/in.h>
#include<netinet/ip.h>
#include<netinet/if_ether.h>
#include<netinet/udp.h>
#include<arpa/inet.h>
#include <netinet/tcp.h>

extern struct ifreq ifreq_ip;
extern int sock_raw;
extern unsigned char *sendbuff;
extern int total_len;
uint32_t seq_num = 2636;        // begin seq, can be random num
uint32_t ack_num = 0;

unsigned short checksum(unsigned char* buf, int size) {
    unsigned int checkSum = 0;
    for (int i = 0; i < size; i += 2) {
        unsigned short first = (unsigned short)buf[i] << 8;
        unsigned short second = (unsigned short)buf[i+1] & 0x00ff;
        checkSum += first + second;
    }

    while (1) {
        unsigned short c = (checkSum >> 16);
        if (c > 0) {
            checkSum = (checkSum << 16) >> 16;
            checkSum += c;
        } else {
            break;
        }
    }

    return ~checkSum;
}

void get_data(){
    sendbuff[total_len++]	=	0x68;
    sendbuff[total_len++]	=	0x65;
    sendbuff[total_len++]	=	0x6C;
    sendbuff[total_len++]	=	0x6C;
    sendbuff[total_len++]	=	0x6F;
}

void get_tcp(){

    struct tcphdr *th = (struct tcphdr *)(sendbuff + sizeof(struct iphdr) + sizeof(struct ethhdr));

    th->th_sport = htons(42769);
    th->th_dport = htons(80);       // 80端口
    th->seq = htons(seq_num);
    th->ack_seq = htons(ack_num);
    th->th_off = 5;          // 首部长度
    th->th_x2 = 0;
    th->urg = 0;
    th->ack = 0;
    th->psh = 0;
    th->syn = 1;
    th->fin = 0;
    th->window = htons(64240);
    th->urg_ptr = htons(0);
    total_len+= sizeof(struct tcphdr);
    th->check = htons(
            checksum((unsigned char*)(sendbuff + sizeof(struct ethhdr) + sizeof (struct iphdr)),sizeof(struct tcphdr)));
}

void get_ip_tcp(){
    memset(&ifreq_ip,0,sizeof(ifreq_ip));
    strncpy(ifreq_ip.ifr_name,"ens33",IFNAMSIZ-1);
    if(ioctl(sock_raw,SIOCGIFADDR,&ifreq_ip)<0){
        printf("error in SIOCGIFADDR \n");
    }

    printf("%s\n",inet_ntoa((((struct sockaddr_in*)&(ifreq_ip.ifr_addr))->sin_addr)));

    struct iphdr *iph = (struct iphdr*)(sendbuff + sizeof(struct ethhdr));
    iph->ihl	= 5;
    iph->version	= 4;
    iph->tos	= 0;
    iph->id		= htons(10201);
    iph->ttl	= 64;
    iph->protocol	= 6;
    iph->saddr	= inet_addr(inet_ntoa((((struct sockaddr_in *)&(ifreq_ip.ifr_addr))->sin_addr)));
    iph->daddr	= inet_addr("35.224.170.84"); // put destination IP address
    printf("destIP:%.2X\n",iph->daddr);
    total_len += sizeof(struct iphdr);
    get_tcp();

    iph->tot_len	= htons(total_len - sizeof(struct ethhdr));
    iph->check	= htons(
            checksum((unsigned char*)(sendbuff + sizeof(struct ethhdr)),sizeof(struct iphdr)));
}
