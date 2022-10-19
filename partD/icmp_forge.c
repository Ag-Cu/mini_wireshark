//
// Created by yt on 10/16/22.
//

// an ping packet to "192.168.163.1"
#include<stdio.h>
#include<string.h>
#include<sys/ioctl.h>
#include<net/if.h>
#include<netinet/in.h>
#include<netinet/ip.h>
#include<netinet/if_ether.h>
#include<arpa/inet.h>
#include <netinet/ip_icmp.h>

#define ICMP_DES_IP "192.168.163.1"      // 目的ip地址

extern struct ifreq ifreq_ip;
extern int sock_raw;
extern unsigned char *sendbuff;
extern int total_len;

extern unsigned short checksum(unsigned char* buf, int size);

void get_icmp() {
    struct icmphdr *icmph = (struct icmphdr*)(sendbuff + sizeof(struct iphdr) + sizeof(struct ethhdr));
    icmph->type = 8;
    icmph->code = 0;
    icmph->un.echo.id = htons(1);
    icmph->un.echo.sequence = htons(25856);
    total_len += sizeof (struct icmphdr);
    icmph->checksum = htons(
            checksum((unsigned char*)(sendbuff + sizeof(struct ethhdr) + sizeof (struct iphdr)), sizeof (struct icmphdr)));
}

void get_ip_icmp() {
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
    iph->protocol	= 1;
    iph->saddr	= inet_addr(inet_ntoa((((struct sockaddr_in *)&(ifreq_ip.ifr_addr))->sin_addr)));
    iph->daddr	= inet_addr(ICMP_DES_IP); // put destination IP address
    printf("destIP:%.2X\n",iph->daddr);
    total_len += sizeof(struct iphdr);
    get_icmp();

    iph->tot_len	= htons(total_len - sizeof(struct ethhdr));
    iph->check	= htons(
            checksum((unsigned char*)(sendbuff + sizeof(struct ethhdr)), sizeof(struct iphdr)));
}
