#include <stdbool.h>
#include <netinet/if_ether.h>
#include <netinet/in.h>
#include <memory.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include "filter.h"
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <stdio.h>

bool filterByIpAddress(unsigned char *buffer, char *ip_addr, int type){
    struct sockaddr_in source, dest;
    struct ethhdr *eth = (struct ethhdr *)(buffer);
    // if the type of packet is not IP.
    if((int)ntohs(eth->h_proto) != 2048){
        return false;
    }

    struct iphdr *ip = (struct iphdr*)(buffer + sizeof(struct ethhdr));
    memset(&source, 0, sizeof(source));
    source.sin_addr.s_addr = ip->saddr;
    memset(&dest, 0, sizeof(dest));
    dest.sin_addr.s_addr = ip->daddr;

    char *source_ip;
    char *dest_ip;
    char temp[20];
    source_ip=inet_ntoa(source.sin_addr);
    strcpy(temp,source_ip);
    dest_ip=inet_ntoa(dest.sin_addr);
    if(type == 0){          // filter by source address
        if (!strcmp(temp,ip_addr)){
            return true;
        }else{
            return false;
        }
    }else{                  // filter by distination address
        if(!strcmp(dest_ip,ip_addr)){
            return true;
        }else{
            return false;
        }
    }
}

void trans_MAC(unsigned char array[ETH_ALEN], char* s) {
    sprintf(s,"%02x:%02x:%02x:%02x:%02x:%02x",array[0],
            array[1], array[2], array[3], array[4],array[5]);
}

bool filterByMacAddress(unsigned char *buffer, char *mac_addr, int type){
    /*
     * Todo("exercise 3 : Complete the code of Step 2 correctly, and submit your source code.")
     */

    struct ethhdr *eth = (struct ethhdr *)(buffer);
    char s[17];
    if (type == 0) {
        trans_MAC(eth->h_source, (char*)s);
        if (!strcmp(mac_addr, (char*)s)) {
            return true;
        } else {
            return false;
        }
    } else {
        trans_MAC(eth->h_dest, (char*)s);
        if (!strcmp(mac_addr, (char*)s)) {
            return true;
        } else {
            return false;
        }
    }
}

bool filterByProtocol(unsigned char* buffer, int type) {
    /*
     * Todo("exercise 3 : Complete the code of Step 2 correctly, and submit your source code.")
     */
    struct ethhdr *eth = (struct ethhdr *) (buffer);
    struct iphdr *ip = (struct iphdr *) (buffer + sizeof(struct ethhdr));
    switch (type) {
        case 1:
            if ((int) ntohs(eth->h_proto) != 2054) {        // arp
                return false;
            } else {
                return true;
            }
            break;
        case 2:
            if ((int) ntohs(eth->h_proto) != 2048) {
                return false;
            }
            if (ip->protocol != 1) {            // icmp
                return false;
            } else {
                return true;
            }
            break;
        case 3:
            if ((int) ntohs(eth->h_proto) != 2048) {
                return false;
            }
            if (ip->protocol != 6) {            // tcp
                return false;
            } else {
                return true;
            }
            break;
        case 4:
            if ((int) ntohs(eth->h_proto) != 2048) {
                return false;
            }
            if (ip->protocol != 17) {           // udp
                return false;
            } else {
                return true;
            }
            break;
        default:
            break;
    }
}
bool filterByPort(unsigned char *buffer, unsigned short port, int type){
    /*
     * Todo("exercise 3 : Complete the code of Step 2 correctly, and submit your source code.")
     */
    struct ethhdr *eth = (struct ethhdr *)(buffer);
    // if the type of packet is not IP.
    if((int)ntohs(eth->h_proto) != 2048){
        return false;
    }
    struct iphdr *ip = (struct iphdr*)(buffer + sizeof(struct ethhdr));
    if (ip->protocol != 17 && ip->protocol != 6) {
        return false;
    }
    struct tcphdr *tcp = (struct tcphdr*) (buffer + sizeof(struct ethhdr) + sizeof (struct iphdr));
    struct udphdr *udp = (struct udphdr*) (buffer + sizeof(struct ethhdr) + sizeof (struct iphdr));
    if (type == 0) {
        if (ip->protocol == 6) {
            if (ntohs(tcp->th_sport) != port) {
                return false;
            } else {
                return true;
            }
        } else {
            if (ntohs(udp->uh_sport) != port) {
                return false;
            } else {
                return true;
            }
        }
    } else {
        if (ip->protocol == 6) {
            if (ntohs(tcp->th_dport) != port) {
                return false;
            } else {
                return true;
            }
        } else {
            if (ntohs(udp->uh_dport) != port) {
                return false;
            } else {
                return true;
            }
        }
    }
}
