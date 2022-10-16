#include <stdio.h>
#include <string.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <netinet/ip_icmp.h>
#include <linux/if_arp.h>
#include "packetProcess.h"

struct sockaddr_in source, dest;
int total = 0, tcp = 0, udp = 0, icmp = 0, igmp = 0, other = 0, arp_packet = 0;
int ipheader_len;

// convert uint32 to ip address
void uint32_to_ipadder(uint32_t num_32, uint8_t* n1, uint8_t* n2, uint8_t* n3, uint8_t* n4) {
    *n4 = num_32;
    *n3 = num_32 >> 8;
    *n2 = num_32 >> 16;
    *n1 = num_32 >> 24;
}
// print format of etherNet-header
void mac_header(unsigned char *buffer){
    struct ethhdr *eth = (struct ethhdr*)(buffer);
    printf("\nEthernet Header\n");
    printf("\t|-Source Address      : %.2x-%.2x-%.2x-%.2x-%.2x-%.2x\n",
           eth->h_source[0], eth->h_source[1], eth->h_source[2],
           eth->h_source[3], eth->h_source[4], eth->h_source[5]);
    printf("\t|-Destination Address : %.2x-%.2x-%.2x-%.2x-%.2x-%.2x\n",
           eth->h_dest[0], eth->h_dest[1], eth->h_dest[2],
           eth->h_dest[3], eth->h_dest[4], eth->h_dest[5]);
    printf("\t|-Protocol            : %d\n", ntohs(eth->h_proto));
}

// print format of ip-header
void ip_header(unsigned char *buffer){
    /*
     * Todo("exercise 2 : Complete the code of Step 1 correctly, and submit your source code.")
     */
    struct iphdr *ip = (struct iphdr*)(buffer + sizeof(struct ethhdr));
    uint8_t num1, num2, num3, num4;
    printf("\nIP Header\n");
    printf("\t|-Version                 : %d\n", ip->version);
    printf("\t|-Internet Header Length  : %d DWORDS or %d Bytes\n", ip->ihl, 4 * ip->ihl);
    printf("\t|-Type of Service         : %d\n", ip->tos);
    printf("\t|-Total length            : %d\n", ntohs(ip->tot_len));
    printf("\t|-Identification          : %d\n", ntohs(ip->id));
    printf("\t|-TTL                     : %d\n", ip->ttl);
    printf("\t|-Protocol                : %d\n", ip->protocol);
    printf("\t|-Header Checksum         : %d\n", ntohs(ip->check));
    uint32_to_ipadder(ip->saddr, &num1, &num2, &num3, &num4);
    printf("\t|-Source IP               : %d.%d.%d.%d\n", num4, num3, num2, num1);
    uint32_to_ipadder(ip->daddr, &num1, &num2, &num3, &num4);
    printf("\t|-Destination IP          : %d.%d.%d.%d\n", num4, num3, num2, num1);
}

// print format of arp-header
void arp_header(unsigned char *buffer){
    /*
     * Todo("exercise 2 : Complete the code of Step 1 correctly, and submit your source code.")
     */
    struct arphdr *arp = (struct arphdr*)(buffer + sizeof(struct ethhdr));
    printf("\nARP Header\n");
    printf("\t|-Hardware type           : %d\n", arp->ar_hrd);
    printf("\t|-Protocol type           : %d\n", arp->ar_pro);
    printf("\t|-Hardware address length : %d\n", arp->ar_hln);
    printf("\t|-Protocol address length : %d\n", arp->ar_pln);
    printf("\t|-Operation               : %d\n", arp->ar_op);
}

// print format of tcp-header
void tcp_header(unsigned char* buffer){
    /*
     * Todo("exercise 2 : Complete the code of Step 1 correctly, and submit your source code.")
     */
    struct tcphdr *tcp = (struct tcphdr*) (buffer + sizeof(struct ethhdr) + sizeof (struct iphdr));
    printf("\nTCP Header\n");
    printf("\t|-Source port             : %d\n", ntohs(tcp->th_sport));
    printf("\t|-Destination port        : %d\n", ntohs(tcp->th_dport));
    printf("\t|-Sequence number         : %d\n", ntohs(tcp->th_seq));
    printf("\t|-Acknowledgement number  : %u\n", ntohs(tcp->th_ack));
    printf("\t|-Data offset             : %d\n", tcp->th_off);
    printf("\t|-Reserved                : %d\n", tcp->th_x2);
    printf("\t|-Flags                   : \n");
    printf("\t\t|-ACK                 : %d\n", tcp->ack);
    printf("\t\t|-PSH                 : %d\n", tcp->psh);
    printf("\t\t|-RST                 : %d\n", tcp->rst);
    printf("\t\t|-SYN                 : %d\n", tcp->syn);
    printf("\t\t|-FIN                 : %d\n", tcp->fin);
    printf("\t|-Window                  : %d\n", ntohs(tcp->window));
    printf("\t|-Checksum                : %d\n", ntohs(tcp->check));
    printf("\t|-Urgent pointer          : %d\n", ntohs(tcp->urg_ptr));
}

// print format of udp-header
void udp_header(unsigned char* buffer){
    /*
     * Todo("exercise 2 : Complete the code of Step 1 correctly, and submit your source code.")
     */
    struct udphdr* udp = (struct udphdr*) (buffer + sizeof(struct ethhdr) + sizeof (struct iphdr));
    printf("\nUDP Header\n");
    printf("\t|-Source port             : %d\n", ntohs(udp->uh_sport));
    printf("\t|-Destination port        : %d\n", ntohs(udp->uh_dport));
    printf("\t|-Length                  : %d\n", ntohs(udp->uh_ulen));
    printf("\t|-Checksum                : %d\n", ntohs(udp->uh_sum));
}

// print format of icmp-header
void icmp_header(unsigned char *buffer){
    /*
     * Todo("exercise 2 : Complete the code of Step 1 correctly, and submit your source code.")
     */
    struct icmphdr* icmp = (struct icmphdr*) (buffer + sizeof(struct ethhdr) + sizeof (struct iphdr));
    printf("\nICMP Header\n");
    printf("\t|-Type                    : %d\n", icmp->type);
    printf("\t|-Code                    : %d\n", icmp->code);
    printf("\t|-Checksum                : %d\n", ntohs(icmp->checksum));
    printf("\t|-Sequence                : %d\n", ntohs(icmp->un.echo.sequence));
    printf("\t|-id                      : %d\n", ntohs(icmp->un.echo.id));
}

// print format of payload
void payload(unsigned char* buffer,int buffer_len){

    printf("\nData\n");
    for(int i=0; i<buffer_len; i++){
        if(i!=0 && i%16==0)
            printf("\n");
        printf(" %.2X ",buffer[i]);
    }

    printf("\n");
}

// print ICMP packet
void ICMP_printer(unsigned char *buffer, int buffer_len){
    printf("\n---------------------------ICMP Packet---------------------------");
    // print header
    mac_header(buffer);
    ip_header(buffer);
    icmp_header(buffer);
    // print packet payload
    unsigned char *data = (buffer + ipheader_len  + sizeof(struct ethhdr) + sizeof(struct icmphdr) + sizeof (struct iphdr));
    int data_len = buffer_len - (ipheader_len  + sizeof(struct ethhdr) + sizeof(struct icmphdr) + sizeof (struct iphdr));
    payload(data, data_len);
    printf("--------------------------------------------------------------\n\n\n");
}

// print ARP packet
void ARP_printer(unsigned char *buffer){
    /*
     * Todo("exercise 2 : Complete the code of Step 1 correctly, and submit your source code.")
     */
    printf("\n----------------------------ARP Packet---------------------------");
    // print header
    mac_header(buffer);
    ip_header(buffer);
    arp_header(buffer);
    printf("--------------------------------------------------------------\n\n\n");
}

// print TCP packet
void TCP_printer(unsigned char *buffer, int buffer_len){
    /*
     * Todo("exercise 2 : Complete the code of Step 1 correctly, and submit your source code.")
     */
    printf("\n----------------------------TCP Packet---------------------------");
    // print header
    mac_header(buffer);
    ip_header(buffer);
    tcp_header(buffer);
    // print packet payload
    unsigned char *data = (buffer + ipheader_len  + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof (struct tcphdr));
    int data_len = buffer_len - (ipheader_len  + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof (struct tcphdr));
    payload(data, data_len);
    printf("--------------------------------------------------------------\n\n\n");
}

// print UDP packet
void UDP_printer(unsigned char* buffer, int buffer_len){
    /*
     * Todo("exercise 2 : Complete the code of Step 1 correctly, and submit your source code.")
     */
    printf("\n----------------------------UDP Packet---------------------------");
    // print header
    mac_header(buffer);
    ip_header(buffer);
    udp_header(buffer);
    // print packet payload
    unsigned char *data = (buffer + ipheader_len  + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr));
    int data_len = buffer_len - (ipheader_len  + sizeof(struct ethhdr) + sizeof(struct iphdr)  + sizeof(struct udphdr));
    payload(data, data_len);
    printf("--------------------------------------------------------------\n\n\n");
}

// packet process func
void packet_process(unsigned char* buffer, int buffer_len){
    ++total;
    struct ethhdr *eth = (struct ethhdr*)(buffer);
    switch((int) ntohs(eth->h_proto)){
        case 2048:{  // 0800 -> ip
            struct iphdr *ip = (struct iphdr*)(buffer + sizeof(struct ethhdr));
            switch(ip->protocol){
                case 1:                                     // ICMP packet
                    ++icmp;
                    ICMP_printer(buffer, buffer_len);
                    break;

                case 2:
                    ++igmp;
                    break;

                case 6:                                     // TCP packet
                    ++tcp;
                    TCP_printer(buffer, buffer_len);         // print packet info
                    break;

                case 17:                                    // UDP packet
                    ++udp;
                    UDP_printer(buffer,buffer_len);          // print packet info
                    break;

                default:
                    ++other;
            }
            break;
        }

        case 2054:  // 0806 -> arp
            ++arp_packet;
            ARP_printer(buffer);            // print ARP packet info
            break;

        default:
            ++other;
    }

    printf("Result: [TCP : %d], [UDP : %d], [ARP : %d], [ICMP : %d], [IGMP : %d], [OTHER : %d], [TOTAL : %d]\n",
           tcp, udp, arp_packet, icmp, igmp, other, total);
}