#include <unistd.h>
#include <stdio.h>
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <arpa/inet.h>
#include "packetProcess.h"
#include "filter.h"

#define ARP 1
#define ICMP 2
#define TCP 3
#define UDP 4

int main(){
    int PACKET_LEN = 16000;
    int PACKET_AMOUNT = 1000;
    unsigned char buffer[PACKET_LEN];
    struct sockaddr saddr;
    struct packet_mreq mr;

    // create a raw socket
    int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if(sock < 0){
        printf("error in creating socket.\n");
        return -1;
    }

    // turn on the promiscuous mode
    mr.mr_type = PACKET_MR_PROMISC;
    setsockopt(sock, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &mr, sizeof(mr));

    printf("Start sniffing...\n");
    int count = 0;
    while(1){
        if(count > PACKET_AMOUNT)
            break;

        int saddr_len = sizeof saddr;
        int data_size = recvfrom(sock, buffer, PACKET_LEN, 0,
                                 &saddr, (socklen_t*)&saddr_len);

        /*
         * Todo : In this experiment, you need to analyze the structure of ARP, ICMP, TCP, and UDP packets and
         * print detailed information of them. Refer to the ICMP analysis function given in PacketProcess.h
         * and packetProcess.c to complete the analysis function of the remaining three packets.
         */
        if(data_size > 0){
            /*
             * The following is the sample usage of filter_function and packet_process_function.
             */
            if(filterByProtocol(buffer, UDP)){
                packet_process(buffer, data_size);
            }
        }else{
            printf("error in recvfrom func\n");
            return -1;
        }
        count++;
    }

    close(sock);
    return 0;
}
