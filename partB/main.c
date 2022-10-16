#include <unistd.h>
#include <stdio.h>
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <arpa/inet.h>
#include "packetProcess.h"

int main(){

    /*
     * In this experiment, main.c is supplemented to realize the sniffing function of network packets,
     * we've already shown some code.
     *
     * exercise 1 : Complete the code below to make sure your function works correctly as required.
     * You need to submit your source code.
     */

    int PACKET_LEN = 16000;
    int PACKET_AMOUNT = 1;
    unsigned char buffer[PACKET_LEN];
    struct sockaddr saddr;
    struct packet_mreq mr;

    // create a raw socket
    int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if(sock < 0){
        printf("Error in creating socket.\n");
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

        if(data_size > 0){
            /*
             * Todo("Exercise 1: complete the packet_print function defined in file packetProcess.h.")
             */
            packet_print(buffer, data_size);
        }else{
            printf("Error in recvfrom func\n");
            return -1;
        }
        count++;
    }

    close(sock);
    return 0;
}
