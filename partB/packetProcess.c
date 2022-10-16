#include <stdio.h>
#include "packetProcess.h"

void packet_print(unsigned char* buffer, int buffer_len){
    printf("\n---------------------------- Packet ----------------------------\n");
    /*
     * Todo("Exercise 1: complete the packet_print function.")
     */
     for (int i = 0; i < buffer_len; i++) {
         printf("%02x", buffer[i]);
         if ((i + 1) % 16 == 0) {
             printf("\n");
         } else {
             printf("  ");
         }
     }
    printf("\n----------------------- Packet finished ------------------------");
}
