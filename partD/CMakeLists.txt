cmake_minimum_required(VERSION 3.23)
project(ForgeProject C)

set(CMAKE_C_STANDARD 11)
add_executable(partD forge.c tcp_forge.h tcp_forge.c arp_forge.c arp_forge.h icmp_forge.c icmp_forge.h)
