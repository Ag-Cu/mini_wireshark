cmake_minimum_required(VERSION 3.21)
project(partC_analysis C)

set(CMAKE_C_STANDARD 11)

include_directories(.)

add_executable(partC_analysis
        filter.c
        filter.h
        main.c
        packetProcess.c
        packetProcess.h)
