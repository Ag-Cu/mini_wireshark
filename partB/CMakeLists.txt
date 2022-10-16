cmake_minimum_required(VERSION 3.20)
project(miniWireShark C)

set(CMAKE_C_STANDARD 99)

add_executable(miniWireShark main.c packetProcess.h packetProcess.c)
