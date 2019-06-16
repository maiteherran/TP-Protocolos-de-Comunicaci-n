cmake_minimum_required(VERSION 3.10)
project(TpProtos C)

set(CMAKE_C_STANDARD 99)

add_executable(
        TpProtos
        main.c main.h
        Utils
        Proxy
        Admin
        Client
        )