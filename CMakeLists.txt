cmake_minimum_required(VERSION 3.12)
project(ProbandoTpProtos C)

set(CMAKE_C_STANDARD 99)

add_executable(ProbandoTpProtos main.c main.h Parser/picohttpparser.c Parser/picohttpparser.h
        Utils/netutils.c Utils/netutils.h
        Utils/buffer.c Utils/buffer.h
        Utils/selector.c Utils/selector.h
        Utils/stm.c Utils/stm.h
        Utils/socks5nio.c Utils/socks5nio.h)