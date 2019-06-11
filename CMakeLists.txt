cmake_minimum_required(VERSION 3.12)
project(ProbandoTpProtos C)

set(CMAKE_C_STANDARD 99)

add_executable(ProbandoTpProtos main.c main.h
        Utils/netutils.c Utils/netutils.h
        Utils/buffer.c Utils/buffer.h
        Utils/selector.c Utils/selector.h
        Utils/stm.c Utils/stm.h
        proxy5nio.c proxy5nio.h Parser/http_parser.c Parser/http_parser.h Parser/http_chunk_decoder.c Parser/http_chunk_decoder.h proxy_reporter.c proxy_reporter.h Utils/log.c Utils/log.h)