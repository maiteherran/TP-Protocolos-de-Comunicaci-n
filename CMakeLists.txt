cmake_minimum_required(VERSION 3.12)
project(TpProtos C)

set(CMAKE_C_STANDARD 99)

add_executable(TpProtos main.c main.h
        Utils/netutils.c Utils/netutils.h
        Utils/buffer.c Utils/buffer.h
        Utils/selector.c Utils/selector.h
        Utils/stm.c Utils/stm.h
        Utils/server_arguments.c Utils/server_arguments.h
        Proxy/proxy5nio.c Proxy/proxy5nio.h Proxy/Parsers/http_parser.c Proxy/Parsers/http_parser.h Proxy/Parsers/http_chunk_decoder.c Proxy/Parsers/http_chunk_decoder.h Proxy/proxy_reporter.c Proxy/proxy_reporter.h Utils/log.c Utils/log.h
        Admin/HpcpParser/hpcpRequest.c Admin/HpcpParser/hpcpRequest.h Admin/admin.c Admin/admin.h Proxy/config.h Proxy/metrics.h Utils/string_utils.c Utils/string_utils.h Admin/auth.c Admin/auth.h)