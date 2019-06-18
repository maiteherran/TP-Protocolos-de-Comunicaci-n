cmake_minimum_required(VERSION 3.5)
project(TpProtos C)

set(CMAKE_C_STANDARD 99)

add_executable(Client Client/client.c Client/client.h)

add_executable(Server Server/main.c Server/main.h
        Server/Utils/netutils.c Server/Utils/netutils.h
        Server/Utils/buffer.c Server/Utils/buffer.h
        Server/Utils/selector.c Server/Utils/selector.h
        Server/Utils/stm.c Server/Utils/stm.h
        Server/Utils/server_arguments.c Server/Utils/server_arguments.h
        Server/Proxy/proxy_nio.c Server/Proxy/proxy_nio.h Server/Proxy/Parsers/http_parser.c Server/Proxy/Parsers/http_parser.h Server/Proxy/Parsers/http_chunk_decoder.c Server/Proxy/Parsers/http_chunk_decoder.h Server/Proxy/proxy_reporter.c Server/Proxy/proxy_reporter.h Server/Utils/log.c Server/Utils/log.h
        Server/Admin/HpcpParser/hpcpRequest.c Server/Admin/HpcpParser/hpcpRequest.h Server/Admin/admin_nio.c Server/Admin/admin_nio.h Server/Proxy/config.h Server/Proxy/metrics.h Server/Utils/string_utils.c Server/Utils/string_utils.h Server/Admin/auth.c Server/Admin/auth.h)

target_link_libraries(Client pthread)
target_link_libraries(Client ${CMAKE_THREAD_LIBS_INIT} sctp)
target_link_libraries(Server ${CMAKE_THREAD_LIBS_INIT} sctp)
target_link_libraries(Server pthread)