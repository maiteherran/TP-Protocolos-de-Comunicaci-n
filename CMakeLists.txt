cmake_minimum_required(VERSION 3.12)
project(ProbandoTpProtos C)

set(CMAKE_C_STANDARD 99)

add_executable(ProbandoTpProtos main.c main.h Parser/picohttpparser.c Parser/picohttpparser.h
        Utils/netutils.c Utils/netutils.h
        Utils/buffer.c Utils/buffer.h
        Utils/selector.c Utils/selector.h
        Utils/stm.c Utils/stm.h
        proxy5nio.c proxy5nio.h Admin/HpcpParser/hpcpRequest.c Admin/HpcpParser/hpcpRequest.h Admin/admin.c Admin/admin.h Admin/config.c Admin/config.h Admin/metrics.c Admin/metrics.h)