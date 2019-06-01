cmake_minimum_required(VERSION 3.12)
project(ProbandoTpProtos C)

set(CMAKE_C_STANDARD 99)

add_executable(ProbandoTpProtos main.c main.h Parser/picohttpparser.c Parser/picohttpparser.h)