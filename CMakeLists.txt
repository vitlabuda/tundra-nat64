cmake_minimum_required(VERSION 3.16)
project(tundra-nat64 LANGUAGES C)

set(EXECUTABLE "tundra-nat64")
file(GLOB SOURCES "src/*.c")

set(CMAKE_C_FLAGS "-std=c11 -pedantic -Wall -Wextra -Werror -s -O3 -flto -pthread")

add_executable(${EXECUTABLE} ${SOURCES})
