cmake_minimum_required(VERSION 3.16)
project(tundra-nat64 LANGUAGES C)

set(EXECUTABLE "tundra-nat64")
file(GLOB SOURCES "src/*.c")

set(EXTRA_WARNINGS "")
set(EXTRA_OPTIMIZATIONS "-flto")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=c11 -pedantic -Wall -Wextra -Werror ${EXTRA_WARNINGS} -s -O3 ${EXTRA_OPTIMIZATIONS} -pthread")

set(VERSION_FILE "${CMAKE_SOURCE_DIR}/VERSION")
file(READ "${VERSION_FILE}" VERSION)
string(REGEX REPLACE "[ \t\r\n]" "" VERSION "${VERSION}")
add_compile_definitions("TUNDRA__VERSION_STRING=\"${VERSION}\"")

add_executable(${EXECUTABLE} ${SOURCES})
