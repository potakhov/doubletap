cmake_minimum_required(VERSION 2.8)
project(doubletap)

set(Boost_USE_STATIC_LIBS ON)
find_package(Boost 1.56 REQUIRED COMPONENTS program_options)

set(CMAKE_CXX_FLAGS "-std=c++0x -O3")
set(CMAKE_EXE_LINKER_FLAGS "-static-libgcc -static-libstdc++")

include_directories(doubletap ${NETMAP_DIR})
include_directories(${Boost_INCLUDE_DIRS})

add_executable(doubletap src/main.cpp src/pqueue.cpp src/nmtools.cpp src/config.cpp src/log.cpp src/utils.cpp)

target_link_libraries(doubletap -lz -pthread)
