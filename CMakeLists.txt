cmake_minimum_required(VERSION 3.22)

project(mydig)

set(CMAKE_CXX_STANDARD 20)

aux_source_directory(./src DIR_SRC)

add_executable(mydig ${DIR_SRC})

target_include_directories(mydig PRIVATE ./include)

install(TARGETS mydig DESTINATION /usr/local/bin)

