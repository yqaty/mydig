cmake_minimum_required(VERSION 3.22)

project(mydig)

set(CMAKE_CXX_STANDARD 20)

aux_source_directory(./src DIR_SRC)

# 添加源文件
add_executable(mydig ${DIR_SRC})

# 添加包含目录
target_include_directories(mydig PRIVATE ./include)

install(TARGETS mydig DESTINATION /usr/local/bin)

# 添加其他依赖项
# target_link_libraries(mydig some_library)

# 指定编译选项（可选）
#set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++20")

