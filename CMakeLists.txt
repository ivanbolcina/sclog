cmake_minimum_required(VERSION 2.8.12)
project(sclog)

set (CMAKE_CXX_STANDARD 17)
set (CMAKE_CXX_STANDARD_REQUIRED ON)
add_definitions("-std=c++17")

find_package(PkgConfig)
find_package(Threads REQUIRED)
include(${CMAKE_CURRENT_SOURCE_DIR}/conan/conanbuildinfo.cmake)
conan_basic_setup()

include_directories(include)
add_executable(sclog src/sclog.cpp src/signer.cpp)
target_link_libraries(sclog pistache ${CONAN_LIBS})

