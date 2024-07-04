cmake_minimum_required(VERSION 3.10)
project(ECCExample)

set(CMAKE_CXX_STANDARD 11)

find_package(OpenSSL REQUIRED)
include_directories(${OPENSSL_INCLUDE_DIR})

add_executable(ECCExample ECCRevised.cpp)
target_link_libraries(ECCExample OpenSSL::SSL OpenSSL::Crypto)