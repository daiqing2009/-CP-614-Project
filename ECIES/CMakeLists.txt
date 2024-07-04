cmake_minimum_required(VERSION 3.10)
project(ECIES)

set(CMAKE_CXX_STANDARD 11)

find_package(OpenSSL REQUIRED)
include_directories(${OPENSSL_INCLUDE_DIR})

add_executable(ECIES ECIES.cpp)
target_link_libraries(ECIES OpenSSL::SSL OpenSSL::Crypto)