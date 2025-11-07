cmake_minimum_required(VERSION 3.16)
project(cpp_tls_demo LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

find_package(OpenSSL REQUIRED)

add_executable(server
    src/tls_server.cpp
)

target_include_directories(server PRIVATE include)

target_link_libraries(server PRIVATE OpenSSL::SSL OpenSSL::Crypto)

target_compile_features(server PRIVATE cxx_std_17)

add_executable(client
    src/tls_client.cpp
)

target_include_directories(client PRIVATE include)

target_link_libraries(client PRIVATE OpenSSL::SSL OpenSSL::Crypto)

target_compile_features(client PRIVATE cxx_std_17)

