cmake_minimum_required(VERSION 3.17)
project(websocket)

set(CMAKE_CXX_STANDARD 14)

include_directories(include)
include_directories(${CMAKE_SOURCE_DIR})

option(STATIC_BUILD "enable static build" OFF)

set(CMAKE_POSITION_INDEPENDENT_CODE TRUE)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/bin)

set(EVENT__DISABLE_TESTS ON CACHE BOOL "disable event tests")
set(EVENT__DISABLE_SAMPLES ON CACHE BOOL "disable event samples")
set(EVENT__DISABLE_BENCHMARK ON CACHE BOOL "disable event benchmark")

include(FindOpenSSL)
include(FetchContent)

FetchContent_Declare(
        libevent
        GIT_REPOSITORY https://github.com/libevent/libevent
        GIT_TAG release-2.1.12-stable
)

FetchContent_MakeAvailable(libevent)

FetchContent_Declare(
        zero
        GIT_REPOSITORY https://github.com/Hackerl/zero
        GIT_TAG master
)

FetchContent_MakeAvailable(zero)

add_executable(websocket main.cpp ws/websocket.cpp client/echo_client.cpp)
target_link_libraries(websocket zero event_core_static event_openssl_static event_extra_static OpenSSL::SSL OpenSSL::Crypto $<$<BOOL:${STATIC_BUILD}>:-static-pie>)