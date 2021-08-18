cmake_minimum_required(VERSION 3.17)
project(websocket)

set(CMAKE_CXX_STANDARD 14)

include_directories(include)

option(STATIC_BUILD "enable static build" OFF)

set(CMAKE_POSITION_INDEPENDENT_CODE TRUE)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/bin)

set(EVENT__DISABLE_TESTS ON CACHE BOOL "disable event tests")
set(EVENT__DISABLE_SAMPLES ON CACHE BOOL "disable event samples")
set(EVENT__DISABLE_OPENSSL ON CACHE BOOL "disable event openssl")
set(EVENT__DISABLE_BENCHMARK ON CACHE BOOL "disable event benchmark")

include(FindOpenSSL)
include(cmake/libevent.cmake)

add_executable(websocket main.cpp ws/websocket.cpp)
target_link_libraries(websocket event_core_static event_extra_static OpenSSL::Crypto $<$<BOOL:${STATIC_BUILD}>:-static-pie>)