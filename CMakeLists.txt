cmake_minimum_required(VERSION 2.8...3.5)

project(NetworkAnalayzer VERSION 0.1.0 LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 11)


set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${PROJECT_SOURCE_DIR}/")

find_package(PCAP REQUIRED)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -lpcap")

configure_file(${CMAKE_CURRENT_SOURCE_DIR}/main_analyzer.py ${CMAKE_CURRENT_BINARY_DIR}/main_analyzer.py COPYONLY)


add_executable(NetworkAnalayzer
    src/main.cpp
    src/NetworkAnalyzer/NetworkAnalyzer.cpp
)

target_link_libraries(NetworkAnalayzer ${PCAP_LIBRARY})
