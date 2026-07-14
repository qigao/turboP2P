cmake_minimum_required(VERSION 3.10)
project(uthash)

add_library(uthash INTERFACE)
add_library(uthash::uthash ALIAS uthash)

target_include_directories(
  uthash INTERFACE $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>/src)
set_target_properties(uthash PROPERTIES FOLDER "vendor/uthash")

install(TARGETS uthash EXPORT TurboP2PTargets)
