################################################################################
# Project setting
################################################################################
cmake_minimum_required(VERSION 2.8)

project(MINIGC)

## Set config parameter
set(CMAKE_ALLOW_LOOSE_LOOP_CONSTRUCTS ON)
set(CMAKE_INCLUDE_CURRENT_DIR OFF)

## Set path of cmake files
set(CMAKE_MODULE_PATH ${PROJECT_SOURCE_DIR}/cmake)

## Set target path
set(EXECUTABLE_OUTPUT_PATH ${PROJECT_BINARY_DIR})
set(LIBRARY_OUTPUT_PATH ${PROJECT_BINARY_DIR})

## Build Type: None / Debug / Release / RelWithDebInfo / MinSizeRel
set(CMAKE_BUILD_TYPE Debug)

################################################################################
# Source
################################################################################
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
  add_definitions(-DDO_DEBUG)
endif()

set(SRCS "main.c")

################################################################################
# Libaray
################################################################################
set(GC_SRCS gc.c)

add_library(gc STATIC ${GC_SRCS})

################################################################################
# Executable
################################################################################
add_executable(minigc ${SRCS})

## Link library
target_link_libraries(minigc gc)
