cmake_minimum_required(VERSION 3.12)
project(hebench_seal_backend LANGUAGES C CXX)

set(CMAKE_PROJECT_NAME ${PROJECT_NAME})

# General Setup
if(CMAKE_BUILD_TYPE)
  set(RELEASE_TYPES
      Debug
      Release
      RelWithDebInfo
      MinSizeRel)
  list(FIND RELEASE_TYPES ${CMAKE_BUILD_TYPE} INDEX_FOUND)
  if(${INDEX_FOUND} EQUAL -1)
    message(
      FATAL_ERROR
        "CMAKE_BUILD_TYPE must be one of Debug, Release, RelWithDebInfo, or MinSizeRel"
      )
  endif()
else()
  set(CMAKE_BUILD_TYPE "Debug" CACHE STRING "Choose the type of Build" FORCE)
endif()

message(STATUS "CMAKE_BUILD_TYPE: ${CMAKE_BUILD_TYPE}")

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS}")

set(THREADS_PREFER_PTHREAD_FLAG ON)
find_package(Threads REQUIRED)

find_package (OpenMP REQUIRED)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${OpenMP_C_FLAGS}")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${OpenMP_CXX_FLAGS}")
set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} ${OpenMP_EXE_LINKER_FLAGS}")

###########################################################################################

# benchmarks

set(${PROJECT_NAME}_HEADERS
    "${CMAKE_CURRENT_SOURCE_DIR}/include/benchmarks/ckks/seal_ckks_matmult_cipherbatchaxis_benchmark.h"
    "${CMAKE_CURRENT_SOURCE_DIR}/include/benchmarks/ckks/seal_ckks_matmultval_benchmark.h"
    "${CMAKE_CURRENT_SOURCE_DIR}/include/benchmarks/ckks/seal_ckks_element_wise_benchmark.h"
    "${CMAKE_CURRENT_SOURCE_DIR}/include/benchmarks/ckks/seal_ckks_dot_product_benchmark.h"
    "${CMAKE_CURRENT_SOURCE_DIR}/include/benchmarks/ckks/seal_ckks_logreg_horner.h"
    "${CMAKE_CURRENT_SOURCE_DIR}/include/benchmarks/ckks/seal_ckks_matmult_row_benchmark.h"
    "${CMAKE_CURRENT_SOURCE_DIR}/include/benchmarks/bfv/seal_bfv_matmult_cipherbatchaxis_benchmark.h"
    "${CMAKE_CURRENT_SOURCE_DIR}/include/benchmarks/bfv/seal_bfv_matmultval_benchmark.h"
    "${CMAKE_CURRENT_SOURCE_DIR}/include/benchmarks/bfv/seal_bfv_matmult_row_benchmark.h"
    "${CMAKE_CURRENT_SOURCE_DIR}/include/benchmarks/bfv/seal_bfv_element_wise_benchmark.h"
    "${CMAKE_CURRENT_SOURCE_DIR}/include/benchmarks/bfv/seal_bfv_dot_product_benchmark.h"
    )

set(${PROJECT_NAME}_SOURCES
    "${CMAKE_CURRENT_SOURCE_DIR}/src/benchmarks/ckks/seal_ckks_matmult_cipherbatchaxis_benchmark.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/benchmarks/ckks/seal_ckks_matmultval_benchmark.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/benchmarks/ckks/seal_ckks_element_wise_benchmark.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/benchmarks/ckks/seal_ckks_dot_product_benchmark.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/benchmarks/ckks/seal_ckks_logreg_horner.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/benchmarks/ckks/seal_ckks_matmult_row_benchmark.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/benchmarks/bfv/seal_bfv_matmult_cipherbatchaxis_benchmark.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/benchmarks/bfv/seal_bfv_matmultval_benchmark.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/benchmarks/bfv/seal_bfv_matmult_row_benchmark.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/benchmarks/bfv/seal_bfv_element_wise_benchmark.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/benchmarks/bfv/seal_bfv_dot_product_benchmark.cpp"
    )

# engine
list(APPEND ${PROJECT_NAME}_HEADERS
    "${CMAKE_CURRENT_SOURCE_DIR}/include/engine/seal_context.h"
    "${CMAKE_CURRENT_SOURCE_DIR}/include/engine/seal_engine.h"
    "${CMAKE_CURRENT_SOURCE_DIR}/include/engine/seal_types.h"
    "${CMAKE_CURRENT_SOURCE_DIR}/include/engine/seal_version.h"
    )

list(APPEND ${PROJECT_NAME}_SOURCES
    "${CMAKE_CURRENT_SOURCE_DIR}/src/engine/seal_context.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/engine/seal_engine.cpp"
    )

add_library(${PROJECT_NAME} SHARED)# ${${PROJECT_NAME}_SOURCES} ${${PROJECT_NAME}_HEADERS})

target_include_directories(${PROJECT_NAME} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)

###########################################################################################

# third-party
include(FetchContent)
set(FETCHCONTENT_BASE_DIR ${CMAKE_BINARY_DIR}/third-party)

# Must Set 4 Variable per third-party, have a _COMPONENT_NAME.cmake file ready, then include the import util.
# Goal is for cmake to fail out if particular library (lib + includes) dont exist/aren't found
## _COMPONENT_NAME: The name used to generate lib-specific variables, printing, and filename resolution
## _COMPONENT_HEADER: A path to a known header file relative to the imported include directory
## _COMPONENT_LIB_NAME: The name of the library that will be used to link to it
## _HEADER_ONLY: Whether or not the library being imported is header-only

## API-BRIDGE
set(_COMPONENT_NAME "API_BRIDGE")
set(_COMPONENT_HEADER "hebench/api_bridge/api.h")
set(_COMPONENT_LIB_NAME "hebench_cpp")
set(_HEADER_ONLY FALSE)
include(cmake/utils/import-library.cmake)
include(cmake/third-party/${_COMPONENT_NAME}_check.cmake)

## SEAL
set(_COMPONENT_NAME "SEAL")
set(_COMPONENT_HEADER "seal/seal.h")
set(_COMPONENT_LIB_NAME "seal-3.6")
set(_HEADER_ONLY FALSE)
include(cmake/utils/import-library.cmake)

configure_file("${CMAKE_CURRENT_SOURCE_DIR}/include/engine/seal_version.h.in" "${CMAKE_CURRENT_BINARY_DIR}/include/engine/seal_version.h.in1")
configure_file("${CMAKE_CURRENT_BINARY_DIR}/include/engine/seal_version.h.in1" "${CMAKE_CURRENT_SOURCE_DIR}/include/engine/seal_version.h")

target_sources(${PROJECT_NAME} PRIVATE ${${PROJECT_NAME}_SOURCES} ${${PROJECT_NAME}_HEADERS})

###########################################################################################

include(GNUInstallDirs)
set(CMAKE_INSTALL_RPATH "${CMAKE_INSTALL_PREFIX}/lib")
install(TARGETS ${PROJECT_NAME} DESTINATION lib)

target_compile_options(${PROJECT_NAME} PRIVATE -Wall -Wextra)
