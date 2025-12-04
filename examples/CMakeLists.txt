cmake_minimum_required(VERSION 3.16.0)

project(tuyapp)

option(ENABLE_DEBUG "Enable library debugging" NO)
option(ENABLE_APP_DEBUG "Enable application debugging" NO)


if(ENABLE_DEBUG)
    add_definitions(-DDEBUG)
endif()

if(ENABLE_APP_DEBUG)
    add_definitions(-DAPPDEBUG)
endif()

if(CMAKE_CXX_COMPILER_ID MATCHES "Clang")
  set(CMAKE_CXX_STANDARD 11)
  set(CMAKE_CXX_STANDARD_REQUIRED ON)
  set(CXX_EXTENSIONS NO)
endif()

set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS}  -Wall")

set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/../.lib)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/../.lib)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/..)


# main include dirs
include_directories(${CMAKE_SOURCE_DIR}/../src)


## Sources

# Targets
file(GLOB TUYA_demo_SRCS *.cpp)


# Main library
file(GLOB_RECURSE TUYA_client_SRCS ../src/*.cpp)
add_library(tuyapp STATIC ${TUYA_client_SRCS} ${include_SRCS})


find_package(ZLIB REQUIRED)
if(ZLIB_FOUND)
  message(STATUS "Found Zlib ${ZLIB_VERSION_STRING} at: ${ZLIB_INCLUDE_DIRS}")
else()
  message(FATAL_ERROR "Zlib not found but USE_BUILTIN_ZLIB=NO")
endif(ZLIB_FOUND)

find_package(PkgConfig)
pkg_check_modules(JSONCPP REQUIRED jsoncpp)
IF(JSONCPP_FOUND)
  MESSAGE(STATUS "JSONCPP includes found at: ${JSONCPP_INCLUDE_DIRS}")
  target_include_directories(tuyapp PUBLIC ${JSONCPP_INCLUDE_DIRS})
  target_link_directories(tuyapp PUBLIC ${JSONCPP_LIBRARY_DIRS})
  target_link_libraries(tuyapp ${JSONCPP_LIBRARIES})
ELSE(JSONCPP_FOUND)
  MESSAGE(FATAL_ERROR "JSONCPP not found on your system! try 'sudo apt-get install jsoncpp-dev'")
ENDIF(JSONCPP_FOUND)

find_package(OpenSSL REQUIRED)
IF(OPENSSL_FOUND)
  message(STATUS "OPENSSL library found at: ${OPENSSL_LIBRARIES}")
  include_directories(${OPENSSL_INCLUDE_DIR})
ENDIF()


foreach(demo ${TUYA_demo_SRCS})
  get_filename_component(exefile ${demo} NAME_WE)
  add_executable(${exefile} ${demo})
  target_link_libraries(${exefile} tuyapp ${ZLIB_LIBRARIES} pthread ${OPENSSL_LIBRARIES})
  message(STATUS "Created make target ${exefile}")
endforeach(demo)

