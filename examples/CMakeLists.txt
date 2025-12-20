cmake_minimum_required(VERSION 3.16.0)

project(tuyapp)

option(ENABLE_DEBUG "Enable library debugging" NO)
option(ENABLE_APP_DEBUG "Enable application debugging" NO)

option(WITHOUT_API31 "Disable API 3.1 support" YES)
option(WITHOUT_API33 "Disable API 3.3 support" NO)
option(WITHOUT_API34 "Disable API 3.4 support" NO)
option(WITHOUT_API35 "Disable API 3.5 support" NO)

option(USE_MBEDTLS "Build with mbedtls instead of OpenSSL" NO)


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
foreach(demo ${TUYA_demo_SRCS})
  get_filename_component(exefile ${demo} NAME_WE)
  add_executable(${exefile} ${demo})
  target_link_libraries(${exefile} tuyapp ${ZLIB_LIBRARIES} pthread ${OPENSSL_LIBRARIES})
  message(STATUS "Created make target ${exefile}")
endforeach(demo)



# Main library
file(GLOB_RECURSE TUYA_client_SRCS ../src/*.cpp)
add_library(tuyapp STATIC ${TUYA_client_SRCS} ${include_SRCS})

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

# default encryption routines
set(USE_OPENSSL YES)

if(USE_MBEDTLS)
  set(USE_OPENSSL NO)
  add_definitions(-DUSE_MBEDTLS)
  pkg_check_modules(MBEDTLS REQUIRED mbedtls-3)
  IF(MBEDTLS_FOUND)
    message(STATUS "mbedtls-3 library found at: ${MBEDTLS_LIBRARIES}")
    message(STATUS "mbedtls-3 include files found at: ${MBEDTLS_INCLUDE_DIRS}")
    target_include_directories(tuyapp PUBLIC ${MBEDTLS_INCLUDE_DIRS})
    target_link_libraries(tuyapp ${MBEDTLS_LIBRARIES})
  ENDIF()
  pkg_check_modules(MBEDCRYPTO REQUIRED mbedcrypto-3)
  IF(MBEDTLS_FOUND)
    message(STATUS "mbedcrypto-3 library found at: ${MBEDCRYPTO_LIBRARIES}")
    message(STATUS "mbedcrypto-3 include files found at: ${MBEDCRYPTO_INCLUDE_DIRS}")
    target_include_directories(tuyapp PUBLIC ${MBEDCRYPTO_INCLUDE_DIRS})
    target_link_libraries(tuyapp ${MBEDCRYPTO_LIBRARIES})
  ENDIF()
endif()

if(USE_OPENSSL)
  find_package(OpenSSL REQUIRED)
  IF(OPENSSL_FOUND)
    message(STATUS "OPENSSL library found at: ${OPENSSL_LIBRARIES}")
    target_include_directories(tuyapp PUBLIC ${OPENSSL_INCLUDE_DIR})
    target_link_libraries(tuyapp ${OPENSSL_LIBRARIES})
  ENDIF()
endif()

# definitions to pass to compiler
if(ENABLE_DEBUG)
    add_definitions(-DDEBUG)
endif()
if(ENABLE_APP_DEBUG)
    add_definitions(-DAPPDEBUG)
endif()
if(WITHOUT_API31)
    add_definitions(-DWITHOUT_API31)
endif()
if(WITHOUT_API33)
    add_definitions(-DWITHOUT_API33)
endif()
if(WITHOUT_API34)
    add_definitions(-DWITHOUT_API34)
endif()
if(WITHOUT_API35)
    add_definitions(-DWITHOUT_API35)
endif()


