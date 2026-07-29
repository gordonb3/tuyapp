
# Main library
file(GLOB_RECURSE include_SRCS *.hpp)
file(GLOB_RECURSE TUYA_client_SRCS *.cpp)

add_library(tuyapp STATIC ${TUYA_client_SRCS} ${include_SRCS})

target_include_directories(tuyapp
    PUBLIC
        ${JSONCPP_INCLUDE_DIRS}
        ${CMAKE_CURRENT_LIST_DIR})

target_link_directories(tuyapp PUBLIC ${JSONCPP_LIBRARY_DIRS})
target_link_libraries(tuyapp ${JSONCPP_LIBRARIES})

if (MBEDTLS_FOUND)
    target_include_directories(tuyapp PUBLIC ${MBEDTLS_INCLUDE_DIRS})
    target_link_libraries(tuyapp ${MBEDTLS_LIBRARIES})
endif()

if (MBEDCRYPTO_FOUND)
    target_include_directories(tuyapp PUBLIC ${MBEDCRYPTO_INCLUDE_DIRS})
    target_link_libraries(tuyapp ${MBEDCRYPTO_LIBRARIES})
endif()

if (OPENSSL_FOUND)
    target_include_directories(tuyapp PUBLIC ${OPENSSL_INCLUDE_DIR})
    target_link_libraries(tuyapp ${OPENSSL_LIBRARIES})
endif()
