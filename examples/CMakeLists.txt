
# Example targets:
file(GLOB TUYA_demo_SRCS *.cpp)
foreach(demo ${TUYA_demo_SRCS})
  get_filename_component(exefile ${demo} NAME_WE)
  add_executable(${exefile} ${demo})
  target_link_libraries(${exefile} tuyapp ${ZLIB_LIBRARIES} pthread ${OPENSSL_LIBRARIES})
  message(STATUS "Created make target ${exefile}")
endforeach(demo)



