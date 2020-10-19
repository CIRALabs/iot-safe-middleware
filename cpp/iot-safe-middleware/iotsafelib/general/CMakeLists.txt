add_library (iotsafegeneral SHARED "src/common.cpp")

target_include_directories (iotsafegeneral PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/inc" "${CMAKE_CURRENT_SOURCE_DIR}/../common/inc")
