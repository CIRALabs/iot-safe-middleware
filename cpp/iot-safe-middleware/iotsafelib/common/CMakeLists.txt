set(OPENSSL_USE_STATIC_LIBS TRUE)
find_package(OpenSSL REQUIRED)
add_library (iotsafecommon SHARED "src/Applet.cpp" "src/ROT.cpp" "src/SEInterface.cpp")

target_include_directories (iotsafecommon PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/inc" "${CMAKE_CURRENT_SOURCE_DIR}/../general/inc")
target_link_libraries(iotsafecommon PRIVATE OpenSSL::Crypto iotsafegeneral)
