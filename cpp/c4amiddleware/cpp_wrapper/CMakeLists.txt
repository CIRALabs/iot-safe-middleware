set(OPENSSL_USE_STATIC_LIBS TRUE)
find_package(OpenSSL REQUIRED)

add_library ( "${PROJECT_NAME}" SHARED "src/openssl-util.cpp" "src/sim-access-util.cpp" "src/wrappers.cpp")
target_include_directories ( "${PROJECT_NAME}" PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/inc")
