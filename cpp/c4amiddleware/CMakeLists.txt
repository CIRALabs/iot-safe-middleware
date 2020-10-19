cmake_minimum_required(VERSION "3.14")
project("c4amiddleware")

find_package(OpenSSL REQUIRED)

# We include both include directories defined by Thales' original code as well as
# the added "general" directory
include_directories(
    ${CMAKE_SOURCE_DIR}/../iot-safe-middleware/iotsafelib/platform/modem/inc
    ${CMAKE_SOURCE_DIR}/../iot-safe-middleware/iotsafelib/common/inc
    ${CMAKE_SOURCE_DIR}/../iot-safe-middleware/iotsafelib/general/inc
    ${CMAKE_SOURCE_DIR}/cpp_wrappers/inc
)

# We include the cpp_wrapper which creates a wrapper of the Thales code
add_subdirectory(cpp_wrapper)

# Note that we need to include a few dependencies for the wrapper to build.
# The "PLATFORM_LIB" and "COMMON_LIB" variables are passed by the command
# line (or by the build.sh script). Run the following:
# $ cmake -DPLATFORM_LIB="path/to/platform/modem/libiotsafeplatform.so" \
#         -DCOMMON_LIB="path/to/common/libiotsafecommon.so" \
#         -DGENERAL_LIB="path/to/general/libiotsafegeneral.so"
target_link_libraries(
    "${PROJECT_NAME}"
    ${GENERAL_LIB}
    ${PLATFORM_LIB}
    ${COMMON_LIB}
    OpenSSL::Crypto
)

