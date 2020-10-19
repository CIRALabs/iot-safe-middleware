add_library (iotsafeplatform SHARED "src/ATInterface.cpp" "src/GenericModem.cpp" "src/LSerial.cpp" "src/Serial.cpp")

target_include_directories (iotsafeplatform PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/inc" "${CMAKE_CURRENT_SOURCE_DIR}/../../general/inc")
target_link_libraries(iotsafeplatform PRIVATE iotsafecommon)
