cmake_minimum_required(VERSION 3.21)
project(SmartScanner VERSION 3.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)

# Find Qt6 (requires Qt 6.2+)
find_package(Qt6 6.2 REQUIRED COMPONENTS
    Core Gui Widgets Network WebChannel WebEngineWidgets Xml)

# Collect all source files
file(GLOB ALL_SOURCES "src/*.cpp")
file(GLOB ALL_HEADERS "src/*.h")

# Separate main files from library sources
set(LIB_SOURCES ${ALL_SOURCES})
list(FILTER LIB_SOURCES EXCLUDE REGEX ".*_main\\.cpp$")

# Common library with all shared code
add_library(smartscanner_lib STATIC ${LIB_SOURCES} ${ALL_HEADERS})
target_include_directories(smartscanner_lib PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_link_libraries(smartscanner_lib PUBLIC
    Qt6::Core Qt6::Gui Qt6::Widgets Qt6::Network
    Qt6::WebChannel Qt6::WebEngineWidgets Qt6::Xml)

# ============================================
# CLI Executable (sms.exe)
# ============================================
add_executable(sms src/cli_main.cpp sms_resources.qrc)
target_link_libraries(sms PRIVATE smartscanner_lib)

# ============================================
# GUI Executable (gui.exe)
# ============================================
add_executable(gui WIN32 src/gui_main.cpp gui_resources.qrc)
target_link_libraries(gui PRIVATE smartscanner_lib)

# ============================================
# Post-build: Copy assets to output directory
# ============================================
add_custom_command(TARGET sms POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_directory
    ${CMAKE_SOURCE_DIR}/assets $<TARGET_FILE_DIR:sms>/assets)

add_custom_command(TARGET gui POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_directory
    ${CMAKE_SOURCE_DIR}/assets $<TARGET_FILE_DIR:gui>/assets)

# ============================================
# Tests (optional)
# ============================================
option(BUILD_TESTS "Build test executables" OFF)
if(BUILD_TESTS)
    enable_testing()
    file(GLOB TEST_SOURCES "tests/*_smoke.cpp")
    foreach(TEST_SOURCE ${TEST_SOURCES})
        get_filename_component(TEST_NAME ${TEST_SOURCE} NAME_WE)
        add_executable(${TEST_NAME} ${TEST_SOURCE})
        target_link_libraries(${TEST_NAME} PRIVATE smartscanner_lib)
        add_test(NAME ${TEST_NAME} COMMAND ${TEST_NAME})
    endforeach()
endif()

# ============================================
# Installation
# ============================================
install(TARGETS sms gui RUNTIME DESTINATION bin)
install(DIRECTORY assets/ DESTINATION bin/assets)
