# The following lines of boilerplate have to be in your project's CMakeLists
# in this exact order for cmake to work correctly
cmake_minimum_required(VERSION 3.5)

add_compile_options(-fdiagnostics-color=always)
if(NOT DEFINED IDF_TARGET)
    set(IDF_TARGET "esp32")
endif()

set(EXTRA_COMPONENT_DIRS $ENV{ESPNOW_PATH}/components)

include($ENV{IDF_PATH}/tools/cmake/project.cmake)
project(espnow_alpha)
