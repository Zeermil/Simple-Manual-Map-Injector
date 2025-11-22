cmake_minimum_required(VERSION 3.15)
project(ManualMapInjector)

# Set C++ standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Source files
set(SOURCE_FILES
    "Manual Map Injector/injector.cpp"
    "Manual Map Injector/injector_dll.cpp"
)

set(HEADER_FILES
    "Manual Map Injector/injector.h"
)

# Create shared library (DLL)
add_library(ManualMapInjector SHARED ${SOURCE_FILES} ${HEADER_FILES})

# Set output name based on architecture
if(CMAKE_SIZEOF_VOID_P EQUAL 8)
    set_target_properties(ManualMapInjector PROPERTIES OUTPUT_NAME "ManualMapInjector-x64")
else()
    set_target_properties(ManualMapInjector PROPERTIES OUTPUT_NAME "ManualMapInjector-x86")
endif()

# Disable buffer security checks to match the original project settings
if(MSVC)
    target_compile_options(ManualMapInjector PRIVATE /GS-)
endif()

# Link required Windows libraries (implicit linking for Windows API)

# Add preprocessor definitions
target_compile_definitions(ManualMapInjector PRIVATE
    UNICODE
    _UNICODE
    $<$<CONFIG:Release>:NDEBUG>
    $<$<CONFIG:Debug>:_DEBUG>
)

# Create example executable with cross-architecture support
add_executable(ManualMapInjectorCLI "Manual Map Injector/main.cpp" ${SOURCE_FILES} ${HEADER_FILES})

if(CMAKE_SIZEOF_VOID_P EQUAL 8)
    set_target_properties(ManualMapInjectorCLI PROPERTIES OUTPUT_NAME "Injector-x64")
else()
    set_target_properties(ManualMapInjectorCLI PROPERTIES OUTPUT_NAME "Injector-x86")
endif()

if(MSVC)
    target_compile_options(ManualMapInjectorCLI PRIVATE /GS-)
endif()

target_compile_definitions(ManualMapInjectorCLI PRIVATE
    UNICODE
    _UNICODE
    $<$<CONFIG:Release>:NDEBUG>
    $<$<CONFIG:Debug>:_DEBUG>
)
