cmake_minimum_required(VERSION 3.15)

if (${CMAKE_HOST_SYSTEM_NAME} MATCHES "Darwin")
    set(MACOS TRUE)
    project(shellcoder LANGUAGES C CXX)
else()
    project(shellcoder C CXX RC)
endif()

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if (NOT MACOS)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /EHsc /MD")
endif()

## Sorry all you folks, not making a fancy cmake. for LLVM and capstone
## Go ahead and pass your -DLLVM_CLANG_DIR and those in, or override it here
if (NOT DEFINED LLVM_CLANG_DIR)
    set(LLVM_CLANG_DIR "Z:\\Libraries\\llvm-project\\build")
endif()

if (NOT DEFINED CAPSTONE_INCLUDE_DIR)
    set(CAPSTONE_INCLUDE_DIR "Z:\\Libraries\\capstone\\include")
endif()

if (NOT DEFINED CAPSTONE_LIB_DIR)
    set(CAPSTONE_LIB_DIR "Z:\\Libraries\\capstone\\build")
endif()

set(CMAKE_PREFIX_PATH ${CMAKE_PREFIX_PATH} ${LLVM_CLANG_DIR})
message(STATUS "CMAKE_PREFIX_PATH: ${CMAKE_PREFIX_PATH}")

find_package(LLVM CONFIG REQUIRED)
find_package(CLANG CONFIG REQUIRED)
message(STATUS "Using LLVM ${LLVM_PACKAGE_VERSION}")
message(STATUS "LLVM include directory: ${LLVM_INCLUDE_DIRS}")
message(STATUS "Clang include directory: ${CLANG_INCLUDE_DIRS}")
message(STATUS "Capstone library directory: ${CAPSTONE_LIB_DIR}")

include(FetchContent)
message(STATUS "Checking if ImGui repo needs to be pulled")
FetchContent_Declare(
    imgui
    GIT_REPOSITORY "https://github.com/ocornut/imgui"
    GIT_TAG "v1.89.9"
)

FetchContent_MakeAvailable(imgui)

message(STATUS "ImGui source directory: ${imgui_SOURCE_DIR}")

if(MACOS)
    if ("${CMAKE_SYSTEM_PROCESSOR}" STREQUAL "arm64")
        message(STATUS "Setting arm includes")
        include_directories(/opt/homebrew/include /usr/local/include)
        link_directories(/opt/homebrew/lib)
    else()
        message(STATUS "Setting x86 includes")
        include_directories(/usr/local/include)
        link_directories(/usr/local/lib)
    endif()
endif()

include_directories(include resources ${LLVM_INCLUDE_DIRS} ${CLANG_INCLUDE_DIRS} ${CAPSTONE_INCLUDE_DIR}
                         ${imgui_SOURCE_DIR} ${imgui_SOURCE_DIR}/backends ${imgui_SOURCE_DIR}/misc/cpp)

link_directories(${LLVM_CLANG_BUILD_DIR}/lib ${CAPSTONE_LIB_DIR})

add_definitions(${LLVM_DEFINITIONS} -DNOMINMAX)

set(LLVM_LIBS LLVMExecutionEngine LLVMSupport LLVMTarget
    LLVMBitWriter LLVMMCJIT LLVMPasses LLVMAsmParser)

if ("${CMAKE_SYSTEM_PROCESSOR}" STREQUAL "arm64")
    set(LLVM_LIBS ${LLVM_LIBS} LLVMAArch64CodeGen LLVMAArch64AsmParser)
else()
    set(LLVM_LIBS ${LLVM_LIBS} LLVMX86CodeGen LLVMX86AsmParser)
endif()

set(CLANG_LIBS clangFrontend clangCodeGen)

set(SHELLCODER_SOURCES
    src/main.cpp
    src/code_compiler.cpp)

set(IMGUI_SOURCES
    ${imgui_SOURCE_DIR}/imgui.cpp
    ${imgui_SOURCE_DIR}/imgui_draw.cpp
    ${imgui_SOURCE_DIR}/imgui_tables.cpp
    ${imgui_SOURCE_DIR}/imgui_widgets.cpp
    ${imgui_SOURCE_DIR}/misc/cpp/imgui_stdlib.cpp)

if (MACOS)
    set(SHELLCODER_SOURCES
        ${SHELLCODER_SOURCES}
        src/glad.c)
    set(IMGUI_SOURCES
        ${IMGUI_SOURCES}
        ${imgui_SOURCE_DIR}/backends/imgui_impl_glfw.cpp
        ${imgui_SOURCE_DIR}/backends/imgui_impl_opengl3.cpp)
else()
    set(IMGUI_SOURCES
        ${IMGUI_SOURCES}
        ${imgui_SOURCE_DIR}/backends/imgui_impl_dx11.cpp
        ${imgui_SOURCE_DIR}/backends/imgui_impl_win32.cpp)
endif()

if (MACOS)
    add_definitions(-w)
    set(MACOSX_BUNDLE_ICON_FILE shellcoder.icns)
    find_library(COCOA_FRAMEWORK Cocoa)
    find_library(IOKIT_FRAMEWORK IOKit)
    find_package(fmt)
    set(PROJECT_NAME_ICON ${CMAKE_CURRENT_SOURCE_DIR}/resources/shellcoder.icns)

    set_source_files_properties(${PROJECT_NAME_ICON} PROPERTIES
        MACOSX_PACKAGE_LOCATION "Resources")
    add_executable(${PROJECT_NAME} ${PROJECT_NAME_ICON} ${IMGUI_SOURCES} ${SHELLCODER_SOURCES})

    set_target_properties(${PROJECT_NAME} PROPERTIES
        MACOSX_BUNDLE True
        MACOSX_BUNDLE_INFO_PLIST ${CMAKE_CURRENT_SOURCE_DIR}/resources/Info.plist
        XCODE_ATTRIBUTE_CODE_SIGN_IDENTITY "-"
        XCODE_ATTRIBUTE_CODE_SIGN_ENTITLEMENTS ${CMAKE_CURRENT_SOURCE_DIR}/resources/${PROJECT_NAME}.entitlements
        XCODE_ATTRIBUTE_EXECUTABLE_NAME ${PROJECT_NAME}
        CODE_SIGN_ALLOW_ENTITLEMENTS_MODIFICATION YES
        XCODE_ATTRIBUTE_ENABLE_HARDENED_RUNTIME YES
        XCODE_ATTRIBUTE_DEPLOYMENT_POSTPROCESSING YES)
    target_link_libraries(${PROJECT_NAME} PUBLIC ${COCOA_FRAMEWORK} ${IOKIT_FRAMEWORK})
    target_link_libraries(${PROJECT_NAME} PRIVATE libglfw3.a fmt::fmt-header-only ${LLVM_LIBS} ${CLANG_LIBS} capstone)
else()
    add_executable(${PROJECT_NAME} WIN32 ${SHELLCODER_SOURCES} ${IMGUI_SOURCES})
    target_link_libraries(${PROJECT_NAME} PRIVATE ${LLVM_LIBS} ${CLANG_LIBS} capstone d3d11)
    target_sources(${PROJECT_NAME} PRIVATE shellcoder.rc)
endif()