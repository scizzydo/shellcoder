cmake_minimum_required(VERSION 3.15)

project(shellcoder C CXX RC)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_FLAGS "/EHsc /MD")

## Sorry all you folks, not making a fancy cmake. for LLVM and capstone
## Go ahead and pass your -DLLVM_CLANG_DIR and those in, or override it here
if (NOT DEFINED ${LLVM_CLANG_DIR})
    set(LLVM_CLANG_DIR "Z:\\Libraries\\llvm-project\\build")
endif()

if (NOT DEFINED ${CAPSTONE_INCLUDE_DIR})
    set(CAPSTONE_INCLUDE_DIR "Z:\\Libraries\\capstone\\include")
endif()

if (NOT DEFINED ${CAPSTONE_LIB_DIR})
    set(CAPSTONE_LIB_DIR "Z:\\Libraries\\capstone\\build")
endif()

set(CMAKE_PREFIX_PATH ${CMAKE_PREFIX_PATH} ${LLVM_CLANG_DIR})

find_package(LLVM REQUIRED CONFIG)
find_package(CLANG REQUIRED CONFIG)
message(STATUS "Using LLVM ${LLVM_PACKAGE_VERSION}")
message(STATUS "LLVM include directory: ${LLVM_INCLUDE_DIRS}")
message(STATUS "Clang include directory: ${CLANG_INCLUDE_DIRS}")

include(FetchContent)
message(STATUS "Checking if ImGui repo needs to be pulled")
FetchContent_Declare(
    imgui
    GIT_REPOSITORY "https://github.com/ocornut/imgui"
    GIT_TAG "v1.89.9"
)

FetchContent_MakeAvailable(imgui)

message(STATUS "ImGui source directory: ${imgui_SOURCE_DIR}")

include_directories(include resources ${LLVM_INCLUDE_DIRS} ${CLANG_INCLUDE_DIRS} ${CAPSTONE_INCLUDE_DIR}
                         ${imgui_SOURCE_DIR} ${imgui_SOURCE_DIR}/backends ${imgui_SOURCE_DIR}/misc/cpp)

link_directories(${LLVM_CLANG_BUILD_DIR}/lib ${CAPSTONE_LIB_DIR})

add_definitions(${LLVM_DEFINITIONS} -DNOMINMAX)

set(LLVM_LIBS LLVMExecutionEngine LLVMSupport LLVMTarget LLVMBitWriter
    LLVMMCJIT LLVMX86CodeGen LLVMPasses LLVMAsmParser LLVMX86AsmParser)

set(CLANG_LIBS clangFrontend clangCodeGen)

set(SHELLCODER_SOURCES
    src/main.cpp
    src/code_compiler.cpp)

set(IMGUI_SOURCES
    ${imgui_SOURCE_DIR}/imgui.cpp
    ${imgui_SOURCE_DIR}/imgui_draw.cpp
    ${imgui_SOURCE_DIR}/imgui_tables.cpp
    ${imgui_SOURCE_DIR}/imgui_widgets.cpp
    ${imgui_SOURCE_DIR}/misc/cpp/imgui_stdlib.cpp
    ${imgui_SOURCE_DIR}/backends/imgui_impl_dx11.cpp
    ${imgui_SOURCE_DIR}/backends/imgui_impl_win32.cpp)

add_executable(${PROJECT_NAME} WIN32 ${SHELLCODER_SOURCES} ${IMGUI_SOURCES})
target_link_libraries(${PROJECT_NAME} PRIVATE ${LLVM_LIBS} ${CLANG_LIBS} capstone d3d11)
target_sources(${PROJECT_NAME} PRIVATE shellcoder.rc)