#ifdef __APPLE__
#include <cstdlib>
#include <cstdint>
#include <fmt/core.h>
#include <fmt/chrono.h>
#else
#include <Windows.h>
#include <winuser.h>
#include <tchar.h>
#include <format>
#endif

#include <algorithm>
#include <chrono>
#include <thread>
#include <iostream>

#define IMGUI_DEFINE_MATH_OPERATORS
#include <imgui_internal.h> // For the horizontal splitter
#include <imgui.h>
#include <imgui_stdlib.h>
#ifdef __APPLE__
#include "imgui_impl_glfw.h"
#include "imgui_impl_opengl3.h"
#else
#include <imgui_impl_dx11.h>
#include <imgui_impl_win32.h>
#endif

#include <capstone/capstone.h>

#include "code_compiler.h"
#ifdef __APPLE__
#include <glad/glad.h>
#include <GLFW/glfw3.h>
#else
#include "resource.h"
#include "directx.hpp"
#endif

csh handle;
#ifndef __arm64__
csh handle32;
#endif

std::string code_content{};
std::string code_output{};
std::string compiler_output{};

#ifndef __APPLE__
std::unique_ptr<directx> pdx = nullptr;
RECT screen_rect{};
LONG resize_width;
LONG resize_height;
#endif

namespace ImGui {
	bool Splitter(bool split_vertically, float thickness, float* size1, float* size2, float min_size1, float min_size2, float splitter_long_axis_size = -1.0f) {
		ImGuiContext& g = *GImGui;
		ImGuiWindow* window = g.CurrentWindow;
		ImGuiID id = window->GetID("##Splitter");
		ImRect bb;
		bb.Min = window->DC.CursorPos + (split_vertically ? ImVec2(*size1, 0.0f) : ImVec2(0.0f, *size1));
		bb.Max = bb.Min + CalcItemSize(split_vertically ? ImVec2(thickness, splitter_long_axis_size) : ImVec2(splitter_long_axis_size, thickness), 0.0f, 0.0f);
		return SplitterBehavior(bb, id, split_vertically ? ImGuiAxis_X : ImGuiAxis_Y, size1, size2, min_size1, min_size2, 0.0f);
	}
};

#define MIN_WINDOW_WIDTH 750
#define MIN_WINDOW_HEIGHT 400

#ifndef __APPLE__
bool IsForegroundProcess(DWORD pid) {
	auto hwnd = GetForegroundWindow();
	if (!hwnd)
		return false;
	DWORD foreground_pid;
	if (!GetWindowThreadProcessId(hwnd, &foreground_pid))
		return false;
	return foreground_pid == pid;
}
#endif

namespace string {
	void left_trim(std::string& s) {
		s.erase(s.begin(), std::find_if(s.begin(), s.end(), [](unsigned char ch) {
			return !std::isspace(ch);
			}));
	}

	void right_trim(std::string& s) {
		s.erase(std::find_if(s.rbegin(), s.rend(), [](unsigned char ch) {
			return !std::isspace(ch);
			}).base(), s.end());
	}

	void trim(std::string& s) {
		left_trim(s);
		right_trim(s);
	}
	std::vector<std::string> split(std::string& str, const char* delim) {
		std::vector<std::string> results;
		size_t start = 0, end = 0;
		while ((start = str.find_first_not_of(delim, end)) != std::string::npos) {
			end = str.find(delim, start);
			results.push_back(str.substr(start, end - start));
		}
		return results;
	}
};

#ifdef __APPLE__
static void glfw_error_callback(int error, const char* description) {
    fprintf(stderr, "GLFW Error %d: %s\n", error, description);
    exit(EXIT_FAILURE);
}

int32_t posx = 0, width = 0;
int32_t posy = 0, height = 0;
int32_t offset_cpx = 0, offset_cpy = 0;
int32_t cp_x = 0, cp_y = 0;
int32_t ccp_x = 0, ccp_y = 0;

enum class WindowEvent : int32_t {
    NONE = 0,
    MOVE,
    RESIZE_LEFT,
    RESIZE_RIGHT,
    RESIZE_TOP,
    RESIZE_BOTTOM,
    RESIZE_BOTTOMLEFT,
    RESIZE_TOPLEFT,
    RESIZE_BOTTOMRIGHT,
    RESIZE_TOPRIGHT
};
WindowEvent buttonEvent = WindowEvent::NONE;

enum class ResizeArrow : int {
    NONE = 0,
    HORIZONTAL,
    VERTICAL,
    NESW,
    NWSE,
};
ResizeArrow cursorSet = ResizeArrow::NONE;

GLFWwindow* window = nullptr;
GLFWcursor* hcursor = nullptr;
GLFWcursor* vcursor = nullptr;
GLFWcursor* neswcursor = nullptr;
GLFWcursor* nwsecursor = nullptr;

#define RESIZE_THRESHOLD 7
static void cursor_position_callback(GLFWwindow* window, double x, double y) {
    switch (buttonEvent) {
    case WindowEvent::MOVE:
    {
        offset_cpx = static_cast<int>(x - cp_x);
        offset_cpy = static_cast<int>(y - cp_y);
        break;
    }
    case WindowEvent::RESIZE_BOTTOMLEFT:
    {
        int width, height;
        glfwGetWindowSize(window, &width, &height);
        auto diffx = static_cast<int>(x - cp_x);
        if (width - diffx >= MIN_WINDOW_WIDTH)
            offset_cpx = diffx;
        else
            offset_cpx = width - MIN_WINDOW_WIDTH;
        auto diffy = static_cast<int>(y - cp_y);
        if (height + diffy >= MIN_WINDOW_HEIGHT)
            offset_cpy = diffy;
        else
            offset_cpy = MIN_WINDOW_HEIGHT - height;
        break;
    }
    case WindowEvent::RESIZE_TOPLEFT:
    {
        int width, height;
        glfwGetWindowSize(window, &width, &height);
        auto diffx = static_cast<int>(x - cp_x);
        if (width - diffx >= MIN_WINDOW_WIDTH)
            offset_cpx = diffx;
        else
            offset_cpx = width - MIN_WINDOW_WIDTH;
        auto diffy = static_cast<int>(y - cp_y);
        if (height - diffy >= MIN_WINDOW_HEIGHT)
            offset_cpy = diffy;
        else
            offset_cpy = height - MIN_WINDOW_HEIGHT;
        break;
    }
    case WindowEvent::RESIZE_BOTTOMRIGHT:
    {
        int width, height;
        glfwGetWindowSize(window, &width, &height);
        auto diffx = static_cast<int>(x - cp_x);
        if (width + diffx >= MIN_WINDOW_WIDTH)
            offset_cpx = diffx;
        else
            offset_cpx = MIN_WINDOW_WIDTH - width;
        auto diffy = static_cast<int>(y - cp_y);
        if (height + diffy >= MIN_WINDOW_HEIGHT)
            offset_cpy = diffy;
        else
            offset_cpy = MIN_WINDOW_HEIGHT - height;
        break;
    }
    case WindowEvent::RESIZE_TOPRIGHT:
    {
        int width, height;
        glfwGetWindowSize(window, &width, &height);
        auto diffx = static_cast<int>(x - cp_x);
        if (width + diffx >= MIN_WINDOW_WIDTH)
            offset_cpx = diffx;
        else
            offset_cpx = MIN_WINDOW_WIDTH - width;
        auto diffy = static_cast<int>(y - cp_y);
        if (height - diffy >= MIN_WINDOW_HEIGHT)
            offset_cpy = diffy;
        else
            offset_cpy = height - MIN_WINDOW_HEIGHT;
        break;
    }
    case WindowEvent::RESIZE_RIGHT:
    {
        int width, height;
        glfwGetWindowSize(window, &width, &height);
        auto diffx = static_cast<int>(x - cp_x);
        if (width + diffx >= MIN_WINDOW_WIDTH)
            offset_cpx = diffx;
        else
            offset_cpx = MIN_WINDOW_WIDTH - width;
        break;
    }
    case WindowEvent::RESIZE_LEFT:
    {
        int width, height;
        glfwGetWindowSize(window, &width, &height);
        auto diffx = static_cast<int>(x - cp_x);
        if (width - diffx >= MIN_WINDOW_WIDTH)
            offset_cpx = diffx;
        else
            offset_cpx = width - MIN_WINDOW_WIDTH;
        break;
    }
    case WindowEvent::RESIZE_TOP:
    {
        int width, height;
        glfwGetWindowSize(window, &width, &height);
        auto diffy = static_cast<int>(y - cp_y);
        if (height - diffy >= MIN_WINDOW_HEIGHT)
            offset_cpy = diffy;
        else
            offset_cpy = height - MIN_WINDOW_HEIGHT;
        break;
    }
    case WindowEvent::RESIZE_BOTTOM:
    {
        int width, height;
        glfwGetWindowSize(window, &width, &height);
        auto diffy = static_cast<int>(y - cp_y);
        if (height + diffy >= MIN_WINDOW_HEIGHT)
            offset_cpy = diffy;
        else
            offset_cpy = MIN_WINDOW_HEIGHT - height;
        break;
    }
    default:
    {   
        int posx = static_cast<int>(x), posy = static_cast<int>(y);
        int width, height;
        glfwGetWindowSize(window, &width, &height);
        if (posx >= 0 && posy >= 0 && posx < width && posy < height) {
            if (posx < RESIZE_THRESHOLD) {
                if (posy <= 3) {
                    if (cursorSet != ResizeArrow::NWSE) {
                        glfwSetCursor(window, nwsecursor);
                        cursorSet = ResizeArrow::NWSE;
                    }
                } else if (posy > height - RESIZE_THRESHOLD) {
                    if (cursorSet != ResizeArrow::NESW) {
                        glfwSetCursor(window, neswcursor);
                        cursorSet = ResizeArrow::NESW;
                    }
                } else {
                    if (cursorSet != ResizeArrow::HORIZONTAL) {
                        glfwSetCursor(window, hcursor);
                        cursorSet = ResizeArrow::HORIZONTAL;
                    }
                }
            } else if (posx > width - RESIZE_THRESHOLD) {
                if (posy <= 3) {
                    if (cursorSet != ResizeArrow::NESW) {
                        glfwSetCursor(window, neswcursor);
                        cursorSet = ResizeArrow::NESW;
                    }
                } else if (posy > height - RESIZE_THRESHOLD) {
                    if (cursorSet != ResizeArrow::NWSE) {
                        glfwSetCursor(window, nwsecursor);
                        cursorSet = ResizeArrow::NWSE;
                    }
                } else {
                    if (cursorSet != ResizeArrow::HORIZONTAL) {
                        glfwSetCursor(window, hcursor);
                        cursorSet = ResizeArrow::HORIZONTAL;
                    }
                }
            } else if (posy <= 3) {
                if (cursorSet != ResizeArrow::VERTICAL) {
                    glfwSetCursor(window, vcursor);
                    cursorSet = ResizeArrow::VERTICAL;
                }
            } else if (posy > height - RESIZE_THRESHOLD) {
                if (cursorSet != ResizeArrow::VERTICAL) {
                    glfwSetCursor(window, vcursor);
                    cursorSet = ResizeArrow::VERTICAL;
                }
            } else {
                if (cursorSet != ResizeArrow::NONE) {
                    glfwSetCursor(window, NULL);
                    cursorSet = ResizeArrow::NONE;
                }
            }
        }
        break;
    }
    }
}

static void mouse_button_callback(GLFWwindow* window, int button, int action, int mods) {
    if(button == GLFW_MOUSE_BUTTON_LEFT && action == GLFW_PRESS) {
        double x, y;
        glfwGetCursorPos(window, &x, &y);
        int width = 0, height = 0;
        glfwGetWindowSize(window, &width, &height);
        if (y > 3.0 && x > RESIZE_THRESHOLD && x < width - RESIZE_THRESHOLD && y <= ImGui::GetFrameHeight()) {
            if (cursorSet != ResizeArrow::NONE) {
                glfwSetCursor(window, NULL);
                cursorSet = ResizeArrow::NONE;
            }
            buttonEvent = WindowEvent::MOVE;
            cp_x = floor(x);
            cp_y = floor(y);
        } else {
            int posx = static_cast<int>(x), posy = static_cast<int>(y);
            if (posx < RESIZE_THRESHOLD) {
                if (posy < 3) {
                    buttonEvent = WindowEvent::RESIZE_TOPLEFT;
                } else if (posy > height - RESIZE_THRESHOLD) {
                    buttonEvent = WindowEvent::RESIZE_BOTTOMLEFT;
                } else {
                    buttonEvent = WindowEvent::RESIZE_LEFT;
                }
            } else if (posx > width - RESIZE_THRESHOLD) {
                if (posy <= 3) {
                    buttonEvent = WindowEvent::RESIZE_TOPRIGHT;
                } else if (posy > height - RESIZE_THRESHOLD) {
                    buttonEvent = WindowEvent::RESIZE_BOTTOMRIGHT;
                } else {
                    buttonEvent = WindowEvent::RESIZE_RIGHT;
                }
            } else if (posy <= 3) {
                buttonEvent = WindowEvent::RESIZE_TOP;
            } else if (posy > height - RESIZE_THRESHOLD) {
                buttonEvent = WindowEvent::RESIZE_BOTTOM;
            }
            cp_x = floor(x);
            cp_y = floor(y);
        }
    }
    if(button == GLFW_MOUSE_BUTTON_LEFT && action == GLFW_RELEASE) {
        buttonEvent = WindowEvent::NONE;
        if (cursorSet != ResizeArrow::NONE) {
            glfwSetCursor(window, NULL);
            cursorSet = ResizeArrow::NONE;
        }
        cp_x = 0;
        cp_y = 0;
    }
}

static void framebuffer_size_callback(GLFWwindow* window, int width, int height) {
    glViewport(0, 0, width, height);
}

int main(int argc, char** argv) {
    glfwSetErrorCallback(glfw_error_callback);
    if (!glfwInit()) {
        fprintf(stderr, "Failed to initialize glfw! 0x%X\n", glfwGetError(NULL));
        return EXIT_FAILURE;
    }

    const char* glsl_version = "#version 150";
    glfwWindowHint(GLFW_CONTEXT_VERSION_MAJOR, 3);
    glfwWindowHint(GLFW_CONTEXT_VERSION_MINOR, 2);
    glfwWindowHint(GLFW_OPENGL_PROFILE,GLFW_OPENGL_CORE_PROFILE);
    glfwWindowHint(GLFW_OPENGL_FORWARD_COMPAT, GL_TRUE);

    glfwWindowHint(GLFW_DECORATED, GLFW_FALSE);
    glfwWindowHint(GLFW_RESIZABLE, GLFW_TRUE);

    window = glfwCreateWindow(MIN_WINDOW_WIDTH, MIN_WINDOW_HEIGHT, "shellcoder", NULL, NULL);
    if (!window) {
        fprintf(stderr, "Failed to create glfw window! 0x%X\n", glfwGetError(NULL));
        glfwTerminate();
        return EXIT_FAILURE;
    }

    glfwSetFramebufferSizeCallback(window, framebuffer_size_callback);
    glfwSetCursorPosCallback(window, cursor_position_callback);
    glfwSetMouseButtonCallback(window, mouse_button_callback);

    glfwMakeContextCurrent(window);

    auto status = gladLoadGLLoader(reinterpret_cast<GLADloadproc>(glfwGetProcAddress));
    if (!status) {
        fprintf(stderr, "Failed to load GLLoader! 0x%X\n", status);
        glfwDestroyWindow(window);
        glfwTerminate();
        return EXIT_FAILURE;
    }

    hcursor = glfwCreateStandardCursor(GLFW_HRESIZE_CURSOR);
    vcursor = glfwCreateStandardCursor(GLFW_VRESIZE_CURSOR);
    neswcursor = glfwCreateStandardCursor(GLFW_RESIZE_NESW_CURSOR);
    nwsecursor = glfwCreateStandardCursor(GLFW_RESIZE_NWSE_CURSOR);
#else
LRESULT WINAPI WndProc(HWND, UINT, WPARAM, LPARAM);

INT WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance,
	PSTR lpCmdLine, INT nCmdShow) {
	auto screenX = GetSystemMetrics(SM_CXSCREEN);
	auto screenY = GetSystemMetrics(SM_CYSCREEN);

	WNDCLASSEX wc{ 0 };
	wc.cbSize = sizeof(wc);
	wc.style = CS_HREDRAW | CS_VREDRAW | CS_OWNDC;
	wc.lpfnWndProc = WndProc;
	wc.hInstance = hInstance;
	wc.hCursor = LoadCursor(NULL, IDC_ARROW);
	wc.hbrBackground = NULL;
	wc.lpszClassName = _T("shellcoder");
	wc.hIcon = LoadIcon(hInstance, MAKEINTRESOURCE(IDI_ICON1));
	wc.hIconSm = NULL;
	::RegisterClassEx(&wc);

	pdx.reset(new directx());
	auto scale = pdx->GetDPIScale();
	auto x = static_cast<int32_t>(MIN_WINDOW_WIDTH * scale);
	auto y = static_cast<int32_t>(MIN_WINDOW_HEIGHT * scale);
	screen_rect.right = x;
	screen_rect.bottom = y;

	auto hwnd = CreateWindowEx(0, wc.lpszClassName, wc.lpszClassName, WS_MAXIMIZEBOX, 
			screenX / 2 - x / 2, screenY / 2 - y / 2, x, y, NULL, NULL, wc.hInstance, nullptr);
	if (!pdx->CreateDeviceD3D(hwnd)) {
		MessageBox(NULL, _T("Failed to create device"), _T("Error"), MB_ICONERROR | MB_OK);
		DestroyWindow(hwnd);
		UnregisterClass(wc.lpszClassName, wc.hInstance);
		return EXIT_FAILURE;
	}

	MSG msg;
	ZeroMemory(&msg, sizeof(msg));
#endif

	ImGui::CreateContext();

	auto& io = ImGui::GetIO();
    io.ConfigFlags |= ImGuiConfigFlags_NoMouseCursorChange;
	io.IniFilename = NULL;

#ifdef __APPLE__
    ImGui_ImplGlfw_InitForOpenGL(window, true);
    ImGui_ImplOpenGL3_Init(glsl_version);

    glfwGetWindowSize(window, &width, &height);
#else
	ImGui_ImplWin32_Init(hwnd);
	ImGui_ImplDX11_Init(pdx->GetDevice(), pdx->GetDeviceContext());
#endif

	ImGui::StyleColorsLight();
	auto& style = ImGui::GetStyle();
	style.WindowTitleAlign = ImVec2(0.5f, 0.5f);
	style.ChildRounding = 0.0f;
	style.FramePadding = ImVec2(4, 2);
	style.FrameRounding = 0.0f;
	style.ItemSpacing = ImVec2(8, 4);
	style.ItemInnerSpacing = ImVec2(4, 4);
	style.TouchExtraPadding = ImVec2(0, 0);
	style.IndentSpacing = 21.0f;
	style.ColumnsMinSpacing = 3.0f;
	style.ScrollbarSize = 12.0f;
	style.ScrollbarRounding = 16.0f;
	style.GrabMinSize = 0.1f;
	style.GrabRounding = 16.0f;
	style.ButtonTextAlign = ImVec2(0.5f, 0.5f);
	style.DisplayWindowPadding = ImVec2(22, 22);
	style.DisplaySafeAreaPadding = ImVec2(4, 4);
	style.AntiAliasedLines = true;
	style.AntiAliasedFill = true;
	style.CurveTessellationTol = 1.25f;
	style.WindowRounding = 0.0f;

	// Initialize other targets here if you need them
	llvm::InitializeNativeTarget();
	llvm::InitializeNativeTargetAsmPrinter();
	llvm::InitializeNativeTargetAsmParser();

#ifdef __arm64__
    cs_open(CS_ARCH_AARCH64, CS_MODE_ARM, &handle);
#else
	cs_open(CS_ARCH_X86, CS_MODE_64, &handle);
	cs_open(CS_ARCH_X86, CS_MODE_32, &handle32);
	cs_option(handle32, CS_OPT_DETAIL, CS_OPT_ON);
#endif
	cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);

	// Initialize here for test code to be loaded immediately
	code_content = 
R"(typedef struct {
	int a;
	int b;
} SomeStruct;

extern "C" int test2(SomeStruct* pStrc);

int test(int a, int b) {
	SomeStruct strc { .a = a, .b = b };
	return test2(&strc);
}

__attribute__((noinline))
int test2(SomeStruct* pStrc) {
	return pStrc->a + pStrc->b;
})";

	// Defaulting compiler flags to c++20, and frame pointer to have prologue/epilogue
	std::string compiler_flag_str{"-x c++ -std=c++20 -mframe-pointer=all"};
	std::vector<std::string> compiler_flags = string::split(compiler_flag_str, " ");

	if (code_content.size())
		generate_shellcode(code_content, compiler_flags);
	
#ifndef __APPLE__
	ShowWindow(hwnd, SW_SHOW);
	UpdateWindow(hwnd);
#endif

	const ImVec2 zz{0.f,0.f};
	const float clear[]{0.f, 0.f, 0.f, 0.f};
	const auto frame_padding_x_x8 = ImGui::GetStyle().FramePadding.x * 8.f;
	const auto frame_padding_y_x2 = ImGui::GetStyle().FramePadding.y * 2.f;
	float horizontal_size = 0.4f;

	const auto footer = 
#ifdef __APPLE__
        fmt::
#else
        std::
#endif
        format("scizzydo \u00A9 2020-{:%Y}", std::chrono::system_clock::now());
	
#ifndef __APPLE__
	const auto pid = GetCurrentProcessId();
#endif
	auto start = std::chrono::steady_clock::now();
	
#ifdef __APPLE__
    while (!glfwWindowShouldClose(window)) {
        if (glfwGetWindowAttrib(window, GLFW_ICONIFIED))
            continue;
#else
	while (msg.message != WM_QUIT) {
		if (PeekMessage(&msg, NULL, 0, 0, PM_REMOVE)) {
			TranslateMessage(&msg);
			DispatchMessage(&msg);
			continue;
		}
#endif
		auto now = std::chrono::steady_clock::now();
		auto diff = now - start;
		std::chrono::steady_clock::time_point end;
#ifdef __APPLE__
        if (glfwGetWindowAttrib(window, GLFW_FOCUSED))
#else
		if (IsForegroundProcess(pid))
#endif
			// We are foreground, so rendering at ~24 frames a second
			end = now + std::chrono::milliseconds(41);
		else
			// We're not foreground, so rendering at 2 frames a second
			end = now + std::chrono::milliseconds(500);
		if (diff >= std::chrono::seconds(1))
			start = now;

#ifdef __APPLE__
        if(buttonEvent != WindowEvent::NONE) {
            switch(buttonEvent) {
                case WindowEvent::MOVE:
                {
                    glfwGetWindowPos(window, &posx, &posy);
                    glfwSetWindowPos(window, posx + offset_cpx, posy + offset_cpy);
                    break;
                }
                case WindowEvent::RESIZE_LEFT:
                {
                    if (!offset_cpx) break;
                    glfwGetWindowPos(window, &posx, &posy);
                    glfwGetWindowSize(window, &width, &height);
                    posx += offset_cpx;
                    glfwSetWindowPos(window, posx, posy);
                    width -= offset_cpx;
                    glfwSetWindowSize(window, width, height);
                    break;
                }
                case WindowEvent::RESIZE_RIGHT:
                {
                    glfwGetWindowSize(window, &width, &height);
                    width += offset_cpx;
                    glfwSetWindowSize(window, width, height);
                    cp_x += offset_cpx;
                    break;
                }
                case WindowEvent::RESIZE_TOP:
                {
                    glfwGetWindowPos(window, &posx, &posy);
                    glfwGetWindowSize(window, &width, &height);
                    glfwSetWindowPos(window, posx, posy + offset_cpy);
                    glfwSetWindowSize(window, width, height - offset_cpy);
                    break;
                }
                case WindowEvent::RESIZE_BOTTOM:
                {
                    glfwGetWindowSize(window, &width, &height);
                    glfwSetWindowSize(window, width, height + offset_cpy);
                    cp_y += offset_cpy;
                    break;
                }
                case WindowEvent::RESIZE_TOPLEFT:
                {
                    glfwGetWindowPos(window, &posx, &posy);
                    glfwGetWindowSize(window, &width, &height);
                    glfwSetWindowPos(window, posx + offset_cpx, posy + offset_cpy);
                    glfwSetWindowSize(window, width - offset_cpx, height - offset_cpy);
                    break;
                }
                case WindowEvent::RESIZE_TOPRIGHT:
                {
                    glfwGetWindowPos(window, &posx, &posy);
                    glfwGetWindowSize(window, &width, &height);
                    glfwSetWindowPos(window, posx, posy + offset_cpy);
                    glfwSetWindowSize(window, width + offset_cpx, height - offset_cpy);
                    cp_x += offset_cpx;
                    break;
                }
                case WindowEvent::RESIZE_BOTTOMLEFT:
                {
                    glfwGetWindowPos(window, &posx, &posy);
                    glfwGetWindowSize(window, &width, &height);
                    glfwSetWindowPos(window, posx + offset_cpx, posy);
                    glfwSetWindowSize(window, width - offset_cpx, height + offset_cpy);
                    cp_y += offset_cpy;
                    break;
                }
                case WindowEvent::RESIZE_BOTTOMRIGHT:
                {
                    glfwGetWindowSize(window, &width, &height);
                    glfwSetWindowSize(window, width + offset_cpx, height + offset_cpy);
                    cp_x += offset_cpx;
                    cp_y += offset_cpy;
                    break;
                }
                default: break;
            }
            offset_cpx = 0;
            offset_cpy = 0;
        }
        glfwPollEvents();

        ImGui_ImplOpenGL3_NewFrame();
        ImGui_ImplGlfw_NewFrame();
#else
		if (resize_width != 0 && resize_height != 0) {
			ImGui_ImplDX11_InvalidateDeviceObjects();
			pdx->CleanupRenderTarget();
			pdx->GetSwapChain()->ResizeBuffers(0, resize_width, resize_height, DXGI_FORMAT_UNKNOWN, 0);
			pdx->CreateRenderTarget();
			resize_width = resize_height = 0;
			ImGui_ImplDX11_CreateDeviceObjects();
		}

		ImGui_ImplDX11_NewFrame();
		ImGui_ImplWin32_NewFrame();
#endif
		ImGui::NewFrame();
		ImGui::SetNextWindowPos(zz);
#ifdef __APPLE__
		ImGui::SetNextWindowSize(ImVec2(static_cast<float>(width), static_cast<float>(height)));
#else
		ImGui::SetNextWindowSize(ImVec2(static_cast<float>(screen_rect.right), static_cast<float>(screen_rect.bottom)));
#endif
		if (ImGui::Begin("shellcoder", nullptr, 
			ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse | 
			ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoCollapse | 
			ImGuiWindowFlags_NoMove | ImGuiWindowFlags_MenuBar | ImGuiWindowFlags_NoBringToFrontOnFocus)) {
			//auto& style = ImGui::GetStyle();
			if (ImGui::BeginMenuBar()) {
#ifdef __APPLE__
				auto startx = (width - ImGui::CalcTextSize("X").x * 2 - frame_padding_x_x8);
#else
				auto startx = (screen_rect.right - ImGui::CalcTextSize("X").x * 2 - frame_padding_x_x8);
#endif
				ImGui::SetCursorPosX(startx);
#ifdef __APPLE__
                if (ImGui::MenuItem("_")) glfwIconifyWindow(window);
                if (ImGui::MenuItem("X")) glfwSetWindowShouldClose(window, true);
#else
				if (ImGui::MenuItem("_")) ShowWindow(hwnd, SW_MINIMIZE);
				if (ImGui::MenuItem("X")) msg.message = WM_QUIT;
#endif
				ImGui::EndMenuBar();
			}
			auto region = ImGui::GetContentRegionAvail();
			const auto width = region.x;
			const auto half_width = width / 2.f;
			auto footer_size = ImGui::CalcTextSize(footer.c_str());
#ifdef __APPLE__
			const auto content_bottom = height - footer_size.y - frame_padding_y_x2;
#else
			const auto content_bottom = screen_rect.bottom - footer_size.y - frame_padding_y_x2;
#endif
			auto current = ImGui::GetCursorPos();
			ImGui::SetCursorPos(ImVec2(half_width - footer_size.x / 2.f, content_bottom + style.FramePadding.y));
			ImGui::TextUnformatted(footer.c_str());
			ImGui::SetCursorPos(current);
			ImGui::Columns(2, nullptr, true);
			{
				if (ImGui::InputTextMultiline("##code", &code_content, ImVec2(-1.f, content_bottom - ImGui::GetCursorPosY()), ImGuiInputTextFlags_AllowTabInput)) {
					// Maybe too much, but lets regenerate each key
					generate_shellcode(code_content, compiler_flags);
				};
				
			}
			ImGui::NextColumn();
			{
				/* Helper function to crop the string to fit in the content region currently, and word wrap it
				auto crop_string = [](std::string t) -> std::string {
					std::ostringstream ss;
					auto region = ImGui::GetContentRegionAvail().x - ImGui::GetStyle().FramePadding.x * 2.f;
					const char* predicted_end = ImGui::GetFont()->CalcWordWrapPositionA(1.f, t.c_str(), t.c_str() + t.size(), region);
					while (!t.empty() && predicted_end && strlen(predicted_end) > 0) {
						auto pos = t.find(predicted_end);
						if (pos == std::string::npos)
							break;
						auto chunk = t.substr(0, pos);
						string::left_trim(chunk);
						t.erase(0, pos);
						string::trim(t);
						ss << chunk << "\n";
						predicted_end = ImGui::GetFont()->CalcWordWrapPositionA(1.f, t.c_str(), t.c_str() + t.size(), region);
					}
					ss << t;
					return ss.str();
				};
				*/
				ImGui::Text("Compiler Flags:");
				ImGui::SameLine();
				ImGui::PushItemWidth(-1.f);
				// Upon enter, regenerate the compiler flags
				if (ImGui::InputText("##flags", &compiler_flag_str, ImGuiInputTextFlags_EnterReturnsTrue)) {
					compiler_flags = string::split(compiler_flag_str, " ");
					generate_shellcode(code_content, compiler_flags);
				}
				// Preventing the preview to be overwritten
				std::string preview = code_output;//crop_string(code_output);
				// Work our black magic for window height
				auto const working_height = content_bottom - ImGui::GetCursorPosY();
				float size1 = working_height * horizontal_size;
				float size2 = working_height - size1;
				ImGui::Splitter(false, 3.f, &size1, &size2, 40.f, 30.f);
				// Shouldn't hit this normally, unless resizing down from larger window
				auto const maximum = working_height - 30.f;
				if (size1 > maximum)
					size1 = maximum;
				// Calculate new percentage from the output
				horizontal_size = size1 / working_height;
				ImGui::BeginChild("1", ImVec2(-1, size1));
				ImGui::InputTextMultiline("##output", &preview, ImVec2(-1.f, -1.f));
				ImGui::EndChild();
				ImGui::BeginChild("2", ImVec2(-1, content_bottom - ImGui::GetCursorPosY()));
				ImGui::InputTextMultiline("##console", &compiler_output, ImVec2(-1.f, -1.f));
				ImGui::EndChild();
			}
			ImGui::End();
		}
		ImGui::EndFrame();
		ImGui::Render();
#ifdef __APPLE__
        int display_w, display_h;
        glfwGetFramebufferSize(window, &display_w, &display_h);
        glViewport(0, 0, display_w, display_h);
        glClearColor(clear[0], clear[1], clear[2], clear[3]);
        glClear(GL_COLOR_BUFFER_BIT);
        ImGui_ImplOpenGL3_RenderDrawData(ImGui::GetDrawData());

        glfwSwapBuffers(window);
#else
		auto pContext = pdx->GetDeviceContext();
		auto pRenderTargetView = pdx->GetRenderTargetView();
		pContext->OMSetRenderTargets(1, &pRenderTargetView, NULL);
		pContext->ClearRenderTargetView(pRenderTargetView, clear);
		ImGui_ImplDX11_RenderDrawData(ImGui::GetDrawData());
		pdx->GetSwapChain()->Present(0, 0);
#endif
		std::this_thread::sleep_until(end);
	}

#ifdef __APPLE__
    ImGui_ImplOpenGL3_Shutdown();
    ImGui_ImplGlfw_Shutdown();
#else
	DestroyWindow(hwnd);
	UnregisterClass(wc.lpszClassName, wc.hInstance);
#endif
    ImGui::DestroyContext();

	llvm::llvm_shutdown();

	cs_close(&handle);
#ifndef __arm64__
	cs_close(&handle32);
#endif

	return EXIT_SUCCESS;
}

#ifdef __APPLE__

#else
#define GET_X_LPARAM(lp)    ((int)(short)LOWORD(lp))
#define GET_Y_LPARAM(lp)    ((int)(short)HIWORD(lp))

extern IMGUI_IMPL_API LRESULT ImGui_ImplWin32_WndProcHandler(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);
LRESULT WINAPI WndProc(HWND hwnd, UINT msg, WPARAM wparam, LPARAM lparam) {
	if (ImGui_ImplWin32_WndProcHandler(hwnd, msg, wparam, lparam))
		return 1;
	switch (msg) {
	case WM_NCCALCSIZE:
	{
		auto pncsp = reinterpret_cast<NCCALCSIZE_PARAMS*>(lparam);
		// Handle the top of the box not going outside the screen area when maximized
		if (GetWindowLong(hwnd, GWL_STYLE) & WS_MAXIMIZE) {
			pncsp->rgrc[0].top = pncsp->rgrc[0].top + 6;
		}
		pncsp->rgrc[0].left = pncsp->rgrc[0].left + 6;
		pncsp->rgrc[0].right = pncsp->rgrc[0].right - 6;
		pncsp->rgrc[0].bottom = pncsp->rgrc[0].bottom - 6;
		return 0;
	}
	break;
	case WM_NCHITTEST:
	{
		RECT winrect;
		GetWindowRect(hwnd, &winrect);
		auto x = GET_X_LPARAM(lparam);
		auto y = GET_Y_LPARAM(lparam);
		if (x >= winrect.left && x < winrect.left + 6 &&
			y < winrect.bottom && y >= winrect.bottom - 6)
			return HTBOTTOMLEFT;
		if (x < winrect.right && x >= winrect.right - 6 &&
			y < winrect.bottom && y >= winrect.bottom - 6)
			return HTBOTTOMRIGHT;
		if (x >= winrect.left && x < winrect.left + 6 &&
			y >= winrect.top && y < winrect.top + 6)
			return HTTOPLEFT;
		if (x < winrect.right && x >= winrect.right - 6 &&
			y >= winrect.top && y < winrect.top + 6)
			return HTTOPRIGHT;
		if (x >= winrect.left && x < winrect.left + 6)
			return HTLEFT;
		if (x < winrect.right && x >= winrect.right - 6)
			return HTRIGHT;
		if (y < winrect.bottom && y >= winrect.bottom - 6)
			return HTBOTTOM;
		if (y >= winrect.top && y < winrect.top + 6)
			return HTTOP;
		if (x >= winrect.left && x <= winrect.right &&
			y >= winrect.top && y <= winrect.top + 17)
			return HTCAPTION;
	}
	break;
	case WM_SIZE:
	{
		if (wparam == SIZE_MINIMIZED)
			return 0;
		auto width = LOWORD(lparam);
		auto height = HIWORD(lparam);
		screen_rect.right = resize_width = width;
		screen_rect.bottom = resize_height = height;
		return 0;
	}
	break;
	case WM_GETMINMAXINFO:
	{
		auto lpmmi = reinterpret_cast<LPMINMAXINFO>(lparam);
		lpmmi->ptMinTrackSize.x = static_cast<LONG>(640.f * pdx->GetDPIScale());
		lpmmi->ptMinTrackSize.y = static_cast<LONG>(400.f * pdx->GetDPIScale());
		return 0;
	}
	break;
	case WM_SYSCOMMAND:
	{
		if ((wparam & 0xFFF0) == SC_KEYMENU)
			return 0;
	}
	break;
	case WM_DESTROY:
	{
		::PostQuitMessage(0);
		return 0;
	}
	}
	return DefWindowProc(hwnd, msg, wparam, lparam);
}
#endif