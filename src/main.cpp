#include <Windows.h>
#include <algorithm>
#include <tchar.h>
#include <winuser.h>
#include <chrono>
#include <iostream>

#define IMGUI_DEFINE_MATH_OPERATORS
#include <imgui_internal.h> // For the horizontal splitter
#include <imgui.h>
#include <imgui_stdlib.h>
#include <imgui_impl_dx11.h>
#include <imgui_impl_win32.h>

#include <capstone/capstone.h>

#include "resource.h"
#include "code_compiler.h"
#include "directx.hpp"

csh handle;
std::string code_content{};
std::string code_output{};
std::string compiler_output{};
std::unique_ptr<directx> pdx = nullptr;
RECT screen_rect{};
LONG resize_width;
LONG resize_height;

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

bool IsForegroundProcess(DWORD pid) {
	auto hwnd = GetForegroundWindow();
	if (!hwnd)
		return false;
	DWORD foreground_pid;
	if (!GetWindowThreadProcessId(hwnd, &foreground_pid))
		return false;
	return foreground_pid == pid;
}

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
	auto x = static_cast<int32_t>(750.f * scale);
	auto y = static_cast<int32_t>(400.f * scale);
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

	ImGui::CreateContext();

	auto& io = ImGui::GetIO();
	io.IniFilename = NULL;

	ImGui_ImplWin32_Init(hwnd);
	ImGui_ImplDX11_Init(pdx->GetDevice(), pdx->GetDeviceContext());

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

	cs_open(CS_ARCH_X86, CS_MODE_64, &handle);
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
	
	ShowWindow(hwnd, SW_SHOW);
	UpdateWindow(hwnd);

	const ImVec2 zz{0.f,0.f};
	const float clear[]{0.f, 0.f, 0.f, 0.f};
	const auto frame_padding_x_x8 = ImGui::GetStyle().FramePadding.x * 8.f;
	const auto frame_padding_y_x2 = ImGui::GetStyle().FramePadding.y * 2.f;
	float horizontal_size = 0.4f;

	const auto footer = std::format("scizzydo \u00A9 2020-{:%Y}", std::chrono::system_clock::now());
	
	const auto pid = GetCurrentProcessId();
	auto start = std::chrono::steady_clock::now();
	
	
	while (msg.message != WM_QUIT) {
		if (PeekMessage(&msg, NULL, 0, 0, PM_REMOVE)) {
			TranslateMessage(&msg);
			DispatchMessage(&msg);
			continue;
		}
		auto now = std::chrono::steady_clock::now();
		auto diff = now - start;
		std::chrono::steady_clock::time_point end;
		if (IsForegroundProcess(pid))
			// We are foreground, so rendering at ~24 frames a second
			end = now + std::chrono::milliseconds(41);
		else
			// We're not foreground, so rendering at 2 frames a second
			end = now + std::chrono::milliseconds(500);
		if (diff >= std::chrono::seconds(1))
			start = now;

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
		ImGui::NewFrame();
		ImGui::SetNextWindowPos(zz);
		ImGui::SetNextWindowSize(ImVec2(static_cast<float>(screen_rect.right), static_cast<float>(screen_rect.bottom)));
		if (ImGui::Begin("shellcoder", nullptr, 
			ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse | 
			ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoCollapse | 
			ImGuiWindowFlags_NoMove | ImGuiWindowFlags_MenuBar | ImGuiWindowFlags_NoBringToFrontOnFocus)) {
			//auto& style = ImGui::GetStyle();
			if (ImGui::BeginMenuBar()) {
				auto startx = (screen_rect.right - ImGui::CalcTextSize("X").x * 2 - frame_padding_x_x8);
				ImGui::SetCursorPosX(startx);
				if (ImGui::MenuItem("_")) ShowWindow(hwnd, SW_MINIMIZE);
				if (ImGui::MenuItem("X")) msg.message = WM_QUIT;
				ImGui::EndMenuBar();
			}
			auto region = ImGui::GetContentRegionAvail();
			const auto width = region.x;
			const auto half_width = width / 2.f;
			auto footer_size = ImGui::CalcTextSize(footer.c_str());
			const auto content_bottom = screen_rect.bottom - footer_size.y - frame_padding_y_x2;
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
		auto pContext = pdx->GetDeviceContext();
		auto pRenderTargetView = pdx->GetRenderTargetView();
		pContext->OMSetRenderTargets(1, &pRenderTargetView, NULL);
		pContext->ClearRenderTargetView(pRenderTargetView, clear);
		ImGui_ImplDX11_RenderDrawData(ImGui::GetDrawData());
		pdx->GetSwapChain()->Present(0, 0);
		std::this_thread::sleep_until(end);
	}

	DestroyWindow(hwnd);
	UnregisterClass(wc.lpszClassName, wc.hInstance);

	llvm::llvm_shutdown();

	cs_close(&handle);

	return EXIT_SUCCESS;
}

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