#pragma once
#include <d3d11.h>
//#include "DirectX/WICTextureLoader.h"
//#include "resource.h"

class directx {
private:
	ID3D11Device* g_pd3dDevice;
	ID3D11DeviceContext* g_pd3dDeviceContext;
	IDXGISwapChain* g_pSwapChain;
	ID3D11RenderTargetView* g_mainRenderTargetView;
	bool m_DPIScaleSet;
	float m_DPIScale;
//	ID3D11ShaderResourceView* m_icon;
/*	inline void LoadDXImage(int32_t file) {
		auto rc = FindResource(NULL, MAKEINTRESOURCE(file), "PNG");
		if (!rc)
			return;
		auto rcdata = LoadResource(NULL, rc);
		auto size = SizeofResource(NULL, rc);
		if (!rcdata)
			return;
		const uint8_t* data = static_cast<const uint8_t*>(LockResource(rcdata));
		DirectX::CreateWICTextureFromMemory(g_pd3dDevice, data, size, nullptr, &m_icon);
	}*/
public:
	directx() :
		g_pd3dDevice(nullptr),
		g_pd3dDeviceContext(nullptr),
		g_pSwapChain(nullptr),
		g_mainRenderTargetView(nullptr),
		m_DPIScaleSet(false),
		m_DPIScale(1.f)
	{
	}
	~directx() {
		CleanupDeviceD3D();
	}
	inline ID3D11Device* GetDevice() {
		return g_pd3dDevice;
	}
	inline IDXGISwapChain* GetSwapChain() {
		return g_pSwapChain;
	}
	inline ID3D11DeviceContext* GetDeviceContext() {
		return g_pd3dDeviceContext;
	}
	inline ID3D11RenderTargetView* GetRenderTargetView() {
		return g_mainRenderTargetView;
	}
	inline float GetDPIScale() {
		if (!m_DPIScaleSet) {
			auto hDC = GetDC(NULL);
			auto dpix = GetDeviceCaps(hDC, LOGPIXELSX);
			ReleaseDC(NULL, hDC);
			auto DPI = MulDiv(100, dpix, 96);
			m_DPIScale = DPI / 100.f;
			m_DPIScaleSet = true;
		}
		return m_DPIScale;
	}
	inline bool CreateDeviceD3D(HWND hWnd) {
		DXGI_SWAP_CHAIN_DESC sd;
		ZeroMemory(&sd, sizeof(sd));
		sd.BufferCount = 2;
		sd.BufferDesc.Width = 0;
		sd.BufferDesc.Height = 0;
		sd.BufferDesc.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
		sd.BufferDesc.RefreshRate.Numerator = 60;
		sd.BufferDesc.RefreshRate.Denominator = 1;
		sd.Flags = DXGI_SWAP_CHAIN_FLAG_ALLOW_MODE_SWITCH;
		sd.BufferUsage = DXGI_USAGE_RENDER_TARGET_OUTPUT;
		sd.OutputWindow = hWnd;
		sd.SampleDesc.Count = 1;
		sd.SampleDesc.Quality = 0;
		sd.Windowed = TRUE;
		sd.SwapEffect = DXGI_SWAP_EFFECT_DISCARD;

		UINT createDeviceFlags = 0;
		D3D_FEATURE_LEVEL featureLevel;
		const D3D_FEATURE_LEVEL featureLevelArray[3] = { D3D_FEATURE_LEVEL_10_0, D3D_FEATURE_LEVEL_11_0, D3D_FEATURE_LEVEL_10_0 };
		if (D3D11CreateDeviceAndSwapChain(NULL, D3D_DRIVER_TYPE_HARDWARE, NULL, createDeviceFlags, featureLevelArray, 3, D3D11_SDK_VERSION, &sd, &g_pSwapChain, &g_pd3dDevice, &featureLevel, &g_pd3dDeviceContext) != S_OK)
			return false;

		CreateRenderTarget();
		return true;
	}
	inline void CleanupDeviceD3D() {
		CleanupRenderTarget();
		if (g_pSwapChain) {
			g_pSwapChain->Release();
			g_pSwapChain = NULL;
		}
		if (g_pd3dDeviceContext) {
			g_pd3dDeviceContext->Release();
			g_pd3dDeviceContext = NULL;
		}
		if (g_pd3dDevice) {
			g_pd3dDevice->Release();
			g_pd3dDevice = NULL;
		}
	}
	inline void CreateRenderTarget() {
		ID3D11Texture2D* pBackBuffer;
		g_pSwapChain->GetBuffer(0, __uuidof(ID3D11Texture2D), reinterpret_cast<LPVOID*>(&pBackBuffer));
		if (pBackBuffer) {
			g_pd3dDevice->CreateRenderTargetView(pBackBuffer, NULL, &g_mainRenderTargetView);
			pBackBuffer->Release();
		}
	}
	inline void CleanupRenderTarget() {
		if (g_mainRenderTargetView) {
			g_mainRenderTargetView->Release();
			g_mainRenderTargetView = NULL;
		}
	}
};