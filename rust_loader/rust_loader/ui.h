#pragma once
#include "includes.hpp"

#include <d3d9.h>
#include <d3dx9.h>
#include <tchar.h>

#pragma comment(lib, "d3d9.lib")
#pragma comment(lib, "d3dx9.lib")

#include "imgui/imgui.h"
#include "imgui/imgui_internal.h"
#include "imgui/imgui_impl_dx9.h"
#include "imgui/imgui_impl_win32.h"


extern IMGUI_IMPL_API LRESULT ImGui_ImplWin32_WndProcHandler(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);
LRESULT WINAPI WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);

class ui
{
public:
    static ui& instance()
    {
        static ui instance;
        return instance;
    }

public:
	ui(ui const&) = delete;
    void operator=(ui const&) = delete;

public:
	LPDIRECT3D9              g_pD3D;
	LPDIRECT3DDEVICE9        g_pd3dDevice;
	bool                     g_DeviceLost;
	UINT                     g_ResizeWidth, g_ResizeHeight;
	D3DPRESENT_PARAMETERS    g_d3dpp;
	HWND					 g_hwnd;
	WNDCLASSEXW				 g_wc;
	bool					 quit;
	IDirect3DTexture9*		 dx_image_texture;
	ImTextureID				 im_image_texture;
	D3DXIMAGE_INFO			 info;

public:
	bool CreateDeviceD3D();
	void CleanupDeviceD3D();
	void ResetDevice();

public:
	ui() :
		quit(true)
	{

	}
	void init();

	void render();

	void render_main();
	void render_login();

	void exit();
};