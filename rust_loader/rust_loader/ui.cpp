#include "ui.h"

LRESULT __stdcall WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    if (ImGui_ImplWin32_WndProcHandler(hWnd, msg, wParam, lParam))
        return true;

    switch (msg)
    {
    case WM_SIZE:
        if (wParam == SIZE_MINIMIZED)
            return 0;
        ui::instance().g_ResizeWidth = (UINT) LOWORD(lParam); // Queue resize
        ui::instance().g_ResizeHeight = (UINT) HIWORD(lParam);
        return 0;
    case WM_SYSCOMMAND:
        if ((wParam & 0xfff0) == SC_KEYMENU) // Disable ALT application menu
            return 0;
        break;
    case WM_DESTROY:
        ::PostQuitMessage(0);
        return 0;
    }
    return ::DefWindowProcW(hWnd, msg, wParam, lParam);
}

bool ui::CreateDeviceD3D()
{
    if ((g_pD3D = Direct3DCreate9(D3D_SDK_VERSION)) == nullptr)
        return false;

    // Create the D3DDevice
    ZeroMemory(&g_d3dpp, sizeof(g_d3dpp));
    g_d3dpp.Windowed = TRUE;
    g_d3dpp.SwapEffect = D3DSWAPEFFECT_DISCARD;
    g_d3dpp.BackBufferFormat = D3DFMT_UNKNOWN; // Need to use an explicit format with alpha if needing per-pixel alpha composition.
    g_d3dpp.EnableAutoDepthStencil = TRUE;
    g_d3dpp.AutoDepthStencilFormat = D3DFMT_D16;
    g_d3dpp.PresentationInterval = D3DPRESENT_INTERVAL_ONE;           // Present with vsync
    //g_d3dpp.PresentationInterval = D3DPRESENT_INTERVAL_IMMEDIATE;   // Present without vsync, maximum unthrottled framerate
    if (g_pD3D->CreateDevice(D3DADAPTER_DEFAULT, D3DDEVTYPE_HAL, g_hwnd, D3DCREATE_HARDWARE_VERTEXPROCESSING, &g_d3dpp, &g_pd3dDevice) < 0)
        return false;

    return true;
}

void ui::CleanupDeviceD3D()
{
    if (g_pd3dDevice) { g_pd3dDevice->Release(); g_pd3dDevice = nullptr; }
    if (g_pD3D) { g_pD3D->Release(); g_pD3D = nullptr; }
}

void ui::ResetDevice()
{
    ImGui_ImplDX9_InvalidateDeviceObjects();
    HRESULT hr = g_pd3dDevice->Reset(&g_d3dpp);
    if (hr == D3DERR_INVALIDCALL)
        IM_ASSERT(0);
    ImGui_ImplDX9_CreateDeviceObjects();
}

void ui::init()
{
    // Create application window
    ImGui_ImplWin32_EnableDpiAwareness();
    g_wc = { sizeof(g_wc), CS_CLASSDC, WndProc, 0L, 0L, GetModuleHandle(nullptr), nullptr, nullptr, nullptr, nullptr, L"ImGui Example", nullptr };
    ::RegisterClassExW(&g_wc);
    g_hwnd = ::CreateWindowW(g_wc.lpszClassName, L"Dear ImGui DirectX9 Example", WS_OVERLAPPEDWINDOW, 10, 10, 100, 100, nullptr, nullptr, g_wc.hInstance, nullptr);

    // Initialize Direct3D
    if (!CreateDeviceD3D())
    {
        CleanupDeviceD3D();
        ::UnregisterClassW(g_wc.lpszClassName, g_wc.hInstance);
        return;
    }

    // Show the window
    ::ShowWindow(g_hwnd, SW_HIDE);
    ::UpdateWindow(g_hwnd);

    // Setup Dear ImGui context
    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    ImGuiIO& io = ImGui::GetIO(); (void) io;
    io.ConfigFlags |= ImGuiConfigFlags_NavEnableKeyboard;     // Enable Keyboard Controls
    io.ConfigFlags |= ImGuiConfigFlags_NavEnableGamepad;      // Enable Gamepad Controls
    io.ConfigFlags |= ImGuiConfigFlags_DockingEnable;         // Enable Docking
    io.ConfigFlags |= ImGuiConfigFlags_ViewportsEnable;       // Enable Multi-Viewport / Platform Windows
    //io.ConfigViewportsNoAutoMerge = true;
    //io.ConfigViewportsNoTaskBarIcon = true;

    // Setup Dear ImGui style
    ImGui::StyleColorsDark();

    // When viewports are enabled we tweak WindowRounding/WindowBg so platform windows can look identical to regular ones.
    ImGuiStyle& style = ImGui::GetStyle();
    if (io.ConfigFlags & ImGuiConfigFlags_ViewportsEnable)
    {
        style.WindowRounding = 0.0f;
        style.Colors[ImGuiCol_WindowBg].w = 1.0f;
    }

    // init images
    HRESULT hr = D3DXCreateTextureFromFileInMemoryEx(
        g_pd3dDevice,
        image_data::rust,              // Pointer to the image data
        sizeof(image_data::rust),      // Size of the image data
        D3DX_DEFAULT,                   // Width
        D3DX_DEFAULT,                   // Height
        D3DX_DEFAULT,                   // Mip levels
        0,                              // Usage
        D3DFMT_UNKNOWN,                 // Format
        D3DPOOL_MANAGED,                // Memory pool
        D3DX_DEFAULT,                   // Filter
        D3DX_DEFAULT,                   // Mip filter
        0,                              // Color key
        &info,                          // Info structure to receive image information
        nullptr,                        // Palette (not used)
        &dx_image_texture               // Pointer to the texture
    );

    im_image_texture = reinterpret_cast<ImTextureID>(dx_image_texture);

    // Setup Platform/Renderer backends
    ImGui_ImplWin32_Init(g_hwnd);
    ImGui_ImplDX9_Init(g_pd3dDevice);
}

void ui::render()
{
    if (!quit)
        exit();

    ImVec4 clear_color = ImVec4(0.45f, 0.55f, 0.60f, 1.00f);

    MSG msg;
    while (::PeekMessage(&msg, nullptr, 0U, 0U, PM_REMOVE))
    {
        ::TranslateMessage(&msg);
        ::DispatchMessage(&msg);
        if (msg.message == WM_QUIT)
            exit();
    }

    if (g_DeviceLost)
    {
        HRESULT hr = g_pd3dDevice->TestCooperativeLevel();
        if (hr == D3DERR_DEVICELOST)
        {
            ::Sleep(10);
            return;
        }
        if (hr == D3DERR_DEVICENOTRESET)
            ResetDevice();
        g_DeviceLost = false;
    }

    if (g_ResizeWidth != 0 && g_ResizeHeight != 0)
    {
        g_d3dpp.BackBufferWidth = g_ResizeWidth;
        g_d3dpp.BackBufferHeight = g_ResizeHeight;
        g_ResizeWidth = g_ResizeHeight = 0;
        ResetDevice();
    }

    ImGui_ImplDX9_NewFrame();
    ImGui_ImplWin32_NewFrame();
    ImGui::NewFrame();

    if (!user_data::is_authenticated)
        render_login();
    else
        render_main();

    // Rendering
    ImGui::EndFrame();
    g_pd3dDevice->SetRenderState(D3DRS_ZENABLE, FALSE);
    g_pd3dDevice->SetRenderState(D3DRS_ALPHABLENDENABLE, FALSE);
    g_pd3dDevice->SetRenderState(D3DRS_SCISSORTESTENABLE, FALSE);
    D3DCOLOR clear_col_dx = D3DCOLOR_RGBA((int) (clear_color.x * clear_color.w * 255.0f), (int) (clear_color.y * clear_color.w * 255.0f), (int) (clear_color.z * clear_color.w * 255.0f), (int) (clear_color.w * 255.0f));
    g_pd3dDevice->Clear(0, nullptr, D3DCLEAR_TARGET | D3DCLEAR_ZBUFFER, clear_col_dx, 1.0f, 0);
    if (g_pd3dDevice->BeginScene() >= 0)
    {
        ImGui::Render();
        ImGui_ImplDX9_RenderDrawData(ImGui::GetDrawData());
        g_pd3dDevice->EndScene();
    }

    // Update and Render additional Platform Windows
    ImGuiIO& io = ImGui::GetIO(); (void) io;
    if (io.ConfigFlags & ImGuiConfigFlags_ViewportsEnable)
    {
        ImGui::UpdatePlatformWindows();
        ImGui::RenderPlatformWindowsDefault();
    }

    HRESULT result = g_pd3dDevice->Present(nullptr, nullptr, nullptr, nullptr);
    if (result == D3DERR_DEVICELOST)
        g_DeviceLost = true;
}

void ui::render_main()
{
    // start user session 
    if (!loader_data::session_thread_launched)
    {
        HANDLE h = CreateThread(NULL, NULL, (LPTHREAD_START_ROUTINE) auth::manage_user_session, NULL, NULL, NULL);
        if (h)
            CloseHandle(h);
    }

    static auto style = ImGui::GetStyle();

    ImGui::SetNextWindowSize(ImVec2(0, 0), ImGuiCond_Always);
    ImGui::Begin($("MainWindow"), &quit);

    // Image Child
    ImGui::BeginChildFrame(1, ImVec2(100, 100));
    ImGui::Image(im_image_texture, ImVec2(100 - style.WindowPadding.x, 100 - style.WindowPadding.y));
    ImGui::EndChildFrame();

    // User Info Child
    ImGui::SameLine();
    ImGui::BeginChildFrame(2, ImVec2(450, 100));
    ImGui::Text($("Sub expires on:")); ImGui::SameLine(); ImGui::Text(user_data::expiry_date_str.c_str());
    ImGui::Text($("Cheat Status:")); ImGui::SameLine(); ImGui::TextColored(ImVec4(0, 1, 0, 1), $("Online"));
    ImGui::EndChildFrame();

    // Main Child
    ImGui::SetCursorPosY(ImGui::GetCursorPosY() + style.ItemSpacing.y);
    ImGui::BeginChildFrame(3, ImVec2(450, 200));
    if (ImGui::BeginListBox("##LogBox", ImVec2(-1, -1)))
    {
        for (auto s : loader_data::log)
        {
            ImGui::PushTextWrapPos();
            ImGui::Text(s.c_str());
            ImGui::PopTextWrapPos();
        }
        if (loader_data::log.size() != loader_data::old_log_size)
        {
            ImGui::SetScrollHereY();
            loader_data::old_log_size = loader_data::log.size();
        }

        ImGui::EndListBox();
    }
    ImGui::EndChildFrame();

    // Load Button Child
    ImGui::SameLine();
    ImGui::BeginChildFrame(4, ImVec2(100, 200));
    ImGui::Button($("Load"), ImVec2(-1, 100 - style.ItemSpacing.y - 1)); // TOOD: LOAD PROCESS
    if (ImGui::Button($("Exit"), ImVec2(-1, 100 - style.ItemSpacing.y - 1)))
        exit();
    ImGui::EndChildFrame();

    ImGui::End();
}

void ui::render_login()
{
    ImGui::SetNextWindowSize(ImVec2(0, 0), ImGuiCond_Always);
    ImGui::Begin($("Login"), &quit);
    ImGui::Text($("Please enter your Key to log in!"));
    ImGui::SetNextItemWidth(-1.f);
    ImGui::InputTextWithHint($("##KeyInput"), $("Key"), user_data::key, 256, ImGuiInputTextFlags_CharsUppercase);
    ImGui::TextColored(ImVec4(1, 0, 0, 1), loader_data::auth_errors.c_str());

    bool flags_added = false;
    if (loader_data::processing_request)
    {
        ImGui::PushItemFlag(ImGuiItemFlags_Disabled, true);
        ImGui::PushStyleVar(ImGuiStyleVar_Alpha, ImGui::GetStyle().Alpha * 0.5f);
        flags_added = true;
    }
    if ((ImGui::Button($("Login"), ImVec2(-1, 0)) || GetAsyncKeyState(VK_RETURN) & 0x01) && !loader_data::processing_request)
    {
        loader_data::processing_request = true;
        HANDLE h = CreateThread(NULL, NULL, (LPTHREAD_START_ROUTINE)auth::login, NULL, NULL, NULL);
        if (h)
            CloseHandle(h);
    }
    if (loader_data::processing_request && flags_added)
    {
        ImGui::PopItemFlag();
        ImGui::PopStyleVar();
    }
    ImGui::End();
}

void ui::exit()
{
    ImGui_ImplDX9_Shutdown();
    ImGui_ImplWin32_Shutdown();
    ImGui::DestroyContext();

    CleanupDeviceD3D();
    ::DestroyWindow(g_hwnd);
    ::UnregisterClassW(g_wc.lpszClassName, g_wc.hInstance);

    if (dx_image_texture) {
        dx_image_texture->Release();
        dx_image_texture = nullptr;
    }

    ExitProcess(0);
}