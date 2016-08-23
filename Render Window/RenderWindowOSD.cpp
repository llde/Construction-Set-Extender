﻿#include "RenderWindowOSD.h"
#include "Render Window\RenderWindowManager.h"
#include "IMGUI\imgui_internal.h"

#include "ActiveRefCollectionsOSDLayer.h"
#include "DefaultOverlayOSDLayer.h"
#include "MouseOverTooltipOSDLayer.h"
#include "ToolbarOSDLayer.h"
#include "SelectionControlsOSDLayer.h"

#include <bgsee\RenderWindowFlyCamera.h>

namespace cse
{
	namespace renderWindow
	{
		struct CUSTOMVERTEX
		{
			float    pos[3];
			D3DCOLOR col;
			float    uv[2];
		};
#define D3DFVF_CUSTOMVERTEX (D3DFVF_XYZ|D3DFVF_DIFFUSE|D3DFVF_TEX1)

		void ImGuiDX9::RenderDrawLists(ImDrawData* draw_data)
		{
			ImGuiIO& io = ImGui::GetIO();
			ImGuiDX9* Impl = (ImGuiDX9*)io.UserData;
			SME_ASSERT(Impl->IsInitialized());

			// Avoid rendering when minimized
			if (io.DisplaySize.x <= 0.0f || io.DisplaySize.y <= 0.0f)
				return;

			// Create and grow buffers if needed
			if (!Impl->VertexBuffer || Impl->VertexBufferSize < draw_data->TotalVtxCount)
			{
				if (Impl->VertexBuffer) { Impl->VertexBuffer->Release(); Impl->VertexBuffer = nullptr; }
				Impl->VertexBufferSize = draw_data->TotalVtxCount + 5000;
				if (Impl->D3DDevice->CreateVertexBuffer(Impl->VertexBufferSize * sizeof(CUSTOMVERTEX), D3DUSAGE_DYNAMIC | D3DUSAGE_WRITEONLY, D3DFVF_CUSTOMVERTEX, D3DPOOL_DEFAULT, &Impl->VertexBuffer, nullptr) < 0)
					return;
			}
			if (!Impl->IndexBuffer || Impl->IndexBufferSize < draw_data->TotalIdxCount)
			{
				if (Impl->IndexBuffer) { Impl->IndexBuffer->Release(); Impl->IndexBuffer = nullptr; }
				Impl->IndexBufferSize = draw_data->TotalIdxCount + 10000;
				if (Impl->D3DDevice->CreateIndexBuffer(Impl->IndexBufferSize * sizeof(ImDrawIdx), D3DUSAGE_DYNAMIC | D3DUSAGE_WRITEONLY, sizeof(ImDrawIdx) == 2 ? D3DFMT_INDEX16 : D3DFMT_INDEX32, D3DPOOL_DEFAULT, &Impl->IndexBuffer, nullptr) < 0)
					return;
			}

			// Backup the DX9 state
			IDirect3DStateBlock9* d3d9_state_block = nullptr;
			if (Impl->D3DDevice->CreateStateBlock(D3DSBT_ALL, &d3d9_state_block) < 0)
				return;

			// Copy and convert all vertices into a single contiguous buffer
			CUSTOMVERTEX* vtx_dst;
			ImDrawIdx* idx_dst;
			if (Impl->VertexBuffer->Lock(0, (UINT)(draw_data->TotalVtxCount * sizeof(CUSTOMVERTEX)), (void**)&vtx_dst, D3DLOCK_DISCARD) < 0)
				return;
			if (Impl->IndexBuffer->Lock(0, (UINT)(draw_data->TotalIdxCount * sizeof(ImDrawIdx)), (void**)&idx_dst, D3DLOCK_DISCARD) < 0)
				return;
			for (int n = 0; n < draw_data->CmdListsCount; n++)
			{
				const ImDrawList* cmd_list = draw_data->CmdLists[n];
				const ImDrawVert* vtx_src = &cmd_list->VtxBuffer[0];
				for (int i = 0; i < cmd_list->VtxBuffer.size(); i++)
				{
					vtx_dst->pos[0] = vtx_src->pos.x;
					vtx_dst->pos[1] = vtx_src->pos.y;
					vtx_dst->pos[2] = 0.0f;
					vtx_dst->col = (vtx_src->col & 0xFF00FF00) | ((vtx_src->col & 0xFF0000) >> 16) | ((vtx_src->col & 0xFF) << 16);     // RGBA --> ARGB for DirectX9
					vtx_dst->uv[0] = vtx_src->uv.x;
					vtx_dst->uv[1] = vtx_src->uv.y;
					vtx_dst++;
					vtx_src++;
				}
				memcpy(idx_dst, &cmd_list->IdxBuffer[0], cmd_list->IdxBuffer.size() * sizeof(ImDrawIdx));
				idx_dst += cmd_list->IdxBuffer.size();
			}
			Impl->VertexBuffer->Unlock();
			Impl->IndexBuffer->Unlock();
			Impl->D3DDevice->SetStreamSource(0, Impl->VertexBuffer, 0, sizeof(CUSTOMVERTEX));
			Impl->D3DDevice->SetIndices(Impl->IndexBuffer);
			Impl->D3DDevice->SetFVF(D3DFVF_CUSTOMVERTEX);

			// Setup render state: fixed-pipeline, alpha-blending, no face culling, no depth testing
			Impl->D3DDevice->SetPixelShader(nullptr);
			Impl->D3DDevice->SetVertexShader(nullptr);
			Impl->D3DDevice->SetRenderState(D3DRS_FILLMODE, D3DFILL_SOLID);
			Impl->D3DDevice->SetRenderState(D3DRS_CULLMODE, D3DCULL_NONE);
			Impl->D3DDevice->SetRenderState(D3DRS_LIGHTING, false);
			Impl->D3DDevice->SetRenderState(D3DRS_ZENABLE, false);
			Impl->D3DDevice->SetRenderState(D3DRS_ALPHABLENDENABLE, true);
			Impl->D3DDevice->SetRenderState(D3DRS_ALPHATESTENABLE, false);
			Impl->D3DDevice->SetRenderState(D3DRS_BLENDOP, D3DBLENDOP_ADD);
			Impl->D3DDevice->SetRenderState(D3DRS_SRCBLEND, D3DBLEND_SRCALPHA);
			Impl->D3DDevice->SetRenderState(D3DRS_DESTBLEND, D3DBLEND_INVSRCALPHA);
			Impl->D3DDevice->SetRenderState(D3DRS_SCISSORTESTENABLE, true);
			Impl->D3DDevice->SetTextureStageState(0, D3DTSS_COLOROP, D3DTOP_MODULATE);
			Impl->D3DDevice->SetTextureStageState(0, D3DTSS_COLORARG1, D3DTA_TEXTURE);
			Impl->D3DDevice->SetTextureStageState(0, D3DTSS_COLORARG2, D3DTA_DIFFUSE);
			Impl->D3DDevice->SetTextureStageState(0, D3DTSS_ALPHAOP, D3DTOP_MODULATE);
			Impl->D3DDevice->SetTextureStageState(0, D3DTSS_ALPHAARG1, D3DTA_TEXTURE);
			Impl->D3DDevice->SetTextureStageState(0, D3DTSS_ALPHAARG2, D3DTA_DIFFUSE);
			Impl->D3DDevice->SetSamplerState(0, D3DSAMP_MINFILTER, D3DTEXF_LINEAR);
			Impl->D3DDevice->SetSamplerState(0, D3DSAMP_MAGFILTER, D3DTEXF_LINEAR);

			// Setup orthographic projection matrix
			// Being agnostic of whether <d3dx9.h> or <DirectXMath.h> can be used, we aren't relying on D3DXMatrixIdentity()/D3DXMatrixOrthoOffCenterLH() or DirectX::XMMatrixIdentity()/DirectX::XMMatrixOrthographicOffCenterLH()
			{
				const float L = 0.5f, R = io.DisplaySize.x + 0.5f, T = 0.5f, B = io.DisplaySize.y + 0.5f;
				D3DMATRIX mat_identity = { { 1.0f, 0.0f, 0.0f, 0.0f,  0.0f, 1.0f, 0.0f, 0.0f,  0.0f, 0.0f, 1.0f, 0.0f,  0.0f, 0.0f, 0.0f, 1.0f } };
				D3DMATRIX mat_projection =
				{
					2.0f / (R - L),   0.0f,         0.0f,  0.0f,
					0.0f,         2.0f / (T - B),   0.0f,  0.0f,
					0.0f,         0.0f,         0.5f,  0.0f,
					(L + R) / (L - R),  (T + B) / (B - T),  0.5f,  1.0f,
				};
				Impl->D3DDevice->SetTransform(D3DTS_WORLD, &mat_identity);
				Impl->D3DDevice->SetTransform(D3DTS_VIEW, &mat_identity);
				Impl->D3DDevice->SetTransform(D3DTS_PROJECTION, &mat_projection);
			}

			// Render command lists
			int vtx_offset = 0;
			int idx_offset = 0;
			for (int n = 0; n < draw_data->CmdListsCount; n++)
			{
				const ImDrawList* cmd_list = draw_data->CmdLists[n];
				for (int cmd_i = 0; cmd_i < cmd_list->CmdBuffer.size(); cmd_i++)
				{
					const ImDrawCmd* pcmd = &cmd_list->CmdBuffer[cmd_i];
					if (pcmd->UserCallback)
					{
						pcmd->UserCallback(cmd_list, pcmd);
					}
					else
					{
						const RECT r = { (LONG)pcmd->ClipRect.x, (LONG)pcmd->ClipRect.y, (LONG)pcmd->ClipRect.z, (LONG)pcmd->ClipRect.w };
						Impl->D3DDevice->SetTexture(0, (LPDIRECT3DTEXTURE9)pcmd->TextureId);
						Impl->D3DDevice->SetScissorRect(&r);
						Impl->D3DDevice->DrawIndexedPrimitive(D3DPT_TRIANGLELIST, vtx_offset, 0, (UINT)cmd_list->VtxBuffer.size(), idx_offset, pcmd->ElemCount / 3);
					}
					idx_offset += pcmd->ElemCount;
				}
				vtx_offset += cmd_list->VtxBuffer.size();
			}

			// Restore the DX9 state
			d3d9_state_block->Apply();
			d3d9_state_block->Release();
		}

		bool ImGuiDX9::CreateFontsTexture()
		{
			// Build texture atlas
			ImGuiIO& io = ImGui::GetIO();
			ImFontConfig config;
			config.OversampleH = 8;
			config.OversampleV = 8;

			std::string FontPath(BGSEEWORKSPACE->GetDefaultWorkspace());
			FontPath.append("Data\\Fonts\\").append(settings::renderWindowOSD::kFontFace().s);
			if (GetFileAttributes(FontPath.c_str()) != INVALID_FILE_ATTRIBUTES)
				io.Fonts->AddFontFromFileTTF(FontPath.c_str(), settings::renderWindowOSD::kFontSize().i, &config);

			unsigned char* pixels;
			int width, height, bytes_per_pixel;
			io.Fonts->GetTexDataAsRGBA32(&pixels, &width, &height, &bytes_per_pixel);

			// Upload texture to graphics system
			SAFERELEASE_D3D(FontTexture);
			if (D3DDevice->CreateTexture(width, height, 1, D3DUSAGE_DYNAMIC, D3DFMT_A8R8G8B8, D3DPOOL_DEFAULT, &FontTexture, nullptr) < 0)
				return false;
			D3DLOCKED_RECT tex_locked_rect;
			if (FontTexture->LockRect(0, &tex_locked_rect, nullptr, 0) != D3D_OK)
				return false;
			for (int y = 0; y < height; y++)
				memcpy((unsigned char *)tex_locked_rect.pBits + tex_locked_rect.Pitch * y, pixels + (width * bytes_per_pixel) * y, (width * bytes_per_pixel));
			FontTexture->UnlockRect(0);

			// Store our identifier
			io.Fonts->TexID = (void *)FontTexture;

			return true;
		}

		ImGuiDX9::ImGuiDX9()
		{
			VertexBuffer = nullptr;
			IndexBuffer = nullptr;
			VertexBufferSize = 5000;
			IndexBufferSize = 10000;
			FontTexture = nullptr;
			Time = 0;
			TicksPerSecond = 0;
			RenderWindowHandle = nullptr;
			D3DDevice = nullptr;
			MouseDoubleClicked[0] = MouseDoubleClicked[1] = false;
			Initialized = false;
		}

		ImGuiDX9::~ImGuiDX9()
		{
			Shutdown();
		}

		bool ImGuiDX9::Initialize(HWND RenderWindow, IDirect3DDevice9* Device)
		{
			RenderWindowHandle = RenderWindow;
			D3DDevice = Device;
			SME_ASSERT(RenderWindowHandle && D3DDevice);

			if (!QueryPerformanceFrequency((LARGE_INTEGER *)&TicksPerSecond))
				return false;
			if (!QueryPerformanceCounter((LARGE_INTEGER *)&Time))
				return false;

			ImGuiIO& io = ImGui::GetIO();
			io.KeyMap[ImGuiKey_Tab] = VK_TAB;
			io.KeyMap[ImGuiKey_LeftArrow] = VK_LEFT;
			io.KeyMap[ImGuiKey_RightArrow] = VK_RIGHT;
			io.KeyMap[ImGuiKey_UpArrow] = VK_UP;
			io.KeyMap[ImGuiKey_DownArrow] = VK_DOWN;
			io.KeyMap[ImGuiKey_PageUp] = VK_PRIOR;
			io.KeyMap[ImGuiKey_PageDown] = VK_NEXT;
			io.KeyMap[ImGuiKey_Home] = VK_HOME;
			io.KeyMap[ImGuiKey_End] = VK_END;
			io.KeyMap[ImGuiKey_Delete] = VK_DELETE;
			io.KeyMap[ImGuiKey_Backspace] = VK_BACK;
			io.KeyMap[ImGuiKey_Enter] = VK_RETURN;
			io.KeyMap[ImGuiKey_Escape] = VK_ESCAPE;
			io.KeyMap[ImGuiKey_A] = 'A';
			io.KeyMap[ImGuiKey_C] = 'C';
			io.KeyMap[ImGuiKey_V] = 'V';
			io.KeyMap[ImGuiKey_X] = 'X';
			io.KeyMap[ImGuiKey_Y] = 'Y';
			io.KeyMap[ImGuiKey_Z] = 'Z';
			io.MouseDoubleClickTime = 1.f;
			io.RenderDrawListsFn = RenderDrawLists;
			io.UserData = this;

			Initialized = true;
			return true;
		}

		void ImGuiDX9::Shutdown()
		{
			InvalidateDeviceObjects();
			ImGui::Shutdown();
		}

		void ImGuiDX9::NewFrame()
		{
			SME_ASSERT(Initialized);

			if (!FontTexture)
				CreateDeviceObjects();

			ImGuiIO& io = ImGui::GetIO();

			// Setup display size (every frame to accommodate for window resizing)
			RECT rect;
			GetClientRect(RenderWindowHandle, &rect);
			io.DisplaySize = ImVec2((float)(rect.right - rect.left), (float)(rect.bottom - rect.top));

			// Setup time step
			INT64 current_time;
			QueryPerformanceCounter((LARGE_INTEGER *)&current_time);
			io.DeltaTime = (float)(current_time - Time) / TicksPerSecond;
			Time = current_time;

			// Read keyboard modifiers inputs
			io.KeyCtrl = (GetKeyState(VK_CONTROL) & 0x8000) != 0;
			io.KeyShift = (GetKeyState(VK_SHIFT) & 0x8000) != 0;
			io.KeyAlt = (GetKeyState(VK_MENU) & 0x8000) != 0;
			io.KeySuper = false;

			// set up window styles and colors
			ImGuiStyle& style = ImGui::GetStyle();

			style.WindowPadding = ImVec2(10, 10);
			style.WindowRounding = 5.0f;
			style.ChildWindowRounding = 5.0f;
			style.FramePadding = ImVec2(5, 3);
			style.FrameRounding = 4.0f;
			style.ItemSpacing = ImVec2(12, 8);
			style.ItemInnerSpacing = ImVec2(8, 6);
			style.IndentSpacing = 25.0f;
			style.ScrollbarSize = 15.0f;
			style.ScrollbarRounding = 9.0f;
			style.GrabRounding = 3.0f;

			style.Colors[ImGuiCol_WindowBg] = ImVec4(0.00f, 0.00f, 0.00f, settings::renderWindowOSD::kWindowBGAlpha().f);
			style.Colors[ImGuiCol_ChildWindowBg] = ImVec4(0.00f, 0.00f, 0.00f, settings::renderWindowOSD::kWindowBGAlpha().f);
			style.Colors[ImGuiCol_FrameBgHovered] = ImVec4(0.90f, 0.80f, 0.80f, 0.49f);
			style.Colors[ImGuiCol_TitleBg] = ImVec4(0.00f, 0.00f, 0.00f, 0.31f);
			style.Colors[ImGuiCol_TitleBgCollapsed] = ImVec4(0.00f, 0.00f, 0.00f, 0.20f);
			style.Colors[ImGuiCol_TitleBgActive] = ImVec4(0.00f, 0.00f, 0.00f, 0.78f);
			style.Colors[ImGuiCol_ScrollbarGrab] = ImVec4(0.40f, 0.40f, 0.80f, 0.53f);
			style.Colors[ImGuiCol_Button] = ImVec4(0.35f, 0.55f, 0.61f, 0.51f);
			style.Colors[ImGuiCol_Header] = ImVec4(0.69f, 0.42f, 0.39f, 0.00f);
			style.Colors[ImGuiCol_HeaderHovered] = ImVec4(0.69f, 0.42f, 0.44f, 0.44f);

			// Start the frame
			ImGui::NewFrame();

			// manually update the double click state as ImGui's default polling doesn't consistently catch the events given our conditional rendering
			io.MouseDoubleClicked[0] = MouseDoubleClicked[0];
			io.MouseDoubleClicked[1] = MouseDoubleClicked[1];
		}

		void ImGuiDX9::Render()
		{
			ImGui::Render();

			// reset mouse double click state for the next frame
			MouseDoubleClicked[0] = MouseDoubleClicked[1] = false;
		}

		void ImGuiDX9::InvalidateDeviceObjects()
		{
			if (!D3DDevice)
				return;

			SAFERELEASE_D3D(VertexBuffer);
			SAFERELEASE_D3D(IndexBuffer);

			if (LPDIRECT3DTEXTURE9 tex = (LPDIRECT3DTEXTURE9)ImGui::GetIO().Fonts->TexID)
			{
				tex->Release();
				ImGui::GetIO().Fonts->TexID = 0;
			}

			FontTexture = nullptr;
		}

		bool ImGuiDX9::CreateDeviceObjects()
		{
			if (!D3DDevice)
				return false;

			if (!CreateFontsTexture())
				return false;

			return true;
		}

		bool ImGuiDX9::UpdateInputState(HWND, UINT msg, WPARAM wParam, LPARAM lParam)
		{
			ImGuiIO& io = ImGui::GetIO();

			switch (msg)
			{
			case WM_LBUTTONDOWN:
				io.MouseDown[0] = true;
				return true;
			case WM_LBUTTONUP:
				io.MouseDown[0] = false;
				return true;
			case WM_RBUTTONDOWN:
				io.MouseDown[1] = true;
				return true;
			case WM_RBUTTONUP:
				io.MouseDown[1] = false;
				return true;
			case WM_MBUTTONDOWN:
				io.MouseDown[2] = true;
				return true;
			case WM_MBUTTONUP:
				io.MouseDown[2] = false;
				return true;
			case WM_MOUSEWHEEL:
				io.MouseWheel += GET_WHEEL_DELTA_WPARAM(wParam) > 0 ? +1.0f : -1.0f;
				return true;
			case WM_MOUSEMOVE:
				io.MousePos.x = (signed short)(lParam);
				io.MousePos.y = (signed short)(lParam >> 16);
				return true;
			case WM_KEYDOWN:
				if (wParam < 256)
					io.KeysDown[wParam] = 1;
				return true;
			case WM_KEYUP:
				if (wParam < 256)
					io.KeysDown[wParam] = 0;
				return true;
			case WM_CHAR:
				// You can also use ToAscii()+GetKeyboardState() to retrieve characters.
				if (wParam > 0 && wParam < 0x10000)
					io.AddInputCharacter((unsigned short)wParam);
				return true;
			case WM_LBUTTONDBLCLK:
				MouseDoubleClicked[0] = true;
				return true;
			case WM_RBUTTONDBLCLK:
				MouseDoubleClicked[1] = true;
				return true;
			}

			return false;
		}

		bool ImGuiDX9::NeedsInput() const
		{
			ImGuiIO& io = ImGui::GetIO();
			return io.WantCaptureMouse || io.WantCaptureKeyboard || io.WantTextInput;
		}

		bool ImGuiDX9::IsInitialized() const
		{
			return Initialized;
		}

		bool ImGuiDX9::IsDraggingWindow() const
		{
			if (Initialized == false)
				return false;

			ImGuiContext* RenderContext = ImGui::GetCurrentContext();
			if (ImGui::IsMouseDragging() && RenderContext->ActiveId == RenderContext->MovedWindowMoveId)
				return true;
			else
				return false;
		}

		bool ImGuiDX9::IsPopupHovered() const
		{
			ImGuiContext& g = *GImGui;
			int popup_idx = g.CurrentPopupStack.Size - 1;
			if (popup_idx < 0 || popup_idx > g.OpenPopupStack.Size || g.CurrentPopupStack[popup_idx].PopupId != g.OpenPopupStack[popup_idx].PopupId)
				return false;

			ImGuiPopupRef& Itr = g.OpenPopupStack[popup_idx];
			return g.HoveredWindow == Itr.Window;
		}

		RenderWindowOSD::DialogExtraData::DialogExtraData(RenderWindowOSD* OSD) :
			bgsee::WindowExtraData(kTypeID),
			Parent(OSD)
		{
			SME_ASSERT(OSD);
		}

		RenderWindowOSD::DialogExtraData::~DialogExtraData()
		{
			Parent = nullptr;
		}

		RenderWindowOSD::GUIState::GUIState()
		{
			MouseInClientArea = false;
		}

		// lParam = DialogExtraData*
#define WM_RENDERWINDOWOSD_INITXDATA			(WM_USER + 2015)

		LRESULT CALLBACK RenderWindowOSD::OSDSubclassProc(HWND hWnd, UINT uMsg, WPARAM wParam, LPARAM lParam, bool& Return, bgsee::WindowExtraDataCollection* ExtraData)
		{
			LRESULT DlgProcResult = TRUE;
			Return = false;

			if (uMsg == WM_RENDERWINDOWOSD_INITXDATA)
			{
				bool Added = ExtraData->Add((DialogExtraData*)lParam);
				SME_ASSERT(Added);
			}

			DialogExtraData* xData = BGSEE_GETWINDOWXDATA_QUICK(DialogExtraData, ExtraData);
			if (xData == nullptr)
				return DlgProcResult;

			RenderWindowOSD* Parent = xData->Parent;
			ImGuiDX9* Pipeline = Parent->Pipeline;

			if (bgsee::RenderWindowFlyCamera::IsActive() && uMsg != WM_DESTROY)
			{
				// do nothing if the fly camera is active
				return DlgProcResult;
			}
			else if (Parent->RenderingLayers)
			{
				// do nothing if we're still rendering the previous frame
				return DlgProcResult;
			}

			// get input data and flag the viewport for update
			if (Pipeline->UpdateInputState(hWnd, uMsg, wParam, lParam))
			{
				if (GetCapture() != hWnd && GetActiveWindow() == hWnd)
				{
					TESRenderWindow::Redraw();

					// check if the GUI needs input, skip the org wndproc if true
					// the check is performed on the previous frame's state but it works for our purposes
					if (Pipeline->NeedsInput())
					{
						if (uMsg != WM_KEYDOWN && uMsg != WM_KEYUP)
							Return = true;
						else
						{
							// special-case shortcuts
							ImGuiIO& io = ImGui::GetIO();
							if (io.WantTextInput)
								Return = true;
						}
					}
				}
			}


			switch (uMsg)
			{
			case WM_DESTROY:
				ExtraData->Remove(DialogExtraData::kTypeID);
				delete xData;

				break;
			case WM_LBUTTONDBLCLK:
				{
					if (Parent->NeedsInput())
					{
						// preempt the vanilla handler
						Return = true;
					}
				}

				break;
			case WM_MOUSEMOVE:
			case WM_NCMOUSEMOVE:
				if (GetActiveWindow() == hWnd)
					Parent->State.MouseInClientArea = true;

				break;
			case WM_MOUSELEAVE:
			case WM_NCMOUSELEAVE:
				Parent->State.MouseInClientArea = false;

				break;
			case WM_ACTIVATE:
				if (LOWORD(wParam) == WA_INACTIVE)
					Parent->State.MouseInClientArea = false;

				break;
			case WM_TIMER:
				// main render loop
				if (wParam == TESRenderWindow::kTimer_ViewportUpdate && *TESRenderWindow::ActiveCell)
				{
					// refresh the viewport if the mouse is in the client area or there are pending notifications
					if (Parent->State.MouseInClientArea || Parent->NeedsBackgroundUpdate())
						TESRenderWindow::Redraw();
				}

				break;
			}

			return DlgProcResult;
		}

		void RenderWindowOSD::RenderLayers()
		{
			SME::MiscGunk::ScopedSetter<bool> Sentry(RenderingLayers, true);
			for (auto Itr : AttachedLayers)
			{
				if (Itr->IsEnabled())
					Itr->Draw(this, Pipeline);
			}
		}

		bool RenderWindowOSD::NeedsBackgroundUpdate() const
		{
			for (auto Itr : AttachedLayers)
			{
				if (Itr->NeedsBackgroundUpdate())
					return true;
			}

			return false;
		}

		RenderWindowOSD::RenderWindowOSD() :
			State(),
			AttachedLayers()
		{
			Pipeline = new ImGuiDX9();
			AttachedLayers.reserve(10);
			Initialized = false;
			RenderingLayers = false;
		}

		RenderWindowOSD::~RenderWindowOSD()
		{
			DEBUG_ASSERT(Initialized == false);
			DEBUG_ASSERT(AttachedLayers.size() == 0);

			SAFEDELETE(Pipeline);
			AttachedLayers.clear();
		}

		bool RenderWindowOSD::Initialize()
		{
			SME_ASSERT(Initialized == false);
			SME_ASSERT(_NIRENDERER);

			Pipeline->Initialize(*TESRenderWindow::WindowHandle, _NIRENDERER->device);
			BGSEEUI->GetSubclasser()->RegisterDialogSubclass(TESDialog::kDialogTemplate_RenderWindow, OSDSubclassProc);
			SendMessage(*TESRenderWindow::WindowHandle, WM_RENDERWINDOWOSD_INITXDATA, NULL, (LPARAM)new DialogExtraData(this));

			AttachLayer(&ModalWindowProviderOSDLayer::Instance);
			AttachLayer(&DefaultOverlayOSDLayer::Instance);
			AttachLayer(&MouseOverTooltipOSDLayer::Instance);
			AttachLayer(&NotificationOSDLayer::Instance);
			AttachLayer(&ToolbarOSDLayer::Instance);
			AttachLayer(&SelectionControlsOSDLayer::Instance);
			AttachLayer(&ActiveRefCollectionsOSDLayer::Instance);
#ifndef NDEBUG
			AttachLayer(&DebugOSDLayer::Instance);
#endif
			Initialized = true;

			return Initialized;
		}

		void RenderWindowOSD::Deinitialize()
		{
			SME_ASSERT(Initialized);

			DetachLayer(&ModalWindowProviderOSDLayer::Instance);
			DetachLayer(&DefaultOverlayOSDLayer::Instance);
			DetachLayer(&MouseOverTooltipOSDLayer::Instance);
			DetachLayer(&NotificationOSDLayer::Instance);
			DetachLayer(&ToolbarOSDLayer::Instance);
			DetachLayer(&SelectionControlsOSDLayer::Instance);
			DetachLayer(&ActiveRefCollectionsOSDLayer::Instance);
#ifndef NDEBUG
			DetachLayer(&DebugOSDLayer::Instance);
#endif
			Initialized = false;
		}

		void RenderWindowOSD::Draw()
		{
			if (Initialized && bgsee::RenderWindowFlyCamera::IsActive() == false)
			{
				Pipeline->NewFrame();
				RenderLayers();
			}
		}

		void RenderWindowOSD::Render()
		{
			if (Initialized && bgsee::RenderWindowFlyCamera::IsActive() == false)
			{
				if (RenderingLayers == false)
				{
					// defer the final render call until all layers are done drawing
					Pipeline->Render();
				}
			}
		}

		void RenderWindowOSD::AttachLayer(IRenderWindowOSDLayer* Layer)
		{
			SME_ASSERT(Layer);

			if (std::find(AttachedLayers.begin(), AttachedLayers.end(), Layer) != AttachedLayers.end())
				BGSEECONSOLE_MESSAGE("Attempting to re-add the same OSD layer");
			else
			{
				AttachedLayers.push_back(Layer);
				std::sort(AttachedLayers.begin(), AttachedLayers.end(),
						  [](const IRenderWindowOSDLayer* LHS, const IRenderWindowOSDLayer* RHS) { return LHS->GetPriority() > RHS->GetPriority(); });
			}
		}

		void RenderWindowOSD::DetachLayer(IRenderWindowOSDLayer* Layer)
		{
			SME_ASSERT(Layer);

			LayerArrayT::iterator Match = std::find(AttachedLayers.begin(), AttachedLayers.end(), Layer);
			if (Match != AttachedLayers.end())
				AttachedLayers.erase(Match);
		}

		void RenderWindowOSD::HandleD3DRelease()
		{
			if (Initialized)
				Pipeline->InvalidateDeviceObjects();
		}

		void RenderWindowOSD::HandleD3DRenew()
		{
			;// nothing to do here as the device objects get renewed on demand
		}

		bool RenderWindowOSD::NeedsInput() const
		{
			if (Initialized == false)
				return false;
			else
				return Pipeline->NeedsInput() || ImGui::IsRootWindowOrAnyChildHovered();
		}


		void IRenderWindowOSDLayer::StateData::TextInputData::Update(ImGuiDX9* GUI)
		{
			GotFocus = LostFocus = false;

			if (ImGui::IsMouseHoveringWindow() == false)
				return;

			ImGuiIO& io = ImGui::GetIO();
			if (io.WantTextInput)
			{
				if (Active == false)
				{
					Active = true;
					GotFocus = true;
				}
			}
			else if (Active)
			{
				Active = false;
				LostFocus = true;
			}
		}

		void IRenderWindowOSDLayer::StateData::DragInputData::Update(ImGuiDX9* GUI)
		{
			DragBegin = DragEnd = false;

			if (GUI->IsDraggingWindow())
				return;
			else if (ImGui::IsMouseHoveringWindow() == false)
				return;

			if (ImGui::IsMouseDragging() && ImGui::IsAnyItemActive())
			{
				if (Active == false)
				{
					Active = true;
					DragBegin = true;
				}
			}
			else if (ImGui::IsMouseDragging() == false)
			{
				if (Active)
				{
					Active = false;
					DragEnd = true;
				}
			}
		}

		IRenderWindowOSDLayer::StateData::StateData()
		{
			TextInput.Active = TextInput.GotFocus = TextInput.LostFocus = false;
			DragInput.Active = DragInput.DragBegin = DragInput.DragEnd = false;
		}

		void IRenderWindowOSDLayer::StateData::Update(ImGuiDX9* GUI)
		{
			TextInput.Update(GUI);
			DragInput.Update(GUI);
		}

		IRenderWindowOSDLayer::IRenderWindowOSDLayer(INISetting& Toggle, UInt32 Priority) :
			Toggle(&Toggle),
			Priority(Priority),
			State()
		{
			;//
		}

		IRenderWindowOSDLayer::IRenderWindowOSDLayer(UInt32 Priority) :
			Toggle(nullptr),
			Priority(Priority),
			State()
		{
			;//
		}

		UInt32 IRenderWindowOSDLayer::GetPriority() const
		{
			return Priority;
		}

		bool IRenderWindowOSDLayer::IsEnabled() const
		{
			return Toggle == nullptr || Toggle->GetData().i == 1;
		}


		NotificationOSDLayer		NotificationOSDLayer::Instance;

		NotificationOSDLayer::Notification::Notification(std::string Message) :
			Message(Message),
			StartTickCount(0)
		{
			ZeroMemory(&StartTickCount, sizeof(StartTickCount));
		}

		bool NotificationOSDLayer::Notification::HasElapsed()
		{
			if (StartTickCount == 0)
			{
				StartTickCount = GetTickCount64();
				return false;
			}

			if (GetTickCount64() - StartTickCount > kNotificationDisplayTime)
				return true;
			else
				return false;
		}

		NotificationOSDLayer::NotificationOSDLayer() :
			IRenderWindowOSDLayer(settings::renderWindowOSD::kShowNotifications, IRenderWindowOSDLayer::kPriority_Notifications),
			Notifications()
		{
			;//
		}

		NotificationOSDLayer::~NotificationOSDLayer()
		{
			while (Notifications.size())
				Notifications.pop();
		}

		void NotificationOSDLayer::Draw(RenderWindowOSD* OSD, ImGuiDX9* GUI)
		{
			if (HasNotifications() == false)
				return;

			ImGui::SetNextWindowPos(ImVec2(10, *TESRenderWindow::ScreeHeight - 150));
			if (!ImGui::Begin("Notification Overlay", nullptr, ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoResize | ImGuiWindowFlags_AlwaysAutoResize |
							  ImGuiWindowFlags_NoBringToFrontOnFocus | ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoSavedSettings | ImGuiWindowFlags_NoFocusOnAppearing | ImGuiWindowFlags_NoInputs))
			{
				ImGui::End();
				return;
			}

			ImGui::Text("%s", GetNextNotification().Message.c_str());
			ImGui::End();
		}

		bool NotificationOSDLayer::NeedsBackgroundUpdate()
		{
			return HasNotifications();
		}

		bool NotificationOSDLayer::HasNotifications()
		{
			while (Notifications.size())
			{
				Notification& Next = Notifications.front();
				if (Next.HasElapsed())
					Notifications.pop();
				else
					return true;
			}

			return false;
		}

		const NotificationOSDLayer::Notification& NotificationOSDLayer::GetNextNotification() const
		{
			SME_ASSERT(Notifications.size() > 0);

			return Notifications.front();
		}

		void NotificationOSDLayer::ShowNotification(const char* Format, ...)
		{
			if (Format == nullptr)
				return;

			char Buffer[0x1000] = { 0 };
			va_list Args;
			va_start(Args, Format);
			vsprintf_s(Buffer, sizeof(Buffer), Format, Args);
			va_end(Args);

			if (strlen(Buffer))
				Notifications.push(Notification(Buffer));
		}


		DebugOSDLayer			DebugOSDLayer::Instance;

		DebugOSDLayer::DebugOSDLayer() :
			IRenderWindowOSDLayer(IRenderWindowOSDLayer::kPriority_Debug)
		{

		}

		DebugOSDLayer::~DebugOSDLayer()
		{
			;//
		}

		void DebugOSDLayer::Draw(RenderWindowOSD* OSD, ImGuiDX9* GUI)
		{
			ImGui::ShowTestWindow();
		}

		bool DebugOSDLayer::NeedsBackgroundUpdate()
		{
			return false;
		}


		ModalWindowProviderOSDLayer			ModalWindowProviderOSDLayer::Instance;

		ModalWindowProviderOSDLayer::ModalData::ModalData(const char* Name, ModalRenderDelegateT Delegate, void* UserData, ImGuiWindowFlags_ Flags) :
			WindowName(Name),
			Delegate(Delegate),
			UserData(UserData),
			Flags(Flags),
			Open(false)
		{
			char Buffer[0x100] = {0};
			SME::MersenneTwister::init_genrand(GetTickCount());
			FORMAT_STR(Buffer, "##%d_%s", SME::MersenneTwister::genrand_int32(), Name);

			WindowName.append(Buffer);
		}

		ModalWindowProviderOSDLayer::ModalWindowProviderOSDLayer() :
			IRenderWindowOSDLayer(kPriority_ModalProvider),
			OpenModals()
		{
			;//
		}

		ModalWindowProviderOSDLayer::~ModalWindowProviderOSDLayer()
		{
			while (OpenModals.size())
			{
				OpenModals.pop();
				ImGui::CloseCurrentPopup();
			}
		}

		void ModalWindowProviderOSDLayer::Draw(RenderWindowOSD* OSD, ImGuiDX9* GUI)
		{
			if (OpenModals.size())
			{
				// only renders one modal at a time (the topmost)
				ModalData& Top = OpenModals.top();
				if (Top.Open == false)
				{
					ImGui::OpenPopup(Top.WindowName.c_str());
					Top.Open = true;
				}

				if (ImGui::BeginPopupModal(Top.WindowName.c_str(), nullptr, Top.Flags))
				{
					if (Top.Delegate(OSD, GUI, Top.UserData))
					{
						ImGui::CloseCurrentPopup();
						OpenModals.pop();
					}

					ImGui::EndPopup();
				}
			}
		}

		bool ModalWindowProviderOSDLayer::NeedsBackgroundUpdate()
		{
			return false;
		}

		void ModalWindowProviderOSDLayer::ShowModal(const char* Name, ModalRenderDelegateT Delegate, void* UserData, ImGuiWindowFlags_ Flags)
		{
			SME_ASSERT(Name && Delegate);

			// flag the current open modal, if any, as closed
			if (OpenModals.size())
			{
				ModalData& Top = OpenModals.top();
				if (Top.Open)
					Top.Open = false;
			}

			ModalData NewModal(Name, Delegate, UserData, Flags);
			OpenModals.push(NewModal);
		}

		bool ModalWindowProviderOSDLayer::HasOpenModals() const
		{
			return OpenModals.size() != 0;
		}
	}
}