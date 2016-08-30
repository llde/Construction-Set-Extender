#pragma once
#include "IMGUI\imgui.h"

namespace cse
{
	namespace renderWindow
	{
		class RenderWindowOSD;
		class IRenderWindowOSDLayer;

		class ImGuiDX9
		{
			typedef std::vector<ImGuiID>		ImGuiWidgetIDArrayT;

			LPDIRECT3DVERTEXBUFFER9			VertexBuffer;
			LPDIRECT3DINDEXBUFFER9			IndexBuffer;

			int								VertexBufferSize;
			int								IndexBufferSize;

			LPDIRECT3DTEXTURE9				FontTexture;

			INT64							Time;
			INT64							TicksPerSecond;

			HWND							RenderWindowHandle;
			IDirect3DDevice9*				D3DDevice;
			bool							MouseDoubleClicked[2];		// for the left and right mouse buttons

			// when the active widget is whitelisted, input events are allowed to be handled by the org wnd proc
			ImGuiWidgetIDArrayT				PassthroughWhitelistMouseEvents;

			bool							Initialized;

			static void						RenderDrawLists(ImDrawData* draw_data);

			bool							CreateFontsTexture();
			void							Shutdown();

			bool							IsActiveItemInWhitelist(const ImGuiWidgetIDArrayT& Whitelist) const;
			bool							HasActiveItem() const;
		public:
			ImGuiDX9();
			~ImGuiDX9();

			bool			Initialize(HWND RenderWindow, IDirect3DDevice9* Device);
			void			NewFrame();
			void			Render();

			void			InvalidateDeviceObjects();
			bool			CreateDeviceObjects();

			bool			UpdateInputState(HWND, UINT msg, WPARAM wParam, LPARAM lParam);		// returns true if the message was processed
			void			NeedsInput(bool& OutNeedsMouse, bool& OutNeedsKeyboard, bool& OutNeedsTextInput) const;
			void			WhitelistItemForMouseEvents();										// adds the last item to the mouse event whitelist
			bool			CanAllowInputEventPassthrough(UINT msg, WPARAM wParam, LPARAM lParam, bool& OutNeedsMouse, bool& OutNeedsKeyboard) const;		// returns false if the message/input event needs to be handled exclusively by the GUI

			bool			IsInitialized() const;
			bool			IsDraggingWindow() const;
			bool			IsPopupHovered() const;												// must be called inside a BeginPopup block
			bool			IsHoveringWindow() const;

			void*			GetLastItemID() const;
			void*			GetMouseHoverItemID() const;

			void*			GetCurrentWindow() const;
			void*			GetHoveredWindow() const;
		};

		class RenderWindowOSD
		{
			class DialogExtraData : public bgsee::WindowExtraData
			{
			public:
				RenderWindowOSD*		Parent;

				DialogExtraData(RenderWindowOSD* OSD);
				virtual ~DialogExtraData();

				enum { kTypeID = 'XOSD' };
			};

			struct GUIState
			{
				bool		MouseInClientArea;				// true when the mouse is inside the window
				bool		ConsumeMouseInputEvents;		// true when the OSD wnd proc needs exclusive access to the mouse
				bool		ConsumeKeyboardInputEvents;		// same as above but for the keyboard

				GUIState();
			};

			static LRESULT CALLBACK		OSDSubclassProc(HWND hWnd, UINT uMsg, WPARAM wParam, LPARAM lParam, bool& Return, bgsee::WindowExtraDataCollection* ExtraData);

			typedef std::vector<IRenderWindowOSDLayer*>			LayerArrayT;

			ImGuiDX9*		Pipeline;
			GUIState		State;
			LayerArrayT		AttachedLayers;
			bool			Initialized;
			bool			RenderingLayers;

			void			RenderLayers();
			bool			NeedsBackgroundUpdate() const;
		public:
			RenderWindowOSD();
			~RenderWindowOSD();

			bool			Initialize();
			void			Deinitialize();

			void			Draw();			// draws the attached layers
			void			Render();		// rendered the queued draw calls from the last Draw() call

			void			AttachLayer(IRenderWindowOSDLayer* Layer);
			void			DetachLayer(IRenderWindowOSDLayer* Layer);

			void			HandleD3DRelease();
			void			HandleD3DRenew();

			bool			NeedsInput() const;			// returns true if the OSD requires mouse or keyboard input
		};

		// queues ImGui drawcalls
		class IRenderWindowOSDLayer
		{
			const INISetting*				Toggle;
			UInt32							Priority;
		protected:
			enum
			{
				kPriority_Notifications = 1001,
				kPriority_MouseTooltip = 1000,
				kPriority_Toolbar = 999,

				kPriority_SelectionControls = 998,
				kPriority_CellLists = 997,
				kPriority_ActiveRefCollections = 996,

				kPriority_Debug = 2,
				kPriority_DefaultOverlay = 1,
				kPriority_ModalProvider = 0,
			};

			// tracked over multiple frames
			struct StateData
			{
				struct TextInputData
				{
					bool	Active;
					bool	GotFocus;
					bool	LostFocus;

					void	Update(ImGuiDX9* GUI);
				};

				struct DragInputData
				{
					bool	Active;
					bool	DragBegin;
					bool	DragEnd;

					void	Update(ImGuiDX9* GUI);
				};

				TextInputData		TextInput;
				DragInputData		DragInput;

				StateData();

				void				Update(ImGuiDX9* GUI);				// must be called inside a ImGui::Begin() block
			};

			struct Helpers
			{
				static std::string			GetRefEditorID(TESObjectREFR* Ref);
				static bool					ResolveReference(UInt32 FormID, TESObjectREFR*& OutRef);		// returns false if the formID didn't resolve to a valid ref, true otherwise
			};
		public:
			IRenderWindowOSDLayer(INISetting& Toggle, UInt32 Priority);
			IRenderWindowOSDLayer(UInt32 Priority);
			virtual ~IRenderWindowOSDLayer() = 0
			{
				;//
			}

			virtual void					Draw(RenderWindowOSD* OSD, ImGuiDX9* GUI) = 0;
			virtual bool					NeedsBackgroundUpdate() = 0;			// returns true if the layer needs to be rendered when the render window doesn't have input focus

			virtual UInt32					GetPriority() const;					// layers with higher priority get rendered first
			virtual bool					IsEnabled() const;
		};

		class NotificationOSDLayer : public IRenderWindowOSDLayer
		{
			struct Notification
			{
				static const int		kNotificationDisplayTime = 2.5 * 1000;		// in ms

				std::string		Message;
				ULONGLONG		StartTickCount;

				Notification(std::string Message);

				bool			HasElapsed();
			};

			typedef std::queue<Notification>			NotificationQueueT;

			NotificationQueueT		Notifications;

			bool					HasNotifications();
			const Notification&		GetNextNotification() const;
		public:
			NotificationOSDLayer();
			virtual ~NotificationOSDLayer();

			virtual void					Draw(RenderWindowOSD* OSD, ImGuiDX9* GUI);
			virtual bool					NeedsBackgroundUpdate();

			void							ShowNotification(const char* Format, ...);

			static NotificationOSDLayer		Instance;
		};

		class DebugOSDLayer : public IRenderWindowOSDLayer
		{
		public:
			DebugOSDLayer();
			virtual ~DebugOSDLayer();

			virtual void					Draw(RenderWindowOSD* OSD, ImGuiDX9* GUI);
			virtual bool					NeedsBackgroundUpdate();

			static DebugOSDLayer			Instance;
		};

		class ModalWindowProviderOSDLayer : public IRenderWindowOSDLayer
		{
		public:
			typedef std::function<bool(RenderWindowOSD*, ImGuiDX9*, void*)>		ModalRenderDelegateT;			// draws the modal's contents and returns true to close it, false otherwise
		private:
			struct ModalData
			{
				std::string						WindowName;		// salted with a random integer to prevent collisions
				ModalRenderDelegateT			Delegate;
				void*							UserData;
				ImGuiWindowFlags_				Flags;
				bool							Open;

				ModalData(const char* Name, ModalRenderDelegateT Delegate, void* UserData, ImGuiWindowFlags_ Flags);
			};

			typedef std::stack<ModalData>		ModalDataStackT;

			ModalDataStackT			OpenModals;
		public:
			ModalWindowProviderOSDLayer();
			virtual ~ModalWindowProviderOSDLayer();

			virtual void					Draw(RenderWindowOSD* OSD, ImGuiDX9* GUI);
			virtual bool					NeedsBackgroundUpdate();

			void							ShowModal(const char* Name, ModalRenderDelegateT Delegate, void* UserData, ImGuiWindowFlags_ Flags);
			bool							HasOpenModals() const;

			static ModalWindowProviderOSDLayer		Instance;
		};
	}
}