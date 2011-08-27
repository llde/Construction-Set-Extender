#pragma once
#include "Includes.h"
#include "ComponentDLLInterface.h"

const int SW_SHOWNOACTIVATE = 4;
const int HWND_TOPMOST = -1;
const UInt32 SWP_NOACTIVATE = 0x0010;

namespace NativeWrapper
{
	[DllImport("Construction Set Extender.dll")]
	void*											QueryInterface(void);

	[DllImport("user32.dll")]
	bool											LockWindowUpdate(IntPtr hWndLock);
	[DllImport("user32.dll")]
	IntPtr											WindowFromPoint(Point Point);
	[DllImport("user32.dll")]
	IntPtr											GetParent(IntPtr Handle);
	[DllImport("user32.dll")]
	bool											SetWindowPos(IntPtr hWnd, int hWndInsertAfter, int X, int Y, int cx, int cy, UInt32 uFlags);
	[DllImport("user32.dll")]
	bool											ShowWindow(IntPtr hWnd, int nCmdShow);
	[DllImport("user32.dll")]
	IntPtr											SendMessageA(IntPtr hWnd, int Msg, IntPtr wParam, IntPtr lParam);

	void											WriteToMainWindowStatusBar(int PanelIndex, String^ Message);
	void											ShowNonActivatingWindow(Control^ Window, IntPtr ParentHandle);

	extern ComponentDLLInterface::CSEInterface*		g_CSEInterface;
};