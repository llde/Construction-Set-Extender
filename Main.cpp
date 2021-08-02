#include "Main.h"
#include "PluginAPIManager.h"
#include "VersionInfo.h"

#include "[Common]\CLIWrapper.h"
#include "Hooks\Hooks-Dialog.h"
#include "Hooks\Hooks-LOD.h"
#include "Hooks\Hooks-Plugins.h"
#include "Hooks\Hooks-AssetSelector.h"
#include "Hooks\Hooks-ScriptEditor.h"
#include "Hooks\Hooks-Renderer.h"
#include "Hooks\Hooks-Misc.h"
#include "Hooks\Hooks-Events.h"

#include "Achievements.h"
#include "Console.h"
#include "Render Window\RenderWindowManager.h"
#include "HallOfFame.h"
#include "UIManager.h"
#include "WorkspaceManager.h"
#include "ChangeLogManager.h"
#include "Render Window\AuxiliaryViewport.h"
#include "OldCSInteropManager.h"
#include "Coda\Coda.h"
#include "GlobalClipboard.h"
#include "FormUndoStack.h"
#include "MainWindowOverrides.h"
#include "CellViewWindowOverrides.h"
#include "ObjectWindowOverrides.h"

#include <bgsee\ToolBox.h>
#include <bgsee\Script\CodaVM.h>

namespace cse
{
	OBSEMessagingInterface*						XSEMsgIntfc = nullptr;
	OBSECommandTableInterface*					XSECommandTableIntfc = nullptr;
	PluginHandle								XSEPluginHandle = kPluginHandle_Invalid;

	ReleaseNameTable							ReleaseNameTable::Instance;
	bool										IsWarholAGenius = false;

	ReleaseNameTable::ReleaseNameTable() :
		bgsee::ReleaseNameTable()
	{
		RegisterRelease(6, 0, "Konniving Kelpie");
		RegisterRelease(6, 1, "Cretinous Codpiece");
		RegisterRelease(6, 2, "Talkative Badger");
		RegisterRelease(6, 3, "Drunken Glaswegian");
		RegisterRelease(6, 4, "Subterranean Homesick Alien");
		RegisterRelease(7, 0, "Patagonian Petticoat");
		RegisterRelease(7, 1, "Bull-buggering Bollocks");
		RegisterRelease(8, 0, "Dead Dove");
		RegisterRelease(8, 1, "Logical Half Nelson");
		RegisterRelease(10, 0, "Y-Y-Zed");
		RegisterRelease(11, 0, "Time To Move On");
	}

	ReleaseNameTable::~ReleaseNameTable()
	{
		;//
	}

	InitCallbackQuery::InitCallbackQuery(const OBSEInterface* OBSE) :
		bgsee::DaemonCallback(),
		OBSE(OBSE)
	{
		;//
	}

	InitCallbackQuery::~InitCallbackQuery()
	{
		;//
	}

	bool InitCallbackQuery::Handle(void* Parameter)
	{
		BGSEECONSOLE_MESSAGE("Initializing OBSE Interfaces");
		BGSEECONSOLE->Indent();
		XSEMsgIntfc = (OBSEMessagingInterface*)OBSE->QueryInterface(kInterface_Messaging);
		XSECommandTableIntfc = (OBSECommandTableInterface*)OBSE->QueryInterface(kInterface_CommandTable);

		if (XSEMsgIntfc == nullptr || XSECommandTableIntfc == nullptr)
		{
			BGSEECONSOLE_MESSAGE("Messaging/CommandTable interface not found");
			return false;
		}
		BGSEECONSOLE->Outdent();

		BGSEECONSOLE_MESSAGE("Initializing Component DLLs");
		BGSEECONSOLE->Indent();
		if (cliWrapper::ImportInterfaces(OBSE) == false)
			return false;
		BGSEECONSOLE->Outdent();

		return true;
	}

	InitCallbackLoad::InitCallbackLoad(const OBSEInterface* OBSE) :
		bgsee::DaemonCallback(),
		OBSE(OBSE)
	{
		;//
	}

	InitCallbackLoad::~InitCallbackLoad()
	{
		;//
	}

	bool InitCallbackLoad::Handle(void* Parameter)
	{
		BGSEECONSOLE_MESSAGE("Initializing Hooks");
		BGSEECONSOLE->Indent();
		hooks::PatchEntryPointHooks();
		hooks::PatchDialogHooks();
		hooks::PatchLODHooks();
		hooks::PatchTESFileHooks();
		hooks::PatchAssetSelectorHooks();
		hooks::PatchScriptEditorHooks();
		hooks::PatchRendererHooks();
		hooks::PatchMiscHooks();
		hooks::PatchMessageHanders();
		hooks::PatchEventHooks();
		BGSEECONSOLE->Outdent();

		BGSEECONSOLE_MESSAGE("Initializing Events");
		BGSEECONSOLE->Indent();
		events::InitializeSinks();
		events::InitializeSources();
		BGSEECONSOLE->Outdent();

		BGSEECONSOLE_MESSAGE("Initializing Serialization");
		BGSEECONSOLE->Indent();
		serialization::Initialize();
		BGSEECONSOLE->Outdent();

		BGSEECONSOLE_MESSAGE("Initializing UI Manager");
		BGSEECONSOLE->Indent();
		bool ComponentInitialized = bgsee::UIManager::Initialize("TES Construction Set",
																 LoadMenu(BGSEEMAIN->GetExtenderHandle(), MAKEINTRESOURCE(IDR_MAINMENU)));
		BGSEECONSOLE->Outdent();

		if (ComponentInitialized == false)
			return false;

		BGSEECONSOLE_MESSAGE("Registering OBSE Plugin Message Handlers");
		XSEMsgIntfc->RegisterListener(XSEPluginHandle, "OBSE", OBSEMessageHandler);

		BGSEECONSOLE_MESSAGE("Initializing Plugin Interface Manager");
		PluginAPIManager::Instance.Initialize();

		return true;
	}

	InitCallbackPostMainWindowInit::~InitCallbackPostMainWindowInit()
	{
		;//
	}

	bool InitCallbackPostMainWindowInit::Handle(void* Parameter)
	{
		uiManager::InitializeMainWindowOverrides();
		uiManager::InitializeObjectWindowOverrides();
		uiManager::InitializeCellViewWindowOverrides();
		uiManager::DeferredComboBoxController::Instance.Initialize();

		BGSEECONSOLE_MESSAGE("Initializing Render Window Manager");
		BGSEECONSOLE->Indent();
		bool ComponentInitialized = _RENDERWIN_MGR.Initialize();
		SME_ASSERT(ComponentInitialized);
		BGSEECONSOLE->Outdent();

		if (settings::dialogs::kShowMainWindowsInTaskbar.GetData().i)
		{
			bgsee::WindowStyler::StyleData RegularAppWindow = { 0 };
			RegularAppWindow.Extended = WS_EX_APPWINDOW;
			RegularAppWindow.ExtendedOp = bgsee::WindowStyler::StyleData::kOperation_OR;

			BGSEEUI->GetWindowStyler()->RegisterStyle(TESDialog::kDialogTemplate_FindText, RegularAppWindow);
			BGSEEUI->GetWindowStyler()->RegisterStyle(TESDialog::kDialogTemplate_SearchReplace, RegularAppWindow);
		}

		return true;
	}

	InitCallbackEpilog::~InitCallbackEpilog()
	{
		;//
	}

	bool InitCallbackEpilog::Handle(void* Parameter)
	{
		BGSEECONSOLE_MESSAGE("Initializing Component DLL Interfaces");
		BGSEECONSOLE->Indent();
		cliWrapper::QueryInterfaces();
		BGSEECONSOLE->Outdent();

		BGSEECONSOLE_MESSAGE("Initializing Console");
		BGSEECONSOLE->Indent();
		console::Initialize();
		BGSEECONSOLE->Outdent();

		BGSEECONSOLE_MESSAGE("Initializing Auxiliary Viewport");
		BGSEECONSOLE->Indent();
		AUXVIEWPORT->Initialize();
		BGSEECONSOLE->Outdent();

		BGSEECONSOLE_MESSAGE("Initializing Achievements");
		BGSEECONSOLE->Indent();
		achievements::Initialize();
		BGSEECONSOLE->Outdent();

		BGSEECONSOLE_MESSAGE("Initializing Hall of Fame");
		BGSEECONSOLE->Indent();
		hallOfFame::Initialize();
		BGSEECONSOLE->Outdent();

		BGSEECONSOLE_MESSAGE("Initializing ScriptEditor");
		BGSEECONSOLE->Indent();

		componentDLLInterface::CommandTableData XSECommandTableData;
		XSECommandTableData.GetCommandReturnType = XSECommandTableIntfc->GetReturnType;
		XSECommandTableData.GetParentPlugin = XSECommandTableIntfc->GetParentPlugin;
		XSECommandTableData.GetRequiredOBSEVersion = XSECommandTableIntfc->GetRequiredOBSEVersion;
		XSECommandTableData.CommandTableStart = XSECommandTableIntfc->Start();
		XSECommandTableData.CommandTableEnd = XSECommandTableIntfc->End();
		PluginAPIManager::Instance.ConsumeIntelliSenseInterface(&XSECommandTableData);

		componentDLLInterface::IntelliSenseUpdateData GMSTCollectionData;
		GameSettingCollection::Instance->MarshalAll(&GMSTCollectionData.GMSTListHead, &GMSTCollectionData.GMSTCount, false);
		cliWrapper::interfaces::SE->InitializeComponents(&XSECommandTableData, &GMSTCollectionData);

		BGSEECONSOLE->Outdent();

		BGSEECONSOLE_MESSAGE("Initializing Coda \"Virtual Machine\"");
		BGSEECONSOLE->Indent();
		script::Initialize();
		BGSEECONSOLE->Outdent();

		BGSEECONSOLE_MESSAGE("Initializing Toolbox");
		BGSEECONSOLE->Indent();
		bgsee::ToolBox::Initialize(BGSEEMAIN->INIGetter(), BGSEEMAIN->INISetter());
		BGSEECONSOLE->Outdent();

		BGSEECONSOLE_MESSAGE("Initializing Workspace Manager");
		BGSEECONSOLE->Indent();
		workspaceManager::Initialize();
		BGSEECONSOLE->Outdent();

		BGSEECONSOLE_MESSAGE("Initializing Dialogs");
		BGSEECONSOLE->Indent();
		uiManager::Initialize();
		BGSEECONSOLE->Outdent();

		BGSEECONSOLE_MESSAGE("Initializing Render Window");
		BGSEECONSOLE->Indent();
		renderWindow::Initialize();
		BGSEECONSOLE->Outdent();

		BGSEECONSOLE_MESSAGE("Initializing GMST Default Copy");
		BGSEECONSOLE->Indent();
		GameSettingCollection::Instance->CreateDefaultCopy();
		BGSEECONSOLE->Outdent();

		BGSEECONSOLE_MESSAGE("Initializing IdleAnim Tree");
		BGSEECONSOLE->Indent();
		TESIdleForm::InitializeIdleFormTreeRootNodes();
		BGSEECONSOLE->Outdent();

		BGSEECONSOLE_MESSAGE("Initializing Archive Manager");
		BGSEECONSOLE->Indent();
		ArchiveManager::LoadSkippedArchives((std::string(std::string(BGSEEMAIN->GetAPPPath()) + "Data\\")).c_str());
		BGSEECONSOLE->Outdent();

		BGSEECONSOLE_MESSAGE("Initializing Change Log Manager");
		BGSEECONSOLE->Indent();
		changeLogManager::Initialize();
		BGSEECONSOLE->Outdent();

		BGSEECONSOLE_MESSAGE("Initializing Panic Save Handler");
		BGSEECONSOLE->Indent();
		_DATAHANDLER->PanicSave(true);
		BGSEECONSOLE->Outdent();

		BGSEECONSOLE_MESSAGE("Initializing Global Clipboard");
		BGSEECONSOLE->Indent();
		globalClipboard::Initialize();
		BGSEECONSOLE->Outdent();

		BGSEECONSOLE_MESSAGE("Initializing Form Undo Stack");
		BGSEECONSOLE->Indent();
		formUndoStack::Initialize();
		BGSEECONSOLE->Outdent();

		BGSEECONSOLE_MESSAGE("Initializing Startup Manager");
		BGSEECONSOLE->Indent();
		StartupManager::LoadStartupWorkspace();
		StartupManager::LoadStartupPlugin();
		StartupManager::LoadStartupScript();
		BGSEECONSOLE->Outdent();

		BGSEECONSOLE->OutdentAll();
		BGSEECONSOLE_MESSAGE("%s Initialized!", BGSEEMAIN->ExtenderGetDisplayName());
		BGSEECONSOLE->Pad(2);

		BGSEEACHIEVEMENTS->Unlock(achievements::kTheWiseOne);

		if (BGSEECONSOLE->GetLogsWarnings() == false)
			BGSEEACHIEVEMENTS->Unlock(achievements::kFlyingBlind);

		for (const CommandInfo* Itr = XSECommandTableData.CommandTableStart; Itr < XSECommandTableData.CommandTableEnd; ++Itr)
		{
			if (strlen(Itr->longName) > 0)
				BGSEEACHIEVEMENTS->Unlock(achievements::kCommandant);
		}

		BGSEEACHIEVEMENTS->Unlock(achievements::kHappyBDayMoi, false, false, true);

		return true;
	}

	DeinitCallback::~DeinitCallback()
	{
		;//
	}

	bool DeinitCallback::Handle(void* Parameter)
	{
		TESDialog::WriteBoundsToINI(*TESCSMain::WindowHandle, nullptr);
		TESDialog::WriteBoundsToINI(*TESCellViewWindow::WindowHandle, "Cell View");
		TESDialog::WriteBoundsToINI(*TESObjectWindow::WindowHandle, "Object Window");
		TESDialog::WriteBoundsToINI(*TESRenderWindow::WindowHandle, "Render Window");

		BGSEECONSOLE_MESSAGE("Flushed CS INI Settings");

		settings::dialogs::kRenderWindowState.SetInt((GetMenuState(*TESCSMain::MainMenuHandle,
			TESCSMain::kMainMenu_View_RenderWindow, MF_BYCOMMAND) & MF_CHECKED) != 0);
		settings::dialogs::kCellViewWindowState.SetInt((GetMenuState(*TESCSMain::MainMenuHandle,
			TESCSMain::kMainMenu_View_CellViewWindow, MF_BYCOMMAND) & MF_CHECKED) != 0);
		settings::dialogs::kObjectWindowState.SetInt((GetMenuState(*TESCSMain::MainMenuHandle,
			TESCSMain::kMainMenu_View_ObjectWindow, MF_BYCOMMAND) & MF_CHECKED) != 0);

		TESCSMain::DeinitializeCSWindows();
		cse::events::general::kShutdown.RaiseEvent();

		BGSEECONSOLE_MESSAGE("Deinitializing Plugin Interface Manager");
		PluginAPIManager::Instance.Deinitailize();

		BGSEECONSOLE_MESSAGE("Deinitializing Render Window");
		BGSEECONSOLE->Indent();
		renderWindow::Deinitialize();
		BGSEECONSOLE->Outdent();

		BGSEECONSOLE_MESSAGE("Deinitializing Achievements Manager");
		BGSEECONSOLE->Indent();
		achievements::Deinitialize();
		BGSEECONSOLE->Outdent();

		BGSEECONSOLE_MESSAGE("Deinitializing Hall Of Fame");
		BGSEECONSOLE->Indent();
		hallOfFame::Deinitialize();
		BGSEECONSOLE->Outdent();

		BGSEECONSOLE_MESSAGE("Deinitializing Tool Manager");
		BGSEECONSOLE->Indent();
		bgsee::ToolBox::Deinitialize();
		BGSEECONSOLE->Outdent();

		BGSEECONSOLE_MESSAGE("Deinitializing Workspace Manager");
		BGSEECONSOLE->Indent();
		workspaceManager::Deinitialize();
		BGSEECONSOLE->Outdent();

		BGSEECONSOLE_MESSAGE("Deinitializing Coda \"Virtual Machine\"");
		BGSEECONSOLE->Indent();
		script::Deinitialize();
		BGSEECONSOLE->Outdent();

		BGSEECONSOLE_MESSAGE("Deinitializing Global Clipboard");
		BGSEECONSOLE->Indent();
		globalClipboard::Deinitialize();
		BGSEECONSOLE->Outdent();

		BGSEECONSOLE_MESSAGE("Deinitializing Form Undo Stack");
		BGSEECONSOLE->Indent();
		formUndoStack::Deinitialize();
		BGSEECONSOLE->Outdent();

		BGSEECONSOLE_MESSAGE("Deinitializing Auxiliary Viewport");
		BGSEECONSOLE->Indent();
		delete AUXVIEWPORT;
		BGSEECONSOLE->Outdent();

		BGSEECONSOLE_MESSAGE("Deinitializing Script Editor");
		BGSEECONSOLE->Indent();
		cliWrapper::interfaces::SE->Deinitalize();
		BGSEECONSOLE->Outdent();

		BGSEECONSOLE_MESSAGE("Deinitializing Change Log Manager");
		BGSEECONSOLE->Indent();
		changeLogManager::Deinitialize();
		BGSEECONSOLE->Outdent();

		BGSEECONSOLE_MESSAGE("Deinitializing Serialization");
		BGSEECONSOLE->Indent();
		serialization::Deinitialize();
		BGSEECONSOLE->Outdent();

		BGSEECONSOLE_MESSAGE("Deinitializing Events");
		BGSEECONSOLE->Indent();
		events::DeinitializeSinks();
		events::DeinitializeSources();
		BGSEECONSOLE->Outdent();

#ifndef NDEBUG
		BGSEECONSOLE_MESSAGE("Performing Diagnostics...");
		BGSEECONSOLE->Indent();
		componentDLLInterface::DumpInstanceCounters();
		BGSEECONSOLE->Outdent();
#endif

		return true;
	}

	CrashCallback::CrashCallback()
	{
		HandlerCalled = false;
	}

	CrashCallback::~CrashCallback()
	{
		;//
	}

	struct UserContext {
		UInt32 eip;
		UInt32 moduleBase;
		CHAR* name;
	};

	BOOL CALLBACK EumerateModulesCallback(PCSTR name, ULONG moduleBase, ULONG moduleSize, PVOID context) {
		UserContext* info = (UserContext*)context;
		if (info->eip >= (UInt32)moduleBase && info->eip <= (UInt32)moduleBase + (UInt32)moduleSize) {
			//_MESSAGE("%0X %0X  %0X", (UInt32)moduleBase, info->eip, (UInt32)moduleBase + (UInt32) moduleSize);
			info->moduleBase = moduleBase;
			strcpy_s(info->name, 100, name);
		}
		BGSEECONSOLE_MESSAGE(" - 0x%08X - 0x%08X: %s", (UInt32)moduleBase, (UInt32)moduleBase + (UInt32)moduleSize, name);
		return TRUE;
	}

	BOOL CALLBACK EumerateModulesCallbackSym(PCSTR name, ULONG moduleBase, PVOID context) {
		UserContext* info = (UserContext*)context;
		IMAGEHLP_MODULE modu;
		SymGetModuleInfo(GetCurrentProcess(), moduleBase, &modu);
		if (info->eip >= (UInt32)moduleBase && info->eip <= (UInt32)moduleBase + modu.ImageSize) {
			//            _MESSAGE("%0X %0X  %0X", (UInt32)moduleBase, info->eip, (UInt32)moduleBase + moduleSize);
			info->moduleBase = moduleBase;
			strcpy_s(info->name, 100, name);
		}
		BGSEECONSOLE_MESSAGE(" - 0x%08X - 0x%08X: %s", (UInt32)moduleBase, (UInt32)moduleBase + modu.ImageSize, name);
		return TRUE;
	}
#pragma comment(lib, "dbghelp")
void StackWalk(EXCEPTION_POINTERS* info, HANDLE process, HANDLE thread) {
	BGSEECONSOLE->Pad(2);
	BGSEECONSOLE_MESSAGE("Walk the stack!");
	BGSEECONSOLE->Indent();
    DWORD machine = IMAGE_FILE_MACHINE_I386;
    CONTEXT context = {};
    memcpy(&context, info->ContextRecord, sizeof(CONTEXT));
//	SymCleanup(process);
    SymSetOptions(SYMOPT_LOAD_LINES | SYMOPT_DEFERRED_LOADS | SYMOPT_UNDNAME | SYMOPT_ALLOW_ABSOLUTE_SYMBOLS | SYMOPT_IGNORE_CVREC | SYMOPT_LOAD_ANYTHING);
    if (SymInitialize(process, NULL, TRUE) != TRUE) {
        BGSEECONSOLE_MESSAGE("Error initializing symbol store");
    }

    STACKFRAME frame = {};
    frame.AddrPC.Offset    = info->ContextRecord->Eip;
    frame.AddrPC.Mode      = AddrModeFlat;
    frame.AddrFrame.Offset = info->ContextRecord->Ebp;
    frame.AddrFrame.Mode   = AddrModeFlat;
    frame.AddrStack.Offset = info->ContextRecord->Esp;
    frame.AddrStack.Mode   = AddrModeFlat;
    DWORD eip = 0;
    while (StackWalk(machine, process, thread, &frame, &context, NULL, SymFunctionTableAccess, SymGetModuleBase, NULL)) {
        if (frame.AddrPC.Offset == eip) break;
        eip = frame.AddrPC.Offset;
        IMAGEHLP_MODULE module = { 0 };
        module.SizeOfStruct = sizeof(IMAGEHLP_MODULE);

        BOOL moduleAv = SymGetModuleInfo(process, frame.AddrPC.Offset, &module);
        std::string functioName;
        char symbolBuffer[sizeof(IMAGEHLP_SYMBOL) + 255];
        IMAGEHLP_SYMBOL* symbol = (IMAGEHLP_SYMBOL*)symbolBuffer;
        symbol->SizeOfStruct = sizeof(IMAGEHLP_SYMBOL);
        symbol->MaxNameLength = 254;
        DWORD  offset = 0;
        if (moduleAv) {
            if (SymGetSymFromAddr(process, frame.AddrPC.Offset, &offset, symbol)) {
                functioName = symbol->Name;
                BGSEECONSOLE_MESSAGE("0x%08X ==> %s+0x%0X in %s (0x%08X) ", frame.AddrPC.Offset, functioName.c_str(), offset, module.ModuleName, frame.AddrFrame.Offset);
            }
            else {
                BGSEECONSOLE_MESSAGE("0x%08X ==> %s+0x%0X in %s (0x%08X) ", frame.AddrPC.Offset, "EntryPoint", (UInt32)-1, module.ModuleName, frame.AddrFrame.Offset);
            }
        }
        else {
            BGSEECONSOLE_MESSAGE("0x%08X ==> ¯\\(°_o)/¯ (Corrupt stack or heap?)  (0x%08X)", frame.AddrPC.Offset, frame.AddrFrame.Offset);
        }
		
    }
	BGSEECONSOLE->Pad(2);
	BGSEECONSOLE->Outdent();
	UserContext infoUser = { info->ContextRecord->Eip,  0, (char*)calloc(sizeof(char), 100) };
	EnumerateLoadedModules(process, EumerateModulesCallback, &infoUser);
	//        SymEnumerateModules(processHandle, EumerateModulesCallbackSym, &infoUser);
	BGSEECONSOLE->Pad(2);
	if (infoUser.moduleBase) {
		BGSEECONSOLE_MESSAGE("\nGAME CRASHED AT INSTRUCTION Base+0x%08X IN MODULE: %s", (infoUser.eip - infoUser.moduleBase), infoUser.name);
		BGSEECONSOLE_MESSAGE("Please note that this does not automatically mean that that module is responsible. \n"
			"It may have been supplied bad data or program state as the result of an issue in \n"
			"the base game or a different DLL.");
	}
	else {
		BGSEECONSOLE_MESSAGE("\nUNABLE TO IDENTIFY MODULE CONTAINING THE CRASH ADDRESS.");
		BGSEECONSOLE_MESSAGE("This can occur if the crashing instruction is located in the vanilla address space, \n"
			"but it can also occur if there are too many DLLs for us to list, and if the crash \n"
			"occurred in one of their address spaces. Please note that even if the crash occurred \n"
			"in vanilla code, that does not necessarily mean that it is a vanilla problem. The \n"
			"vanilla code may have been supplied bad data or program state as the result of an \n"
			"issue in a loaded DLL.");
	}

}
	bool CrashCallback::Handle(void* Parameter)
	{
		if (HandlerCalled)
			return false;
		else
			HandlerCalled = true;

		BGSEECONSOLE->Pad(2);
		BGSEECONSOLE_MESSAGE("The editor crashed, dammit!");
		BGSEECONSOLE->Indent();

		bool PanicSaved = false;
		if (settings::general::kSalvageActivePluginOnCrash().i)
		{
			BGSEECONSOLE_MESSAGE("Attempting to salvage the active file...");
			BGSEECONSOLE->Indent();

			if ((PanicSaved = _DATAHANDLER->PanicSave()))
				BGSEECONSOLE_MESSAGE("Yup, we're good! Look for the panic save file in the Backup directory");
			else
				BGSEECONSOLE_MESSAGE("Bollocks-bollocks-bollocks! No can do...");

			BGSEECONSOLE->Outdent();
		}

		BGSEECONSOLE->Outdent();

		if (BGSEEDAEMON->GetFullInitComplete())
			BGSEEACHIEVEMENTS->Unlock(achievements::kSaboteur, false, true);

		// it's highly inadvisable to do anything inside the handler apart from the bare minimum of diagnostics
		// memory allocations are a big no-no as the CRT state can potentially be corrupted...
		// ... but sod that! Achievements are more important, obviously.
		EXCEPTION_POINTERS* CrashInfo = (EXCEPTION_POINTERS*)Parameter;
		bool ResumeExecution = false;

		std::string CrashMessage("The editor has encountered a critical error!\n\nA crash report will be generated shortly in the following folder: ");
		CrashMessage += BGSEEMAIN->GetCrashReportDirPath();
		CrashMessage += "\n\n";
		int MBFlags = MB_TASKMODAL | MB_TOPMOST | MB_SETFOREGROUND | MB_ICONSTOP | MB_OK;

		if (PanicSaved)
			CrashMessage += "Unsaved changes were saved to the panic save file in the Data\\Backup folder.\n\n";

		int CrashHandlerMode = settings::general::kCrashHandlerMode.GetData().i;
		if (CrashHandlerMode == kCrashHandlerMode_Terminate)
			ResumeExecution = false;
		else if (CrashHandlerMode == kCrashHandlerMode_Resume)
			ResumeExecution = true;
		else if (CrashHandlerMode == kCrashHandlerMode_Ask)
		{
			bool FunnyGuyUnlocked = BGSEEDAEMON->GetFullInitComplete() &&
				(achievements::kFunnyGuy->GetUnlocked() || achievements::kFunnyGuy->GetTriggered());

			MBFlags &= ~MB_OK;

			if (FunnyGuyUnlocked == false)
			{
				MBFlags |= MB_YESNOCANCEL;
				CrashMessage += "Do you wish to resume execution once you've:\n   1. Prayed to your various deities\n   2. Sent the shadeMe a pile of cash, and\n   3. Pleaded to the editor in a soft, sultry voice in hopes of preventing it from crashing outright upon selecting 'Yes' in this dialog?";
			}
			else
			{
				MBFlags |= MB_YESNO;
				CrashMessage += "Do you wish to resume execution? The editor will probably terminate anyway.";
			}
		}

		switch (MessageBox(nullptr, CrashMessage.c_str(), BGSEEMAIN->ExtenderGetDisplayName(), MBFlags))
		{
		case IDOK:
			// nothing to do here
			break;
		case IDYES:
			ResumeExecution = true;
			break;
		case IDNO:
			ResumeExecution = false;
			break;
		case IDCANCEL:
			if (BGSEEDAEMON->GetFullInitComplete())
				BGSEEACHIEVEMENTS->Unlock(achievements::kFunnyGuy, false, true);

			MessageBox(nullptr, "Hah! Nice try, Bob.", BGSEEMAIN->ExtenderGetDisplayName(), MB_TASKMODAL | MB_TOPMOST | MB_SETFOREGROUND | MB_ICONERROR);
			break;
		}
		StackWalk(CrashInfo, GetCurrentProcess(), GetCurrentThread()) ;
		return ResumeExecution;
	}


	void StartupManager::LoadStartupPlugin()
	{
		bool Load = settings::startup::kLoadPlugin.GetData().i;
		const char* PluginName = settings::startup::kPluginName.GetData().s;

		if (Load)
		{
			hooks::_MemHdlr(AutoLoadActivePluginOnStartup).WriteJump();

			TESFile* File = _DATAHANDLER->LookupPluginByName(PluginName);
			if (File)
			{
				BGSEECONSOLE_MESSAGE("Loading plugin '%s'", PluginName);
				BGSEECONSOLE->Indent();

				File->SetLoaded(true);
				if (_stricmp(PluginName, "Oblivion.esm"))
					File->SetActive(true);

				SendMessage(*TESCSMain::WindowHandle, WM_COMMAND, TESCSMain::kToolbar_DataFiles, 0);

				BGSEECONSOLE->Outdent();
			}
			else if (strlen(PluginName) >= 1)
				BGSEECONSOLE_MESSAGE("Non-existent startup plugin '%s'", PluginName);

			hooks::_MemHdlr(AutoLoadActivePluginOnStartup).WriteBuffer();
		}
	}

	void StartupManager::LoadStartupScript()
	{
		bool Load = settings::startup::kOpenScriptWindow.GetData().i;
		const char* ScriptID = settings::startup::kScriptEditorID.GetData().s;

		if (Load)
		{
			if (strcmp(ScriptID, ""))
				TESDialog::ShowScriptEditorDialog(TESForm::LookupByEditorID(ScriptID));
			else
				TESDialog::ShowScriptEditorDialog(nullptr);
		}
	}

	void StartupManager::LoadStartupWorkspace()
	{
		bool Load = settings::startup::kSetWorkspace.GetData().i;
		const char* WorkspacePath = settings::startup::kWorkspacePath.GetData().s;

		if (Load)
			BGSEEWORKSPACE->SelectCurrentWorkspace(WorkspacePath);
	}

	void CSEInteropHandler(OBSEMessagingInterface::Message* Msg)
	{
		switch (Msg->type)
		{
		case 'CSEI':
			{
				BGSEECONSOLE_MESSAGE("Dispatching Plugin Interop Interface to '%s'", Msg->sender);
				BGSEECONSOLE->Indent();
				XSEMsgIntfc->Dispatch(XSEPluginHandle, 'CSEI', (void*)PluginAPIManager::Instance.GetInterface(), 4, Msg->sender);
				BGSEECONSOLE->Outdent();
			}

			break;
		}
	}

	void OBSEMessageHandler(OBSEMessagingInterface::Message* Msg)
	{
		switch (Msg->type)
		{
		case OBSEMessagingInterface::kMessage_PostLoad:
			XSEMsgIntfc->RegisterListener(XSEPluginHandle, nullptr, CSEInteropHandler);
			break;
		case OBSEMessagingInterface::kMessage_PostPostLoad:

			break;
		}
	}
}

using namespace cse;

CrashCallback* ctdCallback = nullptr;
LPTOP_LEVEL_EXCEPTION_FILTER  origin = nullptr;

LONG WINAPI  Filter(EXCEPTION_POINTERS* excp) {
	ctdCallback->Handle(excp);
	if (origin) return origin(excp);
	return EXCEPTION_CONTINUE_SEARCH;
}

extern "C"
{
	__declspec(dllexport) bool OBSEPlugin_Query(const OBSEInterface * obse, PluginInfo * info)
	{
		info->infoVersion = PluginInfo::kInfoVersion;
		info->name = BGSEEMAIN_EXTENDERSHORTNAME;
		info->version = PACKED_SME_VERSION;

		XSEPluginHandle = obse->GetPluginHandle();

		if (obse->isEditor == false)
			return false;

		SME::MersenneTwister::init_genrand(GetTickCount());
		if (SME::MersenneTwister::genrand_real1() < 0.05)
			IsWarholAGenius = true;

		bgsee::Main::InitializationParams InitParams;
		InitParams.LongName = BGSEEMAIN_EXTENDERLONGNAME;
		InitParams.DisplayName = IsWarholAGenius ? "ConstruKction Set Extender" : nullptr;
		InitParams.ShortName = BGSEEMAIN_EXTENDERSHORTNAME;
		InitParams.ReleaseName = ReleaseNameTable::Instance.LookupRelease(VERSION_MAJOR, VERSION_MINOR);
		InitParams.Version = PACKED_SME_VERSION;
		InitParams.EditorID = bgsee::Main::kExtenderParentEditor_TES4CS;
		InitParams.EditorSupportedVersion = CS_VERSION_1_2;
		InitParams.EditorCurrentVersion = obse->editorVersion;
		InitParams.APPPath = obse->GetOblivionDirectory();
		InitParams.SEPluginHandle = XSEPluginHandle;
		InitParams.SEMinimumVersion = 21;
		InitParams.SECurrentVersion = obse->obseVersion;
		InitParams.DotNETFrameworkVersion = "v4.0.30319";
		InitParams.CLRMemoryProfiling = false;

		settings::Register(InitParams.INISettings);
		AuxiliaryViewport::RegisterINISettings(InitParams.INISettings);

#ifdef WAIT_FOR_DEBUGGER
		InitParams.WaitForDebugger = true;
#else
		InitParams.WaitForDebugger = false;
#endif

#ifdef NDEBUG
	#ifndef WAIT_FOR_DEBUGGER
		InitParams.CrashRptSupport = true;
		TODO("Save debug symbols, dammit!")
	#else
		InitParams.CrashRptSupport = false;
	#endif
#else
		InitParams.CrashRptSupport = false;
#endif

		bool ComponentInitialized = bgsee::Main::Initialize(InitParams);
		if (ComponentInitialized == false)
		{
			MessageBox(nullptr,
					   "The Construction Set Extender failed to initialize correctly!\n\nCouldn't initialize main module.",
					   "Fatal Error",
					   MB_TASKMODAL | MB_SETFOREGROUND | MB_ICONERROR | MB_OK);

			return false;
		}
		BGSEEDAEMON->RegisterInitCallback(bgsee::Daemon::kInitCallback_Query, new InitCallbackQuery(obse));
		BGSEEDAEMON->RegisterInitCallback(bgsee::Daemon::kInitCallback_Load, new InitCallbackLoad(obse));
		BGSEEDAEMON->RegisterInitCallback(bgsee::Daemon::kInitCallback_PostMainWindowInit, new InitCallbackPostMainWindowInit());
		BGSEEDAEMON->RegisterInitCallback(bgsee::Daemon::kInitCallback_Epilog, new InitCallbackEpilog());
		BGSEEDAEMON->RegisterDeinitCallback(new DeinitCallback());
		ctdCallback = new CrashCallback();
		BGSEEDAEMON->RegisterCrashCallback(ctdCallback);
		origin = SetUnhandledExceptionFilter(Filter);
		if (BGSEEDAEMON->ExecuteInitCallbacks(bgsee::Daemon::kInitCallback_Query) == false)
		{
			MessageBox(nullptr,
					   "The Construction Set Extender failed to initialize correctly!\n\nIt's highly advised that you close the CS right away. More information can be found in the log file (Construction Set Extender.log in the root game directory).",
					   "The Cyrodiil Bunny Ranch",
					   MB_TASKMODAL | MB_SETFOREGROUND | MB_ICONERROR | MB_OK);

			BGSEECONSOLE->OpenDebugLog();
			return false;
		}

		return true;
	}

	__declspec(dllexport) bool OBSEPlugin_Load(const OBSEInterface * obse)
	{
		if (BGSEEDAEMON->ExecuteInitCallbacks(bgsee::Daemon::kInitCallback_Load) == false)
		{
			MessageBox(nullptr,
					   "The Construction Set Extender failed to load correctly!\n\nIt's highly advised that you close the CS right away. More information can be found in the log file (Construction Set Extender.log in the root game directory).",
					   "Rumpy-Pumpy!!",
					   MB_TASKMODAL | MB_SETFOREGROUND | MB_ICONERROR | MB_OK);

			BGSEECONSOLE->OpenDebugLog();
			return false;
		}

		return true;
	}
};

BOOL WINAPI DllMain(HANDLE hDllHandle, DWORD dwReason, LPVOID lpreserved)
{
	switch (dwReason)
	{
	case DLL_PROCESS_ATTACH:
#ifdef WAIT_FOR_DEBUGGER
		bgsee::Daemon::WaitForDebugger();
#endif
		break;
	case DLL_PROCESS_DETACH:
		break;
	}

	return TRUE;
}