#include "Hooks-CompilerErrorDetours.h"
#include "[Common]/CLIWrapper.h"

#pragma warning(push)
#pragma warning(disable: 4005 4748)

namespace cse
{
	namespace hooks
	{
		UInt32		ScriptCompileResultBuffer = 0;	// saves the result of a compile operation so as to allow it to go on unhindered
//		static UInt32 ScriptReportCall = 0;
		static DWORD (WINAPI* ScriptReportCall)(HWND, const char*, const char*, UINT);
		static UInt32 UseNewHook = 0;
		_DefineNopHdlr(RidUnknownFunctionCodeMessage, 0x0050310C, 5);
		_DefineHookHdlr(CompilerPrologReset, 0x00503330);
		_DefineHookHdlr(CompilerEpilogCheck, 0x0050341F);
		_DefineHookHdlr(ParseScriptLineOverride, 0x00503401);
		_DefineHookHdlr(CheckLineLengthLineCount, 0x0050013B);
		_DefineHookHdlr(ResultScriptErrorNotification, 0x005035EE);
		_DefineHookHdlr(MaxScriptSizeExceeded, 0x005031DB);
		_DefineHookHdlr(RerouteScriptErrors,  0x004FFF9C);
		_DefineHookHdlr(OverrideMessageBox, 0x004FFFFA);
		//There were multiple hooks that are removed to simplify debugging, should be readd seamlessy
		int __cdecl Porco(const char* format, ...) { return 0; }

		void PatchCompilerErrorDetours()
		{
			if (*(UInt8*)0x004FFFFA == 0xE8) {
				BGSEECONSOLE_MESSAGE("Relative Call, OBSE patch applyied"); //If not replicate more hooks
				UseNewHook = 1;
				*(UInt32*)&ScriptReportCall = *(UInt32*)(0x004FFFFA + 1) + 4 + 1 + 0x004FFFFA;
				BGSEECONSOLE_MESSAGE("%08X", ScriptReportCall);
			}
			else {
				SafeWrite8(0x004FFFEA, 0x90);
				SafeWrite8(0x004FFFEA + 1, 0x90);
				SafeWrite8(0x004FFFE2, 0x90);
				SafeWrite8(0x004FFFE2 + 1, 0x90);
				SafeWrite8(0x004FFFDA, 0x90);
				SafeWrite8(0x004FFFDA + 1, 0x90);
				WriteRelCall(0x00500006, (UInt32)Porco);  //Stub to avoid nopping a lot of stuffs
				*(UInt32*)&ScriptReportCall = (UInt32)MessageBoxA;
				BGSEECONSOLE_MESSAGE("OBSE is not patching the spot, replicate a bit more");
			}

			_MemHdlr(RidUnknownFunctionCodeMessage).WriteNop();
			_MemHdlr(CompilerPrologReset).WriteJump();
			_MemHdlr(CompilerEpilogCheck).WriteJump();
			_MemHdlr(ParseScriptLineOverride).WriteJump();
			_MemHdlr(CheckLineLengthLineCount).WriteJump();
			_MemHdlr(ResultScriptErrorNotification).WriteJump();
			_MemHdlr(MaxScriptSizeExceeded).WriteJump();
			_MemHdlr(RerouteScriptErrors).WriteJump();
			_MemHdlr(OverrideMessageBox).WriteJump();
		}

		UInt32 line = -1;
		#define _hhName		RerouteScriptErrors
		_hhBegin()
		{
			_hhSetVar(Retn, 0x004FFFA5);
			__asm
			{
				mov     [esp + 0x18], ebx
				mov     [esp + 0x1C], bx

				push	edx 
				mov		edx, [esi + 0x1C]
				mov		[line], edx
				pop		edx 
				jmp		_hhGetVar(Retn)
			}
		}

#define WARNING   0x80000000
#define SUPPRESSED 0x20000000
		DWORD WINAPI stub(HWND hwnd, const char* buffer, const char* caption, DWORD flags) {
			bool isWarning = flags & WARNING;
			bool isSuppressed = flags & SUPPRESSED;
			DWORD ret = 0;
			if (TESScriptCompiler::PreventErrorDetours == false)	// don't handle when compiling result scripts or recompiling
				TESScriptCompiler::AuxiliaryErrorDepot.push_back(TESScriptCompiler::CompilerErrorData(line, buffer, isWarning));
			else if(!isSuppressed ) {
				if (!UseNewHook) flags &= ~WARNING;
				ret = (*ScriptReportCall)(hwnd, buffer, caption, flags);
			}
			if (!isWarning) ScriptCompileResultBuffer = 0;
			line = -1;
			return ret;
		}

		#define _hhName     OverrideMessageBox  //0x004FFFFA
		_hhBegin() {
			_hhSetVar(Retn, 0x00500000);
			__asm {
				/*
				push eax
				mov     al, [TESScriptCompiler::PreventErrorDetours]
				test     al, al
				pop eax
				jz		EARLY

				cmp     UseNewHook, 1
				jne     oldMethod
				call	ScriptReportCall
				jmp		EXIT1
			OldMethod:
				call     MessageBoxA
			EXIT1: */
				call stub
				jmp		_hhGetVar(Retn)
/*
			EARLY:
				call stub
				jmp EXIT1 */
			}
		}


		#define _hhName		CompilerEpilogCheck
		_hhBegin()
		{
			_hhSetVar(Retn, 0x00503424);
			_hhSetVar(Call, 0x00500190);
			__asm
			{
				call	_hhGetVar(Call)
				mov		eax, ScriptCompileResultBuffer

				jmp		_hhGetVar(Retn)
			}
		}
		UInt32	MaxScriptSizeExceeded = 0;

		#define _hhName		CompilerPrologReset
		_hhBegin()
		{
			_hhSetVar(Retn, 0x00503336);
			__asm
			{
				mov		ScriptCompileResultBuffer, 1
				mov		MaxScriptSizeExceeded, 0
				pushad
			}
			TESScriptCompiler::AuxiliaryErrorDepot.clear();
			__asm
			{
				popad
				push    ebx
				push    ebp
				mov     ebp, [esp + 0xC]

				jmp		_hhGetVar(Retn)
			}
		}

		#define _hhName		ParseScriptLineOverride
		_hhBegin()
		{
			_hhSetVar(Retn, 0x0050340A);
			_hhSetVar(Call, 0x005028D0);
			_hhSetVar(Exit, 0x005033BE);
			__asm
			{
				call	_hhGetVar(Call)
				test	al, al
				jz		FAIL

				jmp		_hhGetVar(Retn)
			FAIL:
				mov		ScriptCompileResultBuffer, 0
				mov		eax, MaxScriptSizeExceeded
				test	eax, eax
				jnz		EXIT

				jmp		_hhGetVar(Retn)
			EXIT:
				jmp		_hhGetVar(Exit)
			}
		}

		#define _hhName		CheckLineLengthLineCount
		_hhBegin()
		{
			_hhSetVar(Retn, 0x00500143);
			__asm
			{
				mov		eax, [esp + 0x18]
				add		[eax + 0x1C], 1

				add     dword ptr [esi], 1
				push    0x200

				jmp		_hhGetVar(Retn)
			}
		}

		void __stdcall DoResultScriptErrorNotificationHook(void)
		{
			BGSEEUI->MsgBoxE(nullptr,
							MB_TASKMODAL|MB_TOPMOST|MB_SETFOREGROUND|MB_OK,
							"Result script compilation failed. Check the console for error messages.");
		}

		#define _hhName		ResultScriptErrorNotification
		_hhBegin()
		{
			_hhSetVar(Retn, 0x005035F3);
			_hhSetVar(Call, 0x00503330);
			__asm
			{
				mov		TESScriptCompiler::PreventErrorDetours, 1
				call	_hhGetVar(Call)
				mov		TESScriptCompiler::PreventErrorDetours, 0
				test	al, al
				jz		FAIL

				jmp		_hhGetVar(Retn)
			FAIL:
				pushad
				call	DoResultScriptErrorNotificationHook
				popad

				jmp		_hhGetVar(Retn)
			}
		}

		#define _hhName		MaxScriptSizeExceeded
		_hhBegin()
		{
			_hhSetVar(Retn, 0x00502A7C);
			__asm
			{
				mov		MaxScriptSizeExceeded, 1
				push	0x0094AD6C
				jmp		_hhGetVar(Retn)
			}
		}

	}
}

#pragma warning(pop)