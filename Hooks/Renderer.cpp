#include "Renderer.h"
#include "..\RenderSelectionGroupManager.h"
#include "..\ElapsedTimeCounter.h"
#include "..\RenderWindowTextPainter.h"
#include "PathGridUndoManager.h"
#include "AuxiliaryViewport.h"

#pragma warning (disable : 4410)

namespace Hooks
{
	#define PI					3.151592653589793

	TESForm*					g_TESObjectREFRUpdate3DBuffer = NULL;
	bool						g_RenderWindowAltMovementSettings = false;
	float						g_MaxLandscapeEditBrushRadius = 25.0f;

	_DefineHookHdlr(DoorMarkerProperties, 0x00429EA1);
	_DefineHookHdlr(TESObjectREFRGet3DData, 0x00542950);
	_DefineHookHdlr(NiWindowRender, 0x00406442);
	_DefineHookHdlr(NiDX9RendererRecreate, 0x006D7260);
	_DefineHookHdlr(RenderWindowStats, 0x0042D3F4);
	_DefineHookHdlr(UpdateViewport, 0x0042CE70);
	_DefineHookHdlr(RenderWindowSelection, 0x0042AE71);
	_DefineHookHdlr(TESRenderControlPerformMove, 0x00425670);
	_DefineHookHdlr(TESRenderControlPerformRotate, 0x00425D6E);
	_DefineHookHdlr(TESRenderControlPerformScale, 0x00424650);
	_DefineHookHdlr(TESRenderControlPerformFall, 0x0042886A);
	_DefineHookHdlr(TESObjectREFRSetupDialog, 0x005499FB);
	_DefineHookHdlr(TESObjectREFRCleanDialog, 0x00549B52);
	_DefineHookHdlr(TESRenderControlPerformFallVoid, 0x004270C2);
	_DefineHookHdlrWithBuffer(TESObjectREFRUpdate3D, 0x00549AC5, 5, 0x56, 0x8B, 0x74, 0x24, 0x34);
	_DefineHookHdlr(ForceShowTESObjectREFRDialog, 0x00429EE3);
	_DefineHookHdlr(TESRenderControlAltSnapGrid, 0x00425A34);
	_DefineHookHdlr(TESRenderControlAltRefMovementSpeedA, 0x00425737);
	_DefineHookHdlr(TESRenderControlAltRefMovementSpeedB, 0x0042BE80);
	_DefineHookHdlr(TESRenderControlAltRefMovementSpeedC, 0x0042D0AD);
	_DefineHookHdlr(TESRenderControlAltRefRotationSpeed, 0x00425DBB);
	_DefineHookHdlr(TESRenderControlAltRefSnapAngle, 0x00425DC7);
	_DefineHookHdlr(TESRenderControlAltCamRotationSpeed, 0x0042CCAB);
	_DefineHookHdlr(TESRenderControlAltCamZoomSpeedA, 0x0042CCE0);
	_DefineHookHdlr(TESRenderControlAltCamZoomSpeedB, 0x0042CDAF);
	_DefineHookHdlr(TESRenderControlAltCamPanSpeedA, 0x0042CD26);
	_DefineHookHdlr(TESRenderControlAltCamPanSpeedB, 0x0042CD71);
	_DefineHookHdlr(TESRenderControlRedrawGrid, 0x004283F7);
	_DefineHookHdlr(TESPreviewControlCallWndProc, 0x0044D700);
	_DefineHookHdlr(ActivateRenderWindowPostLandTextureChange, 0x0042B4E5);
	_DefineHookHdlr(TESPathGridRecordOperationMoveA, 0x0042A62D);
	_DefineHookHdlr(TESPathGridRecordOperationMoveB, 0x0042BE6D);
	_DefineHookHdlr(TESPathGridRecordOperationLink, 0x0042A829);
	_DefineHookHdlr(TESPathGridRecordOperationFlag, 0x0042A714);
	_DefineHookHdlr(TESPathGridRecordOperationRef, 0x00428367);
	_DefineHookHdlr(TESPathGridDeletePoint, 0x004291C6);
	_DefineHookHdlr(TESPathGridPointDtor, 0x00556190);
	_DefineHookHdlr(TESPathGridToggleEditMode, 0x00550660);
	_DefineHookHdlr(TESPathGridCreateNewLinkedPoint, 0x0042B37B);
	_DefineHookHdlr(TESPathGridPerformFall, 0x00428612);
	_DefineHookHdlr(TESPathGridShowMultipleSelectionRing, 0x0042FC7C);
	_DefinePatchHdlr(TESPathGridDtor, 0x00550B81);
	_DefineHookHdlr(InitialCellLoadCameraPosition, 0x0040A8AE);
	_DefinePatchHdlr(LandscapeEditBrushRadius, 0x0041F2EE + 2);
	_DefineHookHdlrWithBuffer(ConvertNiRenderedTexToD3DBaseTex, 0x00411616, 5, 0x85, 0xC0, 0x75, 0x2E, 0x8B);
	_DefineHookHdlr(DuplicateReferences, 0x0042EC2E);
	_DefinePatchHdlrWithBuffer(NiDX9RendererPresent, 0x006D5C9D, 2, 0xFF, 0xD0);
	_DefineHookHdlr(RenderToAuxiliaryViewport, 0x0042D405);

	void PatchRendererHooks(void)
	{
		_MemHdlr(DoorMarkerProperties).WriteJump();
		_MemHdlr(TESObjectREFRGet3DData).WriteJump();
		_MemHdlr(NiWindowRender).WriteJump();
		_MemHdlr(NiDX9RendererRecreate).WriteJump();
		_MemHdlr(RenderWindowStats).WriteJump();
		_MemHdlr(UpdateViewport).WriteJump();
		_MemHdlr(RenderWindowSelection).WriteJump();
		_MemHdlr(TESRenderControlPerformMove).WriteJump();
		_MemHdlr(TESRenderControlPerformRotate).WriteJump();
		_MemHdlr(TESRenderControlPerformScale).WriteJump();
		_MemHdlr(TESRenderControlPerformFall).WriteJump();
		_MemHdlr(TESObjectREFRSetupDialog).WriteJump();
		_MemHdlr(TESObjectREFRCleanDialog).WriteJump();
		_MemHdlr(TESRenderControlPerformFallVoid).WriteJump();
		_MemHdlr(ForceShowTESObjectREFRDialog).WriteJump();
		_MemHdlr(TESRenderControlAltSnapGrid).WriteJump();
		_MemHdlr(TESRenderControlAltRefMovementSpeedA).WriteJump();
		_MemHdlr(TESRenderControlAltRefMovementSpeedB).WriteJump();
		_MemHdlr(TESRenderControlAltRefMovementSpeedC).WriteJump();
		_MemHdlr(TESRenderControlAltRefRotationSpeed).WriteJump();
		_MemHdlr(TESRenderControlAltRefSnapAngle).WriteJump();
		_MemHdlr(TESRenderControlAltCamRotationSpeed).WriteJump();
		_MemHdlr(TESRenderControlAltCamZoomSpeedA).WriteJump();
		_MemHdlr(TESRenderControlAltCamZoomSpeedB).WriteJump();
		_MemHdlr(TESRenderControlAltCamPanSpeedA).WriteJump();
		_MemHdlr(TESRenderControlAltCamPanSpeedB).WriteJump();
		_MemHdlr(TESRenderControlRedrawGrid).WriteJump();
		_MemHdlr(TESPreviewControlCallWndProc).WriteJump();
		_MemHdlr(ActivateRenderWindowPostLandTextureChange).WriteJump();
		_MemHdlr(TESPathGridRecordOperationMoveA).WriteJump();
		_MemHdlr(TESPathGridRecordOperationMoveB).WriteJump();
		_MemHdlr(TESPathGridRecordOperationLink).WriteJump();
		_MemHdlr(TESPathGridRecordOperationFlag).WriteJump();
		_MemHdlr(TESPathGridRecordOperationRef).WriteJump();
		_MemHdlr(TESPathGridDeletePoint).WriteJump();
		_MemHdlr(TESPathGridPointDtor).WriteJump();
		_MemHdlr(TESPathGridToggleEditMode).WriteJump();
		_MemHdlr(TESPathGridCreateNewLinkedPoint).WriteJump();
		_MemHdlr(TESPathGridPerformFall).WriteJump();
		_MemHdlr(TESPathGridShowMultipleSelectionRing).WriteJump();
		_MemHdlr(TESPathGridDtor).WriteUInt8(0xEB);
		_MemHdlr(InitialCellLoadCameraPosition).WriteJump();
		_MemHdlr(LandscapeEditBrushRadius).WriteUInt32((UInt32)&g_MaxLandscapeEditBrushRadius);
		_MemHdlr(DuplicateReferences).WriteJump();
		_MemHdlr(RenderToAuxiliaryViewport).WriteJump();
	}

	#define _hhName		DoorMarkerProperties
	_hhBegin()
	{
		_hhSetVar(Properties, 0x00429EAB);
		_hhSetVar(Teleport, 0x00429EE8);
		__asm
		{
			mov		eax, [esi + 0x8]
			shr		eax, 0x0E
			test	al, 1
			jnz		DOORMARKER

			jmp		[_hhGetVar(Properties)]
		TELEPORT:
			popad
			jmp		[_hhGetVar(Teleport)]
		DOORMARKER:
			pushad
			call	IsControlKeyDown
			test	eax, eax
			jz		TELEPORT
			popad

			jmp		[_hhGetVar(Properties)]
		}
	}

	void __stdcall DoTESObjectREFRGet3DDataHook(TESObjectREFR* Object, NiNode* Node)
	{
		if ((Node->m_flags & kNiNodeSpecialFlags_DontUncull))
			return;

		ToggleFlag(&Node->m_flags, NiNode::kFlag_AppCulled, false);

		BSExtraData* xData = Object->extraData.GetExtraDataByType(BSExtraData::kExtra_EnableStateParent);
		if (xData)
		{
			ExtraEnableStateParent* xParent = CS_CAST(xData, BSExtraData, ExtraEnableStateParent);
			if ((xParent->parent->formFlags & kTESObjectREFRSpecialFlags_Children3DInvisible))
				ToggleFlag(&Node->m_flags, NiNode::kFlag_AppCulled, true);
		}

		if ((Object->formFlags & kTESObjectREFRSpecialFlags_3DInvisible))
			ToggleFlag(&Node->m_flags, NiNode::kFlag_AppCulled, true);
	}

	#define _hhName		TESObjectREFRGet3DData
	_hhBegin()
	{
		_hhSetVar(Call, 0x0045B1B0);
		__asm
		{
			push	esi
			push	ecx		// store
			push	0x56
			add		ecx, 0x4C
			xor		esi, esi
			call	[_hhGetVar(Call)]
			test	eax, eax
			jz		NO3DDATA

			mov		eax, [eax + 0xC]
			pop		ecx		// restore
			push	ecx		// store again for epilog

			pushad
			push	eax
			push	ecx
			call	DoTESObjectREFRGet3DDataHook
			popad
			jmp		EXIT
		NO3DDATA:
			mov		eax, esi
		EXIT:
			pop		ecx
			pop		esi
			retn
		}
	}

	void __stdcall NiWindowRenderDrawHook(void)
	{
		RENDERTEXT->Render();
	}

	#define _hhName		NiWindowRender
	_hhBegin()
	{
		_hhSetVar(Call, 0x0076A3B0);
		_hhSetVar(Retn, 0x00406447);
		__asm
		{
			call	[_hhGetVar(Call)]

			pushad
			call	NiWindowRenderDrawHook
			popad

			jmp		[_hhGetVar(Retn)]
		}
	}

	void __stdcall DoNiDX9RendererRecreateHook(void)
	{
		RENDERTEXT->Recreate();
	}

	#define _hhName		NiDX9RendererRecreate
	_hhBegin()
	{
		_hhSetVar(Retn, 0x006D7266);
		__asm
		{
			pushad
			call	DoNiDX9RendererRecreateHook
			popad

			sub     esp, 0x10
			push    ebx
			push    ebp
			push    esi

			jmp		[_hhGetVar(Retn)]
		}
	}

	void __stdcall DoRenderWindowStatsHook(void)
	{
		if (g_INIManager->GetINIInt("DisplaySelectionStats", "Extender::Renderer"))
		{
			if ((*g_TESRenderSelectionPrimary)->selectionCount > 1)
			{
				PrintToBuffer("%d Objects Selected", (*g_TESRenderSelectionPrimary)->selectionCount);
				RENDERTEXT->QueueDrawTask(RenderWindowTextPainter::kRenderChannel_1, g_TextBuffer, 0);
			}
			else if ((*g_TESRenderSelectionPrimary)->selectionCount)
			{
				TESObjectREFR* Selection = CS_CAST((*g_TESRenderSelectionPrimary)->selectionList->Data, TESForm, TESObjectREFR);
				char Buffer[0x50] = {0};
				sprintf_s(Buffer, 0x50, "");

				BSExtraData* xData = Selection->extraData.GetExtraDataByType(BSExtraData::kExtra_EnableStateParent);
				if (xData)
				{
					ExtraEnableStateParent* xParent = CS_CAST(xData, BSExtraData, ExtraEnableStateParent);
					sprintf_s(Buffer, 0x50, "Parent: %s [%08X]  Opposite State: %d",
																	((xParent->parent->editorID.Size())?(xParent->parent->editorID.c_str()):("")),
																	xParent->parent->formID, (UInt8)xParent->oppositeState);
				}

				PrintToBuffer("%s (%08X) BASE[%s (%08X)]\nP[%.04f, %.04f, %.04f]\nR[%.04f, %.04f, %.04f]\nS[%.04f]\nFlags: %s %s %s %s %s %s\n%s",
								((Selection->editorID.Size())?(Selection->editorID.c_str()):("")), Selection->formID,
								((Selection->baseForm->editorID.Size())?(Selection->baseForm->editorID.c_str()):("")), Selection->baseForm->formID,
								Selection->position.x, Selection->position.y, Selection->position.z,
								Selection->rotation.x * 180.0 / PI,
								Selection->rotation.y * 180.0 / PI,
								Selection->rotation.z * 180.0 / PI,
								Selection->scale,
								((Selection->formFlags & TESForm::kFormFlags_QuestItem)?("P"):("-")),
								((Selection->formFlags & TESForm::kFormFlags_Disabled)?("D"):("-")),
								((Selection->formFlags & TESForm::kFormFlags_VisibleWhenDistant)?("V"):("-")),
								((Selection->formFlags & kTESObjectREFRSpecialFlags_3DInvisible)?("I"):("-")),
								((Selection->formFlags & kTESObjectREFRSpecialFlags_Children3DInvisible)?("CI"):("-")),
								((Selection->formFlags & kTESObjectREFRSpecialFlags_Frozen)?("F"):("-")),
								Buffer);

				RENDERTEXT->QueueDrawTask(RenderWindowTextPainter::kRenderChannel_1, g_TextBuffer, 0);
			}
			else
				RENDERTEXT->QueueDrawTask(RenderWindowTextPainter::kRenderChannel_1, NULL, 0);
		}
		else
			RENDERTEXT->QueueDrawTask(RenderWindowTextPainter::kRenderChannel_1, NULL, 0);
	}

	#define _hhName		RenderWindowStats
	_hhBegin()
	{
		_hhSetVar(Call, 0x006F25E0);
		_hhSetVar(Retn, 0x0042D3F9);
		__asm
		{
			call	[_hhGetVar(Call)]

			pushad
			call	DoRenderWindowStatsHook
			popad

			jmp		[_hhGetVar(Retn)]
		}
	}

	bool __stdcall DoUpdateViewportHook(void)
	{
		if (RENDERTEXT->GetRenderChannelQueueSize(RenderWindowTextPainter::kRenderChannel_2) || g_INIManager->GetINIInt("UpdateViewPortAsync", "Extender::Renderer"))
			return true;
		else
			return false;
	}

	#define _hhName		UpdateViewport
	_hhBegin()
	{
		_hhSetVar(Retn, 0x0042EF86);
		_hhSetVar(Jump, 0x0042CE7D);
		__asm
		{
			mov		eax, [g_RenderWindowUpdateViewPortFlag]
			mov		eax, [eax]
			cmp		al, 0
			jz		DONTUPDATE

			jmp		[_hhGetVar(Jump)]
		DONTUPDATE:
			pushad
			xor		eax, eax
			call	DoUpdateViewportHook
			test	al, al
			jz		EXIT

			popad
			jmp		[_hhGetVar(Jump)]
		EXIT:
			popad
			jmp		[_hhGetVar(Retn)]
		}
	}

	bool __stdcall DoRenderWindowSelectionHook(TESObjectREFR* Ref)
	{
		bool Result = false;

		TESObjectCELL* CurrentCell = (*g_TES)->currentInteriorCell;
		if (CurrentCell == NULL)
			CurrentCell = (*g_TES)->currentExteriorCell;

		if (CurrentCell)
		{
			TESRenderSelection* Selection = g_RenderSelectionGroupManager.GetRefSelectionGroup(Ref, CurrentCell);
			if (Selection)
			{
				for (TESRenderSelection::SelectedObjectsEntry* Itr = Selection->selectionList; Itr && Itr->Data; Itr = Itr->Next)
					(*g_TESRenderSelectionPrimary)->AddToSelection(Itr->Data, true);

				RENDERTEXT->QueueDrawTask(RenderWindowTextPainter::kRenderChannel_2, "Selected object selection group", 3);
				Result = true;
			}
		}

		return Result;
	}

	#define _hhName		RenderWindowSelection
	_hhBegin()
	{
		_hhSetVar(Retn, 0x0042AE76);
		_hhSetVar(Jump, 0x0042AE84);
		_hhSetVar(Call, 0x00511C20);
		__asm
		{
			call	[_hhGetVar(Call)]
			xor		eax, eax

			pushad
			push	esi
			call	DoRenderWindowSelectionHook
			test	al, al
			jnz		GROUPED
			popad

			jmp		[_hhGetVar(Retn)]
		GROUPED:
			popad
			jmp		[_hhGetVar(Jump)]
		}
	}

	void __stdcall TESRenderControlProcessFrozenRefs(void)
	{
		std::vector<TESForm*> FrozenRefs;
		for (TESRenderSelection::SelectedObjectsEntry* Itr = (*g_TESRenderSelectionPrimary)->selectionList; Itr && Itr->Data; Itr = Itr->Next)
		{
			if ((Itr->Data->formFlags & kTESObjectREFRSpecialFlags_Frozen))
				FrozenRefs.push_back(Itr->Data);
		}

		for (std::vector<TESForm*>::const_iterator Itr = FrozenRefs.begin(); Itr != FrozenRefs.end(); Itr++)
			(*g_TESRenderSelectionPrimary)->RemoveFromSelection(*Itr, true);
	}

	#define _hhName		TESRenderControlPerformMove
	_hhBegin()
	{
		_hhSetVar(Retn, 0x00425676);
		__asm
		{
			sub		esp, 0x114
			pushad
			call	TESRenderControlProcessFrozenRefs
			popad

			jmp		[_hhGetVar(Retn)]
		}
	}

	#define _hhName		TESRenderControlPerformRotate
	_hhBegin()
	{
		_hhSetVar(Retn, 0x00425D74);
		__asm
		{
			sub		esp, 0xC0
			pushad
			call	TESRenderControlProcessFrozenRefs
			popad

			jmp		[_hhGetVar(Retn)]
		}
	}

	#define _hhName		TESRenderControlPerformScale
	_hhBegin()
	{
		_hhSetVar(Retn, 0x00424659);
		__asm
		{
			sub		esp, 0x40
			mov		ecx, [g_TESRenderSelectionPrimary]
			mov		ecx, [ecx]

			pushad
			call	TESRenderControlProcessFrozenRefs
			popad

			jmp		[_hhGetVar(Retn)]
		}
	}

	#define _hhName		TESRenderControlPerformFall
	_hhBegin()
	{
		_hhSetVar(Retn, 0x0042886F);
		_hhSetVar(Call, 0x00512990);
		__asm
		{
			pushad
			call	TESRenderControlProcessFrozenRefs
			popad

			call	[_hhGetVar(Call)]
			jmp		[_hhGetVar(Retn)]
		}
	}

	void __stdcall DoTESObjectREFREditDialogHook(NiNode* Node, bool State)
	{
		ToggleFlag(&Node->m_flags, kNiNodeSpecialFlags_DontUncull, State);
	}

	#define _hhName		TESObjectREFRSetupDialog
	_hhBegin()
	{
		_hhSetVar(Retn, 0x00549A05);
		__asm
		{
			mov     eax, [edx + 0x180]
			mov     ecx, esi
			call    eax

			pushad
			push	1
			push	eax
			call	DoTESObjectREFREditDialogHook
			popad

			jmp		[_hhGetVar(Retn)]
		}
	}

	#define _hhName		TESObjectREFRCleanDialog
	_hhBegin()
	{
		_hhSetVar(Retn, 0x00549B57);
		__asm
		{
			push    edi
			mov     ecx, ebx
			call    edx

			pushad
			push	0
			push	eax
			call	DoTESObjectREFREditDialogHook
			popad

			jmp		[_hhGetVar(Retn)]
		}
	}

	#define _hhName		TESRenderControlPerformFallVoid
	_hhBegin()
	{
		_hhSetVar(Retn, 0x004270C9);
		_hhSetVar(Jump, 0x00427193);
		__asm
		{
			test	eax, eax
			jz		FIX

			mov		edx, [eax + 0x8]
			mov		[esp + 0x3C], edx

			jmp		[_hhGetVar(Retn)]
		FIX:
			jmp		[_hhGetVar(Jump)]
		}
	}

	#define _hhName		TESObjectREFRUpdate3D
	_hhBegin()
	{
		_hhSetVar(Retn, 0x00549B2E);
		__asm
		{
			push	esi
			mov		ebp, ecx
			mov		ebx, g_TESObjectREFRUpdate3DBuffer

			jmp		[_hhGetVar(Retn)]
		}
	}

	void __stdcall DoForceShowTESObjectREFRDialogHook(HWND PropertiesDialog)
	{
		TESDialog::RedrawRenderWindow();
		SetWindowPos(PropertiesDialog, HWND_TOP, 0, 0, 0, 0, SWP_NOMOVE|SWP_NOSIZE);
	}

	#define _hhName		ForceShowTESObjectREFRDialog
	_hhBegin()
	{
		_hhSetVar(Retn, 0x0042EF86);
		__asm
		{
			pushad
			push	eax
			call	DoForceShowTESObjectREFRDialogHook
			popad

			jmp		[_hhGetVar(Retn)]
		}
	}

	static float s_MovementSettingBuffer = 0.0;

	void __stdcall InitializeCurrentRenderWindowMovementSetting(const char* SettingName)
	{
		if (g_RenderWindowAltMovementSettings)
			s_MovementSettingBuffer = g_INIManager->GetINIFlt((std::string("Alt" + std::string(SettingName)).c_str()), "Extender::Renderer");
		else
		{
			if (!_stricmp(SettingName, "RefMovementSpeed"))
				s_MovementSettingBuffer = *g_RenderWindowRefMovementSpeed;
			else if (!_stricmp(SettingName, "RefSnapGrid"))
				s_MovementSettingBuffer = *g_RenderWindowSnapGridDistance;
			else if (!_stricmp(SettingName, "RefRotationSpeed"))
				s_MovementSettingBuffer = *g_RenderWindowRefRotationSpeed;
			else if (!_stricmp(SettingName, "RefSnapAngle"))
				s_MovementSettingBuffer = *g_RenderWindowSnapAngle;
			else if (!_stricmp(SettingName, "CamRotationSpeed"))
				s_MovementSettingBuffer = *g_RenderWindowCameraRotationSpeed;
			else if (!_stricmp(SettingName, "CamZoomSpeed"))
				s_MovementSettingBuffer = *g_RenderWindowCameraZoomSpeed;
			else if (!_stricmp(SettingName, "CamPanSpeed"))
				s_MovementSettingBuffer = *g_RenderWindowCameraPanSpeed;
			else
				s_MovementSettingBuffer = 0.0;
		}
	}

	#define _hhName		TESRenderControlAltSnapGrid
	_hhBegin()
	{
		_hhSetVar(Retn, 0x00425A3E);
		__asm	pushad
		InitializeCurrentRenderWindowMovementSetting("RefSnapGrid");
		__asm	popad
		__asm
		{
			fild	s_MovementSettingBuffer
			fstp	dword ptr [esp + 0x20]

			jmp		[_hhGetVar(Retn)]
		}
	}

	#define _hhName		TESRenderControlAltRefMovementSpeedA
	_hhBegin()
	{
		_hhSetVar(Retn, 0x00425741);
		__asm	pushad
		InitializeCurrentRenderWindowMovementSetting("RefMovementSpeed");
		__asm	popad
		__asm
		{
			fmul	s_MovementSettingBuffer
			lea		ecx, [esp + 0x28]

			jmp		[_hhGetVar(Retn)]
		}
	}

	#define _hhName		TESRenderControlAltRefMovementSpeedB
	_hhBegin()
	{
		_hhSetVar(Retn, 0x0042BE85);
		__asm	pushad
		InitializeCurrentRenderWindowMovementSetting("RefMovementSpeed");
		__asm	popad
		__asm
		{
			lea		ecx, s_MovementSettingBuffer

			jmp		[_hhGetVar(Retn)]
		}
	}

	#define _hhName		TESRenderControlAltRefMovementSpeedC
	_hhBegin()
	{
		_hhSetVar(Retn, 0x0042D0B2);
		__asm	pushad
		InitializeCurrentRenderWindowMovementSetting("RefMovementSpeed");
		__asm	popad
		__asm
		{
			lea		ecx, s_MovementSettingBuffer

			jmp		[_hhGetVar(Retn)]
		}
	}

	#define _hhName		TESRenderControlAltRefRotationSpeed
	_hhBegin()
	{
		_hhSetVar(Retn, 0x00425DC1);
		__asm	pushad
		InitializeCurrentRenderWindowMovementSetting("RefRotationSpeed");
		__asm	popad
		__asm
		{
			fmul	s_MovementSettingBuffer

			mov		eax, [g_RenderWindowStateFlags]
			mov		eax, [eax]
			test	eax, 0x2

			jmp		[_hhGetVar(Retn)]
		}
	}

	#define _hhName		TESRenderControlAltRefSnapAngle
	_hhBegin()
	{
		_hhSetVar(Retn, 0x00425DCD);
		__asm	pushad
		InitializeCurrentRenderWindowMovementSetting("RefSnapAngle");
		__asm	popad
		__asm
		{
			fild	s_MovementSettingBuffer

			jmp		[_hhGetVar(Retn)]
		}
	}

	#define _hhName		TESRenderControlAltCamRotationSpeed
	_hhBegin()
	{
		_hhSetVar(Retn, 0x0042CCB0);
		__asm	pushad
		InitializeCurrentRenderWindowMovementSetting("CamRotationSpeed");
		__asm	popad
		__asm
		{
			lea		ecx, s_MovementSettingBuffer

			jmp		[_hhGetVar(Retn)]
		}
	}

	#define _hhName		TESRenderControlAltCamZoomSpeedA
	_hhBegin()
	{
		_hhSetVar(Retn, 0x0042CCE5);
		__asm	pushad
		InitializeCurrentRenderWindowMovementSetting("CamZoomSpeed");
		__asm	popad
		__asm
		{
			lea		ecx, s_MovementSettingBuffer

			jmp		[_hhGetVar(Retn)]
		}
	}

	#define _hhName		TESRenderControlAltCamZoomSpeedB
	_hhBegin()
	{
		_hhSetVar(Retn, 0x0042CDB4);
		__asm	pushad
		InitializeCurrentRenderWindowMovementSetting("CamZoomSpeed");
		__asm	popad
		__asm
		{
			lea		ecx, s_MovementSettingBuffer

			jmp		[_hhGetVar(Retn)]
		}
	}

	#define _hhName		TESRenderControlAltCamPanSpeedA
	_hhBegin()
	{
		_hhSetVar(Retn, 0x0042CD2B);
		__asm	pushad
		InitializeCurrentRenderWindowMovementSetting("CamPanSpeed");
		__asm	popad
		__asm
		{
			lea		ecx, s_MovementSettingBuffer

			jmp		[_hhGetVar(Retn)]
		}
	}

	#define _hhName		TESRenderControlAltCamPanSpeedB
	_hhBegin()
	{
		_hhSetVar(Retn, 0x0042CD76);
		__asm	pushad
		InitializeCurrentRenderWindowMovementSetting("CamPanSpeed");
		__asm	popad
		__asm
		{
			lea		ecx, s_MovementSettingBuffer

			jmp		[_hhGetVar(Retn)]
		}
	}

	#define _hhName		TESRenderControlRedrawGrid
	_hhBegin()
	{
		_hhSetVar(Retn, 0x0042EF88);
		_asm	pushad
		TESDialog::RedrawRenderWindow();
		SetActiveWindow(*g_HWND_CSParent);
		SetActiveWindow(*g_HWND_RenderWindow);
		__asm
		{
			popad
			mov		eax, 1
			jmp		[_hhGetVar(Retn)]
		}
	}

	UInt32 __stdcall DoTESPreviewControlCallWndProcHook(void* OrgWindowProc, HWND hWnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
	{
		if (OrgWindowProc)
			return CallWindowProc((WNDPROC)OrgWindowProc, hWnd, uMsg, wParam, lParam);
		else
			return DefWindowProc(hWnd, uMsg, wParam, lParam);
	}

	#define _hhName		TESPreviewControlCallWndProc
	_hhBegin()
	{
		_hhSetVar(Retn, 0x0044D70E);
		__asm
		{
			push    ebx
			push    ebp
			push    edi
			push    esi
			push	eax
			call	DoTESPreviewControlCallWndProcHook

			jmp		[_hhGetVar(Retn)]
		}
	}

	void __stdcall DoActivateRenderWindowPostLandTextureChangeHook(void)
	{
		SetForegroundWindow(*g_HWND_RenderWindow);
	}

	#define _hhName		ActivateRenderWindowPostLandTextureChange
	_hhBegin()
	{
		_hhSetVar(Retn, 0x0042B4EB);
		__asm
		{
			pushad
			call	IATCacheSendMessageAddress
			popad

			call	g_TempIATProcBuffer
			pushad
			call	DoActivateRenderWindowPostLandTextureChangeHook
			popad

			jmp		[_hhGetVar(Retn)]
		}
	}

	static bool s_PathGridMoveStart = false;

	#define _hhName		TESPathGridRecordOperationMoveA
	_hhBegin()
	{
		_hhSetVar(Call, 0x0054D600);
		_hhSetVar(Retn, 0x0042A632);
		__asm
		{
			mov		s_PathGridMoveStart, 1
			call	[_hhGetVar(Call)]
			jmp		[_hhGetVar(Retn)]
		}
	}

	void __stdcall DoTESPathGridRecordOperation(void)
	{
		g_PathGridUndoManager.ResetRedoStack();

		if (g_RenderWindowSelectedPathGridPoints->Count())
			g_PathGridUndoManager.RecordOperation(PathGridUndoManager::kOperation_DataChange, g_RenderWindowSelectedPathGridPoints);
	}

	void __stdcall DoTESPathGridRecordOperationMoveBHook(void)
	{
		if (s_PathGridMoveStart)
		{
			s_PathGridMoveStart = false;
			DoTESPathGridRecordOperation();
		}
	}

	#define _hhName		TESPathGridRecordOperationMoveB
	_hhBegin()
	{
		_hhSetVar(Call, 0x004FC950);
		_hhSetVar(Retn, 0x0042BE72);
		__asm
		{
			pushad
			call	DoTESPathGridRecordOperationMoveBHook
			popad
			call	[_hhGetVar(Call)]
			jmp		[_hhGetVar(Retn)]
		}
	}

	#define _hhName		TESPathGridRecordOperationLink
	_hhBegin()
	{
		_hhSetVar(Call, 0x00405DA0);
		_hhSetVar(Retn, 0x0042A82E);
		__asm
		{
			pushad
			call	DoTESPathGridRecordOperation
			popad
			call	[_hhGetVar(Call)]
			jmp		[_hhGetVar(Retn)]
		}
	}

	#define _hhName		TESPathGridRecordOperationFlag
	_hhBegin()
	{
		_hhSetVar(Call, 0x005557A0);
		_hhSetVar(Retn, 0x0042A719);
		__asm
		{
			pushad
			call	DoTESPathGridRecordOperation
			popad
			call	[_hhGetVar(Call)]
			jmp		[_hhGetVar(Retn)]
		}
	}

	#define _hhName		TESPathGridRecordOperationRef
	_hhBegin()
	{
		_hhSetVar(Call, 0x00405DA0);
		_hhSetVar(Retn, 0x0042836C);
		__asm
		{
			pushad
			call	DoTESPathGridRecordOperation
			popad
			call	[_hhGetVar(Call)]
			jmp		[_hhGetVar(Retn)]
		}
	}

	void __stdcall DoTESPathGridDeletePointHook(void)
	{
		g_PathGridUndoManager.ResetRedoStack();
		g_PathGridUndoManager.HandlePathGridPointDeletion(g_RenderWindowSelectedPathGridPoints);

		if (g_RenderWindowSelectedPathGridPoints->Count())
			g_PathGridUndoManager.RecordOperation(PathGridUndoManager::kOperation_PointDeletion, g_RenderWindowSelectedPathGridPoints);
	}

	#define _hhName		TESPathGridDeletePoint
	_hhBegin()
	{
		_hhSetVar(Call, 0x0048E0E0);
		_hhSetVar(Retn, 0x004291CB);
		__asm
		{
			pushad
			call	DoTESPathGridDeletePointHook
			popad
			call	[_hhGetVar(Call)]
			jmp		[_hhGetVar(Retn)]
		}
	}

	void __stdcall DoTESPathGridPointDtorHook(TESPathGridPoint* Point)
	{
		PathGridPointListT* DeletionList = (PathGridPointListT*)PathGridPointListT::Create(&FormHeap_Allocate);
		DeletionList->AddAt(Point, eListEnd);
		g_PathGridUndoManager.HandlePathGridPointDeletion(DeletionList);
		DeletionList->RemoveAll();
		FormHeap_Free(DeletionList);
	}

	#define _hhName		TESPathGridPointDtor
	_hhBegin()
	{
		_hhSetVar(Retn, 0x00556197);
		__asm
		{
			mov		eax, [esp]
			sub		eax, 5
			cmp		eax, 0x0054E5A3
			jnz		CULL

			mov		eax, [esp + 0x18]
			sub		eax, 5
			cmp		eax, 0x00429200		// don't handle deletion if called from the render window wnd proc, as we already do that in the previous hook
			jz		SKIP
		CULL:
			pushad
			push	ecx
			call	DoTESPathGridPointDtorHook
			popad
		SKIP:
			push    ebx
			push    esi
			mov     esi, ecx
			lea     ecx, [esi + 0x10]
			jmp		[_hhGetVar(Retn)]
		}
	}

	void __stdcall DoTESPathGridToggleEditModeHook(void)
	{
		g_PathGridUndoManager.ResetRedoStack();
		g_PathGridUndoManager.ResetUndoStack();
	}

	#define _hhName		TESPathGridToggleEditMode
	_hhBegin()
	{
		_hhSetVar(Call, 0x0054C560);
		_hhSetVar(Retn, 0x00550665);
		__asm
		{
			pushad
			call	DoTESPathGridToggleEditModeHook
			popad
			call	[_hhGetVar(Call)]
			jmp		[_hhGetVar(Retn)]
		}
	}

	void __stdcall DoTESPathGridCreateNewLinkedPointHook(void)
	{
		g_PathGridUndoManager.ResetRedoStack();

		if (g_RenderWindowSelectedPathGridPoints->Count())
			g_PathGridUndoManager.RecordOperation(PathGridUndoManager::kOperation_PointCreation, g_RenderWindowSelectedPathGridPoints);
	}

	#define _hhName		TESPathGridCreateNewLinkedPoint
	_hhBegin()
	{
		_hhSetVar(Call, 0x004E3900);
		_hhSetVar(Retn, 0x0042B380);
		__asm
		{
			call	[_hhGetVar(Call)]
			pushad
			call	DoTESPathGridCreateNewLinkedPointHook
			popad
			jmp		[_hhGetVar(Retn)]
		}
	}

	void __stdcall DoTESPathGridShowMultipleSelectionRingHook(TESPathGridPoint* Point)
	{
		Point->ShowSelectionRing();
	}

	#define _hhName		TESPathGridShowMultipleSelectionRing
	_hhBegin()
	{
		_hhSetVar(Call, 0x004E3900);
		_hhSetVar(Retn, 0x0042FC81);
		__asm
		{
			pushad
			push	esi
			call	DoTESPathGridShowMultipleSelectionRingHook
			popad
			call	[_hhGetVar(Call)]
			jmp		[_hhGetVar(Retn)]
		}
	}

	#define _hhName		TESPathGridPerformFall
	_hhBegin()
	{
		_hhSetVar(Call, 0x0048E0E0);
		_hhSetVar(Retn, 0x00428617);
		__asm
		{
			pushad
			call	DoTESPathGridRecordOperation
			popad
			call	[_hhGetVar(Call)]
			jmp		[_hhGetVar(Retn)]
		}
	}

	void __stdcall DoInitialCellLoadCameraPositionHook(void)
	{
		static long double s_Offset = -1;
		if (s_Offset < 0.0)
		{
			s_Offset = 0.0;
			SafeWrite32(0x0042E69B + 2, (UInt32)&s_Offset);
		}

		SendMessage(*g_HWND_RenderWindow, 0x40D, NULL, (LPARAM)&Vector3(0.0, 0.0, 0.0));
	}

	#define _hhName		InitialCellLoadCameraPosition
	_hhBegin()
	{
		_hhSetVar(Call, 0x00532240);
		_hhSetVar(Retn, 0x0040A8B7);
		_hhSetVar(Jump, 0x0040A8D8);
		__asm
		{
			call	[_hhGetVar(Call)]
			test	al, al
			jnz		FIX

			jmp		[_hhGetVar(Retn)]
		FIX:
			call	DoInitialCellLoadCameraPositionHook
			jmp		[_hhGetVar(Jump)]
		}
	}

	#define _hhName		ConvertNiRenderedTexToD3DBaseTex
	_hhBegin()
	{
		_hhSetVar(Retn, 0x004116A5);
		__asm
		{
			push	esi		// store IDirect3DBaseTexture9*

			mov     esi, [esp + 0x30]
			lea     eax, [esi + 4]
			push    eax
			pushad
			call	IATCacheInterlockedDecrementAddress
			popad
			call	g_TempIATProcBuffer
			test    eax, eax
			jnz     EXIT
			mov     edx, [esi]
			mov     eax, [edx]
			push    1
			mov     ecx, esi
			call    eax
		EXIT:
			pop		esi		// restore
			mov		eax, esi
			jmp		[_hhGetVar(Retn)]
		}
	}

	void __stdcall DoDuplicateReferencesHook(void)
	{
		for (TESRenderSelection::SelectedObjectsEntry* Itr = (*g_TESRenderSelectionPrimary)->selectionList; Itr && Itr->Data; Itr = Itr->Next)
		{
			TESObjectREFR* Reference = CS_CAST(Itr->Data, TESForm, TESObjectREFR);
			Reference->position.z += 10.0f;
			Reference->UpdateNiNode();
		}
	}

	#define _hhName		DuplicateReferences
	_hhBegin()
	{
		_hhSetVar(Retn, 0x0042EC6C);
		__asm
		{
			pushad
			call	DoDuplicateReferencesHook
			popad

			jmp		[_hhGetVar(Retn)]
		}
	}

	void __stdcall DoRenderToAuxiliaryViewportHook(void)
	{
		if (AUXVIEWPORT->IsHidden())
			return;

		if (AUXVIEWPORT->IsFrozen() == false)
			AUXVIEWPORT->SyncViewportCamera(_RENDERCMPT->primaryCamera);
		else
		{
			RENDERTEXT->SkipNextFrame();
			_MemHdlr(NiDX9RendererPresent).WriteUInt16(0x9090);
			_RENDERCMPT->RenderNode(AUXVIEWPORT->GetViewportCamera());
			_MemHdlr(NiDX9RendererPresent).WriteBuffer();
		}

		_RENDERER->device->Present(NULL, NULL, AUXVIEWPORT->GetWindow(), NULL);
	}

	#define _hhName		RenderToAuxiliaryViewport
	_hhBegin()
	{
		_hhSetVar(Retn, 0x0042D415);
		__asm
		{
			pushad
			call	DoRenderToAuxiliaryViewportHook
			popad

			mov     ecx, [eax]
			mov     edx, [ecx]
			mov     eax, [eax+8]
			mov     edx, [edx]
			push    0
			push    0
			push	eax
			call	edx

			jmp		[_hhGetVar(Retn)]
		}
	}
}