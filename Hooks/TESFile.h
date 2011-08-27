#pragma once
#include "Common.h"

namespace Hooks
{
	// hooks that modify how the CS handles plugin files
	void PatchTESFileHooks(void);

	extern bool		g_LoadingSavingPlugins;

	_DeclareMemHdlr(SavePluginMasterEnum, "allows esps to be enumerated while filling the file header");
	_DeclareNopHdlr(CheckIsActivePluginAnESM, "allows master files to be set as active plugins");
	_DeclareNopHdlr(TESFormGetUnUsedFormID, "");
	_DeclareMemHdlr(LoadPluginsProlog, "");
	_DeclareMemHdlr(LoadPluginsEpilog, "");
	_DeclareMemHdlr(DataDialogPluginDescription, "allows the Author and Description fields of an ESM file to be viewed and modified correctly");
	_DeclareMemHdlr(DataDialogPluginAuthor, "");
	_DeclareMemHdlr(SavePluginCommonDialog, "allows the creation of ESM files in the CS");
	_DeclareMemHdlr(DataHandlerPostError, "fixes a crash when the CS attempts to load an unknown record/group");
	_DeclareMemHdlr(DataHandlerSaveFormToFile, "allows records in esp masters to be overridden with deleted records");
	_DeclareMemHdlr(TESFileUpdateHeader, "prevents TESFile::UpdateHeader from continuing for locked files");
	_DeclareMemHdlr(DataHandlerSavePluginEpilog, "prevents the esm flag bit from being reset");
	_DeclareMemHdlr(TESFileUpdateHeaderFlagBit, "");
	_DeclareMemHdlr(TESObjectCELLSaveReferencesProlog, "prevents malformed records of deleted refs from being written");
	_DeclareMemHdlr(TESObjectCELLSaveReferencesEpilog, "");
	_DeclareMemHdlr(MissingMasterOverride, "allows the loading of plugins with missing masters");
	_DeclareMemHdlr(QuickLoadPluginLoadHandler, "adds support for the quick loading of plugins (only loads the active plugin)");
	_DeclareMemHdlr(AutoLoadActivePluginOnStartup, "temporary hook that allows the automatic loading of plugins on startup");
	_DeclareMemHdlr(DataHandlerSavePluginResetA, "patches various locations in DataHandler::SavePlugin to prevent a premature exit from disabling the save tool");
	_DeclareMemHdlr(DataHandlerSavePluginResetB, "");
	_DeclareMemHdlr(DataHandlerSavePluginResetC, "");
	_DeclareNopHdlr(DataHandlerSavePluginOverwriteESM, "allows the overwriting of ESM files");
	_DeclareMemHdlr(DataHandlerSavePluginRetainTimeStamps, "allows the retention of plugin timestamps during save operations");
	_DeclareMemHdlr(TESObjectLANDLoadForm, "patches the routine to defer the initialization of grass data until the cell is actually loaded into the render window");
}