#include "Script.h"
#include "Hooks\ScriptEditor.h"

TESScriptCompiler::_ShowMessage			TESScriptCompiler::ShowMessage = (TESScriptCompiler::_ShowMessage)0x004FFF40;

Script::VariableInfo* Script::LookupVariableInfoByName(const char* Name)
{
	for (VariableListT::Iterator Itr = varList.Begin(); !Itr.End(); ++Itr)
	{
		VariableInfo* Variable = Itr.Get();

		if (Variable && !Variable->name.Compare(Name))
			return Variable;
	}

	return NULL;
}

Script::RefVariable* Script::LookupRefVariableByIndex(UInt32 Index)
{
	UInt32 Idx = 1;	// yes, really starts at 1

	for (RefVariableListT::Iterator Itr = refList.Begin(); !Itr.End(); ++Itr)
	{
		RefVariable* Variable = Itr.Get();

		if (Variable && Idx == Index)
			return Variable;

		Idx++;
	}

	return NULL;
}

bool Script::Compile(bool AsResultScript)
{
	if (AsResultScript)
		return thisCall<bool>(0x005034E0, 0x00A0B128, this, 0, 0);
	else
		return thisCall<bool>(0x00503450, 0x00A0B128, this, 0);
}

void Script::SetText(const char* Text)
{
	thisCall<UInt32>(0x004FC6C0, this, Text);
}

void TESScriptCompiler::ToggleScriptCompilation( bool State )
{
	if (!State)
		Hooks::_MemHdlr(ToggleScriptCompilingNewData).WriteBuffer();
	else
		Hooks::_MemHdlr(ToggleScriptCompilingOriginalData).WriteBuffer();
}