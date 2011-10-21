#include "MiscUtilities.h"
#include "NativeWrapper.h"

CString::CString(System::String^% Source)
{
	P = Marshal::StringToHGlobalAnsi(Source);
}

void DebugDump(UInt8 Source, String^% Message)
{
	CString CStr(Message);
	NativeWrapper::g_CSEInterface->CSEEditorAPI.DebugPrint(Source, CStr.c_str());
}

void ToggleFlag(UInt32* Flag, UInt32 Mask, bool State)
{
	if (State)	*Flag |= Mask;
	else		*Flag &= ~Mask;
}

ImageResourceManager::ImageResourceManager(String^ BaseName)
{
	Manager = gcnew ResourceManager(BaseName, Assembly::GetExecutingAssembly());
}

Image^ ImageResourceManager::CreateImageFromResource(String^ ResourceIdentifier)
{
	try
	{
		return dynamic_cast<Image^>(Manager->GetObject(ResourceIdentifier));
	}
	catch (...)
	{
		return nullptr;
	}
}

void ImageResourceManager::SetupImageForToolStripButton(ToolStripButton^ Control)
{
	Control->Image = CreateImageFromResource(Control->Name);
}

CSEControlDisposer::CSEControlDisposer( Control^% Source )
{
	for each (Control^ Itr in Source->Controls)
	{
		CSEControlDisposer Disposer(Itr);
		delete Itr;
	}
}

void DeleteManagedHeapPointer( void* Pointer, bool IsArray )
{
	if (IsArray)
		delete [] Pointer;
	else
		delete Pointer;
}

void CopyStringToCharBuffer( String^% Source, char* Buffer, UInt32 Size )
{
	int i = 0;
	for (i=0; i < Source->Length && i < Size; i++)
		*(Buffer + i) = Source[i];

	if (i < Size)
		*(Buffer + i) = '\0';
	else
		Buffer[Size - 1] = '\0';
}

namespace Log
{
	namespace ScriptEditor
	{
		void DebugPrint(String^ Message, bool Achtung)
		{
			if (Achtung)
			{
				Media::SystemSounds::Hand->Play();
			}

			DebugDump(e_SE, Message);
		}
	}
	namespace UseInfoList
	{
		void DebugPrint(String^ Message, bool Achtung)
		{
			if (Achtung)
			{
				Media::SystemSounds::Hand->Play();
			}

			DebugDump(e_UL, Message);
		}
	}
	namespace BatchEditor
	{
		void DebugPrint(String^ Message, bool Achtung)
		{
			if (Achtung)
			{
				Media::SystemSounds::Hand->Play();
			}

			DebugDump(e_BE, Message);
		}
	}
	namespace BSAViewer
	{
		void DebugPrint(String^ Message, bool Achtung)
		{
			if (Achtung)
			{
				Media::SystemSounds::Hand->Play();
			}

			DebugDump(e_BSA, Message);
		}
	}
	namespace TagBrowser
	{
		void DebugPrint(String^ Message, bool Achtung)
		{
			if (Achtung)
			{
				Media::SystemSounds::Hand->Play();
			}

			DebugDump(e_TAG, Message);
		}
	}
}