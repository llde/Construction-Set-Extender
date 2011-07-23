#include "Archive.h"

ArchiveListT**			g_LoadedBSAArchives = (ArchiveListT**)0x00A0DD8C;

Archive* ArchiveManager::LoadArchive( const char* ArchiveName, UInt16 Unk02, UInt8 Unk03)
{
	return cdeclCall<Archive*>(0x004665C0, ArchiveName, Unk02, Unk03);
}

void ArchiveManager::LoadSkippedArchives(const char* ArchiveDirectory)
{
	if (*g_LoadedBSAArchives == 0)		return;

	for (IDirectoryIterator Itr(ArchiveDirectory, "*.bsa"); !Itr.Done(); Itr.Next())
	{
		std::string FileName(Itr.Get()->cFileName);
		FileName = FileName.substr(FileName.find_last_of("\\") + 1);

		bool IsLoaded = false;
		for (ArchiveListT::Iterator Itr = (*g_LoadedBSAArchives)->Begin(); !Itr.End() && Itr.Get(); ++Itr)
		{
			std::string LoadedFileName(Itr.Get()->fileName);
			LoadedFileName = LoadedFileName.substr(LoadedFileName.find_last_of("\\") + 1);

			if (!_stricmp(LoadedFileName.c_str(), FileName.c_str()))
			{
				IsLoaded = true;
				break;
			}
		}

		if (IsLoaded == false)
		{
			LoadArchive(FileName.c_str(), 0, 0);
			DebugPrint("BSA Archive %s loaded", FileName.c_str());
		}
	}
}

bool ArchiveManager::ExtractArchiveFile( const char* InPath, const char* OutPath, bool AppendFilePath /*= false*/ )
{
	bool Result = false;

	if (InPath)
	{
		std::string Path(InPath); MakeLower(Path);
		if (Path.find("data\\") != -1)
			Path = Path.substr(Path.find("data\\") + 5);

		if (_FILEFINDER->FindFile(Path.c_str()) == 2)
		{
			ArchiveFile* ArchiveFileStream = CS_CAST(_FILEFINDER->GetFileStream(Path.c_str(), false, 0x50000), NiBinaryStream, ArchiveFile);
			if (ArchiveFileStream)
			{
				UInt32 FileSize = ArchiveFileStream->GetFileSize();
				std::string ArchiveFilePath = ArchiveFileStream->fileName;
				std::string ArchiveFileName = ArchiveFilePath.substr(ArchiveFilePath.rfind("\\") + 1);
				std::string FileOut = OutPath;

				if (AppendFilePath)
					FileOut += "\\" + ArchiveFilePath;

				BSFile* TempFile = BSFile::CreateInstance(FileOut.c_str(), NiFile::kFileMode_WriteOnly, FileSize);
				assert(TempFile);

				void* Buffer = FormHeap_Allocate(FileSize);
				ZeroMemory(Buffer, FileSize);

				if (!ArchiveFileStream->DirectRead(Buffer, FileSize))
				{
					DebugPrint("ArchiveManager::ExtractArchiveFile - Couldn't read file %s from archive %s", ArchiveFileStream->fileName, ArchiveFileStream->parentArchive->fileName);
				}
				else
				{
					if (!TempFile->DirectWrite(Buffer, FileSize))
					{
						DebugPrint("ArchiveManager::ExtractArchiveFile - Couldn't write to file %s", TempFile->fileName);
					}
					else
						Result = true;
				}

				TempFile->Flush();
				TempFile->DeleteInstance();
				ArchiveFileStream->DeleteInstance();
				FormHeap_Free(Buffer);
			}
		}
	}

	return Result;
}