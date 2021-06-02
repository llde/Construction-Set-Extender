#pragma once

#include "TESTopicInfo.h"

//	EditorAPI: TESDialog and related classes.
//	A number of class definitions are directly derived from the COEF API; Credit to JRoush for his comprehensive decoding

/*
	TESDialog is a 'container' classes for dealing with CS interface dialogs.
	The static methods and data here may actually belong in a number of other classes, but they are grouped together
	in the executable images, and apparently had their own file in the BS repository ("TESDialog.cpp").
	At the moment, these classes are defined for convenience, to group code related to the CS interface in one place.

	TESDialogs store a BaseExtraDataList for DialogExtra*** objects in their window 'user param' (e.g. GetWindowLong(-0x15))

	There seems to be a strong distinction between dialogs that edit forms and those that edit simpler component objects or
	provide services like import/export or text searching.  Some members are only for dialogs that edit forms, and some are
	only for dialogs that edit forms accessible in the Objects Window.
	*/

class	TESForm;
class	TESQuest;
class	TESRace;
class	Script;
class	TESObjectREFR;
class	BSExtraData;
class	TESBoundObject;
class	TESPreviewControl;
class	BaseExtraList;

// FormEditParam - for form-editing dialogs.
// passed as initParam to CreateDialogParam() (i.e. lParam on WM_INITDIALOG message) for form-editing dialogs
// 0C
class FormEditParam
{
public:
	/*00*/ UInt8		typeID;
	/*01*/ UInt8		pad01[3];
	/*04*/ TESForm*		form;
	/*08*/ UInt32		unk08;				// never initialized or accessed

	FormEditParam(const char* EditorID);
	FormEditParam(UInt32 FormID);
	FormEditParam(TESForm* Form);
};
STATIC_ASSERT(sizeof(FormEditParam) == 0xC);

// 20
class Subwindow
{
public:
	typedef tList<HWND>		ControlListT;

	/*00*/ ControlListT     controls;		// items are actually HWNDs; declared as such due to tList's definition
	/*08*/ HWND             hDialog;		// handle of parent dialog window
	/*0C*/ HINSTANCE        hInstance;		// module instance of dialog template
	/*10*/ POINT            position;		// position of subwindow within parent dialog
	/*18*/ HWND             hContainer;		// handle of container control (e.g. Tab Control)
	/*1C*/ HWND             hSubwindow;		// handle of subwindow, if created

	// methods
	bool					Build(UInt32 TemplateID);
	void					TearDown(void);

	static Subwindow*		CreateInstance(void);
	void					DeleteInstance(void);
};
STATIC_ASSERT(sizeof(Subwindow) == 0x20);

// 2C
class ResponseEditorData
{
public:
	struct VoiceRecorderData
	{
		/*00*/ HWND			recorderDlg;
	};

	typedef tList<TESRace>			VoicedRaceListT;

	/*00*/ const char*				editorTitle;
	/*04*/ UInt32					maxResponseLength;
	/*08*/ DialogResponse*			selectedResponse;
	/*0C*/ DialogResponse*			responseLocalCopy;
	/*10*/ VoiceRecorderData*		recorderData;
	/*14*/ TESTopic*				parentTopic;
	/*18*/ TESTopicInfo*			infoLocalCopy;
	/*1C*/ TESTopicInfo*			selectedInfo;
	/*20*/ TESQuest*				selectedQuest;
	/*24*/ VoicedRaceListT			voicedRaces;

	static ResponseEditorData**		EditorCache;				// accessed by the response editor dlg and set by the last opened one

	enum
	{
		kVoiceFileListView = 2168,
		kGenerateLIPFileButton = 1016,
		kCopyExternalFileButton = 2223,
	};
};
STATIC_ASSERT(sizeof(ResponseEditorData) == 0x2C);

// 12C
class ScriptEditorData
{
public:
	/*00*/ RECT						editorBounds;
	/*10*/ Script*					currentScript;
	/*14*/ UInt8					newScript;					// set to 1 when a new script is created, used to remove the new script when it's discarded
	/*15*/ UInt8					pad15[3];
	/*18*/ HMENU					editorMenu;
	/*1C*/ HWND						editorStatusBar;
	/*20*/ HWND						editorToolBar;
	/*24*/ HWND						scriptableFormList;			// handle to the TESScriptableForm combo box, passed as the lParam during init
	/*28*/ char						findTextQuery[0x104];
};
STATIC_ASSERT(sizeof(ScriptEditorData) == 0x12C);

// 18
// stored in the dialog's DialogExtraWorkingData's localCopy member
class FindTextWindowData
{
public:
	typedef tList<Script>				ScriptListT;
	typedef tList<TESQuest>				QuestListT;
	typedef tList<TESForm>				FormListT;

	// 0C
	struct TopicSearchResult
	{
		typedef tList<TESTopicInfo>		TopicInfoListT;

		/*00*/ TESTopic*				topic;
		/*04*/ TopicInfoListT			infos;
	};
	typedef tList<TopicSearchResult>	TopicSearchResultListT;

	// members
	/*00*/ ScriptListT*					searchResultsScripts;
	/*04*/ TopicSearchResultListT*		searchResultsTopics;
	/*08*/ FormListT*					searchResultsForms;
	/*0C*/ QuestListT*					searchResultsQuests;
	/*10*/ UInt32						currentResultTab;				// init to 0
	/*14*/ UInt32						resultListViewSortOrder;
};
STATIC_ASSERT(sizeof(FindTextWindowData) == 0x18);

enum
{
	kFindTextListView_Topics = 1019,
	kFindTextListView_Infos = 1952,
	kFindTextListView_Objects = 1018,			// displays scripts and quests too

	kFindTextTextBox_Query = 1000,
};

// 18
class SelectTopicWindowData
{
public:
	typedef tList<TESTopic>				TopicListT;

	// members
	/*00*/ TopicListT					selectedTopics;		// topics selected in the window are added to this list
	/*08*/ TESQuest*					currentQuest;
	/*0C*/ TESTopicInfo*				currentTopicInfo;
	/*10*/ UInt32						topicType;
	/*14*/ UInt32						triggerCtrlID;		// ID of the list view that invoked the window

	static SelectTopicWindowData**		Singleton;

	// method
	void								RefreshListView(HWND Dialog);
};
STATIC_ASSERT(sizeof(SelectTopicWindowData) == 0x18);

// 10
class SelectQuestWindowData
{
public:
	typedef tList<TESQuest>				QuestListT;

	// members
	/*00*/ TESQuest*					currentQuest;
	/*04*/ UInt8						unk04;
	/*05*/ UInt8						pad05[3];
	/*08*/ QuestListT					selectedQuests;		// the default selection is also passed in this member

	static SelectQuestWindowData**		Singleton;

	// method
	void								RefreshListView(HWND Dialog);
};
STATIC_ASSERT(sizeof(SelectQuestWindowData) == 0x10);

class RefSelectControl
{
public:
	typedef bool(__cdecl *Comparator)(TESObjectREFR*, void*);

	// 0C
	struct Params
	{

		// members
		/*00*/ TESObjectREFR*			defaultSelection;
		/*04*/ Comparator				refComparator;
		/*08*/ void*					userData;			// to be passed to the comparator
	};

	enum
	{
		kRefSelect_CellDropdown		= 2063,
		kRefSelect_RefDropdown		= 1983,
		kRefSelect_SelectRefButton	= 1982,
	};

	// 1C
	struct Data
	{
		// members
		/*00*/ HWND				parent;
		/*04*/ Comparator		refComparator;
		/*08*/ void*			userData;				// init to Param::userData
		/*0C*/ int				selectRefButtonID;
		/*10*/ int				cellComboBoxID;
		/*14*/ int				refComboBoxID;
		/*18*/ UInt8			allowNone;
		/*19*/ UInt8			pad19[3];
	};

	static TESObjectREFR*		ShowSelectReferenceDialog(HWND Parent, TESObjectREFR* DefaultSelection, bool OnlyPersistent);
};

// control IDs of listview controls that are populated with TESForm instances
enum
{
	kFormList_ObjectWindowObjects = 1041,
	kFormList_TESPackage = 1977,
	kFormList_CellViewCells = 1155,
	kFormList_CellViewRefs = 1156,
	kFormList_TESFormIDListView = 2064,
	kFormList_DialogEditorTopics = 1448,
	kFormList_DialogEditorTopicInfos = 1449,
	kFormList_DialogEditorAddedTopics = 1453,
	kFormList_DialogEditorLinkedToTopics = 1456,
	kFormList_DialogEditorLinkedFromTopics = 1455,
	kFormList_Generic = 1018,
	kFormList_TESContainer = 2035,
	kFormList_TESSpellList = 1485,
	kFormList_ActorFactions = 1088,
	kFormList_TESLeveledList = 2036,
	kFormList_WeatherSounds = 2286,
	kFormList_ClimateWeatherRaceHairFindTextTopics = 1019,
	kFormList_RaceEyes = 2163,
	kFormList_TESReactionForm = 1591,
	kFormList_FindTextTopicInfos = 1952,
	kFormList_LandTextures = 1492,
	kFormList_CrossReferences = 1637,
	kFormList_CellUseList = 1638,
};

enum
{
	kAssetFileButton_Model = 1043,		// includes idle animations and trees
	kAssetFileButton_Texture = 1044,
	kAssetFileButton_Sound = 1451,
	kAssetFileButton_Script = 1226,		// not really an asset (or a button) but meh
	kAssetFileButton_BipedModel_Male = 1045,
	kAssetFileButton_BipedModel_Female = 1046,
	kAssetFileButton_WorldModel_Male = 2088,
	kAssetFileButton_WorldModel_Female = 2091,
	kAssetFileButton_BipedIcon_Male = 2089,
	kAssetFileButton_BipedIcon_Female = 2092,
};

enum
{
	kFaceGenControl_AgeEditCtrl = 2117,
	kFaceGenControl_ComplexionEditCtrl = 2125,
	kFaceGenControl_HairLengthEditCtrl = 2127,
	kFaceGenControl_AdvancedEditCtrl = 2115,

	kFaceGenControl_PreviewCtrl = 2175,

	kFaceGenControl_AdvancedTrackbar = 2114,
	kFaceGenControl_AgeTrackbar = 2116,
	kFaceGenControl_ComplexionTrackbar = 2124,
	kFaceGenControl_HairLengthTrackbar = 2126,

	kFaceGenControl_AdvancedParamsListView = 1020,
};

class DataDialog
{
public:
	enum
	{
		kCtrlId_PluginFileList = 1056,
		kCtrlId_ParentMasterFileList = 1057,
	};

	static TESFile**				ActivePlugin;
	static TESFile**				CurrentSelection;
};



enum
{
	kDialogEditor_ResultScriptTextBox = 1444,
	kDialogEditor_CompileResultScriptButton = 1591,
};

enum
{
	kAboutDialog_LogoPictureControl = 1963,
	kAboutDialog_VersionLabel = 1580,
	kAboutDialog_CopyrightTextBox = 1000,
};

// container class
class TESDialog
{
public:
	enum
	{
		// CS Main Dialogs
		kDialogTemplate_SplashScreen = 235,
		kDialogTemplate_About = 100,
		kDialogTemplate_Temp = 102,
		kDialogTemplate_ObjectWindow = 122,
		kDialogTemplate_CellView = 175,
		kDialogTemplate_CellEdit = 125,
		kDialogTemplate_Data = 162,
		kDialogTemplate_Preferences = 169,
		kDialogTemplate_RenderWindow = 176,
		kDialogTemplate_PreviewWindow = 315,		// accessible through View > Preview Window
		kDialogTemplate_ScriptEdit = 188,
		kDialogTemplate_SearchReplace = 198,
		kDialogTemplate_LandscapeEdit = 203,
		kDialogTemplate_FindText = 233,
		kDialogTemplate_RegionEditor = 250,
		kDialogTemplate_HeightMapEditor = 295,
		kDialogTemplate_IdleAnimations = 302,
		kDialogTemplate_AIPackages = 303,
		kDialogTemplate_AdjustExteriorCells = 306,
		kDialogTemplate_OpenWindows = 307,
		kDialogTemplate_DistantLODExport = 317,
		kDialogTemplate_FilteredDialog = 3235,
		kDialogTemplate_CreateLocalMaps = 3249,
		kDialogTemplate_TextureUse = 316,

		// TESBoundObject/FormEdit Dialogs
		kDialogTemplate_Weapon = 135,
		kDialogTemplate_Armor = 136,
		kDialogTemplate_Clothing = 137,
		kDialogTemplate_MiscItem = 138,
		kDialogTemplate_Static = 140,
		kDialogTemplate_Reference = 141,
		kDialogTemplate_Apparatus = 143,
		kDialogTemplate_Book = 144,
		kDialogTemplate_Container = 145,
		kDialogTemplate_Activator = 147,
		kDialogTemplate_AIForm = 154,
		kDialogTemplate_Light = 156,
		kDialogTemplate_Potion = 165,
		kDialogTemplate_Enchantment = 166,
		kDialogTemplate_LeveledCreature = 168,
		kDialogTemplate_Sound = 190,
		kDialogTemplate_Door = 196,
		kDialogTemplate_LeveledItem = 217,
		kDialogTemplate_LandTexture = 230,
		kDialogTemplate_SoulGem = 261,
		kDialogTemplate_Ammo = 262,
		kDialogTemplate_Spell = 279,
		kDialogTemplate_Flora = 280,
		kDialogTemplate_Tree = 287,
		kDialogTemplate_CombatStyle = 305,
		kDialogTemplate_Water = 314,
		kDialogTemplate_NPC = 3202,
		kDialogTemplate_Creature = 3206,
		kDialogTemplate_Grass = 3237,
		kDialogTemplate_Furniture = 3239,
		kDialogTemplate_LoadingScreen = 3246,
		kDialogTemplate_Ingredient = 3247,
		kDialogTemplate_LeveledSpell = 3250,
		kDialogTemplate_AnimObject = 3251,
		kDialogTemplate_Subspace = 3252,
		kDialogTemplate_EffectShader = 3253,
		kDialogTemplate_SigilStone = 3255,

		// TESFormIDListView Dialogs
		kDialogTemplate_Faction = 157,
		kDialogTemplate_Race = 159,
		kDialogTemplate_Class = 160,
		kDialogTemplate_Skill = 161,
		kDialogTemplate_EffectSetting = 163,
		kDialogTemplate_GameSetting = 170,
		kDialogTemplate_Globals = 192,
		kDialogTemplate_Birthsign = 223,
		kDialogTemplate_Climate = 285,
		kDialogTemplate_Worldspace = 286,
		kDialogTemplate_Hair = 289,
		kDialogTemplate_Quest = 3225,
		kDialogTemplate_Eyes = 3228,
		kDialogTemplate_Weather = 308,

		// Misc Dialogs
		kDialogTemplate_StringEdit = 174,
		kDialogTemplate_SelectForm = 189,			// used by TESListBox
		kDialogTemplate_SoundPick = 195,
		kDialogTemplate_UseReport = 220,
		kDialogTemplate_DialogNameConflicts = 227,
		kDialogTemplate_Package = 243,
		kDialogTemplate_FileInUse = 244,
		kDialogTemplate_RegionSystemTester = 247,			// could be deprecated
		kDialogTemplate_EffectItem = 267,
		kDialogTemplate_TESFileDetails = 180,
		kDialogTemplate_SelectWorldspace = 291,
		kDialogTemplate_FunctionParams = 300,
		kDialogTemplate_ConfirmFormUserChanges = 301,
		kDialogTemplate_ClimateChanceWarning = 310,
		kDialogTemplate_Progress = 3166,
		kDialogTemplate_ChooseReference = 3224,
		kDialogTemplate_SelectTopic = 3226,
		kDialogTemplate_ResponseEditor = 3231,
		kDialogTemplate_SelectAudioFormat = 107,
		kDialogTemplate_SelectAudioCaptureDevice = 134,
		kDialogTemplate_SelectQuests = 3234,
		kDialogTemplate_SelectQuestsEx = 3236,
		kDialogTemplate_SoundRecording = 3241,

		// Subwindows
		kDialogTemplate_DialogData = 151,
		kDialogTemplate_AIPackageLocationData = 240,
		kDialogTemplate_AIPackageTargetData = 241,
		kDialogTemplate_AIPackageTimeData = 242,
		kDialogTemplate_RegionEditorWeatherData = 251,
		kDialogTemplate_RegionEditorObjectsData = 252,
		kDialogTemplate_RegionEditorGeneral = 253,
		kDialogTemplate_Reference3DData = 254,
		kDialogTemplate_RegionEditorMapData = 256,
		kDialogTemplate_ReferenceLockData = 257,
		kDialogTemplate_ReferenceTeleportData = 258,
		kDialogTemplate_ReferenceOwnershipData = 259,
		kDialogTemplate_ReferenceExtraData = 260,
		kDialogTemplate_IdleConditionData = 263,
		kDialogTemplate_RaceBodyData = 264,
		kDialogTemplate_RaceGeneral = 265,
		kDialogTemplate_RaceTextData = 266,
		kDialogTemplate_CellLightingData = 283,
		kDialogTemplate_CellGeneral = 284,
		kDialogTemplate_NPCStatsData = 288,
		kDialogTemplate_RegionEditorObjectsExtraData = 309,
		kDialogTemplate_WeatherGeneral = 311,
		kDialogTemplate_WeatherPecipitationData = 312,
		kDialogTemplate_WeatherSoundData = 313,
		kDialogTemplate_HeightMapEditorBrushData = 3167,			// doubtful
		kDialogTemplate_HeightMapEditorToolBar = 3169,
		kDialogTemplate_HeightMapEditorOverview = 3180,
		kDialogTemplate_HeightMapEditorPreview = 3193,
		kDialogTemplate_HeightMapEditorColorData = 3201,
		kDialogTemplate_ActorFactionData = 3203,
		kDialogTemplate_ActorInventoryData = 3204,
		kDialogTemplate_ActorSpellData = 3205,
		kDialogTemplate_CreatureStatsData = 3208,
		kDialogTemplate_RaceFactionReactionData = 3209,
		kDialogTemplate_PreferencesRenderWindow = 3210,
		kDialogTemplate_PreferencesMovement = 3211,
		kDialogTemplate_PreferencesMisc = 3212,
		kDialogTemplate_RegionEditorLandscapeData = 3214,
		kDialogTemplate_ActorAnimationData = 3215,
		kDialogTemplate_RaceFaceGenData = 3216,
		kDialogTemplate_CreatureModelData = 3219,
		kDialogTemplate_RegionEditorGrassData = 3220,
		kDialogTemplate_PreferencesShader = 3221,
		kDialogTemplate_PreferencesLOD = 3222,
		kDialogTemplate_ReferenceMapMarkerData = 3223,
		kDialogTemplate_QuestGeneral = 3227,
		kDialogTemplate_RaceFaceData = 3229,
		kDialogTemplate_PreferencesPreviewMovement = 3230,
		kDialogTemplate_ConditionData = 3232,
		kDialogTemplate_RegionEditorSoundData = 3233,
		kDialogTemplate_QuestStageData = 3240,
		kDialogTemplate_CreatureSoundData = 3242,
		kDialogTemplate_CellInteriorData = 3244,
		kDialogTemplate_QuestTargetData = 3245,
		kDialogTemplate_ReferenceSelectRefData = 3248,
		kDialogTemplate_CreatureBloodData = 3254,
		kDialogTemplate_NPCFaceData = 3218,
		kDialogTemplate_NPCFaceAdvancedData = 3256,
		kDialogTemplate_WeatherHDRData = 3257,
		kDialogTemplate_ReferenceLeveledCreatureData = 3259,

		// Deprecated
		kDialogTemplate_SelectModel = 110,
		kDialogTemplate_IngredientEx = 139,
		kDialogTemplate_AnimGroup = 155,
		kDialogTemplate_BodyPart = 153,
		kDialogTemplate_FactionRankDisposition = 158,
		kDialogTemplate_FindObject = 205,
		kDialogTemplate_PathGrid = 208,
		kDialogTemplate_JournalPreview = 222,
		kDialogTemplate_ExtDoorTeleport = 224,			// haven't seen it around
		kDialogTemplate_SoundGen = 228,
		kDialogTemplate_IntDoorTeleport = 229,			// same here
		kDialogTemplate_IntNorthMarker = 231,
		kDialogTemplate_VersionControl = 238,
		kDialogTemplate_VersionControlCheckInProbs = 255,
		kDialogTemplate_MemoryUsage = 304,
		kDialogTemplate_CreatureSoundEx = 3243,

		// Unknown
		kDialogTemplate_Progress3238 = 3238,			// could be version control/convert ESM for xBox tool related
		kDialogTemplate_Preview3258 = 3258,
		kDialogTemplate_Preview181 = 181,
	};

	enum
	{
		kStandardButton_Ok = 1,
		kStandardButton_Cancel = 2,
	};

	enum
	{
		kWindowMessage_HandleDragDrop = 0x407,		// lParam = POINT* mousePos
		kWindowMessage_Destroy = 0x417,
		kWindowMessage_Refresh = 0x41A,
	};

	// methods
	static UInt32							WriteBoundsToINI(HWND Handle, const char* WindowClassName);
	static bool								ReadBoundsFromINI(const char* WindowClassName, LPRECT OutRect);

	static UInt32							GetDialogTemplateForFormType(UInt8 FormTypeID);
	static BSExtraData*						GetDialogExtraByType(HWND Dialog, UInt16 Type);
	static TESForm*							GetDialogExtraParam(HWND Dialog);
	static TESForm*							GetDialogExtraLocalCopy(HWND Dialog);
	static bool								GetIsWindowDragDropRecipient(UInt16 FormType, HWND hWnd);

	static DLGPROC							GetFormEditDlgProc(TESForm* Form, bool& FormIDListViewForm);
	static bool								CallFormDialogMessageCallback(HWND hWnd, UINT uMsg, WPARAM wParam, LPARAM lParam, LONG* outLong);
	static HWND								GetActiveFormEditDialog(TESForm* Form);

	static bool								SelectTESFileCommonDialog(HWND Parent, const char* SaveDir, bool SaveAsESM, char* FileNameOut, size_t OutSize);
	static HWND								ShowFormEditDialog(TESForm* Form);
	static void								ShowScriptEditorDialog(TESForm* InitScript);
	static HWND								ShowUseReportDialog(TESForm* Form);

	static void								ResetFormListControls();

	static float							GetDlgItemFloat(HWND Dialog, int ID);
	static void								SetDlgItemFloat(HWND Dialog, int ID, float Value, int DecimalPlaces);
	static void								ClampDlgEditField(HWND EditControl, float Min, float Max, bool NoDecimals = false, UInt32 DecimalPlaces = 2);

	static void								ShowDialogPopupMenu(HMENU Menu, POINT* Coords, HWND Parent, LPARAM Data = NULL);
	static BaseExtraList*					GetDialogExtraDataList(HWND Dialog);
	static BaseExtraList*					CreateDialogExtraDataList(HWND Dialog);
	static void								DestroyDialogExtraDataList(HWND Dialog);

	static void								AddDialogToOpenList(HWND Dialog);
	static void								RemoveDialogFromOpenList(HWND Dialog);

	// Display an open/save file dialog.  relativePath is relative to Oblivion/ directory
	// returns false if canceled, or selected file is invalid
	static bool								ShowFileSelect(HWND parent, const char* relativePath, const char* filter,
												const char* title, const char* defaultExtension, LPOFNHOOKPROC proc,
												bool fileMustExist, bool saveVsOpen, char* filenameBuffer, UInt32 bufferSize);

	static tList<HWND>*						OpenDialogWindows;

	static UInt8*							ObjectWindowDragDropInProgress;
	static UInt8*							TESFormIDListViewDragDropInProgress;
	static bool								PackageCellDragDropInProgress;

	static void*							LandscapeTextureSortComparator;
};

class TESComboBox
{
public:
	// methods
	static void								AddItem(HWND hWnd, const char* Text, void* Data, bool ResizeDroppedWidth = true);
	static void*							GetSelectedItemData(HWND hWnd);
	static void								SetSelectedItemByData(HWND hWnd, void* Data);

	static void								PopulateWithForms(HWND hWnd, UInt8 FormType, bool ClearItems, bool AddDefaultItem);
	static void								ClearItems(HWND hWnd);
};

class TESListView
{
public:
	// methods
	static void								SetSelectedItem(HWND hWnd, int Index);
	static void*							GetSelectedItemData(HWND hWnd);
	static void*							GetItemData(HWND hWnd, int Index);
	static int								GetItemByData(HWND hWnd, void* Data);
	static void								ScrollToItem(HWND hWnd, int Index);
	static void								InsertItem(HWND hWnd, void* Data, bool ImageCallback = false, int Index = -1);
	static UInt32							GetSelectedItemCount(HWND hWnd);

	static void								AddColumnHeader(HWND hWnd, int Index, const char* Name, int Width, UInt32 Format = LVCFMT_LEFT);
	static void								ClearColumnHeaders(HWND hWnd);
	static void								ClearItems(HWND hWnd);
};

class TESTreeView
{
public:
	// methods
	static void*							GetItemData(HWND hWnd, HTREEITEM Item);
};

class TESTabControl
{
public:
	enum
	{
		kTabControl = 1777,
	};
};

class TESPreviewWindow
{
public:
	static void								Display(TESBoundObject* Object);

	// methods
	static void								SetSourceObject(TESBoundObject* Object);

	static void								HandleResize(HWND PreviewWindow);
	static void								Initialize(HWND PreviewWindow);
	static void								Deinitialize(HWND PreviewWindow);

	static HWND*							WindowHandle;
	static HWND*							AnimationListHandle;
	static TESPreviewControl**				PreviewControl;
	static DWORD*							InitialTickCount;
	static TESObjectREFR**					PreviewRef;
	static TESObjectSTAT**					PreviewStatic;

	static DLGPROC							DialogProc;

	enum
	{
		kAnimListCtrlID = 2408,
	};
};

// container class, arbitrarily named
class TESCSMain
{
public:
	static LRESULT							WriteToStatusBar(int PanelIndex, const char* Message);

	static void								InitializeCSWindows();
	static void								DeinitializeCSWindows();
	static void		 						SetTitleModified(bool State);
	static void								AutoSave();								// should probably be in TES/TESDataHandler
	static void								InvokeMainMenuTool(int Identifier);		// works with toolbar items too
	static bool								ConfirmUnsavedChanges();				// returns false if the confirmation was canceled or if the save operation failed

	static HINSTANCE*						Instance;
	static HWND*							WindowHandle;
	static HWND*							MainToolbarHandle;
	static HMENU*							MainMenuHandle;

	static char**							ActivePluginNameBuffer;
	static UInt8*							AllowAutoSaveFlag;
	static UInt8*							ExittingCSFlag;
	static UInt8*							UnsavedChangesFlag;

	static const char*						INIFilePath;
	static HIMAGELIST*						BoundObjectIcons;
	static char**							FileSelectionBuffer;
	static char*							ProfileFolderPath;

	enum
	{
		kMainMenu_World_EditCellPathGrid = 40194,
		kMainMenu_View_PreviewWindow = 40121,
		kMainMenu_Help_Contents = 40157,
		kMainMenu_Character_ExportDialogue = 40413,
		kMainMenu_View_CellViewWindow = 40200,
		kMainMenu_View_RenderWindow = 40423,
		kMainMenu_View_ObjectWindow = 40199,
		kMainMenu_View_Sky = 40223,
		kMainMenu_Edit_SearchReplace = 40179,
	};

	enum
	{
		kTimer_Autosave = 2,

		kToolbar_PathGridEdit = 40195,
		kToolbar_DataFiles = 40145,
		kToolbar_Save = 40146,

		kWindowMessage_Unk413 = 0x413,	// appears to be used in some of the older dialog windows (from the Morrowind codebase) too, probably has something to do with loading
		kWindowMessage_Save = 0x40C,
	};
};

// container class, arbitrarily named
class TESObjectWindow
{
public:
	enum
	{
		kWindowMessage_Reload = 0x412,
	};


	// 14
	class TreeEntryInfo
	{
	public:
		typedef tList<TESForm> FormListT;

		// members
		/*00*/ UInt8         formType;           // form type for this tree entry
		/*01*/ UInt8         pad01[3];
		/*04*/ UInt32        columnCount;        // number of columns in listview
		/*08*/ UInt32        selectedIndex;      // index of currently selected item in listview (??)
		/*0C*/ FormListT     formList;

		static const UInt32		kTreeEntryCount = 0x24; // size of static tree entry arrays
	};
	STATIC_ASSERT(sizeof(TreeEntryInfo) == 0x14);

	// 210
	struct TreeViewItemData
	{
		enum
		{
			kGroup_Actors = 0,
			kGroup_Items,
			kGroup_Magic,
			kGroup_WorldObjects,
			kGroup_Miscellaneous,

			kGroup__MAX
		};

		enum
		{
			kType_Activator = 0,
			kType_Apparatus,
			kType_Armor,
			kType_Book,
			kType_Clothing,
			kType_Container,
			kType_Door,
			kType_Ingredient,
			kType_Light,
			kType_MiscItem,
			kType_Static,
			kType_Grass,
			kType_Tree,
			kType_Weapon,
			kType_NPC,
			kType_Creature,
			kType_LeveledCreature,
			kType_Spell,
			kType_Enchantment,
			kType_Potion,
			kType_LeveledItem,
			kType_Key,
			kType_SoulGem,
			kType_Ammo,
			kType_Flora,
			kType_Furniture,
			kType_Sound,
			kType_LandTexture,
			kType_CombatStyle,
			kType_LoadScreen,
			kType_LeveledSpell,
			kType_AnimObject,
			kType_WaterType,
			kType_SubSpace,
			kType_EffectShader,
			kType_SigilStone,

			kType__MAX
		};

		// members
		/*000*/ SInt32		type;						// one of the above IDs, -1 for groups
		/*004*/ UInt32		group;						// parent group ID
		/*008*/ char		hierarchy[MAX_PATH];		// path to the item in the tree view hierarchy, including the item name
														// only filled for items with depth > 2
		/*10C*/ char		name[MAX_PATH];				// display name
	};
	STATIC_ASSERT(sizeof(TreeViewItemData) == 0x210);

	// stored as the splitter control's userdata
	// 1C
	class SplitterData
	{
	public:
		// members
		/*00*/ HWND         treeView;
		/*04*/ HWND			listView;
		/*08*/ HWND			parent;				// object window
		/*0C*/ WNDPROC		orgWndProc;
		/*10*/ UInt8		mouseOver;			// set when the cursor is over the splitter control
		/*11*/ UInt8		performingDrag;
		/*12*/ UInt8		enabled;			// disables all message processing when not set
		/*13*/ UInt8		pad13;
		/*14*/ POINT		dragOrigin;			// buffer used to store the coords of the cursor during a drag op
	};
	STATIC_ASSERT(sizeof(SplitterData) == 0x1C);

	// column indices for the formlist
	enum
	{
		kColumn_EditorID	= 0,
		kColumn_FormID,
		kColumn_Count,
		kColumn_Users,			// not handled by the vanilla sort comparator
		kColumn_Model,
		kColumn_Size,
		kColumn_Name,
		kColumn_Race,
		kColumn_Class,
		kColumn_Faction,
		kColumn_Script,
		kColumn_Rank,
		kColumn_Type,
		kColumn_Weight,
		kColumn_Value,
		kColumn_Health,
		kColumn_Quality,
		kColumn_Icon,
		kColumn_Enchantment,
		kColumn_Rating,
		kColumn_Speed,
		kColumn_Reach,
		kColumn_AttackDamage,
		kColumn_IgnoresResist,
		kColumn_Part,			// not handled by the vanilla sort comparator
		kColumn_Female,
		kColumn_Scroll,
		kColumn_Teaches,
		kColumn_Level,
		kColumn_Effect1,
		kColumn_Effect2,
		kColumn_Effect3,
		kColumn_Effect4,
		kColumn_Time,
		kColumn_Radius,
		kColumn_Uses,
		kColumn_Cost,
		kColumn_Animation,
		kColumn_LeveledList,
		kColumn_Inventory,
		kColumn_Enchanting,
		kColumn_Playable,		// not handled by the vanilla sort comparator
		kColumn_Charge,
		kColumn_WeightClass,
		kColumn_AutoCalc,
		kColumn_Essential,
		kColumn_Respawns,
		kColumn_MovementType,
		kColumn_WeaponShield,
		kColumn_BipedAnim,
		kColumn_AllPC,
		kColumn_QuestObject,
		kColumn_PCStartSpell,
		kColumn_Sound,
		kColumn_Texture,		// not handled by the vanilla sort comparator
		kColumn_LevelSchool,
		kColumn_Poison,
		kColumn_FlickerEffect,
		kColumn_Material,
		kColumn_IdleAnim,
		kColumn_OpenSound,
		kColumn_CloseSound,
		kColumn_Text,

		kColumn__MAX
	};

	static void						RefreshFormList(void);
	static void						InitializeSplitter(HWND Splitter, HWND TreeView, HWND ListView);
	static void						SetSplitterEnabled(HWND Splitter, bool State);
	static bool						GetMinimized(void);
	static HTREEITEM				LookupTreeItemByData(HWND TreeView, HTREEITEM SearchStartItem, SInt32 TreeItemType, UInt32 TreeItemGroup, const char* TreeItemHierachy);

	// object window imposter wrappers
	// caches must point to the calling imposter's child controls
	static void						PerformLimitedInit(HWND ObjectWindow);
	static void						PerformLimitedDeinit(HWND ObjectWindow);
	static void						UpdateTreeChildren(HWND ObjectWindow);

	// caches used by the object window, and to a lesser extent, other dialogs
	static HWND*					WindowHandle;
	static HWND*					FormListHandle;
	static HWND*					TreeViewHandle;
	static HWND*					SplitterHandle;

	static UInt8*					Initialized;			// set when the window is created and initialized
	static UInt32*					CurrentTreeNodeType;	// TreeViewItemData::type the current tree view selection, used with the tree entry and sort column arrays
	static int*						SortColumnArray;
	static TreeEntryInfo**			TreeEntryArray;

	static DLGPROC					DialogProc;
	enum
	{
		kFormListCtrlID = 1041,
		kTreeViewCtrlID = 2093,
		kSplitterCtrlID = 2157,
	};

	static HWND						PrimaryObjectWindowHandle;			// always points to the main object window instance
};

// container class, arbitrarily named
class TESCellViewWindow
{
public:
	static void						SetCellSelection(TESObjectCELL* Cell);
	static void						RefreshObjectList(void);
	static void						RefreshCellList(bool RefreshWorldspaces = false);
	static void						UpdateCurrentWorldspace();
	static void						SetCurrentCell(Vector3* Position, bool ReloadObjectList);
	static TESWorldSpace*			GetCurrentWorldSpace();
	static bool						CellListNeedsUpdate(Vector3* TargetCoords = nullptr);

	static void						OnSelectCellListItem(TESObjectCELL* ItemCell, bool ClearRenderWindowSelection);

	static HWND*					WindowHandle;
	static HWND*					ObjectListHandle;
	static HWND*					CellListHandle;

	static UInt8*					MainMenuState;
	static TESObjectCELL**			CurrentCellSelection;
	static int*						ObjectListSortColumn;
	static int*						CellListSortColumn;

	enum
	{
		kWorldspaceLabel = 1164,
		kWorldspaceComboBox = 2083,
		kCellLabel = 1163,
		kCellListView = 1155,
		kObjectRefListView = 1156,
	};

	enum
	{
		kWindowMessage_ReloadWorldspacesAndCells	= 0x40E,		// wParam - reload worldspaces, lParam - don't reload cells
		kWindowMessage_ReloadObjects				= 0x40F,
	};
};

// 18
class TESObjectSelection
{
public:
	// 0C
	struct SelectedObjectsEntry
	{
		/*00*/ TESForm*					Data;
		/*08*/ SelectedObjectsEntry*	Prev;
		/*0C*/ SelectedObjectsEntry*	Next;
	};

	// members
	/*00*/ SelectedObjectsEntry*		selectionList;
	/*04*/ UInt32						selectionCount;
	/*08*/ Vector3						selectionPositionVectorSum;
	/*14*/ float						selectionBounds;						// init to 0.0

	// methods
	void								AddToSelection(TESForm* Form, bool AddSelectionBox = false);
	void								RemoveFromSelection(TESForm* Form, bool RemoveSelectionBox = false);
	void								ClearSelection(bool RemoveSelectionBox = false);
	void								CalculatePositionVectorSum(void);
	bool								HasObject(TESForm* Form);
	void								CalculateBounds(void);

	static TESObjectSelection*			CreateInstance(TESObjectSelection* Source = nullptr);
	void								DeleteInstance();

	static TESObjectSelection**			PrimaryInstance;
};
STATIC_ASSERT(sizeof(TESObjectSelection) == 0x18);

typedef TESObjectSelection		TESRenderSelection;

#define _PRIMARYOBJSEL			(*TESObjectSelection::PrimaryInstance)
#define _RENDERSEL				(*TESObjectSelection::PrimaryInstance)

// container class, arbitrarily named
class TESFileFormListWindow
{
public:
	static void					Show(HWND Parent, TESFile* File);
};

// 4024
class TESSliderControl
{
	// 40
	struct CustomLabel
	{
		/*00*/ char				value[0x40];
	};

	enum
	{
		kLabelType_Integer	= 0,
		kLabelType_Float	= 1,
		kLabelType_Custom	= 2,
	};

	// members
	/*0000*/ HWND				dialog;
	/*0004*/ HWND				slider;
	/*0008*/ int				sliderID;
	/*000C*/ int				labelID;
	/*0010*/ UInt32				labelType;
	/*0014*/ UInt8				numericalValue;		// set to 1 when the value is calculated from the min/max values
	/*0015*/ CustomLabel		labelValues[0x100];	// for each slider position/value
	/*4015*/ UInt8				pad4015[3];
	/*4018*/ float				minValue;
	/*401C*/ float				maxValue;
	/*4020*/ UInt8				decimalPlaces;		// when calculating the label text from the mix/max values
	/*4021*/ UInt8				pad4021[3];
};
STATIC_ASSERT(sizeof(TESSliderControl) == 0x4024);