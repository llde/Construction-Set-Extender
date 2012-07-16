#include "UseInfoList.h"
#include "[Common]\ListViewUtilities.h"
#include "[Common]\HandshakeStructs.h"
#include "[Common]\NativeWrapper.h"

namespace ConstructionSetExtender
{
	UseInfoList^% UseInfoList::GetSingleton()
	{
		if (Singleton == nullptr)
		{
			Singleton = gcnew UseInfoList();
		}
		return Singleton;
	}

	UseInfoList::UseInfoList()
	{
		Application::EnableVisualStyles();
		FormList = (gcnew ListView());
		FormListCType = (gcnew ColumnHeader());
		FormListCEditorID = (gcnew ColumnHeader());
		FormListCFormID = (gcnew ColumnHeader());
		UseListObject = (gcnew ListView());
		UseListObjectCType = (gcnew ColumnHeader());
		UseListObjectCEditorID = (gcnew ColumnHeader());
		UseListObjectCFormID = (gcnew ColumnHeader());
		UseListObjectGroup = (gcnew GroupBox());
		UseListCellGroup = (gcnew GroupBox());
		UseListCell = (gcnew ListView());
		UseListCellCWorldEditorID = (gcnew ColumnHeader());
		UseListCellCCellFormID = (gcnew ColumnHeader());
		UseListCellCCellEditorID = (gcnew ColumnHeader());
		UseListCellCCellGrid = (gcnew ColumnHeader());
		UseListCellCUseCount = (gcnew ColumnHeader());
		UseListCellCFirstRef = (gcnew ColumnHeader());
		SearchBox = (gcnew TextBox());
		ExportDataButton = (gcnew Button());

		FormList->Columns->AddRange(gcnew cli::array< ColumnHeader^  >(3) {this->FormListCType, this->FormListCEditorID,
			FormListCFormID});
		FormList->Location = System::Drawing::Point(12, 12);
		FormList->Name = L"FormList";
		FormList->Size = System::Drawing::Size(340, 394);
		FormList->TabIndex = 0;
		FormList->UseCompatibleStateImageBehavior = false;
		FormList->View = View::Details;
		FormList->MultiSelect = false;
		FormList->CheckBoxes = false;
		FormList->FullRowSelect = true;
		FormList->HideSelection = false;
		FormList->SelectedIndexChanged += gcnew EventHandler(this, &UseInfoList::FormList_SelectedIndexChanged);
		FormList->KeyDown += gcnew KeyEventHandler(this, &UseInfoList::FormList_KeyDown);
		FormList->ColumnClick += gcnew ColumnClickEventHandler(this, &UseInfoList::FormList_ColumnClick);
		FormList->MouseUp += gcnew MouseEventHandler(this, &UseInfoList::FormList_MouseUp);
		FormList->MouseDoubleClick += gcnew MouseEventHandler(this, &UseInfoList::FormList_MouseDoubleClick);

		FormListCType->Text = L"Type";
		FormListCType->Width = 46;

		FormListCEditorID->Text = L"Editor ID";
		FormListCEditorID->Width = 167;

		FormListCFormID->Text = L"Form ID";
		FormListCFormID->Width = 121;

		UseListObject->Columns->AddRange(gcnew cli::array< ColumnHeader^  >(3) {this->UseListObjectCType,
			UseListObjectCEditorID, this->UseListObjectCFormID});
		UseListObject->Location = System::Drawing::Point(6, 19);
		UseListObject->Name = L"UseListObject";
		UseListObject->Size = System::Drawing::Size(355, 190);
		UseListObject->TabIndex = 1;
		UseListObject->UseCompatibleStateImageBehavior = false;
		UseListObject->View = View::Details;
		UseListObject->MultiSelect = false;
		UseListObject->CheckBoxes = false;
		UseListObject->FullRowSelect = true;
		UseListObject->HideSelection = false;
		UseListObject->MouseDoubleClick += gcnew MouseEventHandler(this, &UseInfoList::UseListObject_MouseDoubleClick);

		UseListObjectCType->Text = L"Type";

		UseListObjectCEditorID->Text = L"Editor ID";

		UseListObjectCFormID->Text = L"Form ID";

		UseListObjectGroup->Controls->Add(this->UseListObject);
		UseListObjectGroup->Location = System::Drawing::Point(365, 12);
		UseListObjectGroup->Name = L"UseListObjectGroup";
		UseListObjectGroup->Size = System::Drawing::Size(367, 215);
		UseListObjectGroup->TabIndex = 2;
		UseListObjectGroup->TabStop = false;
		UseListObjectGroup->Text = L"Used by these objects";

		UseListCellGroup->Controls->Add(this->UseListCell);
		UseListCellGroup->Location = System::Drawing::Point(365, 234);
		UseListCellGroup->Name = L"UseListCellGroup";
		UseListCellGroup->Size = System::Drawing::Size(367, 215);
		UseListCellGroup->TabIndex = 3;
		UseListCellGroup->TabStop = false;
		UseListCellGroup->Text = L"Used in these cells";

		UseListCell->Columns->AddRange(gcnew cli::array< ColumnHeader^  >(6) {this->UseListCellCWorldEditorID,
			UseListCellCCellFormID, this->UseListCellCCellEditorID, this->UseListCellCCellGrid, UseListCellCFirstRef, this->UseListCellCUseCount});
		UseListCell->Location = System::Drawing::Point(6, 19);
		UseListCell->Name = L"UseListCell";
		UseListCell->Size = System::Drawing::Size(355, 190);
		UseListCell->TabIndex = 1;
		UseListCell->UseCompatibleStateImageBehavior = false;
		UseListCell->View = View::Details;
		UseListCell->MultiSelect = false;
		UseListCell->CheckBoxes = false;
		UseListCell->FullRowSelect = true;
		UseListCell->HideSelection = false;
		UseListCell->MouseDoubleClick += gcnew MouseEventHandler(this, &UseInfoList::UseListCell_MouseDoubleClick);

		UseListCellCWorldEditorID->Text = L"World Editor ID";
		UseListCellCWorldEditorID->Width = 104;

		UseListCellCCellFormID->Text = L"Cell Form ID";
		UseListCellCCellFormID->Width = 5;

		UseListCellCCellEditorID->Text = L"Cell Editor ID";
		UseListCellCCellEditorID->Width = 112;

		UseListCellCCellGrid->Text = L"Cell Grid";

		UseListCellCUseCount->Text = L"Use Count";
		UseListCellCUseCount->Width = 69;

		UseListCellCFirstRef->Text = L"First Reference";
		UseListCellCFirstRef->Width = 100;

		SearchBox->Location = System::Drawing::Point(12, 419);
		SearchBox->MaxLength = 100;
		SearchBox->Multiline = true;
		SearchBox->Name = L"SearchBox";
		SearchBox->Size = System::Drawing::Size(340, 29);
		SearchBox->TabIndex = 4;
		SearchBox->TextChanged += gcnew EventHandler(this, &UseInfoList::SearchBox_TextChanged);
		SearchBox->KeyDown += gcnew KeyEventHandler(this, &UseInfoList::SearchBox_KeyDown);
		SearchBox->Font = gcnew Font("Consolas", 14.25F, FontStyle::Regular);

		ExportDataButton->Visible = false;
		ExportDataButton->Location = System::Drawing::Point(253, 419);
		ExportDataButton->Size = System::Drawing::Size(98, 29);
		ExportDataButton->TabIndex = 5;
		ExportDataButton->Text = L"Export To CSV";
		ExportDataButton->UseVisualStyleBackColor = true;
		ExportDataButton->Click += gcnew EventHandler(this, &UseInfoList::ExportDataButton_Click);

		UseInfoListBox = gcnew Form();
		UseInfoListBox->AutoScaleDimensions = System::Drawing::SizeF(6, 13);
		UseInfoListBox->AutoScaleMode = AutoScaleMode::Font;
		UseInfoListBox->ClientSize = System::Drawing::Size(744, 461);
		UseInfoListBox->Controls->Add(ExportDataButton);
		UseInfoListBox->Controls->Add(SearchBox);
		UseInfoListBox->Controls->Add(UseListCellGroup);
		UseInfoListBox->Controls->Add(FormList);
		UseInfoListBox->Controls->Add(UseListObjectGroup);
		UseInfoListBox->FormBorderStyle = FormBorderStyle::FixedSingle;
		UseInfoListBox->MaximizeBox = false;
		UseInfoListBox->StartPosition = FormStartPosition::CenterScreen;
		UseInfoListBox->Text = L"Centralized Use Info Listing";
		UseInfoListBox->Closing += gcnew CancelEventHandler(this, &UseInfoList::UseInfoListBox_Cancel);
		UseInfoListBox->KeyPress += gcnew KeyPressEventHandler(this, &UseInfoList::UseInfoListBox_KeyPress);
		UseInfoListBox->KeyDown += gcnew KeyEventHandler(this, &UseInfoList::UseInfoListBox_KeyDown);
		UseInfoListBox->KeyPreview = true;

		UseInfoListBox->Hide();
		LastSortColumn = -1;
	}

	void UseInfoList::UseInfoListBox_Cancel(Object^ Sender, CancelEventArgs^ E)
	{
		Close();
		E->Cancel = true;
	}

	void UseInfoList::UseInfoListBox_KeyDown(Object^ Sender, KeyEventArgs^ E)
	{
		switch (E->KeyCode)
		{
		case Keys::Back:
			if (SearchBox->Text->Length >= 1)
			{
				SearchBox->Text = SearchBox->Text->Remove(SearchBox->Text->Length - 1);
				FormList->Focus();
			}

			E->Handled = true;
			break;
		}
	}

	void UseInfoList::UseInfoListBox_KeyPress(Object^ Sender, KeyPressEventArgs^ E)
	{
		if ((E->KeyChar > 0x29 && E->KeyChar < 0x3A) ||
			(E->KeyChar > 0x60 && E->KeyChar < 0x7B))
		{
			SearchBox->Text += E->KeyChar.ToString();
			FormList->Focus();
			E->Handled = true;
		}
	}

	void UseInfoList::ClearLists()
	{
		UseListCell->Items->Clear();
		UseListObject->Items->Clear();
	}

	void UseInfoList::Close()
	{
		SearchBox->Text = "";
		UseInfoListBox->Hide();
	}

	void UseInfoList::Open(const char* FilterString)
	{
		if (UseInfoListBox->Visible)
		{
			UseInfoListBox->Focus();
		}
		else
		{
			ClearLists();
			PopulateFormList();
			UseInfoListBox->Show();
			UseInfoListBox->Focus();
		}

		if (FilterString)
			SearchBox->Text = gcnew String(FilterString);
	}

	void UseInfoList::PopulateFormList()
	{
		FormList->Items->Clear();
		FormList->BeginUpdate();

		ComponentDLLInterface::UseInfoListFormData* Data = NativeWrapper::g_CSEInterfaceTable->UseInfoList.GetLoadedForms();
		if (Data)
		{
			for (int i = 0; i < Data->FormCount; i++)
			{
				ComponentDLLInterface::FormData* ThisForm = &Data->FormListHead[i];

				ListViewItem^ Item = gcnew ListViewItem(TypeIdentifier[(int)ThisForm->TypeID]);
				Item->SubItems->Add(gcnew String(ThisForm->EditorID));
				Item->SubItems->Add(ThisForm->FormID.ToString("X8"));

				FormList->Items->Add(Item);
			}
		}
		NativeWrapper::g_CSEInterfaceTable->DeleteNativeHeapPointer(Data, false);
		FormList->EndUpdate();
	}

	void UseInfoList::PopulateUseLists(const char* EditorID)
	{
		ClearLists();

		UseListObject->BeginUpdate();
		ComponentDLLInterface::UseInfoListCrossRefData* Data = NativeWrapper::g_CSEInterfaceTable->UseInfoList.GetCrossRefDataForForm(EditorID);
		if (Data)
		{
			for (int i = 0; i < Data->FormCount; i++)
			{
				ComponentDLLInterface::FormData* ThisForm = &Data->FormListHead[i];

				ListViewItem^ Item = gcnew ListViewItem(TypeIdentifier[(int)ThisForm->TypeID]);
				Item->SubItems->Add(gcnew String(ThisForm->EditorID));
				Item->SubItems->Add(ThisForm->FormID.ToString("X8"));

				UseListObject->Items->Add(Item);
			}
		}
		NativeWrapper::g_CSEInterfaceTable->DeleteNativeHeapPointer(Data, false);
		UseListObject->EndUpdate();

		UseListCell->BeginUpdate();
		ComponentDLLInterface::UseInfoListCellItemListData* DataEx = NativeWrapper::g_CSEInterfaceTable->UseInfoList.GetCellRefDataForForm(EditorID);
		if (Data)
		{
			for (int i = 0; i < DataEx->UseInfoListCellItemListCount; i++)
			{
				ComponentDLLInterface::UseInfoListCellItemData* ThisForm = &DataEx->UseInfoListCellItemListHead[i];

				ListViewItem^ Item = gcnew ListViewItem(gcnew String(ThisForm->WorldEditorID));
				Item->SubItems->Add(ThisForm->FormID.ToString("X8"));
				Item->SubItems->Add(gcnew String(ThisForm->EditorID));
				Item->SubItems->Add(((!ThisForm->Flags)?String::Format("{0}, {1}", ThisForm->XCoord, ThisForm->YCoord):"Interior"));
				Item->SubItems->Add(gcnew String(ThisForm->RefEditorID));
				Item->SubItems->Add(ThisForm->UseCount.ToString());

				UseListCell->Items->Add(Item);
			}
		}
		NativeWrapper::g_CSEInterfaceTable->DeleteNativeHeapPointer(Data, false);
		UseListCell->EndUpdate();
	}

	void UseInfoList::FormList_SelectedIndexChanged(Object^ Sender, EventArgs^ E)
	{
		if (GetListViewSelectedItem(FormList) == nullptr)
			return;

		CString CEID(GetListViewSelectedItem(FormList)->SubItems[1]->Text);
		PopulateUseLists(CEID.c_str());
	}

	void UseInfoList::FormList_KeyDown(Object^ Sender, KeyEventArgs^ E)
	{
		switch (E->KeyCode)
		{
		case Keys::Escape:
			UseInfoListBox->Close();
			break;
		}
	}

	void UseInfoList::FormList_MouseUp(Object^ Sender, MouseEventArgs^ E)
	{
		;//
	}

	void UseInfoList::FormList_ColumnClick(Object^ Sender, ColumnClickEventArgs^ E)
	{
		if (E->Column != LastSortColumn)
		{
			LastSortColumn = E->Column;
			FormList->Sorting = SortOrder::Ascending;
		}
		else
		{
			if (FormList->Sorting == SortOrder::Ascending)
				FormList->Sorting = SortOrder::Descending;
			else
				FormList->Sorting = SortOrder::Ascending;
		}

		FormList->Sort();
		System::Collections::IComparer^ Sorter;
		switch (E->Column)
		{
		case 2:							// FormID
			Sorter = gcnew ListViewIntSorter(E->Column, FormList->Sorting, true);
			break;
		default:
			Sorter = gcnew ListViewStringSorter(E->Column, FormList->Sorting);
			break;
		}
		FormList->ListViewItemSorter = Sorter;
	}

	void UseInfoList::SearchBox_TextChanged(Object^ Sender, EventArgs^ E)
	{
		if (SearchBox->Text != "")
		{
			ListViewItem^% Result = FormList->FindItemWithText(SearchBox->Text, true, 0, true);

			if (Result != nullptr)
			{
				Result->Selected = true;
				FormList->TopItem = Result;
			}
			else
			{
				Result = GetListViewSelectedItem(FormList);
				if (Result != nullptr)
					Result->Selected = false;
			}
		}
	}

	void UseInfoList::SearchBox_KeyDown(Object^ Sender, KeyEventArgs^ E)
	{
		UseInfoList::FormList_KeyDown(nullptr, E);
	}

	void UseInfoList::FormList_MouseDoubleClick(Object^ Sender, MouseEventArgs^ E)
	{
		if (GetListViewSelectedItem(FormList) == nullptr)
			return;

		CString CEID(GetListViewSelectedItem(FormList)->SubItems[1]->Text);

		NativeWrapper::g_CSEInterfaceTable->EditorAPI.LoadFormForEdit(CEID.c_str());
	}

	void UseInfoList::UseListObject_MouseDoubleClick(Object^ Sender, MouseEventArgs^ E)
	{
		if (GetListViewSelectedItem(UseListObject) == nullptr)
			return;

		CString CEID(GetListViewSelectedItem(UseListObject)->SubItems[1]->Text);

		NativeWrapper::g_CSEInterfaceTable->EditorAPI.LoadFormForEdit(CEID.c_str());
	}

	void UseInfoList::UseListCell_MouseDoubleClick(Object^ Sender, MouseEventArgs^ E)
	{
		if (GetListViewSelectedItem(UseListCell) == nullptr)
			return;

		if (GetListViewSelectedItem(UseListCell)->SubItems[4]->Text != "<Unnamed>")
		{
			CString CEID(GetListViewSelectedItem(UseListCell)->SubItems[4]->Text);
			NativeWrapper::g_CSEInterfaceTable->EditorAPI.LoadFormForEdit(CEID.c_str());
		}
	}

	void UseInfoList::ExportDataButton_Click( Object^ Sender, EventArgs^ E )
	{
		ExportListData();
	}

	void UseInfoList::ExportListData( void )
	{
		;//
	}
}