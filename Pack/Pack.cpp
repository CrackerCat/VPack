
#include "stdafx.h"
#include "Pack.h"

VPack::VPack()
{
	stcStub = { 0 };
	hFile = NULL;

	//����Ĭ�ϲ���
	dwKey = 0x15;
	pTextSecName = ".VPack";
	pRelocSecName = ".Vreloc";
	nSrcFileSize = 0;

	pStrFileData = nullptr;

	pDos = nullptr;
	pNt = nullptr;
	pFile = nullptr;
	pOpt = nullptr;
	pDataDir = nullptr;
}

VPack::~VPack()
{
	//�ͷ��������ݻ���
	if (!pStrFileData)
	{
		delete[] pStrFileData;
		pStrFileData = nullptr;

		pDos = nullptr;
		pNt = nullptr;
		pFile = nullptr;
		pOpt = nullptr;
		pDataDir = nullptr;
	}
}

//�ӿ�������
bool VPack::Packing(_In_ const char* pFilePath)
{
	//���ļ�	;
	if (!GetFileData(pFilePath))
	{
		DBGINFO("�������ļ�ʧ��\n");
		return false;
	}
	//����Ƿ���ЧPE�ļ�
	if (!CheckPE())
	{
		DBGINFO("��ѡ����Ч����\n");
		return false;
	}

	//��ȡoep����Ϣ
	GetPEInfo();

	//���浼���
	SaveImport();

	//���IAT
	ClsIAT();

	//����α���
	EncodeData();

	//�������
	dwPackSecRVA=AddNewSection(pStrFileData, pTextSecName, stcStub.dwTextDataSize,0xE00000E0);

	GetTLS();

	//���Stub�ض�λ����
	AddNewSection(pStrFileData, pRelocSecName, stcStub.dwRelocDataSize,0x42000040);

	//�޸�Stub�ض�λ����
	RelocStub(stcStub.pStubData, pOpt->ImageBase, GetSectionHeader(pStrFileData, pTextSecName)->VirtualAddress);

	//�޸�OEPָ��Stub
	SetNewOEP();

	//����ļ�
	if (!SaveFile(pFilePath))
	{
		DBGINFO("����ӿ��ļ�ʧ��\n");
		return false;
	}

	return true;
}

//�����ļ�
bool VPack::SaveFile(_In_ const char* pFilePath)
{
	//����·��
	char *pNewFilePath = new char[MAX_PATH];
	char *pPack = "[VPack].exe";
	//����·��
	strcpy_s(pNewFilePath, MAX_PATH, pFilePath);
	//ȥ����׺��
	int nLen = strlen(pFilePath);
	pNewFilePath[nLen - 4] = '\0';
	//ƴ������
	strcat_s(pNewFilePath, MAX_PATH, pPack);

	//�����ļ�
	FILE* pFile = NULL;

	if (fopen_s(&pFile, pNewFilePath, "wb"))
	{
		DBGINFO("�����ļ�ʧ��\n");
		return false;
	}
	//д��������Ϣ
	fwrite(pStrFileData, 1, nSrcFileSize, pFile);

	//�����ļ�ָ��
	fseek(pFile, GetSectionHeader(pStrFileData, pTextSecName)->PointerToRawData, SEEK_SET);
	//д��stubText
	fwrite(stcStub.pTextData, 1, stcStub.dwTextDataSize, pFile);

	//�����ļ�ָ��
	fseek(pFile, GetSectionHeader(pStrFileData, pRelocSecName)->PointerToRawData, SEEK_SET);
	//д��stubText
	fwrite(stcStub.pRelocData, 1, stcStub.dwRelocDataSize, pFile);

	fclose(pFile);

	delete[] pNewFilePath;

	return true;
}

//���浼���
bool VPack::SaveImport()
{	
	//�ж��Ƿ���ڵ����
	if (!pDataDir[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress)
	{
		stcStub.pPackConf->dwImportRva = 0;
		return false;
	}		
	
	//��ȡĿ¼��FOA
	DWORD dwDirFO = RVA2FO(pDataDir[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress, pNt);
	stcStub.pPackConf->dwImportRva = pDataDir[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
	//��ȡ�����FOA
	PIMAGE_IMPORT_DESCRIPTOR pImport = (PIMAGE_IMPORT_DESCRIPTOR)(pStrFileData + dwDirFO);
	
	DWORD dwNumber = 0;

	//������ģ��
	while (pImport->Name)
	{
		//��ȡDLL����
		char *DllName = (CHAR*)(pStrFileData + RVA2FO(pImport->Name, pNt));

		//��ȡINT
		PIMAGE_THUNK_DATA32 pThunkINT= (PIMAGE_THUNK_DATA32)
			(pStrFileData+RVA2FO(pImport->OriginalFirstThunk, pNt));	

		//�޸��ڴ�����
		DWORD dwOldProt = 0;
		VirtualProtect((LPVOID)(pThunkINT), 1, PAGE_READWRITE, &dwOldProt);

		//�ڴ����ģ���к���
		while (pThunkINT->u1.AddressOfData)
		{
			//�������
			if (IMAGE_SNAP_BY_ORDINAL32(pThunkINT->u1.Ordinal))
			{
				//�����������
				pThunkINT->u1.Ordinal;
			}
			//��������
			else
			{
				//��ȡ��������
				PIMAGE_IMPORT_BY_NAME pName = (PIMAGE_IMPORT_BY_NAME)
					(pStrFileData +	RVA2FO(pThunkINT->u1.AddressOfData, pNt));
				//����Hash
				DWORD dwHash=FunHash(pName->Name);
				//����Hash
				pThunkINT->u1.AddressOfData = dwHash;
				//��պ�������
				memset(pName->Name, 0, strlen(pName->Name));
			}
			//��һ��INT			
			pThunkINT++;

			//��ȡ��������
			dwNumber++;
		}

		//�ָ��ڴ�����
		VirtualProtect((LPVOID)(pThunkINT), 1, dwOldProt, &dwOldProt);

		//��һ�������
		pImport++;
	}

	//���溯������
	stcStub.pPackConf->dwNumberFun = dwNumber;

	//���Ŀ¼���е������
	pDataDir[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress = 0;
	pDataDir[IMAGE_DIRECTORY_ENTRY_IMPORT].Size = 0;

	return true;
}

//���IAT
bool VPack::ClsIAT()
{
	//�ж��Ƿ���ڵ����
	if (!pDataDir[IMAGE_DIRECTORY_ENTRY_IAT].VirtualAddress)
	{
		stcStub.pPackConf->dwIATRva = 0;
		return false;
	}

	//��ȡĿ¼��FOA
	DWORD dwDirFO = RVA2FO(pDataDir[IMAGE_DIRECTORY_ENTRY_IAT].VirtualAddress, pNt);
	//��ȡIAT��FOA
	PIMAGE_THUNK_DATA32 pIAT = (PIMAGE_THUNK_DATA32)(pStrFileData + dwDirFO);
	
	//�޸��ڴ�����
	DWORD dwOldProt = 0;
	VirtualProtect((LPVOID)(pIAT), pDataDir[IMAGE_DIRECTORY_ENTRY_IAT].Size, PAGE_READWRITE, &dwOldProt);
	//���IAT
	memset(pIAT, 0, pDataDir[IMAGE_DIRECTORY_ENTRY_IAT].Size);		
	//�ָ��ڴ�����
	VirtualProtect((LPVOID)(pIAT), pDataDir[IMAGE_DIRECTORY_ENTRY_IAT].Size, dwOldProt, &dwOldProt);

	//���Ŀ¼����IAT
	pDataDir[IMAGE_DIRECTORY_ENTRY_IAT].VirtualAddress = 0;
	pDataDir[IMAGE_DIRECTORY_ENTRY_IAT].Size = 0;
	
	return true;
}

//��ȡTLS
bool VPack::GetTLS()
{
	//�Ƿ����TLS
	if (pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress == 0)
	{
		stcStub.pPackConf->dwTLSCallbacks = 0;
		return false;
	}
	
	//��ȡTLS��Ϣ
	PIMAGE_TLS_DIRECTORY32 DirTls = (PIMAGE_TLS_DIRECTORY32)
		(RVA2FO(pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress,pNt) + pStrFileData);

	stcStub.pPackConf->dwTLSCallbacks = DirTls->AddressOfCallBacks- pOpt->ImageBase;//����TLS����RVA
	DirTls->AddressOfCallBacks = 0;													//��Ϊ0,���лָ�
	
}

//���㺯������HASH
DWORD VPack::FunHash(const char* FunName)
{
	DWORD dwDigest = 0;
	while (*FunName)
	{
		dwDigest = ((dwDigest<<25)|(dwDigest>>7));
		dwDigest += *FunName;
		FunName++;
	}
	return dwDigest;
}

//����dll�ļ�
bool VPack::LoadStub(_In_ const char* StubDllPath)
{
	//���ص��ڴ�//ExA������λ��ֻ���룬������
	HMODULE StubhModule = LoadLibraryExA(StubDllPath, NULL, DONT_RESOLVE_DLL_REFERENCES);
	if (!StubhModule)
	{
		DBGINFO("stub.dll����ʧ��");
		return false;
	}
	//��ȡ��Ϣ
	stcStub.pStubData = (LPBYTE)StubhModule;

	pStubDos = GetDosHeader((LPBYTE)StubhModule);
	pStubFile = GetFileHeader((LPBYTE)StubhModule);
	pStubNt = GetNtHeader((LPBYTE)StubhModule);
	pStubOpt = GetOptionalHeader((LPBYTE)StubhModule);

	PIMAGE_SECTION_HEADER pTextSec;
	pTextSec = GetSectionHeader((LPBYTE)StubhModule, ".text");
	stcStub.pTextData = (PBYTE)(pTextSec->VirtualAddress + (PBYTE)StubhModule);
	stcStub.dwTextDataSize = pTextSec->SizeOfRawData;

	//��ȡ�ض�λ����Ϣ
	PIMAGE_SECTION_HEADER pRelocSec;
	pRelocSec = GetSectionHeader((LPBYTE)StubhModule, ".reloc");
	stcStub.pRelocData = (PBYTE)(pRelocSec->VirtualAddress + (PBYTE)StubhModule);
	stcStub.dwRelocDataSize = pRelocSec->SizeOfRawData;

	//ͨ��GetProcAddress��ȡ������Ϣ
	stcStub.pfnPackFun = (LPBYTE)GetProcAddress(StubhModule, "PackStup");
	stcStub.pPackConf = (STUBCONF*)GetProcAddress(StubhModule, "g_Conf");

	//����ֵ
	return stcStub.pfnPackFun != NULL&&stcStub.pPackConf != NULL;

}

//��ȡ�����ļ�����
bool VPack::GetFileData(_In_ const char* pFilePath)
{
	//���ļ�
	hFile = OpenPEFile(pFilePath);

	if (hFile == INVALID_HANDLE_VALUE)
		return false;

	//��ȡ�ļ���С
	nSrcFileSize = GetFileSize(hFile, NULL);

	//����ռ�
	pStrFileData = new BYTE[nSrcFileSize];
	memset(pStrFileData, 0, nSrcFileSize);

	//��ȡ�ļ�
	DWORD dwRead = 0;
	ReadFile(hFile, pStrFileData, nSrcFileSize, &dwRead, NULL);
	CloseHandle(hFile);

	return true;
}

//����Ƿ���ЧPE�ļ�
bool VPack::CheckPE()
{
	//��ȡDOSͷ/NTͷ����Ϣ
	pDos = GetDosHeader(pStrFileData);
	pNt = GetNtHeader(pStrFileData);
	pOpt = GetOptionalHeader(pStrFileData);
	pFile = GetFileHeader(pStrFileData);
	pDataDir = pOpt->DataDirectory;

	//��ȡ��־�ֽ�
	PBYTE pByte1 = (PBYTE)pDos;
	PBYTE pByte2 = (PBYTE)pDos + 1;
	PBYTE pByte3 = (PBYTE)pNt;
	PBYTE pByte4 = (PBYTE)pNt + 1;

	//���MZ/PE��־
	if (*pByte1 == 0x4D
		&& *pByte2 == 0x5A
		&& *pByte3 == 0x50
		&& *pByte4 == 0x45)
		return true;

	else return false;
}

//��ȡ����PE��Ϣ
void VPack::GetPEInfo()
{
	stcStub.pPackConf->dwSrcOep = pOpt->AddressOfEntryPoint;
	stcStub.pPackConf->dwEncodeKey = dwKey;

	stcStub.pPackConf->dwEncodeDataRva = GetSectionHeader(pStrFileData, ".text")->VirtualAddress;
	stcStub.pPackConf->dwEncodeDataSize = GetSectionHeader(pStrFileData, ".text")->Misc.VirtualSize;
	
	//�ж��Ƿ����ض�λ
	if (pDataDir[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress)
	{
		stcStub.pPackConf->dwRelocRva = GetSectionHeader(pStrFileData, ".reloc")->VirtualAddress;
		stcStub.pPackConf->dwRelocSize = GetSectionHeader(pStrFileData, ".reloc")->Misc.VirtualSize;
	}
	else
	{
		stcStub.pPackConf->dwRelocRva = 0;
		stcStub.pPackConf->dwRelocSize = 0;
	}

}

//����α���
void VPack::EncodeData()
{
	DWORD dwSrcTextFOA = GetSectionHeader(pStrFileData, ".text")->PointerToRawData;
	LPBYTE pEnCodeData = (LPBYTE)(pStrFileData + dwSrcTextFOA);
	//ѭ�����dwKey
	for (DWORD i = 0; i < stcStub.pPackConf->dwEncodeDataSize; i++)
	{
		pEnCodeData[i] ^= dwKey;
		pEnCodeData[i] ^= i;
	}
}

//�޸�OEP
void VPack::SetNewOEP()
{
	//ָ��stub��ʼ����
	DWORD dwNewOEP = (DWORD)stcStub.pfnPackFun;

	//��ȥStub��ַ
	dwNewOEP -= (DWORD)stcStub.pStubData;

	//��ȥStub����RVA
	dwNewOEP -= GetSectionHeader(stcStub.pStubData, ".text")->VirtualAddress;

	//����������RVA
	dwNewOEP += GetSectionHeader(pStrFileData, pTextSecName)->VirtualAddress;

	//����OEP
	pOpt->AddressOfEntryPoint = dwNewOEP;
}

void VPack::RelocStub(PBYTE pData, DWORD dwNewImageBase, DWORD dwNewRva)
{
	//�ҵ��ض�λ��
	PIMAGE_BASE_RELOCATION pStubReloc = NULL;

	//��ȡ�ض�λ��RVA
	DWORD dwStubRelocRva = GetOptionalHeader(pData)->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
	//��ȡ��С�ֽ�
	DWORD dwStubRelocSize = GetOptionalHeader(pData)->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;
	DWORD dwStubRelocSize2 = dwStubRelocSize;

	//��ȡStub�����RVA
	DWORD dwStubTextRva = GetSectionHeader(pData, ".text")->VirtualAddress;
	//��ȡStub�¸�����RVA
	DWORD dwStubIdataRva= GetSectionHeader(pData, ".idata")->VirtualAddress;
	
	pStubReloc = (PIMAGE_BASE_RELOCATION)(pData + dwStubRelocRva);
	
	//��ȡStub�ļ���С//��Ҫ�޸�PEͷ��Text��,�ض�λ��
	DWORD dwStubFileSize = GetOptionalHeader(pData)->SizeOfImage;

	//�޸�����Stub���ԣ��������ʱ����ָ����������
	DWORD dwOldProt = 0;
	VirtualProtect((LPVOID)(pData), dwStubFileSize, PAGE_READWRITE, &dwOldProt);

	//�޸�stub
	while (pStubReloc->SizeOfBlock != 0)
	{
		//��ȡ�ض�λ����
		DWORD dwCount = (pStubReloc->SizeOfBlock - 8) / 2;
		//��ȡ��һ��
		PTYPEOFFSET pTypeOffset = (PTYPEOFFSET)(pStubReloc + 1);

		//��ȡ�ض�λRVA
		if (pStubReloc->VirtualAddress >= dwStubTextRva
			&&pStubReloc->VirtualAddress < dwStubIdataRva)
		{
			//�ڵ�ַ��Χ���޸��ض�λ����,��ַ1000W��Ϊ40W
			//ѭ���޸�
			for (DWORD i = 0; i < dwCount; i++)
			{
				//�ض�λ����3
				if (pTypeOffset[i].Type == 3)
				{
					//��ȡ�ض�λ��RVA
					DWORD dwRva = pTypeOffset[i].Offset + pStubReloc->VirtualAddress;

					//��ȡҪ�޸ĵ����ݡ�ȡ���ݡ�
					PDWORD pFixData = (PDWORD)(dwRva + pData);

					//��ȥ��ǰ��ַ
					*pFixData -= (DWORD)pData;

					//��ȥ��ǰ����RVA
					*pFixData -= dwStubTextRva;

					//����������RVA
					*pFixData += dwNewRva;

					//�������������ַ
					*pFixData += dwNewImageBase;
				}	
			}
			//��ȥԭStubText��RVA
			pStubReloc->VirtualAddress -= dwStubTextRva;
			//��������Ӷ�StubText��RVA
			pStubReloc->VirtualAddress += dwNewRva;			
		}
		//����text�������
		else
		{	
			//���Stub���������ض�λ��
			for (DWORD i = 0; i < dwCount; i++)
			{
				pTypeOffset[i] = { 0 };
			}
			dwStubRelocSize -= pStubReloc->SizeOfBlock;
			pStubReloc->VirtualAddress = 0;
			pStubReloc->SizeOfBlock = 0;
		}	
		//�޸���һ���ض�λ����
		pStubReloc = (PIMAGE_BASE_RELOCATION)((LPBYTE)pStubReloc + pStubReloc->SizeOfBlock);
	}

	//��ȡ��RVA
	DWORD dwStubRelocNewRva = GetSectionHeader(pStrFileData, pRelocSecName)->VirtualAddress;
	
	//�޸�PEͷ����
	DWORD dwOldProtPE = 0;

	//ָ���µ��ض�λ��
	pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress= dwStubRelocNewRva;
	//��ȡ��С
	
	pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size= dwStubRelocSize;

	//�ָ�Stub�ڴ�����
	VirtualProtect((LPVOID)(pData), dwStubFileSize, dwOldProtPE, &dwOldProtPE);

}

//���������
DWORD  VPack::AddNewSection(PBYTE pData, const char* pSecName, DWORD dwSecSize,DWORD dwSecChara)
{
	//��ȡ���һ������
	PIMAGE_SECTION_HEADER pLastSection = GetLastSection(pStrFileData);
	//�޸���������
	pFile->NumberOfSections += 1;
	//�޸���������Ϣ
	PIMAGE_SECTION_HEADER pNewSec = GetLastSection(pStrFileData);
	memcpy(pNewSec->Name, pSecName, strlen(pSecName) + 1);//�˴������ַ�������Ҫ��strlen��������sizeof
															  //ƫ��FOA
	pNewSec->PointerToRawData = pLastSection->PointerToRawData + pLastSection->SizeOfRawData;
	//ƫ��RVA
	pNewSec->VirtualAddress = pLastSection->VirtualAddress + Aligment(pLastSection->SizeOfRawData, pOpt->SectionAlignment);
	//���δ�С
	pNewSec->Misc.VirtualSize = dwSecSize;
	//�ļ�����
	pNewSec->SizeOfRawData = Aligment(dwSecSize, pOpt->FileAlignment);
	//��������
	pNewSec->Characteristics = dwSecChara;

	//�����С
	pOpt->SizeOfImage = pNewSec->VirtualAddress + pNewSec->SizeOfRawData;

	//����RVA
	return pNewSec->VirtualAddress;
}

DWORD VPack::Aligment(_In_ DWORD dwSize, _In_ DWORD dwAligment)
{
	return dwSize % dwAligment == 0 ? dwSize : (dwSize / dwAligment + 1)*dwAligment;
}

//��ȡָ����������ͷ
PIMAGE_SECTION_HEADER VPack::GetSectionHeader(_In_ PBYTE pFileData, _In_ const char * SecName)
{
	//��ȡ������Ϣ
	DWORD dwNumberSection = GetFileHeader(pFileData)->NumberOfSections;

	//��ȡ��һ������
	PIMAGE_SECTION_HEADER  pSec = IMAGE_FIRST_SECTION(GetNtHeader(pFileData));

	char Name[10] = { 0 };
	//ѭ������
	for (DWORD i = 0; i < dwNumberSection; i++)
	{
		memcpy(Name, pSec[i].Name, 10);
		//�ȶ�����
		if (!strcmp(Name, SecName))
		{
			return &pSec[i];
		}
	}

	return nullptr;
}


//��ȡDOSͷ
PIMAGE_DOS_HEADER VPack::GetDosHeader(PBYTE hModule)
{
	return (PIMAGE_DOS_HEADER)hModule;
}

//��ȡNTͷ
PIMAGE_NT_HEADERS VPack::GetNtHeader(PBYTE hModule)
{
	return (PIMAGE_NT_HEADERS)(hModule + *(PDWORD)(hModule + 0x3C));
}

//��ȡ�ļ�ͷ
PIMAGE_FILE_HEADER VPack::GetFileHeader(PBYTE hModule)
{
	return (PIMAGE_FILE_HEADER)&(GetNtHeader(hModule)->FileHeader);
}

//��ȡ��չͷ
PIMAGE_OPTIONAL_HEADER VPack::GetOptionalHeader(PBYTE hModule)
{
	return (PIMAGE_OPTIONAL_HEADER)&(GetNtHeader(hModule)->OptionalHeader);
}

//��ȡ���һ������
PIMAGE_SECTION_HEADER VPack::GetLastSection(PBYTE pData)
{
	//��ȡ��������
	DWORD dwSecCount = pFile->NumberOfSections;
	//��ȡ��һ������
	PIMAGE_SECTION_HEADER pFirstSec = IMAGE_FIRST_SECTION(pNt);
	//�������һ������
	return pFirstSec + (dwSecCount - 1);
}

//RVAתFO
DWORD VPack::RVA2FO(DWORD dwRva, PIMAGE_NT_HEADERS32 pNt)
{
	//�ļ��������ڴ�������
	if (pNt->OptionalHeader.FileAlignment == pNt->OptionalHeader.SectionAlignment)
	{
		return dwRva;
	}
	//����ͷ
	PIMAGE_SECTION_HEADER pSec = IMAGE_FIRST_SECTION(pNt);

	//ѭ������
	for (int i = 0; i < pNt->FileHeader.NumberOfSections; i++)
	{
		//�ȶԵ�ַ
		if (dwRva >= pSec[i].VirtualAddress&&
			dwRva <= pSec[i].VirtualAddress + pSec[i].SizeOfRawData)
		{
			return	dwRva - pSec[i].VirtualAddress + pSec[i].PointerToRawData;
		}
	}
	return 0;
}

//���ļ�
HANDLE VPack::OpenPEFile(_In_ const char* pFilePath)
{
	return CreateFileA(pFilePath,
		GENERIC_READ,
		FILE_SHARE_READ,
		NULL,
		OPEN_ALWAYS,
		FILE_ATTRIBUTE_NORMAL,
		NULL);
}
