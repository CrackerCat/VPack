
#include "stdafx.h"
#include "Pack.h"

VPack::VPack()
{
	stcStub = { 0 };
	hFile = NULL;

	//程序默认参数
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
	//释放宿主数据缓存
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

//加壳主程序
bool VPack::Packing(_In_ const char* pFilePath)
{
	//打开文件	;
	if (!GetFileData(pFilePath))
	{
		DBGINFO("打开宿主文件失败\n");
		return false;
	}
	//检查是否有效PE文件
	if (!CheckPE())
	{
		DBGINFO("请选择有效程序\n");
		return false;
	}

	//获取oep等信息
	GetPEInfo();

	//保存导入表
	SaveImport();

	//清空IAT
	ClsIAT();

	//代码段编码
	EncodeData();

	//添加区段
	dwPackSecRVA=AddNewSection(pStrFileData, pTextSecName, stcStub.dwTextDataSize,0xE00000E0);

	GetTLS();

	//添加Stub重定位区段
	AddNewSection(pStrFileData, pRelocSecName, stcStub.dwRelocDataSize,0x42000040);

	//修复Stub重定位数据
	RelocStub(stcStub.pStubData, pOpt->ImageBase, GetSectionHeader(pStrFileData, pTextSecName)->VirtualAddress);

	//修改OEP指向Stub
	SetNewOEP();

	//另存文件
	if (!SaveFile(pFilePath))
	{
		DBGINFO("保存加壳文件失败\n");
		return false;
	}

	return true;
}

//保存文件
bool VPack::SaveFile(_In_ const char* pFilePath)
{
	//处理路径
	char *pNewFilePath = new char[MAX_PATH];
	char *pPack = "[VPack].exe";
	//拷贝路径
	strcpy_s(pNewFilePath, MAX_PATH, pFilePath);
	//去除后缀名
	int nLen = strlen(pFilePath);
	pNewFilePath[nLen - 4] = '\0';
	//拼接名称
	strcat_s(pNewFilePath, MAX_PATH, pPack);

	//保存文件
	FILE* pFile = NULL;

	if (fopen_s(&pFile, pNewFilePath, "wb"))
	{
		DBGINFO("创建文件失败\n");
		return false;
	}
	//写入宿主信息
	fwrite(pStrFileData, 1, nSrcFileSize, pFile);

	//对齐文件指针
	fseek(pFile, GetSectionHeader(pStrFileData, pTextSecName)->PointerToRawData, SEEK_SET);
	//写入stubText
	fwrite(stcStub.pTextData, 1, stcStub.dwTextDataSize, pFile);

	//对齐文件指针
	fseek(pFile, GetSectionHeader(pStrFileData, pRelocSecName)->PointerToRawData, SEEK_SET);
	//写入stubText
	fwrite(stcStub.pRelocData, 1, stcStub.dwRelocDataSize, pFile);

	fclose(pFile);

	delete[] pNewFilePath;

	return true;
}

//保存导入表
bool VPack::SaveImport()
{	
	//判断是否存在导入表
	if (!pDataDir[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress)
	{
		stcStub.pPackConf->dwImportRva = 0;
		return false;
	}		
	
	//获取目录表FOA
	DWORD dwDirFO = RVA2FO(pDataDir[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress, pNt);
	stcStub.pPackConf->dwImportRva = pDataDir[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
	//获取导入表FOA
	PIMAGE_IMPORT_DESCRIPTOR pImport = (PIMAGE_IMPORT_DESCRIPTOR)(pStrFileData + dwDirFO);
	
	DWORD dwNumber = 0;

	//外层遍历模块
	while (pImport->Name)
	{
		//获取DLL名称
		char *DllName = (CHAR*)(pStrFileData + RVA2FO(pImport->Name, pNt));

		//获取INT
		PIMAGE_THUNK_DATA32 pThunkINT= (PIMAGE_THUNK_DATA32)
			(pStrFileData+RVA2FO(pImport->OriginalFirstThunk, pNt));	

		//修改内存属性
		DWORD dwOldProt = 0;
		VirtualProtect((LPVOID)(pThunkINT), 1, PAGE_READWRITE, &dwOldProt);

		//内存遍历模块中函数
		while (pThunkINT->u1.AddressOfData)
		{
			//序号命名
			if (IMAGE_SNAP_BY_ORDINAL32(pThunkINT->u1.Ordinal))
			{
				//序号命名不变
				pThunkINT->u1.Ordinal;
			}
			//名称命名
			else
			{
				//获取函数名称
				PIMAGE_IMPORT_BY_NAME pName = (PIMAGE_IMPORT_BY_NAME)
					(pStrFileData +	RVA2FO(pThunkINT->u1.AddressOfData, pNt));
				//计算Hash
				DWORD dwHash=FunHash(pName->Name);
				//保存Hash
				pThunkINT->u1.AddressOfData = dwHash;
				//清空函数名称
				memset(pName->Name, 0, strlen(pName->Name));
			}
			//下一个INT			
			pThunkINT++;

			//获取函数数量
			dwNumber++;
		}

		//恢复内存属性
		VirtualProtect((LPVOID)(pThunkINT), 1, dwOldProt, &dwOldProt);

		//下一个导入表
		pImport++;
	}

	//保存函数数量
	stcStub.pPackConf->dwNumberFun = dwNumber;

	//清空目录表中导入表项
	pDataDir[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress = 0;
	pDataDir[IMAGE_DIRECTORY_ENTRY_IMPORT].Size = 0;

	return true;
}

//清空IAT
bool VPack::ClsIAT()
{
	//判断是否存在导入表
	if (!pDataDir[IMAGE_DIRECTORY_ENTRY_IAT].VirtualAddress)
	{
		stcStub.pPackConf->dwIATRva = 0;
		return false;
	}

	//获取目录表FOA
	DWORD dwDirFO = RVA2FO(pDataDir[IMAGE_DIRECTORY_ENTRY_IAT].VirtualAddress, pNt);
	//获取IAT表FOA
	PIMAGE_THUNK_DATA32 pIAT = (PIMAGE_THUNK_DATA32)(pStrFileData + dwDirFO);
	
	//修改内存属性
	DWORD dwOldProt = 0;
	VirtualProtect((LPVOID)(pIAT), pDataDir[IMAGE_DIRECTORY_ENTRY_IAT].Size, PAGE_READWRITE, &dwOldProt);
	//清空IAT
	memset(pIAT, 0, pDataDir[IMAGE_DIRECTORY_ENTRY_IAT].Size);		
	//恢复内存属性
	VirtualProtect((LPVOID)(pIAT), pDataDir[IMAGE_DIRECTORY_ENTRY_IAT].Size, dwOldProt, &dwOldProt);

	//清空目录表中IAT
	pDataDir[IMAGE_DIRECTORY_ENTRY_IAT].VirtualAddress = 0;
	pDataDir[IMAGE_DIRECTORY_ENTRY_IAT].Size = 0;
	
	return true;
}

//获取TLS
bool VPack::GetTLS()
{
	//是否存在TLS
	if (pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress == 0)
	{
		stcStub.pPackConf->dwTLSCallbacks = 0;
		return false;
	}
	
	//获取TLS信息
	PIMAGE_TLS_DIRECTORY32 DirTls = (PIMAGE_TLS_DIRECTORY32)
		(RVA2FO(pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress,pNt) + pStrFileData);

	stcStub.pPackConf->dwTLSCallbacks = DirTls->AddressOfCallBacks- pOpt->ImageBase;//保存TLS函数RVA
	DirTls->AddressOfCallBacks = 0;													//设为0,壳中恢复
	
}

//计算函数名称HASH
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

//载入dll文件
bool VPack::LoadStub(_In_ const char* StubDllPath)
{
	//加载到内存//ExA版带标记位，只载入，不运行
	HMODULE StubhModule = LoadLibraryExA(StubDllPath, NULL, DONT_RESOLVE_DLL_REFERENCES);
	if (!StubhModule)
	{
		DBGINFO("stub.dll加载失败");
		return false;
	}
	//读取信息
	stcStub.pStubData = (LPBYTE)StubhModule;

	pStubDos = GetDosHeader((LPBYTE)StubhModule);
	pStubFile = GetFileHeader((LPBYTE)StubhModule);
	pStubNt = GetNtHeader((LPBYTE)StubhModule);
	pStubOpt = GetOptionalHeader((LPBYTE)StubhModule);

	PIMAGE_SECTION_HEADER pTextSec;
	pTextSec = GetSectionHeader((LPBYTE)StubhModule, ".text");
	stcStub.pTextData = (PBYTE)(pTextSec->VirtualAddress + (PBYTE)StubhModule);
	stcStub.dwTextDataSize = pTextSec->SizeOfRawData;

	//获取重定位段信息
	PIMAGE_SECTION_HEADER pRelocSec;
	pRelocSec = GetSectionHeader((LPBYTE)StubhModule, ".reloc");
	stcStub.pRelocData = (PBYTE)(pRelocSec->VirtualAddress + (PBYTE)StubhModule);
	stcStub.dwRelocDataSize = pRelocSec->SizeOfRawData;

	//通过GetProcAddress获取导出信息
	stcStub.pfnPackFun = (LPBYTE)GetProcAddress(StubhModule, "PackStup");
	stcStub.pPackConf = (STUBCONF*)GetProcAddress(StubhModule, "g_Conf");

	//返回值
	return stcStub.pfnPackFun != NULL&&stcStub.pPackConf != NULL;

}

//获取宿主文件数据
bool VPack::GetFileData(_In_ const char* pFilePath)
{
	//打开文件
	hFile = OpenPEFile(pFilePath);

	if (hFile == INVALID_HANDLE_VALUE)
		return false;

	//获取文件大小
	nSrcFileSize = GetFileSize(hFile, NULL);

	//申请空间
	pStrFileData = new BYTE[nSrcFileSize];
	memset(pStrFileData, 0, nSrcFileSize);

	//读取文件
	DWORD dwRead = 0;
	ReadFile(hFile, pStrFileData, nSrcFileSize, &dwRead, NULL);
	CloseHandle(hFile);

	return true;
}

//检查是否有效PE文件
bool VPack::CheckPE()
{
	//获取DOS头/NT头等信息
	pDos = GetDosHeader(pStrFileData);
	pNt = GetNtHeader(pStrFileData);
	pOpt = GetOptionalHeader(pStrFileData);
	pFile = GetFileHeader(pStrFileData);
	pDataDir = pOpt->DataDirectory;

	//获取标志字节
	PBYTE pByte1 = (PBYTE)pDos;
	PBYTE pByte2 = (PBYTE)pDos + 1;
	PBYTE pByte3 = (PBYTE)pNt;
	PBYTE pByte4 = (PBYTE)pNt + 1;

	//检查MZ/PE标志
	if (*pByte1 == 0x4D
		&& *pByte2 == 0x5A
		&& *pByte3 == 0x50
		&& *pByte4 == 0x45)
		return true;

	else return false;
}

//获取宿主PE信息
void VPack::GetPEInfo()
{
	stcStub.pPackConf->dwSrcOep = pOpt->AddressOfEntryPoint;
	stcStub.pPackConf->dwEncodeKey = dwKey;

	stcStub.pPackConf->dwEncodeDataRva = GetSectionHeader(pStrFileData, ".text")->VirtualAddress;
	stcStub.pPackConf->dwEncodeDataSize = GetSectionHeader(pStrFileData, ".text")->Misc.VirtualSize;
	
	//判断是否有重定位
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

//代码段编码
void VPack::EncodeData()
{
	DWORD dwSrcTextFOA = GetSectionHeader(pStrFileData, ".text")->PointerToRawData;
	LPBYTE pEnCodeData = (LPBYTE)(pStrFileData + dwSrcTextFOA);
	//循环异或dwKey
	for (DWORD i = 0; i < stcStub.pPackConf->dwEncodeDataSize; i++)
	{
		pEnCodeData[i] ^= dwKey;
		pEnCodeData[i] ^= i;
	}
}

//修改OEP
void VPack::SetNewOEP()
{
	//指向stub起始函数
	DWORD dwNewOEP = (DWORD)stcStub.pfnPackFun;

	//减去Stub基址
	dwNewOEP -= (DWORD)stcStub.pStubData;

	//减去Stub段首RVA
	dwNewOEP -= GetSectionHeader(stcStub.pStubData, ".text")->VirtualAddress;

	//加上新区段RVA
	dwNewOEP += GetSectionHeader(pStrFileData, pTextSecName)->VirtualAddress;

	//重设OEP
	pOpt->AddressOfEntryPoint = dwNewOEP;
}

void VPack::RelocStub(PBYTE pData, DWORD dwNewImageBase, DWORD dwNewRva)
{
	//找到重定位表
	PIMAGE_BASE_RELOCATION pStubReloc = NULL;

	//获取重定位表RVA
	DWORD dwStubRelocRva = GetOptionalHeader(pData)->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
	//获取大小字节
	DWORD dwStubRelocSize = GetOptionalHeader(pData)->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;
	DWORD dwStubRelocSize2 = dwStubRelocSize;

	//获取Stub代码段RVA
	DWORD dwStubTextRva = GetSectionHeader(pData, ".text")->VirtualAddress;
	//获取Stub下个区段RVA
	DWORD dwStubIdataRva= GetSectionHeader(pData, ".idata")->VirtualAddress;
	
	pStubReloc = (PIMAGE_BASE_RELOCATION)(pData + dwStubRelocRva);
	
	//获取Stub文件大小//需要修改PE头，Text段,重定位段
	DWORD dwStubFileSize = GetOptionalHeader(pData)->SizeOfImage;

	//修改整个Stub属性，添加区段时重新指定区段属性
	DWORD dwOldProt = 0;
	VirtualProtect((LPVOID)(pData), dwStubFileSize, PAGE_READWRITE, &dwOldProt);

	//修复stub
	while (pStubReloc->SizeOfBlock != 0)
	{
		//获取重定位项数
		DWORD dwCount = (pStubReloc->SizeOfBlock - 8) / 2;
		//获取第一项
		PTYPEOFFSET pTypeOffset = (PTYPEOFFSET)(pStubReloc + 1);

		//获取重定位RVA
		if (pStubReloc->VirtualAddress >= dwStubTextRva
			&&pStubReloc->VirtualAddress < dwStubIdataRva)
		{
			//在地址范围内修复重定位数据,基址1000W改为40W
			//循环修改
			for (DWORD i = 0; i < dwCount; i++)
			{
				//重定位类型3
				if (pTypeOffset[i].Type == 3)
				{
					//获取重定位项RVA
					DWORD dwRva = pTypeOffset[i].Offset + pStubReloc->VirtualAddress;

					//获取要修改的内容【取内容】
					PDWORD pFixData = (PDWORD)(dwRva + pData);

					//减去当前基址
					*pFixData -= (DWORD)pData;

					//减去当前区段RVA
					*pFixData -= dwStubTextRva;

					//加上新区段RVA
					*pFixData += dwNewRva;

					//加上宿主程序基址
					*pFixData += dwNewImageBase;
				}	
			}
			//减去原StubText段RVA
			pStubReloc->VirtualAddress -= dwStubTextRva;
			//加上新添加段StubText段RVA
			pStubReloc->VirtualAddress += dwNewRva;			
		}
		//超过text段则擦除
		else
		{	
			//清除Stub其他区段重定位项
			for (DWORD i = 0; i < dwCount; i++)
			{
				pTypeOffset[i] = { 0 };
			}
			dwStubRelocSize -= pStubReloc->SizeOfBlock;
			pStubReloc->VirtualAddress = 0;
			pStubReloc->SizeOfBlock = 0;
		}	
		//修复下一块重定位数据
		pStubReloc = (PIMAGE_BASE_RELOCATION)((LPBYTE)pStubReloc + pStubReloc->SizeOfBlock);
	}

	//获取新RVA
	DWORD dwStubRelocNewRva = GetSectionHeader(pStrFileData, pRelocSecName)->VirtualAddress;
	
	//修改PE头属性
	DWORD dwOldProtPE = 0;

	//指向新的重定位表
	pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress= dwStubRelocNewRva;
	//获取大小
	
	pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size= dwStubRelocSize;

	//恢复Stub内存属性
	VirtualProtect((LPVOID)(pData), dwStubFileSize, dwOldProtPE, &dwOldProtPE);

}

//添加新区段
DWORD  VPack::AddNewSection(PBYTE pData, const char* pSecName, DWORD dwSecSize,DWORD dwSecChara)
{
	//获取最后一个区段
	PIMAGE_SECTION_HEADER pLastSection = GetLastSection(pStrFileData);
	//修改区段数量
	pFile->NumberOfSections += 1;
	//修改新区段信息
	PIMAGE_SECTION_HEADER pNewSec = GetLastSection(pStrFileData);
	memcpy(pNewSec->Name, pSecName, strlen(pSecName) + 1);//此处计算字符串长度要用strlen，不能用sizeof
															  //偏移FOA
	pNewSec->PointerToRawData = pLastSection->PointerToRawData + pLastSection->SizeOfRawData;
	//偏移RVA
	pNewSec->VirtualAddress = pLastSection->VirtualAddress + Aligment(pLastSection->SizeOfRawData, pOpt->SectionAlignment);
	//区段大小
	pNewSec->Misc.VirtualSize = dwSecSize;
	//文件对齐
	pNewSec->SizeOfRawData = Aligment(dwSecSize, pOpt->FileAlignment);
	//区段属性
	pNewSec->Characteristics = dwSecChara;

	//镜像大小
	pOpt->SizeOfImage = pNewSec->VirtualAddress + pNewSec->SizeOfRawData;

	//返回RVA
	return pNewSec->VirtualAddress;
}

DWORD VPack::Aligment(_In_ DWORD dwSize, _In_ DWORD dwAligment)
{
	return dwSize % dwAligment == 0 ? dwSize : (dwSize / dwAligment + 1)*dwAligment;
}

//获取指定名称区段头
PIMAGE_SECTION_HEADER VPack::GetSectionHeader(_In_ PBYTE pFileData, _In_ const char * SecName)
{
	//获取区段信息
	DWORD dwNumberSection = GetFileHeader(pFileData)->NumberOfSections;

	//获取第一个区段
	PIMAGE_SECTION_HEADER  pSec = IMAGE_FIRST_SECTION(GetNtHeader(pFileData));

	char Name[10] = { 0 };
	//循环遍历
	for (DWORD i = 0; i < dwNumberSection; i++)
	{
		memcpy(Name, pSec[i].Name, 10);
		//比对名称
		if (!strcmp(Name, SecName))
		{
			return &pSec[i];
		}
	}

	return nullptr;
}


//获取DOS头
PIMAGE_DOS_HEADER VPack::GetDosHeader(PBYTE hModule)
{
	return (PIMAGE_DOS_HEADER)hModule;
}

//获取NT头
PIMAGE_NT_HEADERS VPack::GetNtHeader(PBYTE hModule)
{
	return (PIMAGE_NT_HEADERS)(hModule + *(PDWORD)(hModule + 0x3C));
}

//获取文件头
PIMAGE_FILE_HEADER VPack::GetFileHeader(PBYTE hModule)
{
	return (PIMAGE_FILE_HEADER)&(GetNtHeader(hModule)->FileHeader);
}

//获取扩展头
PIMAGE_OPTIONAL_HEADER VPack::GetOptionalHeader(PBYTE hModule)
{
	return (PIMAGE_OPTIONAL_HEADER)&(GetNtHeader(hModule)->OptionalHeader);
}

//获取最后一个区段
PIMAGE_SECTION_HEADER VPack::GetLastSection(PBYTE pData)
{
	//获取区段数量
	DWORD dwSecCount = pFile->NumberOfSections;
	//获取第一个区段
	PIMAGE_SECTION_HEADER pFirstSec = IMAGE_FIRST_SECTION(pNt);
	//返回最后一个区段
	return pFirstSec + (dwSecCount - 1);
}

//RVA转FO
DWORD VPack::RVA2FO(DWORD dwRva, PIMAGE_NT_HEADERS32 pNt)
{
	//文件对齐与内存对齐相等
	if (pNt->OptionalHeader.FileAlignment == pNt->OptionalHeader.SectionAlignment)
	{
		return dwRva;
	}
	//区段头
	PIMAGE_SECTION_HEADER pSec = IMAGE_FIRST_SECTION(pNt);

	//循环查找
	for (int i = 0; i < pNt->FileHeader.NumberOfSections; i++)
	{
		//比对地址
		if (dwRva >= pSec[i].VirtualAddress&&
			dwRva <= pSec[i].VirtualAddress + pSec[i].SizeOfRawData)
		{
			return	dwRva - pSec[i].VirtualAddress + pSec[i].PointerToRawData;
		}
	}
	return 0;
}

//打开文件
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
