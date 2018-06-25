
//ͷ�ļ�
#include "stdio.h"
#include <windows.h>
#include "StubConf.h"


//ȫ�ֱ���
DWORD g_hModule=0;					//���ӿǳ���Ļ�ַ
_declspec(thread) int g_nTls;		//TLS����
DWORD g_dwFused = 10;				//����
DWORD g_dwMcode1 = 0;				//������1
DWORD g_dwMcode2 = 0;				//������2
DWORD g_dwMcode3 = 0;				//������3
char g_strPwd[MAX_PATH] = { 0 };	//��ȷ����
char g_strPwdIn[MAX_PATH] = { 0 };	//��������

//ȫ�ֺ���ָ��
pGetProceAddress pfnGetProcAddress;
pLoadLibraryExA pfnLoadLibraryExA;
pMessageBoxA pfnMessageBoxA;
pVirtualProtect pfnVirtualProtect;
pGetModuleHandleA pfnGetModuleHandleA;
pVirtualAlloc pfnVirtualAlloc;
pExitProcess pfnExitProcess;
pRegisterClassA pfnRegisterClassA;
pCreateWindowExA pfnCreateWindowExA;
pShowWindow pfnShowWindow;
pGetMessageA pfnGetMessageA;
pTranslateMessage pfnTranslateMessage;
pDispatchMessageA pfnDispatchMessageA;
pGetDlgItemTextA pfnGetDlgItemTextA;
pPostQuitMessage pfnPostQuitMessage;
pDefWindowProcA pfnDefWindowProcA;
pGetVolumeInformationA pfnGetVolumeInformationA;
pGetCurrentProcess	pfnGetCurrentProcess;
pNtQueryInformationProcess	 pfnNtQueryInformationProcess;
pGetWindowThreadProcessId	pfnGetWindowThreadProcessId;
pFindWindowA				pfnFindWindowA;
pNtQuerySystemInformation pfnNtQuerySystemInformation;
pNtQueryObject			 pfnNtQueryObject;
pGetCurrentThread		pfnGetCurrentThread;
pZwSetInformationThread pfnZwSetInformationThread;

///////////////////////////////////////////////////////////////////////////////

//��������
extern "C"
{
	__declspec(dllexport)  STUBCONF g_Conf;						//�������ú���

	__declspec(dllexport)  void __declspec(naked) PackStup()	//Stub������
	{			
		
		FusedFunc((DWORD)StubStart);

		__asm
		{
			mov eax, g_Conf.dwSrcOep;
			add eax, g_hModule;
			jmp eax;
		}
	}
}


//����ʵ��
//////////////////////////////////////////////////////////////////
// 
// //TLS����
/*
__declspec(thread) char g_strTLS[5] = { 0x53, 0x4C, 0x53, 0x00 };
void NTAPI t_TlsCallBack_A(PVOID DllHandle, DWORD Reason, PVOID Red){__asm {add g_strTLS,0x01};}
#pragma data_seg(".CRT$XLB")
PIMAGE_TLS_CALLBACK p_thread_callback[] = {t_TlsCallBack_A,	NULL};
#pragma data_seg()*/


void StubStart()
{
	//�ݹ����
	if (!g_dwFused)
	{
		_asm
		{
			nop
			mov   ebp, esp
			push - 1
			push   0
			push   0
			mov   eax, fs:[0]
			push   eax
			mov   fs : [0], esp
			sub   esp, 0x68
			push   ebx
			push   esi
			push   edi
			pop   eax
			pop   eax
			pop   eax
			add   esp, 0x68
			pop   eax
			mov   fs : [0], eax
			pop   eax

			sub g_dwFused, 1

			pop   eax
			pop   eax
			pop   eax
			mov   ebp, eax

			push StubStart
			call FusedFunc
		}
	}

	//�õ�API
	FusedFunc((DWORD)GetAPI);
	
	if (CheckDebug())
	{
		char strError[3] = { 0x47, 0x47, 0x00 };		
		pfnMessageBoxA(0, strError, 0, 0);
	}
	else
	{
		char strError[3] = { 0x4F, 0x4B, 0x00 };
		pfnMessageBoxA(0, strError, 0, 0);
	}
	
	//�����������
	DetachDebug();
	
	//��������	
	StubMain((HINSTANCE)g_hModule, NULL, NULL, NULL);

	//��ζԱ�����
	FusedFunc((DWORD)CmpLisence);


	//���ܴ���
	FusedFunc((DWORD)Decode);

	//��ζԱ�����
	//FusedFunc((DWORD)CmpLisence);

	//�޸��ض�λ
	FusedFunc((DWORD)Reloc);

	//��ζԱ�����
	//FusedFunc((DWORD)CmpLisence);

	//�޸�IAT
	FusedFunc((DWORD)RecIAT);

	//��ζԱ�����
	//FusedFunc((DWORD)CmpLisence);

	//�޸�TLS
	FusedFunc((DWORD)RelTLS);

	//��ζԱ�����
	//FusedFunc((DWORD)CmpLisence);

	//��dump
	FusedFunc((DWORD)AntiDump);

	//��ζԱ�����
	//FusedFunc((DWORD)CmpLisence);
}


void _stdcall FusedFunc(DWORD funcAddress)
{

	_asm
	{
		jmp label1
		label2 :
		_emit 0xeb; //���������call
		_emit 0x04;
		CALL DWORD PTR DS : [EAX + EBX * 2 + 0x123402EB]; //ִ��EB 02  Ҳ����������һ��

														  //call Init;// ��ȡһЩ���������ĵ�ַ

														  //call��һ��,���ڻ��eip
		_emit 0xE8;
		_emit 0x00;
		_emit 0x00;
		_emit 0x00;
		_emit 0x00;
		//-------���������call
		_emit 0xEB;
		_emit 0x0E;

		//��
		PUSH 0x0;
		PUSH 0x0;
		MOV EAX, DWORD PTR FS : [0];
		PUSH EAX;
		//��

		CALL DWORD PTR DS : [EAX + EBX * 2 + 0x5019C083];

		push funcAddress; //��������ǲ����������Ҫע�������add eax,??��??
		retn;

		jmp label3
		// ��
		_emit 0xE8;
		_emit 0x00;
		_emit 0x00;
		_emit 0x00;
		_emit 0x00;
		// ��

	label1:
		jmp label2
			label3 :
	}

}


//��ȡDOSͷ
PIMAGE_DOS_HEADER GetDosHeader(PBYTE hModule)
{
	return (PIMAGE_DOS_HEADER)hModule;
}


//��ȡNTͷ
PIMAGE_NT_HEADERS GetNtHeader(PBYTE hModule)
{
	return (PIMAGE_NT_HEADERS)(hModule + *(PDWORD)(hModule + 0x3C));
}

//��ȡ�ļ�ͷ
PIMAGE_FILE_HEADER GetFileHeader(PBYTE hModule)
{
	return (PIMAGE_FILE_HEADER)&(GetNtHeader(hModule)->FileHeader);
}

//��ȡ��չͷ

PIMAGE_OPTIONAL_HEADER GetOptionalHeader(PBYTE hModule)
{
	return (PIMAGE_OPTIONAL_HEADER)&(GetNtHeader(hModule)->OptionalHeader);
}

//��ȡAPI
void GetAPI()
{
	g_nTls;

	HMODULE hKernel;
	//��ȡģ���ַ
	__asm
	{
		push eax;				//����Ĵ���
		mov eax, fs:[0x30];		//��ȡPEB
		mov eax, [eax + 0x0c];	//��ȡPEB_LDR
		mov eax, [eax + 0x1c];	//��ȡIninitalizationOrderModuleList����
		mov eax, [eax];			//��ȡKernel32.dll/Kerbase.dll
		mov eax, [eax + 0x08];	//��ȡģ���ַ
		mov hKernel, eax		//����ģ���ַ
		pop eax;				//�ָ��Ĵ���
	}

	//ͨ��Hash��ȡ��ַ
	pfnGetProcAddress = pGetProceAddress(FindFunByHash(hKernel, 0xbbafdf85));	

	//��ȡLoadLibraryExA
	pfnLoadLibraryExA = (pLoadLibraryExA)(FindFunByHash(hKernel, 0xc0d83287));


	//��ȡVirtualProtectEx
	pfnVirtualProtect = (pVirtualProtect)(FindFunByHash(hKernel, 0xef64a41e));
	//��ȡGetModuleHandleA
	pfnGetModuleHandleA = (pGetModuleHandleA)(FindFunByHash(hKernel, 0xf4e2f2b2));
	//��ȡVirtualAlloc
	pfnVirtualAlloc = (pVirtualAlloc)(FindFunByHash(hKernel, 0x1ede5967));

	//��ȡ��ַ
	g_hModule = (DWORD)pfnGetModuleHandleA(NULL);
	
	pfnExitProcess = (pExitProcess)(FindFunByHash(hKernel, 0x4fd18963));
	pfnGetVolumeInformationA = (pGetVolumeInformationA)(FindFunByHash(hKernel, 0x7666caec));

	//char strKer32[15] = { 0x4B, 0x65, 0x72, 0x6E, 0x65, 0x6C, 0x33, 0x32, 0x2E, 0x64, 0x6C, 0x6C, 0x00 };
	//HMODULE hKer32 = pfnLoadLibraryExA(strKer32, 0, 0);
	
	pfnGetCurrentProcess = (pGetCurrentProcess)(FindFunByHash(hKernel, 0x3a2fe6bb));
	pfnGetCurrentThread=(pGetCurrentThread)(FindFunByHash(hKernel, 0x8ffb3b6e));

	char strNtdll[10] = {0x4E, 0x74, 0x64, 0x6C, 0x6C, 0x2E, 0x64, 0x6C, 0x6C,0x00};
	HMODULE hNt = pfnLoadLibraryExA(strNtdll, 0, 0);

	pfnNtQueryInformationProcess = (pNtQueryInformationProcess)(FindFunByHash(hNt, 0x72aab605));
	pfnNtQuerySystemInformation = (pNtQuerySystemInformation)(FindFunByHash(hNt, 0xeffc1dbe));
	pfnNtQueryObject = (pNtQueryObject)(FindFunByHash(hNt, 0x0db59c8a));

	//pfnNtQueryInformationProcess = (pNtQueryInformationProcess)(FindFunByHash(hNt, 0xe6aab603));
	//pfnNtQuerySystemInformation = (pNtQuerySystemInformation)(FindFunByHash(hNt, 0xeffc1cf8));
	//pfnNtQueryObject = (pNtQueryObject)(FindFunByHash(hNt, 0x0db59c8a));
	pfnZwSetInformationThread = (pZwSetInformationThread)(FindFunByHash(hNt, 0x3d83d869));
	
	//char strCore[12] = {0x63, 0x6F, 0x72, 0x65, 0x64, 0x6C, 0x6C, 0x2E, 0x64, 0x6C, 0x6C, 0x00};
	//HMODULE hCore = pfnLoadLibraryExA(strCore, 0, 0);
	
	//�����ַ���
	char strDllUser[11] = {0x55, 0x73, 0x65, 0x72, 0x33, 0x32, 0x2E, 0x64, 0x6C, 0x6C, 0x00};
	//����User32
	HMODULE hUser = pfnLoadLibraryExA(strDllUser, 0, 0);
	//��ȡMessageBoxA
	pfnMessageBoxA = (pMessageBoxA)(FindFunByHash(hUser, 0x1e380a6a));
	pfnGetWindowThreadProcessId=(pGetWindowThreadProcessId)(FindFunByHash(hUser, 0xa0667fbe));
	//��ȡ������غ���
	pfnRegisterClassA= (pRegisterClassA)(FindFunByHash(hUser, 0x0bc05e32));
	pfnCreateWindowExA= (pCreateWindowExA)(FindFunByHash(hUser, 0x1fdaf55b));
	pfnShowWindow = (pShowWindow)(FindFunByHash(hUser, 0xdd8b5fb8));
	pfnGetMessageA = (pGetMessageA)(FindFunByHash(hUser, 0x6106044b));
	pfnFindWindowA=(pFindWindowA)(FindFunByHash(hUser, 0x3db19602));

	pfnTranslateMessage = (pTranslateMessage)(FindFunByHash(hUser, 0xe09980a2));	
	pfnDispatchMessageA = (pDispatchMessageA)(FindFunByHash(hUser, 0x7a1506c2));
	pfnGetDlgItemTextA = (pGetDlgItemTextA)(FindFunByHash(hUser, 0x1584c411));	
	pfnPostQuitMessage = (pPostQuitMessage)(FindFunByHash(hUser, 0xcaa94781));	
	pfnDefWindowProcA = (pDefWindowProcA)(FindFunByHash(hUser, 0x22e85ca4));	
	

	return;
}

DWORD FindFunByHash(HMODULE dwImageBase,DWORD dwHash)
{
	//��ȡPE��Ϣ
	PIMAGE_DOS_HEADER pDos = GetDosHeader((PBYTE)dwImageBase);						  //DOSͷ
	PIMAGE_NT_HEADERS pNt = GetNtHeader((PBYTE)dwImageBase);						  //NTͷ
	PIMAGE_FILE_HEADER pFile = GetFileHeader((PBYTE)dwImageBase);					  //FILEͷ
	PIMAGE_OPTIONAL_HEADER pOpt = GetOptionalHeader((PBYTE)dwImageBase);			  //OPͷ
																					  //��ȡEAT/ENT/EOT																
	PIMAGE_EXPORT_DIRECTORY pExport = (PIMAGE_EXPORT_DIRECTORY)
		((PBYTE)dwImageBase + *(PDWORD)((PBYTE)pNt + 0x78));						   //EXPORT	
	PDWORD pENT = (PDWORD)((PBYTE)dwImageBase + pExport->AddressOfNames);			  //ENT
	PDWORD pEAT = (PDWORD)((PBYTE)dwImageBase + pExport->AddressOfFunctions);		  //EAT
	PWORD pEOT = (PWORD)((PBYTE)dwImageBase + pExport->AddressOfNameOrdinals);		  //EOT//���ΪWORD

	DWORD dwOrdinalName = 0;
	// ����ENT
	for (DWORD i = 0; i < pExport->NumberOfNames; i++)
	{
		char* pName = pENT[i] + (char*)dwImageBase;
		
		//����Hash
		DWORD dwNameHash = FunHash(pName);
		
		if (dwNameHash == dwHash)
		{
			dwOrdinalName = i;
			break;
		}
	}

	//��ȡ��ַ���
	WORD dwOrdinal = pEOT[dwOrdinalName];

	DWORD dwFunAddress = (DWORD)(pEAT[dwOrdinal] + (PBYTE)dwImageBase);
		
	//ʹ���Զ����ַ��������Ա�//����������ʵ��
	char pTempDll[MAX_PATH] = { 0 };
	MyStrcpy_s(pTempDll, MAX_PATH, (char*)dwFunAddress);

	//�ȶ��Ƿ����'.'
	char *pDot = strchr(pTempDll, '.');
	if (!pDot)
	{
		return dwFunAddress;
	}

	*pDot = 0;
	//�ָ��ַ���
	char pTempFuction[MAX_PATH] = { 0 };
	char strDll[5] = {0x2E, 0x64, 0x6C, 0x6C, 0x00};

	MyStrcpy_s(pTempFuction, MAX_PATH, pDot + 1);
	strcat_s(pTempDll, MAX_PATH, strDll);

	//��ȡģ���ַ
	HMODULE hDll = pfnLoadLibraryExA(pTempDll,0,0);	//���е�����ʱ�Ѿ���ȡ����pfnLoadLibraryExA��ַ

	if (hDll == NULL)
	{
		return dwFunAddress;
	}
	//����Hash
	DWORD dwNameHash = FunHash(pTempFuction);
	DWORD dwNewFunAddress = FindFunByHash(hDll,dwNameHash);

	return dwNewFunAddress;

}


//���������ܳ���
void Decode()
{	

	LPBYTE pData = (PBYTE)g_hModule + g_Conf.dwEncodeDataRva;

	//�޸Ĵ��������
	DWORD dwOldPro=0;
	pfnVirtualProtect(pData, g_Conf.dwEncodeDataSize, PAGE_READWRITE, &dwOldPro);

	//���ܴ���
	for (DWORD i = 0; i < g_Conf.dwEncodeDataSize; i++)
	{
		pData[i] ^= i;
		pData[i] ^= g_Conf.dwEncodeKey;
	}

	//�ָ����������
	pfnVirtualProtect(pData, g_Conf.dwEncodeDataSize, dwOldPro, &dwOldPro);
}

//�޸��ض�λ
void Reloc()
{
	PBYTE pData = (PBYTE)g_hModule;
	//�ҵ��ض�λ��
	PIMAGE_BASE_RELOCATION pSrcReloc = NULL;
	//��ȡ�����ض�λ�����RVA
	DWORD dwRelocRva = g_Conf.dwRelocRva;
	//û���ض�λ��Ϣ�ͽ���
	if (!dwRelocRva)
		return;

	pSrcReloc = (PIMAGE_BASE_RELOCATION)(pData + dwRelocRva);

	//������Ϣ//����ж��Ƿ�dll�ļ�����ַΪ0x1000 0000;//���߶�ȡ�����ļ�PEͷ
	DWORD dwOldImageBase = 0x400000;
	
	//�޸�stub
	while (pSrcReloc->SizeOfBlock != 0)
	{
		//��ȡ�ض�λ����
		DWORD dwCount = (pSrcReloc->SizeOfBlock - 8) / 2;
		//��ȡ��һ��
		PTYPEOFFSET pTypeOffset = (PTYPEOFFSET)(pSrcReloc + 1);
		
		//�޸��ڴ�����
		DWORD dwOldProt = 0;
		pfnVirtualProtect(pData+ pSrcReloc->VirtualAddress, 1, PAGE_READWRITE, &dwOldProt);

		//ѭ���޸�
		for (DWORD i = 0; i < dwCount; i++)
		{
			//�ض�λ����3
			if (pTypeOffset[i].Type == 3)
			{
				//��ȡ�ض�λ��RVA
				DWORD dwRva = pTypeOffset[i].Offset + pSrcReloc->VirtualAddress;

				//��ȡҪ�޸ĵ����ݡ�ȡ���ݡ�
				PDWORD pFixData = (PDWORD)(dwRva + pData);

				//��ȥ�ɻ�ַ
				*pFixData -= (DWORD)dwOldImageBase;
				
				//�����»�ַ
				*pFixData += (DWORD)pData;
			}
			
		}	
		//�ָ��ڴ�����
		pfnVirtualProtect(pData + pSrcReloc->VirtualAddress, 1, dwOldProt, &dwOldProt);
		
		//�޸���һ���ض�λ����
		pSrcReloc = (PIMAGE_BASE_RELOCATION)((LPBYTE)pSrcReloc + pSrcReloc->SizeOfBlock);
	}


	return;
}

//���㺯������HASH
DWORD FunHash(const char* FunName)
{
	DWORD dwDigest = 0;
	while (*FunName)
	{
		dwDigest = ((dwDigest << 25) | (dwDigest >> 7));
		dwDigest += *FunName;
		FunName++;
	}
	return dwDigest;
}


//�޸�IAT
void RecIAT()
{
	//�ж��Ƿ���ڵ����
	if (!g_Conf.dwImportRva)
	{
		return ;
	}

	//������ת����
	BYTE bJmpByte[] = {
		0xe8, 0x01, 0x00, 0x00, 0x00, 0xe9, 0x58, 0xeb, 0x01, 0xe8, 0xb8, 0x11, 0x11, 0x11, 0x11, 0xeb,
		0x01, 0x15, 0x35, 0x16, 0x16, 0x16, 0x16, 0xeb, 0x01, 0xff, 0x50, 0xeb, 0x02, 0xff, 0x15, 0xc3 };

	//��ȡԭINT��ַ
	PIMAGE_IMPORT_DESCRIPTOR pImport = (PIMAGE_IMPORT_DESCRIPTOR)(g_hModule + g_Conf.dwImportRva);

	//���ѭ������ģ��
	while (pImport->Name)
	{
		//��ȡ����INT
		PIMAGE_THUNK_DATA32 pThunkINT = (PIMAGE_THUNK_DATA32)(g_hModule+ pImport->OriginalFirstThunk);
		//��ȡ����IAT
		PIMAGE_THUNK_DATA32 pThunkIAT = (PIMAGE_THUNK_DATA32)(g_hModule + pImport->FirstThunk);

		//��ȡDLLģ������
		char *DllName = (CHAR*)(g_hModule + pImport->Name);

		//����DLLģ��
		HMODULE hDllModule = pfnLoadLibraryExA(DllName, 0, 0);

		//��ȡģ�� EAT
		PIMAGE_NT_HEADERS pDLLNt = GetNtHeader((PBYTE)hDllModule);						 //NTͷ
		PIMAGE_EXPORT_DIRECTORY pDLLExport = (PIMAGE_EXPORT_DIRECTORY)
			((PBYTE)hDllModule + *(PDWORD)((PBYTE)pDLLNt + 0x78));						 //EXPORT	
		PDWORD pDLLEAT = (PDWORD)((PBYTE)hDllModule + pDLLExport->AddressOfFunctions);	 //EAT
		
		//�޸��ڴ�����
		DWORD dwOldProt = 0;
		pfnVirtualProtect(pThunkIAT, 1, PAGE_READWRITE, &dwOldProt);

		//�ڲ�ѭ������ģ���еĺ���
		while (pThunkINT->u1.AddressOfData)
		{
			//����Ƿ����
			bool IsOrdinal= (pThunkINT->u1.AddressOfData & 0xFFFF0000) == 0;
			DWORD dwFunAddress = 0;
			if (IsOrdinal)
			{
				//ͨ����ŵõ�������ַ,��Ҫ��DLL��ַ
				dwFunAddress = (DWORD)(pDLLEAT[pThunkINT->u1.Ordinal] + (PBYTE)hDllModule);				
			}
			//��������
			else
			{
				//ͨ��Hash��ȡ������ַ
				dwFunAddress = FindFunByHash(hDllModule, pThunkINT->u1.AddressOfData);
			}

			//����ռ�ʵ��IAT��ת
			PBYTE pNewAddr= (PBYTE)pfnVirtualAlloc(0, sizeof(bJmpByte), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
			
			//������Կ
			DWORD dwIATKey = g_Conf.dwEncodeKey;
			IATKey(&dwIATKey);
			
			//�滻��Կ
			PDWORD pKey = (PDWORD)&(bJmpByte[19]);
			*pKey = dwIATKey;

			//�滻��ַ
			PDWORD pAddr = (PDWORD)&(bJmpByte[11]);
			*pAddr = dwFunAddress ^ dwIATKey;
			
			//��������
			memcpy(pNewAddr, bJmpByte, sizeof(bJmpByte));
			//����IAT
			pThunkIAT->u1.AddressOfData = (DWORD)pNewAddr;

			//��һ��INT			
			pThunkINT++;
			pThunkIAT++;		
		}

		//�ָ��ڴ�����
		pfnVirtualProtect(pThunkIAT, 1, dwOldProt, &dwOldProt);

		//��һ�������
		pImport++;
	}

}

//����ʵ���ַ�����������
void MyStrcpy_s(char* strDes, size_t szNumber,const char* strSrc)
{
	if (strDes == 0
		|| strSrc == 0
		|| szNumber == 0)
		return;

	for (size_t i=0;i<szNumber-1;i++)
	{
		if (strSrc[i] == 0)
			break;
		strDes[i] = strSrc[i];
	}	
}


//SDK����������
int WINAPI StubMain(
	_In_ HINSTANCE hInstance,
	_In_opt_ HINSTANCE hPrevInstance,
	_In_ LPSTR lpCmdLine,
	_In_ int nShowCmd) {

	//ע�ᴰ����
	WNDCLASSA wcsStub = {};
	wcsStub.style = CS_HREDRAW | CS_VREDRAW;

	char WinName[6] = {	0x53, 0x74, 0x75, 0x62, 0x00};

	wcsStub.lpszClassName = WinName;
	wcsStub.hbrBackground = (HBRUSH)COLOR_BTNSHADOW;
	wcsStub.hInstance = hInstance;
	wcsStub.lpfnWndProc = StubProc;
	pfnRegisterClassA(&wcsStub);



	//��������
	char cTitle[20] = { 0xd2, 0xfe, 0xdf, 0xf1, 0xdd, 0xfe, 0xa3, 0xc1, 0xc6, 0xb3, 0xc5, 0xe7, 0xd4, 0xc5, 0xaf, 0xd0,	0x00 };
	StrDecode(cTitle);
	
	HWND hWnd = pfnCreateWindowExA(
		NULL,
		WinName,
		cTitle,
		WS_OVERLAPPEDWINDOW,
		500, 300, 400, 150,
		NULL,
		NULL,
		hInstance,
		NULL);

	StrDecode(cTitle);
	
	pfnShowWindow(hWnd, SW_SHOW);

	MSG msg = {};
		
	//��Ϣѭ��
	while (pfnGetMessageA(&msg, 0, 0, 0))
	{	
		pfnTranslateMessage(&msg);//��Ϣת��

		pfnDispatchMessageA(&msg);//��Ϣ�ַ�
	}

	pfnShowWindow(hWnd, SW_HIDE);

	return 0;
}


LRESULT CALLBACK StubProc(
	_In_ HWND   hwnd,
	_In_ UINT   uMsg,
	_In_ WPARAM wParam,
	_In_ LPARAM lParam) {


	switch (uMsg) {

		int wmId, wmEvent;

		char PwdIn[MAX_PATH];
		memset(PwdIn, 0, MAX_PATH);

		//��ʼ��
	case WM_CREATE:
	{
		//��ȡ������
		GetMachineCode(g_strPwd);

		//������ť
		char cBtn[8] = {0x42, 0x75, 0x74, 0x74, 0x6F, 0x6E, 0x00};
		char cBtnTitle[6] = {0xc8, 0xb7, 0xb6, 0xa8, 0x00 };
		HWND hBtn = pfnCreateWindowExA(
			NULL,					//dwExStyle ��չ��ʽ
			cBtn,					//lpClassName ��������
			cBtnTitle,				//lpWindowName ���ڱ���
			WS_CHILD | WS_VISIBLE,	//dwStyle ������ʽ
			300,					//x 
			40,						//y 
			50,						//nWidth ���
			30,						//nHeight �߶�
			hwnd,					//hWndParent �����ھ��
			(HMENU)IDB_BUTTON_OK,	//ID
			pfnGetModuleHandleA(0),	//hInstance Ӧ�ó�����
			NULL					//lpParam ���Ӳ���
		);


		//�����༭��
		char cEdit[8] = {0x45, 0x64, 0x69, 0x74, 0x00};
		HWND hPwd = pfnCreateWindowExA(
			NULL,
			cEdit,
			g_strPwd,
			WS_CHILD | WS_VISIBLE | WS_BORDER,
			25,
			40,
			250,
			30,
			hwnd,
			(HMENU)IDB_EDIT_PWD,
			pfnGetModuleHandleA(0),
			NULL
		);
	}
	break;
	case WM_PAINT:
		break;

		//��������
	case WM_COMMAND:
	{
		wmId = LOWORD(wParam);
		wmEvent = HIWORD(wParam);

		//����ȷ����ť
		if (wmId == IDB_BUTTON_OK)
		{
			//��ȡ����
			pfnGetDlgItemTextA(hwnd, IDB_EDIT_PWD, g_strPwdIn, MAX_PATH);
			pfnPostQuitMessage(0);
		}

	}
	break;
	case WM_CLOSE:	
		pfnExitProcess(0);	
		break;
	case WM_QUIT:			
		break;
	default:
		break;
	}	

	return pfnDefWindowProcA(hwnd, uMsg, wParam, lParam);
}



void GetMachineCode(char *StrSerial)
{
	char    Volume[256];//�����  
	char    FileSysName[256];
	DWORD   SerialNum;//���к�  
	DWORD   FileNameLength;
	DWORD   FileSysFlag;
	char cDiskC[5] = {0x63, 0x3A, 0x5C, 0x00};
	pfnGetVolumeInformationA(cDiskC,
		Volume,
		256,
		&SerialNum,
		&FileNameLength,
		&FileSysFlag,
		FileSysName,
		256);

	if (SerialNum == 0)
	{
		//���������
		DWORD dwError = 0xFFFFFFFF;
		_itoa_s(dwError, StrSerial, MAX_PATH,16);

		return;
	}

	//���������
	DWORD dwMCode1 = SerialNum ^ 0x15151515;

	DWORD dwMCode2 = ~SerialNum;
	DWORD dwMCode3 = dwMCode2 << 16;
	DWORD dwMCode4 = dwMCode2 >> 16;

	DWORD dwMCode5 = dwMCode3 | dwMCode4;

	DWORD dwMCode6 = dwMCode1 & dwMCode5;

	g_dwMcode1 = dwMCode1;
	g_dwMcode2 = dwMCode5;
	g_dwMcode3 = dwMCode6;


	//ת���ַ���
	char McodeTemp1[MAX_PATH];
	char McodeTemp2[MAX_PATH];
	char McodeTemp3[MAX_PATH];
	
	_itoa_s(dwMCode1, McodeTemp1,MAX_PATH, 16);
	_itoa_s(dwMCode5, McodeTemp2, MAX_PATH, 16);
	_itoa_s(dwMCode6, McodeTemp3, MAX_PATH, 16);
		
	//ƴ��
	strcat_s(McodeTemp1, MAX_PATH, McodeTemp2);
	strcat_s(McodeTemp1, MAX_PATH, McodeTemp3);
	
	//ת����д
	for (int i=0; McodeTemp1[i];i++)
	{
		McodeTemp1[i]=toupper(McodeTemp1[i]);
	}

	strcpy_s(StrSerial, MAX_PATH, McodeTemp1);

	return;
}


void GetLisence(char *strlisence)
{
	g_dwMcode1 |= 0x14141414;
	g_dwMcode2 ^= 0x15151515;
	g_dwMcode3 |= 0x16161616;

	//ת���ַ���
	char McodeTemp1[MAX_PATH];
	char McodeTemp2[MAX_PATH];
	char McodeTemp3[MAX_PATH];

	_itoa_s(g_dwMcode1, McodeTemp1, MAX_PATH, 16);
	_itoa_s(g_dwMcode2, McodeTemp2, MAX_PATH, 16);
	_itoa_s(g_dwMcode3, McodeTemp3, MAX_PATH, 16);
	
	strcat_s(McodeTemp1, MAX_PATH, McodeTemp2);
	strcat_s(McodeTemp1, MAX_PATH, McodeTemp3);
	
	//ת����д
	for (int i = 0; McodeTemp1[i]; i++)
	{
		McodeTemp1[i] = toupper(McodeTemp1[i]);
	}

	strcpy_s(strlisence, MAX_PATH, McodeTemp1);
}


//��֤����
void CmpLisence()
{
	//��������
	char Pwd[MAX_PATH] = { 0 };
	GetLisence(Pwd);
	//�ȶ�
	if (strcmp(Pwd, g_strPwdIn))
		pfnExitProcess(0);
}

void StrDecode(char* FunName)
{
	if (!FunName)
		return;

	for (int i=0;FunName[i];i++)
	{
		FunName[i] ^= g_Conf.dwEncodeKey;
	}
}

//��dump���޸�PEͷ����
void AntiDump() 
{
	//��ȡPE��Ϣ
	PIMAGE_DOS_HEADER pDos = GetDosHeader((PBYTE)g_hModule);					  //DOSͷ
	PIMAGE_NT_HEADERS pNt = GetNtHeader((PBYTE)g_hModule);						  //NTͷ
	PIMAGE_FILE_HEADER pFile = GetFileHeader((PBYTE)g_hModule);					  //FILEͷ
	PIMAGE_OPTIONAL_HEADER pOpt = GetOptionalHeader((PBYTE)g_hModule);			  //OPͷ
																					  //�޸Ĵ��������
	DWORD dwOldPro = 0;
	pfnVirtualProtect((LPVOID)g_hModule, 0x200, PAGE_READWRITE, &dwOldPro);

	//�޸�PE��Ϣ
	//pDos->e_magic = 0;

	//pNt->Signature = 0;


	pFile->SizeOfOptionalHeader = 0;
	pFile->NumberOfSections = 0;
	pFile->Characteristics = 0;


	pOpt->BaseOfCode = 0;
	pOpt->BaseOfData = 0;
	pOpt->ImageBase = 0;
	pOpt->SizeOfImage = 0;
	pOpt->SizeOfHeaders = 0;
		
	pfnVirtualProtect((LPVOID)g_hModule, 0x200, dwOldPro, &dwOldPro);

}

void IATKey(PDWORD dwKey)
{
	DWORD dwTempKey = 0;
	PBYTE pbTempKey = (PBYTE)&dwTempKey;
	PWORD pwTempKey = (PWORD)&dwTempKey;
	//��ԿС��0xFF
	if (*dwKey<=0xFF)
	{
		pbTempKey[0] = *dwKey;
		pbTempKey[1] = *dwKey;
		pbTempKey[2] = *dwKey;
		pbTempKey[3] = *dwKey;		
	}
	//��ԿС��0xFFFF
	else if(*dwKey> 0xFF&& *dwKey<=0xFFFF)
	{
		pbTempKey[0] = *dwKey;
		pbTempKey[1] = *dwKey;
	}
	//��Կ����0xFFFF
	else
	{
		dwTempKey= *dwKey;
	}

	*dwKey = dwTempKey;
}

void RelTLS() 
{	
	//��ȡPE��Ϣ
	PIMAGE_OPTIONAL_HEADER pOpt = GetOptionalHeader((PBYTE)g_hModule);			  //OPͷ

	//�������TLS����
	if (g_Conf.dwTLSCallbacks)
	{
		PIMAGE_TLS_DIRECTORY pDirTls =(PIMAGE_TLS_DIRECTORY)
			(pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress + g_hModule);

		//�޸��ڴ�����
		DWORD dwOldProt = 0;
		pfnVirtualProtect((LPVOID)(pDirTls), 4, PAGE_READWRITE, &dwOldProt);
		//�ָ�TLS
		pDirTls->AddressOfCallBacks = g_Conf.dwTLSCallbacks+ g_hModule;		

		pfnVirtualProtect((LPVOID)(pDirTls->AddressOfCallBacks), 4, dwOldProt, &dwOldProt);

		PIMAGE_TLS_CALLBACK* pTLSFun = (PIMAGE_TLS_CALLBACK*)pDirTls->AddressOfCallBacks;		
		//ģ�����
		while (*pTLSFun)
		{			
			(*pTLSFun)((PVOID)g_hModule, DLL_PROCESS_ATTACH, NULL);
			(*pTLSFun)((PVOID)g_hModule, DLL_THREAD_ATTACH, NULL);
			
			pTLSFun++;
		}
	}		
}

//������������
bool CheckDebug()
{
	if (CheckDebugBegin()
		|| CheckDebugGlobal()
		|| CheckDebugNtQ1()
		|| NQIP_CheckParentProcess())
		return true;
	else
		return false;	
}


//���BegingDebug
bool CheckDebugBegin()
{
	bool bDebuging = false;
	_asm push eax;
	_asm mov eax, fs:[0x30];
	_asm mov al, byte ptr ds : [eax + 2];
	_asm mov  bDebuging, al;
	_asm pop eax
	return bDebuging;
}

//���NtGlobalFlag
bool CheckDebugGlobal()
{
	DWORD dwSign = 0;
	_asm push eax;
	_asm mov eax, fs:[0x30];
	_asm mov eax, [eax + 0x68];
	_asm mov dwSign, eax;
	_asm pop eax
	return dwSign == 0x70;
}

bool CheckDebugNtQ1()
{
	int nDebugPort = 0;
	pfnNtQueryInformationProcess(
		pfnGetCurrentProcess(),
		ProcessDebugPort,
		&nDebugPort,
		sizeof(nDebugPort),
		NULL);
	return nDebugPort == -1;
}


/*XX
bool CheckDebugNtQ2()
{
	HANDLE nDebugPort = 0;
	pfnNtQueryInformationProcess(
		GetCurrentProcess(),
		(PROCESSINFOCLASS)0x1E,
		&nDebugPort,
		sizeof(nDebugPort),
		NULL);
	return nDebugPort == NULL ? false : true;
}
*/
/*
xx
bool CheckDebugNtQ3()
{
	DWORD nDebugFlag = 0;
	pfnNtQueryInformationProcess(
		GetCurrentProcess(),
		(PROCESSINFOCLASS)0x1F,//DebugFlag
		&nDebugFlag,
		sizeof(nDebugFlag),
		NULL);
	return nDebugFlag == 0 ? true : false;
}

*/

bool NQIP_CheckParentProcess()
{
	struct PROCESS_BASIC_INFORMATION {
		ULONG ExitStatus; 			 // ���̷�����
		PPEB  PebBaseAddress; 		 // PEB��ַ
		ULONG AffinityMask; 		 // CPU�׺�������
		LONG  BasePriority; 		 // �������ȼ�
		ULONG UniqueProcessId; 		 // ������PID
		ULONG InheritedFromUniqueProcessId; // ������PID
	}stcProcInfo;

	pfnNtQueryInformationProcess(
		pfnGetCurrentProcess(),
		ProcessBasicInformation, //�鿴��������PID
		&stcProcInfo,
		sizeof(stcProcInfo), NULL
	);

	DWORD ExplorerPID = 0;
	DWORD CurrentPID = stcProcInfo.InheritedFromUniqueProcessId;
	char strExplorer[10] = {0x50, 0x72, 0x6F, 0x67, 0x6D, 0x61, 0x6E, 0x00};
	pfnGetWindowThreadProcessId(pfnFindWindowA(strExplorer, NULL), &ExplorerPID);
	
	return ExplorerPID == CurrentPID ? false : true;
}

//���������
void DetachDebug()
{
	pfnZwSetInformationThread(pfnGetCurrentThread(), ThreadHideFromDebugger, NULL, NULL);
}
/*

bool CheckDebugNtQ4()
{
	struct _SYSTEM_KERNEL_DEBUGGER_INFORMATION {
		BOOLEAN DebuggerEanbled;
		BOOLEAN DebuggerNotPresent;
	}DebuggerInfo = { 0 };

	pfnNtQuerySystemInformation(
		(SYSTEM_INFORMATION_CLASS)0x23,
		&DebuggerInfo,
		sizeof(DebuggerInfo),
		NULL);
	//�ܹ���⵱ǰ����ϵͳ�Ƿ��ڵ���ģʽ��
	//���ڵ���ģʽ�����ܵ�ǰ���ڽ����ں˵��ԣ�Windbg);
	return DebuggerInfo.DebuggerEanbled;
}

*/
/*

bool CheckDebugNtQ5()
{
	typedef struct _OBJECT_TYPE_INFORMATION {
		UNICODE_STRING TypeName;
		ULONG TotalNumberOfHanders;
		ULONG TotalNumberOfObjects;
	}OBJECT_TYPE_INFORMATION, *POBJECT_TYPE_INFORMATION;

	typedef struct _OBJECT_ALL_INFORMATION {
		ULONG NumberOfObjectsTypes;
		OBJECT_TYPE_INFORMATION ObjectTypeInfo[1];
	}OBJECT_ALL_INFORMATION, *POBJECT_ALL_INFORMATION;

	// 1. ��ȡ����ѯ��Ϣ��С
	ULONG uSize = 0;
	pfnNtQueryObject(NULL,
		(OBJECT_INFORMATION_CLASS)0x03,
		&uSize,
		sizeof(uSize),
		&uSize);

	// 2. ��ȡ������Ϣ
	POBJECT_ALL_INFORMATION pObjectAllInfo = (POBJECT_ALL_INFORMATION)malloc(uSize);

	pfnNtQueryObject(NULL,
		(OBJECT_INFORMATION_CLASS)0x03,
		pObjectAllInfo,
		uSize,
		&uSize);

	// 3. ѭ�����������������Ϣ
	POBJECT_TYPE_INFORMATION pObjTypeInfo = pObjectAllInfo->ObjectTypeInfo;

	for (int i = 0; i < pObjectAllInfo->NumberOfObjectsTypes; i++)
	{
		// 3.1 �鿴�˶���������Ƿ�ΪDebugObject������Ҫ�ж϶��������������0��˵���е��Զ���
		if (!wcscmp(L"DebugObject", pObjTypeInfo->TypeName.Buffer))
			return true;
		// 3.2 ��ȡ������ռ�ÿռ�Ĵ�С�����ǵ��˽ṹ��������⣩
		ULONG uNameLength = pObjTypeInfo->TypeName.Length;
		ULONG uDataLength = uNameLength - uNameLength % sizeof(ULONG) + sizeof(ULONG);
		// 3.3 ָ����һ��������Ϣ
		pObjTypeInfo = (POBJECT_TYPE_INFORMATION)pObjTypeInfo->TypeName.Buffer;
		pObjTypeInfo = (POBJECT_TYPE_INFORMATION)((PBYTE)pObjTypeInfo + uDataLength);
	}
	delete[] pObjectAllInfo;
	return false;
}
*/
