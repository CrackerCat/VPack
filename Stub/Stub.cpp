
//头文件
#include "stdio.h"
#include <windows.h>
#include "StubConf.h"


//全局变量
DWORD g_hModule=0;					//被加壳程序的基址
_declspec(thread) int g_nTls;		//TLS变量
DWORD g_dwFused = 10;				//混淆
DWORD g_dwMcode1 = 0;				//机器码1
DWORD g_dwMcode2 = 0;				//机器码2
DWORD g_dwMcode3 = 0;				//机器码3
char g_strPwd[MAX_PATH] = { 0 };	//正确密码
char g_strPwdIn[MAX_PATH] = { 0 };	//输入密码

//全局函数指针
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

//导出函数
extern "C"
{
	__declspec(dllexport)  STUBCONF g_Conf;						//导出配置函数

	__declspec(dllexport)  void __declspec(naked) PackStup()	//Stub主函数
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


//函数实现
//////////////////////////////////////////////////////////////////
// 
// //TLS函数
/*
__declspec(thread) char g_strTLS[5] = { 0x53, 0x4C, 0x53, 0x00 };
void NTAPI t_TlsCallBack_A(PVOID DllHandle, DWORD Reason, PVOID Red){__asm {add g_strTLS,0x01};}
#pragma data_seg(".CRT$XLB")
PIMAGE_TLS_CALLBACK p_thread_callback[] = {t_TlsCallBack_A,	NULL};
#pragma data_seg()*/


void StubStart()
{
	//递归混淆
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

	//得到API
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
	
	//主动脱离调试
	DetachDebug();
	
	//弹出窗口	
	StubMain((HINSTANCE)g_hModule, NULL, NULL, NULL);

	//多次对比密码
	FusedFunc((DWORD)CmpLisence);


	//解密代码
	FusedFunc((DWORD)Decode);

	//多次对比密码
	//FusedFunc((DWORD)CmpLisence);

	//修复重定位
	FusedFunc((DWORD)Reloc);

	//多次对比密码
	//FusedFunc((DWORD)CmpLisence);

	//修复IAT
	FusedFunc((DWORD)RecIAT);

	//多次对比密码
	//FusedFunc((DWORD)CmpLisence);

	//修复TLS
	FusedFunc((DWORD)RelTLS);

	//多次对比密码
	//FusedFunc((DWORD)CmpLisence);

	//反dump
	FusedFunc((DWORD)AntiDump);

	//多次对比密码
	//FusedFunc((DWORD)CmpLisence);
}


void _stdcall FusedFunc(DWORD funcAddress)
{

	_asm
	{
		jmp label1
		label2 :
		_emit 0xeb; //跳到下面的call
		_emit 0x04;
		CALL DWORD PTR DS : [EAX + EBX * 2 + 0x123402EB]; //执行EB 02  也就是跳到下一句

														  //call Init;// 获取一些基本函数的地址

														  //call下一条,用于获得eip
		_emit 0xE8;
		_emit 0x00;
		_emit 0x00;
		_emit 0x00;
		_emit 0x00;
		//-------跳到下面的call
		_emit 0xEB;
		_emit 0x0E;

		//花
		PUSH 0x0;
		PUSH 0x0;
		MOV EAX, DWORD PTR FS : [0];
		PUSH EAX;
		//花

		CALL DWORD PTR DS : [EAX + EBX * 2 + 0x5019C083];

		push funcAddress; //这里如果是参数传入的需要注意上面的add eax,??的??
		retn;

		jmp label3
		// 花
		_emit 0xE8;
		_emit 0x00;
		_emit 0x00;
		_emit 0x00;
		_emit 0x00;
		// 花

	label1:
		jmp label2
			label3 :
	}

}


//获取DOS头
PIMAGE_DOS_HEADER GetDosHeader(PBYTE hModule)
{
	return (PIMAGE_DOS_HEADER)hModule;
}


//获取NT头
PIMAGE_NT_HEADERS GetNtHeader(PBYTE hModule)
{
	return (PIMAGE_NT_HEADERS)(hModule + *(PDWORD)(hModule + 0x3C));
}

//获取文件头
PIMAGE_FILE_HEADER GetFileHeader(PBYTE hModule)
{
	return (PIMAGE_FILE_HEADER)&(GetNtHeader(hModule)->FileHeader);
}

//获取扩展头

PIMAGE_OPTIONAL_HEADER GetOptionalHeader(PBYTE hModule)
{
	return (PIMAGE_OPTIONAL_HEADER)&(GetNtHeader(hModule)->OptionalHeader);
}

//获取API
void GetAPI()
{
	g_nTls;

	HMODULE hKernel;
	//获取模块基址
	__asm
	{
		push eax;				//保存寄存器
		mov eax, fs:[0x30];		//获取PEB
		mov eax, [eax + 0x0c];	//获取PEB_LDR
		mov eax, [eax + 0x1c];	//获取IninitalizationOrderModuleList链表
		mov eax, [eax];			//获取Kernel32.dll/Kerbase.dll
		mov eax, [eax + 0x08];	//获取模块基址
		mov hKernel, eax		//保存模块基址
		pop eax;				//恢复寄存器
	}

	//通过Hash获取地址
	pfnGetProcAddress = pGetProceAddress(FindFunByHash(hKernel, 0xbbafdf85));	

	//获取LoadLibraryExA
	pfnLoadLibraryExA = (pLoadLibraryExA)(FindFunByHash(hKernel, 0xc0d83287));


	//获取VirtualProtectEx
	pfnVirtualProtect = (pVirtualProtect)(FindFunByHash(hKernel, 0xef64a41e));
	//获取GetModuleHandleA
	pfnGetModuleHandleA = (pGetModuleHandleA)(FindFunByHash(hKernel, 0xf4e2f2b2));
	//获取VirtualAlloc
	pfnVirtualAlloc = (pVirtualAlloc)(FindFunByHash(hKernel, 0x1ede5967));

	//获取基址
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
	
	//定义字符串
	char strDllUser[11] = {0x55, 0x73, 0x65, 0x72, 0x33, 0x32, 0x2E, 0x64, 0x6C, 0x6C, 0x00};
	//载入User32
	HMODULE hUser = pfnLoadLibraryExA(strDllUser, 0, 0);
	//获取MessageBoxA
	pfnMessageBoxA = (pMessageBoxA)(FindFunByHash(hUser, 0x1e380a6a));
	pfnGetWindowThreadProcessId=(pGetWindowThreadProcessId)(FindFunByHash(hUser, 0xa0667fbe));
	//获取窗口相关函数
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
	//获取PE信息
	PIMAGE_DOS_HEADER pDos = GetDosHeader((PBYTE)dwImageBase);						  //DOS头
	PIMAGE_NT_HEADERS pNt = GetNtHeader((PBYTE)dwImageBase);						  //NT头
	PIMAGE_FILE_HEADER pFile = GetFileHeader((PBYTE)dwImageBase);					  //FILE头
	PIMAGE_OPTIONAL_HEADER pOpt = GetOptionalHeader((PBYTE)dwImageBase);			  //OP头
																					  //获取EAT/ENT/EOT																
	PIMAGE_EXPORT_DIRECTORY pExport = (PIMAGE_EXPORT_DIRECTORY)
		((PBYTE)dwImageBase + *(PDWORD)((PBYTE)pNt + 0x78));						   //EXPORT	
	PDWORD pENT = (PDWORD)((PBYTE)dwImageBase + pExport->AddressOfNames);			  //ENT
	PDWORD pEAT = (PDWORD)((PBYTE)dwImageBase + pExport->AddressOfFunctions);		  //EAT
	PWORD pEOT = (PWORD)((PBYTE)dwImageBase + pExport->AddressOfNameOrdinals);		  //EOT//这个为WORD

	DWORD dwOrdinalName = 0;
	// 遍历ENT
	for (DWORD i = 0; i < pExport->NumberOfNames; i++)
	{
		char* pName = pENT[i] + (char*)dwImageBase;
		
		//计算Hash
		DWORD dwNameHash = FunHash(pName);
		
		if (dwNameHash == dwHash)
		{
			dwOrdinalName = i;
			break;
		}
	}

	//获取地址序号
	WORD dwOrdinal = pEOT[dwOrdinalName];

	DWORD dwFunAddress = (DWORD)(pEAT[dwOrdinal] + (PBYTE)dwImageBase);
		
	//使用自定义字符串函数对比//函数需自行实现
	char pTempDll[MAX_PATH] = { 0 };
	MyStrcpy_s(pTempDll, MAX_PATH, (char*)dwFunAddress);

	//比对是否存在'.'
	char *pDot = strchr(pTempDll, '.');
	if (!pDot)
	{
		return dwFunAddress;
	}

	*pDot = 0;
	//分割字符串
	char pTempFuction[MAX_PATH] = { 0 };
	char strDll[5] = {0x2E, 0x64, 0x6C, 0x6C, 0x00};

	MyStrcpy_s(pTempFuction, MAX_PATH, pDot + 1);
	strcat_s(pTempDll, MAX_PATH, strDll);

	//获取模块基址
	HMODULE hDll = pfnLoadLibraryExA(pTempDll,0,0);	//运行到这里时已经获取到了pfnLoadLibraryExA地址

	if (hDll == NULL)
	{
		return dwFunAddress;
	}
	//计算Hash
	DWORD dwNameHash = FunHash(pTempFuction);
	DWORD dwNewFunAddress = FindFunByHash(hDll,dwNameHash);

	return dwNewFunAddress;

}


//弹窗，解密程序
void Decode()
{	

	LPBYTE pData = (PBYTE)g_hModule + g_Conf.dwEncodeDataRva;

	//修改代码段属性
	DWORD dwOldPro=0;
	pfnVirtualProtect(pData, g_Conf.dwEncodeDataSize, PAGE_READWRITE, &dwOldPro);

	//解密代码
	for (DWORD i = 0; i < g_Conf.dwEncodeDataSize; i++)
	{
		pData[i] ^= i;
		pData[i] ^= g_Conf.dwEncodeKey;
	}

	//恢复代码段属性
	pfnVirtualProtect(pData, g_Conf.dwEncodeDataSize, dwOldPro, &dwOldPro);
}

//修复重定位
void Reloc()
{
	PBYTE pData = (PBYTE)g_hModule;
	//找到重定位表
	PIMAGE_BASE_RELOCATION pSrcReloc = NULL;
	//获取宿主重定位程序段RVA
	DWORD dwRelocRva = g_Conf.dwRelocRva;
	//没有重定位信息就结束
	if (!dwRelocRva)
		return;

	pSrcReloc = (PIMAGE_BASE_RELOCATION)(pData + dwRelocRva);

	//宿主信息//或可判断是否dll文件，基址为0x1000 0000;//或者读取自身文件PE头
	DWORD dwOldImageBase = 0x400000;
	
	//修复stub
	while (pSrcReloc->SizeOfBlock != 0)
	{
		//获取重定位项数
		DWORD dwCount = (pSrcReloc->SizeOfBlock - 8) / 2;
		//获取第一项
		PTYPEOFFSET pTypeOffset = (PTYPEOFFSET)(pSrcReloc + 1);
		
		//修改内存属性
		DWORD dwOldProt = 0;
		pfnVirtualProtect(pData+ pSrcReloc->VirtualAddress, 1, PAGE_READWRITE, &dwOldProt);

		//循环修改
		for (DWORD i = 0; i < dwCount; i++)
		{
			//重定位类型3
			if (pTypeOffset[i].Type == 3)
			{
				//获取重定位项RVA
				DWORD dwRva = pTypeOffset[i].Offset + pSrcReloc->VirtualAddress;

				//获取要修改的内容【取内容】
				PDWORD pFixData = (PDWORD)(dwRva + pData);

				//减去旧基址
				*pFixData -= (DWORD)dwOldImageBase;
				
				//加上新基址
				*pFixData += (DWORD)pData;
			}
			
		}	
		//恢复内存属性
		pfnVirtualProtect(pData + pSrcReloc->VirtualAddress, 1, dwOldProt, &dwOldProt);
		
		//修复下一块重定位数据
		pSrcReloc = (PIMAGE_BASE_RELOCATION)((LPBYTE)pSrcReloc + pSrcReloc->SizeOfBlock);
	}


	return;
}

//计算函数名称HASH
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


//修复IAT
void RecIAT()
{
	//判断是否存在导入表
	if (!g_Conf.dwImportRva)
	{
		return ;
	}

	//构造跳转代码
	BYTE bJmpByte[] = {
		0xe8, 0x01, 0x00, 0x00, 0x00, 0xe9, 0x58, 0xeb, 0x01, 0xe8, 0xb8, 0x11, 0x11, 0x11, 0x11, 0xeb,
		0x01, 0x15, 0x35, 0x16, 0x16, 0x16, 0x16, 0xeb, 0x01, 0xff, 0x50, 0xeb, 0x02, 0xff, 0x15, 0xc3 };

	//获取原INT地址
	PIMAGE_IMPORT_DESCRIPTOR pImport = (PIMAGE_IMPORT_DESCRIPTOR)(g_hModule + g_Conf.dwImportRva);

	//外层循环遍历模块
	while (pImport->Name)
	{
		//获取宿主INT
		PIMAGE_THUNK_DATA32 pThunkINT = (PIMAGE_THUNK_DATA32)(g_hModule+ pImport->OriginalFirstThunk);
		//获取宿主IAT
		PIMAGE_THUNK_DATA32 pThunkIAT = (PIMAGE_THUNK_DATA32)(g_hModule + pImport->FirstThunk);

		//获取DLL模块名称
		char *DllName = (CHAR*)(g_hModule + pImport->Name);

		//载入DLL模块
		HMODULE hDllModule = pfnLoadLibraryExA(DllName, 0, 0);

		//获取模块 EAT
		PIMAGE_NT_HEADERS pDLLNt = GetNtHeader((PBYTE)hDllModule);						 //NT头
		PIMAGE_EXPORT_DIRECTORY pDLLExport = (PIMAGE_EXPORT_DIRECTORY)
			((PBYTE)hDllModule + *(PDWORD)((PBYTE)pDLLNt + 0x78));						 //EXPORT	
		PDWORD pDLLEAT = (PDWORD)((PBYTE)hDllModule + pDLLExport->AddressOfFunctions);	 //EAT
		
		//修改内存属性
		DWORD dwOldProt = 0;
		pfnVirtualProtect(pThunkIAT, 1, PAGE_READWRITE, &dwOldProt);

		//内层循环遍历模块中的函数
		while (pThunkINT->u1.AddressOfData)
		{
			//检测是否序号
			bool IsOrdinal= (pThunkINT->u1.AddressOfData & 0xFFFF0000) == 0;
			DWORD dwFunAddress = 0;
			if (IsOrdinal)
			{
				//通过序号得到函数地址,需要加DLL基址
				dwFunAddress = (DWORD)(pDLLEAT[pThunkINT->u1.Ordinal] + (PBYTE)hDllModule);				
			}
			//名称命名
			else
			{
				//通过Hash获取函数地址
				dwFunAddress = FindFunByHash(hDllModule, pThunkINT->u1.AddressOfData);
			}

			//申请空间实现IAT跳转
			PBYTE pNewAddr= (PBYTE)pfnVirtualAlloc(0, sizeof(bJmpByte), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
			
			//计算秘钥
			DWORD dwIATKey = g_Conf.dwEncodeKey;
			IATKey(&dwIATKey);
			
			//替换秘钥
			PDWORD pKey = (PDWORD)&(bJmpByte[19]);
			*pKey = dwIATKey;

			//替换地址
			PDWORD pAddr = (PDWORD)&(bJmpByte[11]);
			*pAddr = dwFunAddress ^ dwIATKey;
			
			//拷贝代码
			memcpy(pNewAddr, bJmpByte, sizeof(bJmpByte));
			//存入IAT
			pThunkIAT->u1.AddressOfData = (DWORD)pNewAddr;

			//下一个INT			
			pThunkINT++;
			pThunkIAT++;		
		}

		//恢复内存属性
		pfnVirtualProtect(pThunkIAT, 1, dwOldProt, &dwOldProt);

		//下一个导入表
		pImport++;
	}

}

//自行实现字符串拷贝函数
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


//SDK窗口主函数
int WINAPI StubMain(
	_In_ HINSTANCE hInstance,
	_In_opt_ HINSTANCE hPrevInstance,
	_In_ LPSTR lpCmdLine,
	_In_ int nShowCmd) {

	//注册窗口类
	WNDCLASSA wcsStub = {};
	wcsStub.style = CS_HREDRAW | CS_VREDRAW;

	char WinName[6] = {	0x53, 0x74, 0x75, 0x62, 0x00};

	wcsStub.lpszClassName = WinName;
	wcsStub.hbrBackground = (HBRUSH)COLOR_BTNSHADOW;
	wcsStub.hInstance = hInstance;
	wcsStub.lpfnWndProc = StubProc;
	pfnRegisterClassA(&wcsStub);



	//创建窗口
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
		
	//消息循环
	while (pfnGetMessageA(&msg, 0, 0, 0))
	{	
		pfnTranslateMessage(&msg);//消息转换

		pfnDispatchMessageA(&msg);//消息分发
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

		//初始化
	case WM_CREATE:
	{
		//获取机器码
		GetMachineCode(g_strPwd);

		//创建按钮
		char cBtn[8] = {0x42, 0x75, 0x74, 0x74, 0x6F, 0x6E, 0x00};
		char cBtnTitle[6] = {0xc8, 0xb7, 0xb6, 0xa8, 0x00 };
		HWND hBtn = pfnCreateWindowExA(
			NULL,					//dwExStyle 扩展样式
			cBtn,					//lpClassName 窗口类名
			cBtnTitle,				//lpWindowName 窗口标题
			WS_CHILD | WS_VISIBLE,	//dwStyle 窗口样式
			300,					//x 
			40,						//y 
			50,						//nWidth 宽度
			30,						//nHeight 高度
			hwnd,					//hWndParent 父窗口句柄
			(HMENU)IDB_BUTTON_OK,	//ID
			pfnGetModuleHandleA(0),	//hInstance 应用程序句柄
			NULL					//lpParam 附加参数
		);


		//创建编辑框
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

		//处理命令
	case WM_COMMAND:
	{
		wmId = LOWORD(wParam);
		wmEvent = HIWORD(wParam);

		//处理确定按钮
		if (wmId == IDB_BUTTON_OK)
		{
			//获取文字
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
	char    Volume[256];//卷标名  
	char    FileSysName[256];
	DWORD   SerialNum;//序列号  
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
		//构造错误码
		DWORD dwError = 0xFFFFFFFF;
		_itoa_s(dwError, StrSerial, MAX_PATH,16);

		return;
	}

	//计算机器码
	DWORD dwMCode1 = SerialNum ^ 0x15151515;

	DWORD dwMCode2 = ~SerialNum;
	DWORD dwMCode3 = dwMCode2 << 16;
	DWORD dwMCode4 = dwMCode2 >> 16;

	DWORD dwMCode5 = dwMCode3 | dwMCode4;

	DWORD dwMCode6 = dwMCode1 & dwMCode5;

	g_dwMcode1 = dwMCode1;
	g_dwMcode2 = dwMCode5;
	g_dwMcode3 = dwMCode6;


	//转换字符串
	char McodeTemp1[MAX_PATH];
	char McodeTemp2[MAX_PATH];
	char McodeTemp3[MAX_PATH];
	
	_itoa_s(dwMCode1, McodeTemp1,MAX_PATH, 16);
	_itoa_s(dwMCode5, McodeTemp2, MAX_PATH, 16);
	_itoa_s(dwMCode6, McodeTemp3, MAX_PATH, 16);
		
	//拼接
	strcat_s(McodeTemp1, MAX_PATH, McodeTemp2);
	strcat_s(McodeTemp1, MAX_PATH, McodeTemp3);
	
	//转换大写
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

	//转换字符串
	char McodeTemp1[MAX_PATH];
	char McodeTemp2[MAX_PATH];
	char McodeTemp3[MAX_PATH];

	_itoa_s(g_dwMcode1, McodeTemp1, MAX_PATH, 16);
	_itoa_s(g_dwMcode2, McodeTemp2, MAX_PATH, 16);
	_itoa_s(g_dwMcode3, McodeTemp3, MAX_PATH, 16);
	
	strcat_s(McodeTemp1, MAX_PATH, McodeTemp2);
	strcat_s(McodeTemp1, MAX_PATH, McodeTemp3);
	
	//转换大写
	for (int i = 0; McodeTemp1[i]; i++)
	{
		McodeTemp1[i] = toupper(McodeTemp1[i]);
	}

	strcpy_s(strlisence, MAX_PATH, McodeTemp1);
}


//验证密码
void CmpLisence()
{
	//计算密码
	char Pwd[MAX_PATH] = { 0 };
	GetLisence(Pwd);
	//比对
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

//反dump，修改PE头属性
void AntiDump() 
{
	//获取PE信息
	PIMAGE_DOS_HEADER pDos = GetDosHeader((PBYTE)g_hModule);					  //DOS头
	PIMAGE_NT_HEADERS pNt = GetNtHeader((PBYTE)g_hModule);						  //NT头
	PIMAGE_FILE_HEADER pFile = GetFileHeader((PBYTE)g_hModule);					  //FILE头
	PIMAGE_OPTIONAL_HEADER pOpt = GetOptionalHeader((PBYTE)g_hModule);			  //OP头
																					  //修改代码段属性
	DWORD dwOldPro = 0;
	pfnVirtualProtect((LPVOID)g_hModule, 0x200, PAGE_READWRITE, &dwOldPro);

	//修改PE信息
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
	//秘钥小于0xFF
	if (*dwKey<=0xFF)
	{
		pbTempKey[0] = *dwKey;
		pbTempKey[1] = *dwKey;
		pbTempKey[2] = *dwKey;
		pbTempKey[3] = *dwKey;		
	}
	//秘钥小于0xFFFF
	else if(*dwKey> 0xFF&& *dwKey<=0xFFFF)
	{
		pbTempKey[0] = *dwKey;
		pbTempKey[1] = *dwKey;
	}
	//秘钥大于0xFFFF
	else
	{
		dwTempKey= *dwKey;
	}

	*dwKey = dwTempKey;
}

void RelTLS() 
{	
	//获取PE信息
	PIMAGE_OPTIONAL_HEADER pOpt = GetOptionalHeader((PBYTE)g_hModule);			  //OP头

	//如果存在TLS函数
	if (g_Conf.dwTLSCallbacks)
	{
		PIMAGE_TLS_DIRECTORY pDirTls =(PIMAGE_TLS_DIRECTORY)
			(pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress + g_hModule);

		//修改内存属性
		DWORD dwOldProt = 0;
		pfnVirtualProtect((LPVOID)(pDirTls), 4, PAGE_READWRITE, &dwOldProt);
		//恢复TLS
		pDirTls->AddressOfCallBacks = g_Conf.dwTLSCallbacks+ g_hModule;		

		pfnVirtualProtect((LPVOID)(pDirTls->AddressOfCallBacks), 4, dwOldProt, &dwOldProt);

		PIMAGE_TLS_CALLBACK* pTLSFun = (PIMAGE_TLS_CALLBACK*)pDirTls->AddressOfCallBacks;		
		//模拟调用
		while (*pTLSFun)
		{			
			(*pTLSFun)((PVOID)g_hModule, DLL_PROCESS_ATTACH, NULL);
			(*pTLSFun)((PVOID)g_hModule, DLL_THREAD_ATTACH, NULL);
			
			pTLSFun++;
		}
	}		
}

//反调试主程序
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


//检查BegingDebug
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

//检查NtGlobalFlag
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
		ULONG ExitStatus; 			 // 进程返回码
		PPEB  PebBaseAddress; 		 // PEB地址
		ULONG AffinityMask; 		 // CPU亲和性掩码
		LONG  BasePriority; 		 // 基本优先级
		ULONG UniqueProcessId; 		 // 本进程PID
		ULONG InheritedFromUniqueProcessId; // 父进程PID
	}stcProcInfo;

	pfnNtQueryInformationProcess(
		pfnGetCurrentProcess(),
		ProcessBasicInformation, //查看到父进程PID
		&stcProcInfo,
		sizeof(stcProcInfo), NULL
	);

	DWORD ExplorerPID = 0;
	DWORD CurrentPID = stcProcInfo.InheritedFromUniqueProcessId;
	char strExplorer[10] = {0x50, 0x72, 0x6F, 0x67, 0x6D, 0x61, 0x6E, 0x00};
	pfnGetWindowThreadProcessId(pfnFindWindowA(strExplorer, NULL), &ExplorerPID);
	
	return ExplorerPID == CurrentPID ? false : true;
}

//脱离调试器
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
	//能够检测当前操作系统是否处于调试模式，
	//处于调试模式，可能当前正在进行内核调试（Windbg);
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

	// 1. 获取欲查询信息大小
	ULONG uSize = 0;
	pfnNtQueryObject(NULL,
		(OBJECT_INFORMATION_CLASS)0x03,
		&uSize,
		sizeof(uSize),
		&uSize);

	// 2. 获取对象信息
	POBJECT_ALL_INFORMATION pObjectAllInfo = (POBJECT_ALL_INFORMATION)malloc(uSize);

	pfnNtQueryObject(NULL,
		(OBJECT_INFORMATION_CLASS)0x03,
		pObjectAllInfo,
		uSize,
		&uSize);

	// 3. 循环遍历并处理对象信息
	POBJECT_TYPE_INFORMATION pObjTypeInfo = pObjectAllInfo->ObjectTypeInfo;

	for (int i = 0; i < pObjectAllInfo->NumberOfObjectsTypes; i++)
	{
		// 3.1 查看此对象的类型是否为DebugObject，还需要判断对象的数量，大于0则说明有调试对象
		if (!wcscmp(L"DebugObject", pObjTypeInfo->TypeName.Buffer))
			return true;
		// 3.2 获取对象名占用空间的大小（考虑到了结构体对齐问题）
		ULONG uNameLength = pObjTypeInfo->TypeName.Length;
		ULONG uDataLength = uNameLength - uNameLength % sizeof(ULONG) + sizeof(ULONG);
		// 3.3 指向下一个对象信息
		pObjTypeInfo = (POBJECT_TYPE_INFORMATION)pObjTypeInfo->TypeName.Buffer;
		pObjTypeInfo = (POBJECT_TYPE_INFORMATION)((PBYTE)pObjTypeInfo + uDataLength);
	}
	delete[] pObjectAllInfo;
	return false;
}
*/
