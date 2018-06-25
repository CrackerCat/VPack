#pragma once

/*
//函数Hash
#define HASH_ExitProcess            //0x4fd18963
#define HASH_GetProcAddress   		//0xbbafdf85
#define HASH_LoadLibraryExA			//0xc0d83287
#define HASH_MessageBoxA			//0x1e380a6a
#define HASH_VirtualProtect			//0xef64a41e
#define HASH_GetModuleHandleA		//0xf4e2f2b2
#define HASH_VirtualAlloc			//0x1ede5967

#define HASH_RegisterClassA			//0x0bc05e32
#define HASH_CreateWindowExA		//0x1fdaf55b
#define HASH_ShowWindow				//0xdd8b5fb8
#define HASH_GetMessageA			//0x6106044b
#define HASH_TranslateMessage		//0xe09980a2
#define HASH_DispatchMessageA		//0x7a1506c2

#define HASH_GetDlgItemTextA		//0x1584c411
#define HASH_PostQuitMessage		//0xcaa94781
#define HASH_DefWindowProcA			//0x22e85ca4
#define HASH_GetVolumeInformationA  //0x7666caec

GetCurrentProcess					0x3a2fe6bb
NtQueryInformationProcess			0xe6aab603
GetWindowThreadProcessId			0xa0667fbe
FindWindowA							0x3db19602

NtQuerySystemInformation			0xeffc1cf8
NtQueryObject						0x0db59c8a

*/

typedef enum _SYSTEM_INFORMATION_CLASS {
	SystemBasicInformation = 0,
	SystemPerformanceInformation = 2,
	SystemTimeOfDayInformation = 3,
	SystemProcessInformation = 5,
	SystemProcessorPerformanceInformation = 8,
	SystemInterruptInformation = 23,
	SystemExceptionInformation = 33,
	SystemRegistryQuotaInformation = 37,
	SystemLookasideInformation = 45,
	SystemPolicyInformation = 134,
} SYSTEM_INFORMATION_CLASS;


typedef enum _PROCESSINFOCLASS {
	ProcessBasicInformation = 0,
	ProcessDebugPort = 7,
	ProcessWow64Information = 26,
	ProcessImageFileName = 27,
	ProcessBreakOnTermination = 29
} PROCESSINFOCLASS;


typedef enum _OBJECT_INFORMATION_CLASS {
	ObjectBasicInformation = 0,
	ObjectTypeInformation = 2
} OBJECT_INFORMATION_CLASS;

typedef struct _PEB_LDR_DATA {
	BYTE Reserved1[8];
	PVOID Reserved2[3];
	LIST_ENTRY InMemoryOrderModuleList;
} PEB_LDR_DATA, *PPEB_LDR_DATA;

typedef struct _UNICODE_STRING {
	USHORT Length;
	USHORT MaximumLength;
	PWSTR  Buffer;
} UNICODE_STRING;

typedef struct _RTL_USER_PROCESS_PARAMETERS {
	BYTE Reserved1[16];
	PVOID Reserved2[10];
	UNICODE_STRING ImagePathName;
	UNICODE_STRING CommandLine;
} RTL_USER_PROCESS_PARAMETERS, *PRTL_USER_PROCESS_PARAMETERS;

typedef VOID(NTAPI *PPS_POST_PROCESS_INIT_ROUTINE) (VOID);

typedef struct _PEB {
	BYTE Reserved1[2];
	BYTE BeingDebugged;
	BYTE Reserved2[1];
	PVOID Reserved3[2];
	PPEB_LDR_DATA Ldr;
	PRTL_USER_PROCESS_PARAMETERS ProcessParameters;
	PVOID Reserved4[3];
	PVOID AtlThunkSListPtr;
	PVOID Reserved5;
	ULONG Reserved6;
	PVOID Reserved7;
	ULONG Reserved8;
	ULONG AtlThunkSListPtr32;
	PVOID Reserved9[45];
	BYTE Reserved10[96];
	PPS_POST_PROCESS_INIT_ROUTINE PostProcessInitRoutine;
	BYTE Reserved11[128];
	PVOID Reserved12[1];
	ULONG SessionId;
} PEB, *PPEB;




//定义配置文件/保存原始OEP/加密秘钥/
typedef struct _STUBCONF
{
	DWORD dwSrcOep;			//源程序OEP
	DWORD dwEncodeKey;		//编码key

	DWORD dwEncodeDataRva;	//编码RVA
	DWORD dwEncodeDataSize;	//编码数据大小

	DWORD dwRelocRva;		//重定位RVA
	DWORD dwRelocSize;		//重定位数据大小

	DWORD dwImportRva;		//导入表RVA
	DWORD dwIATRva;			//IAT RVA

	DWORD dwNumberFun;		//函数数量,确定申请堆空间大小//或每个函数申请一份空间

	DWORD dwTLSCallbacks;	//TLS Callbacks RVA

}STUBCONF;

//重定位结构体WORD
typedef struct _TYPEOFFSET
{
	WORD Offset : 12;		//偏移
	WORD Type : 4;			//类型
}TYPEOFFSET, *PTYPEOFFSET;


#define IDB_BUTTON_OK       0x2018  
#define IDB_EDIT_PWD		0x0510  

typedef enum THREAD_INFO_CLASS {
	ThreadHideFromDebugger = 17
};