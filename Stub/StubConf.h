#pragma once
#include "StructInfo.h"


//区段合并//区段读写执行属性
#pragma  comment(linker,"/merge:.data=.text")
#pragma  comment(linker,"/merge:.rdata=.text")
#pragma  comment(linker,"/section:.text,RWE")
void StubStart();														//主函数
void GetAPI();															//获取API
void Decode();															//解密代码
void Reloc();															//修复重定位
void RecIAT();															//修复IAT

void RelTLS();															//设置TLS													
void AntiDump();														//反Dump
void StrDecode(char* FunName);											//字符串编码
void IATKey(PDWORD dwKey);												//IAT加密Key
void _stdcall FusedFunc(DWORD funcAddress);								//混淆
DWORD FunHash(const char* FunName);										//计算函数名称Hash
DWORD FindFunByHash(HMODULE dwImageBase, DWORD dwHash);					//通过Hash获取函数地址
																		
void MyStrcpy_s(char* strDes, size_t szNumber, const char* strSrc);		//字符串拷贝

bool CheckDebug();														//反调试主程序
bool CheckDebugBegin();													//PEB Begin
bool CheckDebugGlobal();												//检测PEB Global
bool CheckDebugNtQ1();													//检测NtQ信息
//bool CheckDebugNtQ2();												//检测NtQ信息2
//bool CheckDebugNtQ3();												//检测NtQ信息3
//bool CheckDebugNtQ4();												//检测OS
//bool CheckDebugNtQ5();												//检测调试对象
bool NQIP_CheckParentProcess();											//检测父进程ID
void DetachDebug();														//脱离调试器

//窗口部分
///////////////////////////////////////////////

void GetMachineCode(char *StrSerial);				  //获取机器码
void GetLisence(char *strPwd);						  //计算序列号
void CmpLisence();									  //比较序列号

//回调函数
LRESULT CALLBACK StubProc(							 //窗口回调函数
	_In_ HWND   hwnd,
	_In_ UINT   uMsg,
	_In_ WPARAM wParam,
	_In_ LPARAM lParam
);

int WINAPI StubMain(_In_ HINSTANCE hInstance,		 //窗口主函数
	_In_opt_ HINSTANCE hPrevInstance,
	_In_ LPSTR lpCmdLine,
	_In_ int nShowCmd);


//定义函数指针
//////////////////////////////////////////////
typedef LPVOID(WINAPI *pGetProceAddress)(HMODULE, LPCSTR);
typedef HMODULE(WINAPI *pLoadLibraryExA)(LPCSTR, HANDLE, DWORD);
typedef int(WINAPI* pMessageBoxA)(HWND, LPCSTR, LPCSTR, UINT);
typedef BOOL(WINAPI* pVirtualProtect)(LPVOID, SIZE_T, DWORD, PDWORD);
typedef HMODULE(WINAPI* pGetModuleHandleA)(LPCSTR);
typedef LPVOID(WINAPI* pVirtualAlloc)(LPVOID, SIZE_T, DWORD, DWORD);
typedef VOID(WINAPI* pExitProcess)(_In_  UINT uExitCode);
typedef ATOM(WINAPI* pRegisterClassA)(_In_ CONST WNDCLASSA *lpWndClass);
typedef BOOL(WINAPI* pTranslateMessage)(_In_ CONST MSG *lpMsg);
typedef LRESULT(WINAPI* pDispatchMessageA)(_In_ CONST MSG *lpMsg);
typedef void(WINAPI* pPostQuitMessage)(_In_ int nExitCode);
typedef BOOL(WINAPI* pShowWindow)(HWND, int);
typedef LRESULT(WINAPI* pDefWindowProcA)(_In_ HWND, _In_ UINT, _In_ WPARAM, _In_ LPARAM);
typedef BOOL(WINAPI* pGetMessageA)(_Out_ LPMSG, _In_opt_ HWND, _In_ UINT, _In_ UINT);
typedef UINT(WINAPI* pGetDlgItemTextA)(_In_ HWND, _In_ int, _Out_writes_(cchMax) LPSTR, _In_ int);
typedef HANDLE(WINAPI* pGetCurrentProcess)(VOID);
typedef DWORD (WINAPI* pGetWindowThreadProcessId)(_In_ HWND hWnd,_Out_opt_ LPDWORD lpdwProcessId);
typedef HWND (WINAPI* pFindWindowA)(_In_opt_ LPCSTR lpClassName,_In_opt_ LPCSTR lpWindowName);
typedef HANDLE (WINAPI* pGetCurrentThread)(VOID);


typedef NTSTATUS(NTAPI *pZwSetInformationThread)(
	IN  HANDLE 			ThreadHandle,
	IN  THREAD_INFO_CLASS	ThreadInformaitonClass,
	IN  PVOID 			ThreadInformation,
	IN  ULONG 			ThreadInformationLength);

typedef NTSTATUS (NTAPI*  pNtQueryInformationProcess)(
	IN HANDLE ProcessHandle,
	IN PROCESSINFOCLASS ProcessInformationClass,
	OUT PVOID ProcessInformation,
	IN ULONG ProcessInformationLength,
	OUT PULONG ReturnLength OPTIONAL
	);

typedef  NTSTATUS (NTAPI* pNtQuerySystemInformation)(
	IN SYSTEM_INFORMATION_CLASS SystemInformationClass,
	OUT PVOID SystemInformation,
	IN ULONG SystemInformationLength,
	OUT PULONG ReturnLength OPTIONAL);

typedef  NTSTATUS (NTAPI* pNtQueryObject)(
	_In_opt_ HANDLE Handle,
	_In_ OBJECT_INFORMATION_CLASS ObjectInformationClass,
	_Out_writes_bytes_opt_(ObjectInformationLength) PVOID ObjectInformation,
	_In_ ULONG ObjectInformationLength,
	_Out_opt_ PULONG ReturnLength
);

typedef HWND(WINAPI* pCreateWindowExA)(
	_In_ DWORD dwExStyle,
	_In_opt_ LPCSTR lpClassName,
	_In_opt_ LPCSTR lpWindowName,
	_In_ DWORD dwStyle,
	_In_ int X,
	_In_ int Y,
	_In_ int nWidth,
	_In_ int nHeight,
	_In_opt_ HWND hWndParent,
	_In_opt_ HMENU hMenu,
	_In_opt_ HINSTANCE hInstance,
	_In_opt_ LPVOID lpParam);

typedef BOOL(WINAPI* pGetVolumeInformationA)(
	_In_opt_  LPCSTR lpRootPathName,
	_Out_writes_opt_(nVolumeNameSize) LPSTR lpVolumeNameBuffer,
	_In_      DWORD nVolumeNameSize,
	_Out_opt_ LPDWORD lpVolumeSerialNumber,
	_Out_opt_ LPDWORD lpMaximumComponentLength,
	_Out_opt_ LPDWORD lpFileSystemFlags,
	_Out_writes_opt_(nFileSystemNameSize) LPSTR lpFileSystemNameBuffer,
	_In_      DWORD nFileSystemNameSize
	);

