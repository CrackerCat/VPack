#pragma once
#include "StructInfo.h"


//���κϲ�//���ζ�дִ������
#pragma  comment(linker,"/merge:.data=.text")
#pragma  comment(linker,"/merge:.rdata=.text")
#pragma  comment(linker,"/section:.text,RWE")
void StubStart();														//������
void GetAPI();															//��ȡAPI
void Decode();															//���ܴ���
void Reloc();															//�޸��ض�λ
void RecIAT();															//�޸�IAT

void RelTLS();															//����TLS													
void AntiDump();														//��Dump
void StrDecode(char* FunName);											//�ַ�������
void IATKey(PDWORD dwKey);												//IAT����Key
void _stdcall FusedFunc(DWORD funcAddress);								//����
DWORD FunHash(const char* FunName);										//���㺯������Hash
DWORD FindFunByHash(HMODULE dwImageBase, DWORD dwHash);					//ͨ��Hash��ȡ������ַ
																		
void MyStrcpy_s(char* strDes, size_t szNumber, const char* strSrc);		//�ַ�������

bool CheckDebug();														//������������
bool CheckDebugBegin();													//PEB Begin
bool CheckDebugGlobal();												//���PEB Global
bool CheckDebugNtQ1();													//���NtQ��Ϣ
//bool CheckDebugNtQ2();												//���NtQ��Ϣ2
//bool CheckDebugNtQ3();												//���NtQ��Ϣ3
//bool CheckDebugNtQ4();												//���OS
//bool CheckDebugNtQ5();												//�����Զ���
bool NQIP_CheckParentProcess();											//��⸸����ID
void DetachDebug();														//���������

//���ڲ���
///////////////////////////////////////////////

void GetMachineCode(char *StrSerial);				  //��ȡ������
void GetLisence(char *strPwd);						  //�������к�
void CmpLisence();									  //�Ƚ����к�

//�ص�����
LRESULT CALLBACK StubProc(							 //���ڻص�����
	_In_ HWND   hwnd,
	_In_ UINT   uMsg,
	_In_ WPARAM wParam,
	_In_ LPARAM lParam
);

int WINAPI StubMain(_In_ HINSTANCE hInstance,		 //����������
	_In_opt_ HINSTANCE hPrevInstance,
	_In_ LPSTR lpCmdLine,
	_In_ int nShowCmd);


//���庯��ָ��
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

