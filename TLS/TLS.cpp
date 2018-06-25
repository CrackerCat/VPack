// 02.TLS.cpp: �������̨Ӧ�ó������ڵ㡣
//
#include "stdafx.h"
#include <windows.h>
#pragma comment(linker,"/INCLUDE:__tls_used")
// ���㶨���TLS�������������������32������������ǰ��_,64λ����Ҫ
#pragma comment(linker, "/INCLUDE:_tls_callback_arr")

// 01. TLS����
_declspec(thread)int nNum = 0x12345678;
_declspec(thread)int nNum1 = 0x11223344;
_declspec(thread)int nNum2 = 0xAABBCCDD;

DWORD WINAPI ThreadProc(
	_In_ LPVOID lpParameter
) {
	printf("Thread Proc:%08X\n", nNum++);
	return 0;
}

// 02. TLS����
VOID
NTAPI tls_call_back_1(
	PVOID DllHandle,
	DWORD Reason,
	PVOID Reserved
) {
	if (Reason == DLL_PROCESS_ATTACH)
	{
		printf("Process TLS:%08X\n", nNum1);
	}

	if (Reason == DLL_THREAD_ATTACH)
	{
		printf("Thread TLS:%08X\n", nNum2);
	}
}

/*
CRT:c runtime
X:�������
L��TLS
B:B~Y��һ��ĸ
*/
#pragma data_seg(".CRT$XLB")
extern "C" PIMAGE_TLS_CALLBACK tls_callback_arr[] = { tls_call_back_1 ,NULL };
#pragma data_seg()

int main()
{
	CreateThread(NULL, NULL, ThreadProc, NULL, NULL, NULL);
	Sleep(100);
	//CreateThread(NULL, NULL, ThreadProc, NULL, NULL, NULL);
	system("pause");

	return 0;
}

