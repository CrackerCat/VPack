// 02.TLS.cpp: 定义控制台应用程序的入口点。
//
#include "stdafx.h"
#include <windows.h>
#pragma comment(linker,"/INCLUDE:__tls_used")
// 把你定义的TLS函数数组告诉链接器，32程序数组名称前加_,64位不需要
#pragma comment(linker, "/INCLUDE:_tls_callback_arr")

// 01. TLS变量
_declspec(thread)int nNum = 0x12345678;
_declspec(thread)int nNum1 = 0x11223344;
_declspec(thread)int nNum2 = 0xAABBCCDD;

DWORD WINAPI ThreadProc(
	_In_ LPVOID lpParameter
) {
	printf("Thread Proc:%08X\n", nNum++);
	return 0;
}

// 02. TLS函数
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
X:命名随机
L：TLS
B:B~Y任一字母
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

