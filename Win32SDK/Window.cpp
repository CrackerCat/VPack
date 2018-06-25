#include "stdio.h"
#include <windows.h>


#define IDB_BUTTON_OK       0x2018  
#define IDB_EDIT_PWD		0x0510  

//回调函数
LRESULT CALLBACK StubProc(
	_In_ HWND   hwnd,
	_In_ UINT   uMsg,
	_In_ WPARAM wParam,
	_In_ LPARAM lParam
);
void GetMachineCode(char *StrSerial);
void Getlisence(char *strPwd);

DWORD g_dwMcode1 = 0;
DWORD g_dwMcode2 = 0;
DWORD g_dwMcode3 = 0;

//主函数
int WINAPI WinMain(
	_In_ HINSTANCE hInstance,
	_In_opt_ HINSTANCE hPrevInstance,
	_In_ LPSTR lpCmdLine,
	_In_ int nShowCmd) {



	//注册窗口类
	WNDCLASSA wcsStub = {};
	wcsStub.style = CS_HREDRAW | CS_VREDRAW;
	wcsStub.lpszClassName = "Stub";
	wcsStub.hbrBackground = (HBRUSH)COLOR_BTNSHADOW;
	wcsStub.hInstance = hInstance;
	wcsStub.lpfnWndProc = StubProc;
	RegisterClassA(&wcsStub);


	char FunName[20]= {	0xd2, 0xfe, 0xdf, 0xf1, 0xdd, 0xfe, 0xa3, 0xc1, 0xc6, 0xb3, 0xc5, 0xe7, 0xd4, 0xc5, 0xaf, 0xd0,
		0x00 };
		for (int i = 0; FunName[i]; i++)
		{
			FunName[i] ^= 0x15;
		}

	//创建窗口
	HWND hWnd = CreateWindowExA(
		NULL,
		"Stub",
		FunName,
		WS_OVERLAPPEDWINDOW,
		500,300,350,150,
		NULL,
		NULL,
		hInstance,
		NULL);

	ShowWindow(hWnd, SW_SHOW);
	MSG msg = {};

	//消息循环
	while (GetMessage(&msg,0,0,0))
	{
		
		TranslateMessage(&msg);//消息转换
		
		DispatchMessage(&msg);//消息分发
	}
	return 0;
}


LRESULT CALLBACK StubProc(
	_In_ HWND   hwnd,
	_In_ UINT   uMsg,
	_In_ WPARAM wParam,
	_In_ LPARAM lParam){

	switch (uMsg) {

	int wmId, wmEvent;

	char PwdIn[MAX_PATH];
	memset(PwdIn, 0, MAX_PATH);

	//初始化
	case WM_CREATE:
	{
		//获取机器码
		GetMachineCode(PwdIn);

		//创建按钮
		HWND hBtn = CreateWindowExA(
			NULL,					//dwExStyle 扩展样式
			"Button",				//lpClassName 窗口类名
			"确定",				//lpWindowName 窗口标题
			WS_CHILD | WS_VISIBLE,	//dwStyle 窗口样式
			250,					//x 
			40,						//y 
			60,						//nWidth 宽度
			30,						//nHeight 高度
			hwnd,					//hWndParent 父窗口句柄
			(HMENU)IDB_BUTTON_OK,	//ID
			GetModuleHandle(0),		//hInstance 应用程序句柄
			NULL					//lpParam 附加参数
		);
				
	
		//创建编辑框
		HWND hPwd = CreateWindowExA(
			NULL,
			"Edit",				
			PwdIn,
			WS_CHILD | WS_VISIBLE |WS_BORDER,
			25,					
			40,						
			210,						
			30,						
			hwnd,					
			(HMENU)IDB_EDIT_PWD,
			GetModuleHandle(0),		
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
			GetDlgItemTextA(hwnd, IDB_EDIT_PWD, PwdIn, MAX_PATH);

			//比对密码
			char Pwd[MAX_PATH];
			memset(Pwd, MAX_PATH, 0);
			Getlisence(Pwd);

			if (!strcmp(Pwd,PwdIn))
			{
				MessageBoxA(0,"Pwd Is OK","Good",0);
			}
			else
			{
				MessageBoxA(0, "Pwd Is Error", "Sorry", 0);
			}
		}

	}
		break;
	case WM_CLOSE:
		PostQuitMessage(0);
		break;
	default:
		break;
	}
	return DefWindowProcA(hwnd, uMsg, wParam, lParam);
}


void GetMachineCode(char *StrSerial)
{
	char    Volume[256];//卷标名  
	char    FileSysName[256];
	DWORD   SerialNum;//序列号  
	DWORD   FileNameLength;
	DWORD   FileSysFlag;
	GetVolumeInformationA("c:\\",
		Volume,
		256,
		&SerialNum,
		&FileNameLength,
		&FileSysFlag,
		FileSysName,
		256);

	if (SerialNum==0)
	{
		DWORD dwError = 0xFFFFFFFF;
		sprintf_s(StrSerial, MAX_PATH, "%.08X-%.08X-%.08X", dwError, dwError, dwError);
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

	_itoa_s(dwMCode1, McodeTemp1, MAX_PATH, 16);
	_itoa_s(dwMCode5, McodeTemp2, MAX_PATH, 16);
	_itoa_s(dwMCode6, McodeTemp3, MAX_PATH, 16);

	//拼接
	strcat_s(McodeTemp1, MAX_PATH, McodeTemp2);
	strcat_s(McodeTemp1, MAX_PATH, McodeTemp3);

	//转换大写
	for (int i = 0; McodeTemp1[i]; i++)
	{
		McodeTemp1[i] = toupper(McodeTemp1[i]);
	}

	strcpy_s(StrSerial, MAX_PATH, McodeTemp1);

	return;
}

void Getlisence(char *strlisence)
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