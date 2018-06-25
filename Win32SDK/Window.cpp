#include "stdio.h"
#include <windows.h>


#define IDB_BUTTON_OK       0x2018  
#define IDB_EDIT_PWD		0x0510  

//�ص�����
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

//������
int WINAPI WinMain(
	_In_ HINSTANCE hInstance,
	_In_opt_ HINSTANCE hPrevInstance,
	_In_ LPSTR lpCmdLine,
	_In_ int nShowCmd) {



	//ע�ᴰ����
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

	//��������
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

	//��Ϣѭ��
	while (GetMessage(&msg,0,0,0))
	{
		
		TranslateMessage(&msg);//��Ϣת��
		
		DispatchMessage(&msg);//��Ϣ�ַ�
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

	//��ʼ��
	case WM_CREATE:
	{
		//��ȡ������
		GetMachineCode(PwdIn);

		//������ť
		HWND hBtn = CreateWindowExA(
			NULL,					//dwExStyle ��չ��ʽ
			"Button",				//lpClassName ��������
			"ȷ��",				//lpWindowName ���ڱ���
			WS_CHILD | WS_VISIBLE,	//dwStyle ������ʽ
			250,					//x 
			40,						//y 
			60,						//nWidth ���
			30,						//nHeight �߶�
			hwnd,					//hWndParent �����ھ��
			(HMENU)IDB_BUTTON_OK,	//ID
			GetModuleHandle(0),		//hInstance Ӧ�ó�����
			NULL					//lpParam ���Ӳ���
		);
				
	
		//�����༭��
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

	//��������
	case WM_COMMAND:
	{
		wmId = LOWORD(wParam);
		wmEvent = HIWORD(wParam);

		//����ȷ����ť
		if (wmId == IDB_BUTTON_OK)
		{
			//��ȡ����
			GetDlgItemTextA(hwnd, IDB_EDIT_PWD, PwdIn, MAX_PATH);

			//�ȶ�����
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
	char    Volume[256];//�����  
	char    FileSysName[256];
	DWORD   SerialNum;//���к�  
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

	_itoa_s(dwMCode1, McodeTemp1, MAX_PATH, 16);
	_itoa_s(dwMCode5, McodeTemp2, MAX_PATH, 16);
	_itoa_s(dwMCode6, McodeTemp3, MAX_PATH, 16);

	//ƴ��
	strcat_s(McodeTemp1, MAX_PATH, McodeTemp2);
	strcat_s(McodeTemp1, MAX_PATH, McodeTemp3);

	//ת����д
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