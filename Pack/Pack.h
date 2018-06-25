#pragma once

//����ͷ�ļ�
#include <windows.h>
#include "..\\Stub\StubConf.h"

//��ӡ������Ϣ
#define  DBGINFO(errStr)\
printf("�ļ���:%s,����:%s,�к�:%d,������Ϣ:%s",__FILE__,__FUNCTION__,__LINE__,errStr)

//�������ݽṹ��
typedef struct _STUB
{
	LPBYTE pStubData;		//Stub����

	LPBYTE pTextData;		//Stub���������
	DWORD dwTextDataSize;	//Stub����δ�С

	LPBYTE pRelocData;		//Stub�ض�λ����
	DWORD dwRelocDataSize;	//�ض�λ����δ�С

	LPBYTE pfnPackFun;		//Stub��������
	STUBCONF* pPackConf;	//Stub����g_conf
}STUB;

//�ӿ���
class VPack
{
public:
	VPack();
	~VPack();

	DWORD dwKey;										//����Key
	char *pTextSecName;									//������
	char *pRelocSecName;								//�ض�λ����
	bool LoadStub(_In_ const char* StubDllPath);		//����DLL�ļ�
	bool Packing(_In_ const char* pFilePath);			//�ӿ�

private:
	STUB stcStub;										//stub����
	HANDLE hFile;										//�����ļ����
	DWORD dwPackSecRVA;									//������RVA

	PBYTE pStrFileData;								    //�����ļ�����
	int nSrcFileSize;								    //�����ļ���С

	bool GetFileData(_In_ const char* pFilePath);	    //��ȡ����
	bool CheckPE();									    //����Ƿ���ЧPE�ļ�
	void GetPEInfo();								    //��ȡPE��Ϣ
	void EncodeData();								    //����α���
	void SetNewOEP();								    //������OEP
	bool SaveFile(_In_ const char* pFilePath);			//�����ļ�

	bool SaveImport();									//���浼���
	bool ClsIAT();										//���IAT

	bool GetTLS();										//��ȡTLS
	DWORD FunHash(const char* FunName);					//����Hash

	void RelocStub(PBYTE pData, DWORD dwNewImageBase, DWORD dwNewRva);						//�޸��ض�λ��Ϣ
	DWORD AddNewSection(PBYTE pData, const char* pSecName, DWORD dwSecSize, DWORD dwSecChara);//���������

	DWORD Aligment(_In_ DWORD dwSize, _In_ DWORD dwAligment);								//�����������
	HANDLE OpenPEFile(_In_ const char* pFilePath);											//��PE�ļ�

	PIMAGE_DOS_HEADER pStubDos;							//Stub Dos
	PIMAGE_NT_HEADERS pStubNt;							//Stub NT
	PIMAGE_FILE_HEADER pStubFile;						//Stub File
	PIMAGE_OPTIONAL_HEADER pStubOpt;					//Stub Option
	
	PIMAGE_DOS_HEADER pDos;								//���� Dos
	PIMAGE_NT_HEADERS pNt;								//���� NT
	PIMAGE_FILE_HEADER pFile;							//���� File
	PIMAGE_OPTIONAL_HEADER pOpt;						//���� Option
	PIMAGE_DATA_DIRECTORY pDataDir;						//���� DATA_DIRECTORY

	PIMAGE_SECTION_HEADER GetSectionHeader(_In_ PBYTE pFileData, _In_ const char * SecName);//��ȡָ����������
	PIMAGE_DOS_HEADER GetDosHeader(PBYTE hModule);											//��ȡDOSͷ
	PIMAGE_NT_HEADERS GetNtHeader(PBYTE hModule);											//��ȡNTͷ
	PIMAGE_FILE_HEADER GetFileHeader(PBYTE hModule);										//��ȡ�ļ�ͷ
	PIMAGE_OPTIONAL_HEADER GetOptionalHeader(PBYTE hModule);								//��ȡ��չͷ	
	PIMAGE_SECTION_HEADER GetLastSection(PBYTE pData);										//��ȡ���һ������
	DWORD RVA2FO(DWORD dwRva, PIMAGE_NT_HEADERS32 pNt);										//RVAתFO
};