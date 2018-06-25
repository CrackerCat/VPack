#pragma once

//导入头文件
#include <windows.h>
#include "..\\Stub\StubConf.h"

//打印错误信息
#define  DBGINFO(errStr)\
printf("文件名:%s,函数:%s,行号:%d,错误信息:%s",__FILE__,__FUNCTION__,__LINE__,errStr)

//定义数据结构体
typedef struct _STUB
{
	LPBYTE pStubData;		//Stub数据

	LPBYTE pTextData;		//Stub代码段数据
	DWORD dwTextDataSize;	//Stub代码段大小

	LPBYTE pRelocData;		//Stub重定位数据
	DWORD dwRelocDataSize;	//重定位代码段大小

	LPBYTE pfnPackFun;		//Stub导出函数
	STUBCONF* pPackConf;	//Stub配置g_conf
}STUB;

//加壳类
class VPack
{
public:
	VPack();
	~VPack();

	DWORD dwKey;										//加密Key
	char *pTextSecName;									//区段名
	char *pRelocSecName;								//重定位段名
	bool LoadStub(_In_ const char* StubDllPath);		//载入DLL文件
	bool Packing(_In_ const char* pFilePath);			//加壳

private:
	STUB stcStub;										//stub配置
	HANDLE hFile;										//宿主文件句柄
	DWORD dwPackSecRVA;									//壳区段RVA

	PBYTE pStrFileData;								    //宿主文件数据
	int nSrcFileSize;								    //宿主文件大小

	bool GetFileData(_In_ const char* pFilePath);	    //获取数据
	bool CheckPE();									    //检查是否有效PE文件
	void GetPEInfo();								    //获取PE信息
	void EncodeData();								    //代码段编码
	void SetNewOEP();								    //设置新OEP
	bool SaveFile(_In_ const char* pFilePath);			//保存文件

	bool SaveImport();									//保存导入表
	bool ClsIAT();										//清空IAT

	bool GetTLS();										//获取TLS
	DWORD FunHash(const char* FunName);					//计算Hash

	void RelocStub(PBYTE pData, DWORD dwNewImageBase, DWORD dwNewRva);						//修复重定位信息
	DWORD AddNewSection(PBYTE pData, const char* pSecName, DWORD dwSecSize, DWORD dwSecChara);//添加新区段

	DWORD Aligment(_In_ DWORD dwSize, _In_ DWORD dwAligment);								//计算对齐数据
	HANDLE OpenPEFile(_In_ const char* pFilePath);											//打开PE文件

	PIMAGE_DOS_HEADER pStubDos;							//Stub Dos
	PIMAGE_NT_HEADERS pStubNt;							//Stub NT
	PIMAGE_FILE_HEADER pStubFile;						//Stub File
	PIMAGE_OPTIONAL_HEADER pStubOpt;					//Stub Option
	
	PIMAGE_DOS_HEADER pDos;								//宿主 Dos
	PIMAGE_NT_HEADERS pNt;								//宿主 NT
	PIMAGE_FILE_HEADER pFile;							//宿主 File
	PIMAGE_OPTIONAL_HEADER pOpt;						//宿主 Option
	PIMAGE_DATA_DIRECTORY pDataDir;						//宿主 DATA_DIRECTORY

	PIMAGE_SECTION_HEADER GetSectionHeader(_In_ PBYTE pFileData, _In_ const char * SecName);//获取指定名称区段
	PIMAGE_DOS_HEADER GetDosHeader(PBYTE hModule);											//获取DOS头
	PIMAGE_NT_HEADERS GetNtHeader(PBYTE hModule);											//获取NT头
	PIMAGE_FILE_HEADER GetFileHeader(PBYTE hModule);										//获取文件头
	PIMAGE_OPTIONAL_HEADER GetOptionalHeader(PBYTE hModule);								//获取扩展头	
	PIMAGE_SECTION_HEADER GetLastSection(PBYTE pData);										//获取最后一个区段
	DWORD RVA2FO(DWORD dwRva, PIMAGE_NT_HEADERS32 pNt);										//RVA转FO
};