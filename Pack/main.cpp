// Pack.cpp : 定义控制台应用程序的入口点。
//

#include "stdafx.h"
#include "Pack.h"


int main()
{
	VPack cVpackObj;

	//载入stub
	if (!cVpackObj.LoadStub("Stub.dll"))
		return 0;
	
	//获取路径
	char PEPath[MAX_PATH] = { 0 };
	printf("请输入程序路径:");
	gets_s(PEPath, MAX_PATH);	//get_s不会隔断空格
		
	//加壳
	if (!cVpackObj.Packing(PEPath))
	{
		DBGINFO("加壳失败\n");		
	}
	else
	{
		printf("加壳成功！\n");
	}

	system("pause");

    return 0;
}

