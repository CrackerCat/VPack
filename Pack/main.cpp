// Pack.cpp : �������̨Ӧ�ó������ڵ㡣
//

#include "stdafx.h"
#include "Pack.h"


int main()
{
	VPack cVpackObj;

	//����stub
	if (!cVpackObj.LoadStub("Stub.dll"))
		return 0;
	
	//��ȡ·��
	char PEPath[MAX_PATH] = { 0 };
	printf("���������·��:");
	gets_s(PEPath, MAX_PATH);	//get_s������Ͽո�
		
	//�ӿ�
	if (!cVpackObj.Packing(PEPath))
	{
		DBGINFO("�ӿ�ʧ��\n");		
	}
	else
	{
		printf("�ӿǳɹ���\n");
	}

	system("pause");

    return 0;
}

