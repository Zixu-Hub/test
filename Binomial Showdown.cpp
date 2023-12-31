/*
��������
���������ж����ַ������Դ� n ��Ԫ���в�����˳���ѡ�� k ��Ԫ�أ�������дһ������������������֡�

����˵��
��������:
�������һ����������������ÿ����������һ�У������������� n (n��1)�� k (0��k��n)�������� n = k = 0 ��ֹ��

�������:
��ÿ���������������һ�У�������Ҫ������������趨�������������Χ�ڣ�Ҳ����˵��С��2 
31
 ��
ע�⣺�����������Χ�ڣ��㷨Ҫ��֤���е��м���Ҳ��������Χ�ڡ������������ﵽ���ޡ�ͬѧ�ǿ���ʹ��assert����������ֵ��Χ�ȶԡ�
*/
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <iostream>
#include <string>
#include <cmath>
#include <algorithm>
using namespace std;

typedef long long int64;

int64 work(int64 n, int64 k)
{
	if (k > n / 2)
		k = n - k;
	int64 a = 1, b = 1;
	for (int i = 1; i <= k; i++)
	{
		a *= n + 1 - i;
		b *= i;
		if (a % b == 0)
			a /= b, b = 1;
	}
	return a / b;
}

int main()
{
	int n, k;
	while (~scanf("%d %d", &n, &k) && n)
		printf("%lld\n", work(n, k));
	return 0;
}
