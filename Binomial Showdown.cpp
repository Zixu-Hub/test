/*
任务描述
本关任务：有多少种方法可以从 n 个元素中不考虑顺序地选择 k 个元素？请您编写一个程序来计算这个数字。

测试说明
输入描述:
输入包含一个或多个测试用例。每个测试用例一行，给出两个整数 n (n≥1)和 k (0≤k≤n)。输入以 n = k = 0 终止。

输出描述:
对每个测试用例，输出一行，给出所要求的数。本题设定这个数在整数范围内，也就是说，小于2 
31
 。
注意：结果在整数范围内，算法要保证所有的中间结果也在整数范围内。测试用例将达到极限。同学们可以使用assert函数进行数值范围比对。
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
