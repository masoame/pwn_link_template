#include "pwn_link_template.h"

/*
* 自制简单连接pwn题目的代码模板
*/

int main() 
{
	//----------------------------初始化网络库----------------------------
	pwn_link_template::initglobalNetwork();
	//----------------------------连接到远程服务器----------------------------
	auto handle = pwn_link_template::linktoServer("10.30.0.2", 10001);



	//----------------------------发送数据回调函数设置----------------------------
	pwn_link_template::key_callback["quit"] = [](char* data) ->long long { return -1; };
	pwn_link_template::key_callback["pwn"] = [](char* data) ->long long { 
		printf("执行pwn命令\n");
		memset(data, 'a', 50);
		data[50] = 1;

		return 51;
	};






	//--------------------------等待句柄释放----------------------------
	pwn_link_template::wait_to_close(handle);
	//----------------------------释放网络库----------------------------
	pwn_link_template::releaseglobalNetwork();

	return 0;
}