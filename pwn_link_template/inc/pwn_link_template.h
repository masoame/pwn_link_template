#pragma once
#pragma comment(lib, "ws2_32.lib")
#include <winsock2.h>
#include<string_view>
#include<thread>
#include<optional>
#include<map>
#include<string>
namespace pwn_link_template {

	using send_callback = long long(*)(char* data);

	extern std::map<std::string, send_callback> key_callback;

	struct pwn_data {
		SOCKET sock;
		std::jthread recv_thread;
		std::jthread send_thread;
		~pwn_data() {
			::closesocket(sock);
		}
	};

	using pwn_handle = std::shared_ptr<pwn_data>;

	extern std::size_t deafult_send_callback(std::string_view data);

	extern bool initglobalNetwork();

	extern void releaseglobalNetwork();

	extern pwn_handle linktoServer(std::string_view ip, u_short port,std::size_t send_buffer_size = 1024 * 1024);

	extern void wait_to_close(pwn_handle handle);
}
