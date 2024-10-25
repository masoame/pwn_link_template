#include "pwn_link_template.h"
#include<syncstream>
#include <iostream>
#include <vector>
#include <ws2tcpip.h>
namespace pwn_link_template {
	std::map<std::string, send_callback> key_callback;
	std::size_t deafult_send_callback(std::string_view _data) {
		auto send_callback_ptr = key_callback.find(std::string{ _data });
		if (send_callback_ptr != key_callback.end()) {
			send_stream ss{ (char*)_data.data() };
			(*send_callback_ptr).second(ss);
			return ss.pos;
		}
		else {
			return _data.size();
		}
	}
	bool initglobalNetwork()
	{
		std::osyncstream{ std::cout } << "\033[32m";
		system("chcp 65001");
		std::osyncstream{ std::cout } << "\033[0m";
#ifdef _WIN32
		WSADATA wsaData;
		int iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
		if (iResult != 0) {
			std::osyncstream{ std::cout } << "\033[31m" << "WSAStartup failed with error: " << "\033[0m" << iResult << std::endl;
			return false;
		}
		else {
			std::osyncstream{ std::cout } << "\033[32m" << "WSAStartup successful" << "\33[0m" << std::endl;
			return true;
		}
#endif
		return true;
	}
	void releaseglobalNetwork() {
#ifdef _WIN32
		WSACleanup();
#endif
	}
	pwn_handle linktoServer(std::string_view ip, u_short port, std::size_t send_buffer_size)
	{
		auto handle = std::make_shared<pwn_data>();
		handle->sock = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
		if (handle->sock == INVALID_SOCKET) {
			std::osyncstream{ std::cout } << "\033[31m" << "Error creating socket" << "\033[0m" << std::endl;
			return nullptr;
		}
		addrinfo hints{ 0 }, * res = nullptr;
		if (int err = getaddrinfo(ip.data(), nullptr, &hints, &res) != 0) {
			std::osyncstream{ std::cout } << "\033[31m" << "Error resolving server address" << "\033[0m" << std::endl;
			return nullptr;
		}
		auto server_addr = reinterpret_cast<sockaddr_in*>(res->ai_addr);
		server_addr->sin_family = AF_INET;
		server_addr->sin_port = htons(port);
		long recv_timeout = 500;

		if (::setsockopt(handle->sock, SOL_SOCKET, SO_RCVTIMEO, (char*)&recv_timeout, sizeof(recv_timeout)) == SOCKET_ERROR)
		{
			std::osyncstream{ std::cout } << "\033[31m" << "Error setting recv timeout" << "\033[0m" << std::endl;
			return nullptr;
		}
		if (::connect(handle->sock, (sockaddr*)server_addr, sizeof(sockaddr)) == SOCKET_ERROR) {
			std::osyncstream{ std::cout } << "\033[31m" << "Error connecting to server" << "\033[0m" << std::endl;
			return nullptr;
		}

		handle->recv_thread = std::jthread([handle](std::stop_token st) {
			std::osyncstream{ std::cout } << "\033[32m" << "Waiting for messages from server..." << "\033[0m" << std::endl;
			char buffer[1024];
			while (st.stop_requested() == false) {

				int _size = recv(handle->sock, buffer, sizeof(buffer), 0);
				if (_size == SOCKET_ERROR) {
					continue;
				}
				else if (_size == 0) {
					std::osyncstream{ std::cout } << "\033[31m" << "Server closed connection" << "\033[0m" << std::endl;
					break;
				}
				else {

					{
						std::unique_lock lock{ handle->_recv_buffer.recv_mutex };
						handle->_recv_buffer.recv_deque.insert(handle->_recv_buffer.recv_deque.cend(), buffer, buffer + _size);
						handle->_recv_buffer.recv_cv.notify_one();
					}

					(std::osyncstream{ std::cout } << "\033[33m").write(buffer, _size) << "\033[0m";
				}
			}
			handle->send_thread.request_stop();
		});

		handle->send_thread = std::jthread([handle, send_buffer_size](std::stop_token st) {
			std::osyncstream{ std::cout } << "\033[32m" << "Enter message to send:" << "\033[0m" << std::endl;
			long long send_size = 0;
			std::vector<char> send_buffer;
			send_buffer.resize(send_buffer_size);
			while (st.stop_requested() == false) {

				std::cin.getline(send_buffer.data(), send_buffer.size() - 1, '\n');

				send_size = deafult_send_callback(send_buffer.data());
				if (send_size == -1) break;

				send_buffer[send_size] = '\n';
				send_size++;

				while (send_size > 0) {
					int len = ::send(handle->sock, send_buffer.data(), send_size, 0);
					if (len > 0) {
						send_size -= len;
					}
					else {
						goto SEND_FUNCTION_END;
					}
				}

			}
		SEND_FUNCTION_END:
			handle->recv_thread.request_stop(); 
			return;
		});

		return handle;
	}
	void wait_to_close(pwn_handle handle)
	{
		handle->recv_thread.join();
		handle->send_thread.join();
	}
}