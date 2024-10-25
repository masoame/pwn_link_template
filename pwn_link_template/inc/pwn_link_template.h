#pragma once
#pragma comment(lib, "ws2_32.lib")
#include <winsock2.h>
#include<string_view>
#include<thread>
#include<optional>
#include<map>
#include<string>
#include<queue>
#include<mutex>
#include<functional>
namespace pwn_link_template {

	using pe64_t = unsigned long long;
	using pe32_t = unsigned long;

	inline std::string skip_chars(std::size_t _count, char _fill = 'a') {
		return std::string(_count, _fill);
	}

	struct send_stream {
		char* data;
		std::size_t pos;

		send_stream(char* _data, std::size_t _pos = 0) : data(_data), pos(_pos) { }

		inline send_stream& operator << (std::string_view _data) {
			memcpy(this->data + pos, _data.data(), _data.size());
			pos += _data.size();
			return *this;
		}

		inline send_stream& operator << (pe64_t _data) {
			memcpy(this->data + pos, &_data, 8);
			pos += 8;
			return *this;
		}

		inline send_stream& operator << (pe32_t _data) {
			memcpy(this->data + pos, &_data, 4);
			pos += 4;
			return *this;
		}

		inline char& operator[](std::size_t _pos) {
			return data[_pos];
		}

	};

	struct recv_buffer {
		std::deque<char> recv_deque;
		std::mutex recv_mutex;
		std::condition_variable recv_cv;
		bool recv_exit = false;
		
		template <class _Rep = long long, class _Period = std::ratio<1>>
		inline bool recv_until(std::string_view _data, const std::chrono::duration<_Rep, _Period>& _Rel_time = std::chrono::seconds(60*5)) {

			bool is_timeout;
			bool init_flag = true;

			std::unique_lock<std::mutex> lock(recv_mutex);

			std::deque<char>::const_iterator _buf_it = recv_deque.cbegin();

			for (auto _check_it = _data.cbegin(); _check_it != _data.cend();) {

				if (recv_deque.empty() == true || init_flag) {
					is_timeout = recv_cv.wait_for(lock, _Rel_time, [this]() { return (recv_deque.empty() == false) || (recv_exit == true); });
					_buf_it = recv_deque.cbegin();
					init_flag = false;
				}
				if (is_timeout == false || recv_exit == true) 
					return false;

				if (*_check_it == *_buf_it) {
					++_check_it;
					++_buf_it;
				}
				else {
					recv_deque.pop_front();
					_buf_it = recv_deque.cbegin();
					_check_it = _data.cbegin();
				}
			}

			for (int i = 0; i < _data.size(); ++i) {
				recv_deque.pop_front();
			}
		}

		inline std::vector<char> recv(std::size_t _size) {

			std::vector<char> result;
			std::unique_lock<std::mutex> lock(recv_mutex);

			for (std::size_t i = 0; i < _size; ++i) {
				if (recv_deque.empty() == true) {
					recv_cv.wait(lock, [this]() { return (recv_deque.empty() == false) || (recv_exit == true); });
				}
				if (recv_exit == true) return result;
				result.emplace_back(recv_deque.front());
				recv_deque.pop_front();
			}
			return result;
		}

	};

	using send_callback = std::function<void(send_stream&)>;

	extern std::map<std::string, send_callback> key_callback;

	class pwn_data {
	public:
		SOCKET sock;
		std::jthread recv_thread;
		std::jthread send_thread;
		recv_buffer _recv_buffer;
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
