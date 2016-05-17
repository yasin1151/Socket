
/*
* Socket.hpp
* This file is part of VallauriSoft
*
* Copyright (C) 2012 - Comina Francesco
*
* VallauriSoft is free software; you can redistribute it and/or modify
* it under the terms of the GNU General Public License as published by
* the Free Software Foundation; either version 2 of the License, or
* (at your option) any later version.
*
* VallauriSoft is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
* GNU General Public License for more details.
*
* You should have received a copy of the GNU General Public License
* along with VallauriSoft; if not, write to the Free Software
* Foundation, Inc., 51 Franklin St, Fifth Floor,
* Boston, MA  02110-1301  USA
*/

#ifndef _SOCKET_HPP_
#define _SOCKET_HPP_

#include <iostream>
#include <sstream>
#include <exception>
#include <string>
#include <vector>
#include <fstream>


//in vs2015 default define WIN32 
//not WIN64
#if defined WIN32 || defined WIN64
#define WINDOWS
#endif

#ifdef WINDOWS
	//please link the ws2_32 in windows
	#include <winsock2.h>
#else
	#include <sys/socket.h>
	#include <netinet/in.h>
	#include <arpa/inet.h>
	#include <netdb.h>
#endif

#define SOCKET_MAX_BUFFER_LEN 1024

using namespace std;

namespace Socket
{
	typedef int SocketId;
	typedef string Ip;
	typedef unsigned int Port;
#ifdef WINDOWS
	//2016.5.17
	//in vs 2013 also use int
	typedef int socklen_t;
#endif

	class SocketException : public exception
	{
	private:
		string _error;

	public:
		SocketException(const string&);
		~SocketException() throw();

		virtual const char* what() const throw();
		friend ostream& operator<< (ostream &out, SocketException &e);
	};


	struct Address : protected sockaddr_in
	{
	private:
		void _address(Ip, Port);

	public:
		Address();
		Address(Port);
		Address(Ip, Port);
		Address(struct sockaddr_in);
		Address(const Address&);

		Ip ip(void);
		Ip ip(Ip);

		Port port(void);
		Port port(Port);

		friend ostream& operator<< (ostream&, Address&);
	};
	

	template <class DataType>
	struct Datagram
	{
	public:
		Address address;
		DataType data;
		unsigned int received_bytes;
		unsigned int received_elements;

		template <class T>
		void operator= (const Datagram<T>&);
	};



	class CommonSocket
	{
	private:
#ifdef WINDOWS
		static unsigned int _num_sockets;
#endif
		void _socket(void);

	protected:
		SocketId _socket_id;
		int _socket_type;
		bool _opened;
		bool _binded;

	public:
		CommonSocket(void);
		CommonSocket(int);

		~CommonSocket(void);

		void open(void);
		void close(void);

		virtual void listen_on_port(Port);
	};





	class UDP : public CommonSocket
	{
	public:
		UDP(void);
		UDP(const UDP&);

		template <class T> int send(Ip, Port, const T*, size_t);
		template <class T> int send(Address, const T*, size_t);
		template <class T> int send(Ip, Port, T);
		template <class T> int send(Address, T);
		template <class T> int send(Ip, Port, vector<T>);
		template <class T> int send(Address, vector<T>);

		template <class T> int receive(Address*, T*, size_t, unsigned int*);
		template <class T> Datagram<T*> receive(T*, size_t);
		template <class T, size_t N> Datagram<T[N]> receive(size_t);
		template <class T> Datagram<T> receive(void);
		template <class T> Datagram<vector<T> > receive(size_t);
	};


	class TCP : public CommonSocket
	{
	private:
		Address _address;
	public:
		TCP(void);
		TCP(const TCP&);

		Ip ip(void);
		Port port(void);
		Address address(void);

		void listen_on_port(Port, unsigned int);
		void connect_to(Address);

		TCP accept_client(void);

		template <class T> int send(const T*, size_t);
		template <class T> int receive(T*, size_t);

		void send_file(string);
		void receive_file(string);
	};


	/*SocketException  class*/
	SocketException::SocketException(const string &message)
	{
		this->_error = message;
	}

	SocketException::~SocketException() throw()
	{
	}

	const char* SocketException::what() const throw()
	{
		return this->_error.c_str();
	}

	ostream& operator<< (ostream &out, SocketException &e)
	{
		out << e.what();
		return out;
	}

	/*socketExcption end*/


	/*Adress struct*/

	void Address::_address(Ip ip, Port port)
	{
		this->sin_family = AF_INET;
		this->ip(ip);
		this->port(port);
	}

	Address::Address()
	{
		_address("0.0.0.0", 0);
	}

	Address::Address(Port port)
	{
		_address("0.0.0.0", port);
	}

	Address::Address(Ip ip, Port port)
	{
		_address(ip, port);
	}

	Address::Address(struct sockaddr_in address)
	{
		_address(inet_ntoa(address.sin_addr), address.sin_port);
	}

	Address::Address(const Address &address)
	{
		this->sin_family = address.sin_family;
		this->sin_addr = address.sin_addr;
		this->sin_port = address.sin_port;
	}

	Ip Address::ip(void)
	{
		return inet_ntoa(this->sin_addr);
	}

	Ip Address::ip(Ip ip)
	{
#ifdef WINDOWS
		unsigned long address = inet_addr(ip.c_str());

		if (address == INADDR_NONE)
		{
			stringstream error;
			error << "[ip] with [ip=" << ip << "] Invalid ip address provided";
			throw SocketException(error.str());
		}
		else
		{
			this->sin_addr.S_un.S_addr = address;
		}
#else
		if (inet_aton(ip.c_str(), &this->sin_addr) == 0)
		{
			stringstream error;
			error << "[ip] with [ip=" << ip << "] Invalid ip address provided";
			throw SocketException(error.str());
		}
#endif
		return this->ip();
	}

	Port Address::port(void)
	{
		return ntohs(this->sin_port);
	}

	Port Address::port(Port port)
	{
		this->sin_port = htons(port);
		return this->port();
	}

	ostream& operator<< (ostream &out, Address &address)
	{
		out << address.ip() << ":" << address.port();
		return out;
	}
	/*Adress struct end*/


	/*Datagram struct*/
	template <class DataType>
	template <class T>
	void Datagram<DataType>::operator= (const Datagram<T> &datagram)
	{
		this->address = datagram.address;
		this->data = datagram.data;
	}


	/*Datagram struct end*/

	/*commonSocket class*/
#ifdef WINDOWS
	unsigned int CommonSocket::_num_sockets = 0;
#endif

	void CommonSocket::_socket(void)
	{
#ifdef WINDOWS
		this->_num_sockets++;
		if (this->_num_sockets == 1)
		{
			WSADATA wsaData;
			if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0)
				throw SocketException("[constructor] Cannot initialize socket environment");
		}
#endif
	}

	CommonSocket::CommonSocket(void)
	{
		this->_socket();
	}

	CommonSocket::CommonSocket(int socket_type)
	{
		this->_socket();

		this->_socket_type = socket_type;
		this->_opened = false;
		this->_binded = false;
		this->open();
	}

	CommonSocket::~CommonSocket(void)
	{
#ifdef WINDOWS
		this->_num_sockets--;
		if (this->_num_sockets == 0)
			WSACleanup();
#endif
	}

	void CommonSocket::open(void)
	{
		if (!this->_opened)
		{
			if ((this->_socket_id = socket(AF_INET, this->_socket_type, 0)) == -1)
				throw SocketException("[open] Cannot create socket");
			this->_opened = true;
			this->_binded = false;
		}
	}

	void CommonSocket::close(void)
	{
		if (this->_opened)
#ifdef WINDOWS
			closesocket(this->_socket_id);
#else
			shutdown(this->_socket_id, SHUT_RDWR);
#endif

		this->_opened = false;
		this->_binded = false;
	}

	void CommonSocket::listen_on_port(Port port)
	{
		if (this->_binded) throw SocketException("[listen_on_port] Socket already binded to a port, close the socket before to re-bind");

		if (!this->_opened) this->open();

		Address address(port);

		if (bind(this->_socket_id, (struct sockaddr*)&address, sizeof(struct sockaddr)) == -1)
		{
			stringstream error;
			error << "[listen_on_port] with [port=" << port << "] Cannot bind socket";
			throw SocketException(error.str());
		}

		this->_binded = true;
	}


	/*commonSocket end*/

	/*Udp Class*/
	UDP::UDP(void) : CommonSocket(SOCK_DGRAM)
	{
	}

	UDP::UDP(const UDP &udp) : CommonSocket()
	{
		this->_socket_id = udp._socket_id;
		this->_opened = udp._opened;
		this->_binded = udp._binded;
	}

	template <class T>
	int UDP::send(Ip ip, Port port, const T *data, size_t len)
	{
		if (!this->_opened) this->open();

		len *= sizeof(T);
		if (len > (SOCKET_MAX_BUFFER_LEN * sizeof(T)))
		{
			stringstream error;
			error << "[send] with [ip=" << ip << "] [port=" << port << "] [data=" << data << "] [len=" << len << "] Data length higher then max buffer len";
			throw SocketException(error.str());
		}

		Address address(ip, port);
		int ret;

		if ((ret = sendto(this->_socket_id, (const char*)data, len, 0, (struct sockaddr*)&address, sizeof(struct sockaddr))) == -1)
		{
			stringstream error;
			error << "[send] with [ip=" << ip << "] [port=" << port << "] [data=" << data << "] [len=" << len << "] Cannot send";
			throw SocketException(error.str());
		}

		return ret;
	}

	template <class T>
	int UDP::send(Address address, const T *data, size_t len)
	{
		return this->send<T>(address.ip(), address.port(), data, len);
	}

	template <class T>
	int UDP::send(Ip ip, Port port, T data)
	{
		return this->send<T>(ip, port, &data, 1);
	}

	template <class T>
	int UDP::send(Address address, T data)
	{
		return this->send<T>(address.ip(), address.port(), &data, 1);
	}

	template <>
	int UDP::send<string>(Ip ip, Port port, string data)
	{
		return this->send<char>(ip, port, data.c_str(), data.length() + 1);
	}

	template <>
	int UDP::send<string>(Address address, string data)
	{
		return this->send<char>(address.ip(), address.port(), data.c_str(), data.length() + 1);
	}

	template <class T>
	int UDP::send(Ip ip, Port port, vector<T> data)
	{
		return this->send<T>(ip, port, data.data(), data.size());
	}

	template <class T>
	int UDP::send(Address address, vector<T> data)
	{
		return this->send<T>(address.ip(), address.port(), data.data(), data.size());
	}

	template <class T>
	int UDP::receive(Address *address, T *data, size_t len, unsigned int *received_elements)
	{
		if (!this->_opened) this->open();
		if (!this->_binded) throw SocketException("[receive] Make the socket listening before receiving");

		len *= sizeof(T);
		if (len > (SOCKET_MAX_BUFFER_LEN * sizeof(T)))
		{
			stringstream error;
			error << "[send] with [buffer=" << data << "] [len=" << len << "] Data length higher then max buffer length";
			throw SocketException(error.str());
		}

		int received_bytes;
		socklen_t size = sizeof(struct sockaddr);

		if ((received_bytes = recvfrom(this->_socket_id, (char*)data, len, 0, (struct sockaddr*)address, (socklen_t*)&size)) == -1)
		{
			throw SocketException("[receive] Cannot receive");
		}

		*received_elements = (unsigned int)(received_bytes / sizeof(T));

		return received_bytes;
	}

	template <class T>
	Datagram<T*> UDP::receive(T *buffer, size_t len = SOCKET_MAX_BUFFER_LEN)
	{
		Datagram<T*> ret;

		ret.received_bytes = this->receive<T>(&ret.address, buffer, len, &ret.received_elements);
		ret.data = buffer;

		return ret;
	}

	template <class T, size_t N>
	Datagram<T[N]> UDP::receive(size_t len = N)
	{
		Datagram<T[N]> ret;
		ret.received_bytes = this->receive<T>(&ret.address, ret.data, len, &ret.received_elements);
		return ret;
	}

	template <class T>
	Datagram<T> UDP::receive(void)
	{
		Datagram<T> ret;
		ret.received_bytes = this->receive<T>(&ret.address, &ret.data, 1, &ret.received_elements);
		return ret;
	}

	template <>
	Datagram<string> UDP::receive<string>(void)
	{
		Datagram<string> ret;
		char buffer[SOCKET_MAX_BUFFER_LEN];

		ret.received_bytes = this->receive<char>(&ret.address, buffer, SOCKET_MAX_BUFFER_LEN, &ret.received_elements);
		ret.data = buffer;

		return ret;
	}

	template <class T>
	Datagram<vector<T> > UDP::receive(size_t len)
	{
		Datagram<vector<T> > ret;
		T buffer[len];

		ret.received_bytes = this->receive<T>(&ret.address, buffer, len, &ret.received_elements);
		for (int i = 0; i < ret.received_elements; i++) ret.data.push_back(buffer[i]);

		return ret;
	}


	/*Udp class end*/





	/*Tcp class*/

	TCP::TCP(void) : CommonSocket(SOCK_STREAM)
	{
	}

	TCP::TCP(const TCP &tcp) : CommonSocket()
	{
		this->_socket_id = tcp._socket_id;
		this->_opened = tcp._opened;
		this->_binded = tcp._binded;
	}

	Ip TCP::ip(void)
	{
		return this->_address.ip();
	}

	Port TCP::port(void)
	{
		return this->_address.port();
	}

	Address TCP::address(void)
	{
		return Address(this->_address);
	}

	void TCP::listen_on_port(Port port, unsigned int listeners = 1)
	{
		CommonSocket::listen_on_port(port);

		if (listen(this->_socket_id, listeners) != 0)
		{
			stringstream error;
			error << "[listen_on_port] with [port=" << port << "] [listeners=" << listeners << "] Cannot bind socket";
			throw SocketException(error.str());
		}
	}

	void TCP::connect_to(Address address)
	{
		if (this->_binded) throw SocketException("[connect_to] Socket already binded to a port, use another socket");

		if (!this->_opened) this->open();

		if (connect(this->_socket_id, (struct sockaddr*)&address, sizeof(struct sockaddr_in)) < 0)
		{
			stringstream error;
			error << "[connect_to] with [address=" << address << "] Cannot connect to the specified address";
			throw SocketException(error.str());
		}

		this->_binded = true;
	}

	TCP TCP::accept_client(void)
	{
		TCP ret;
		socklen_t len = sizeof(struct sockaddr_in);

		ret.close();
		ret._socket_id = accept(this->_socket_id, (struct sockaddr*)&ret._address, &len);
		ret._opened = true;
		ret._binded = true;

		return ret;
	}

	template <class T>
	int TCP::send(const T* buffer, size_t len)
	{
		if (!this->_binded) throw SocketException("[send] Socket not binded");
		if (!this->_opened) throw SocketException("[send] Socket not opened");

		len *= sizeof(T);
		if (len > (SOCKET_MAX_BUFFER_LEN * sizeof(T)))
		{
			stringstream error;
			error << "[send] [len=" << len << "] Data length higher then max buffer len (" << SOCKET_MAX_BUFFER_LEN << ")";
			throw SocketException(error.str());
		}

		int ret;
		if ((ret = ::send(this->_socket_id, (const char*)buffer, len, 0)) == -1) throw SocketException("[send] Cannot send");
		return ret;
	}

	template <class T>
	int TCP::receive(T* buffer, size_t len)
	{
		if (!this->_binded) throw SocketException("[send_file] Socket not binded");
		if (!this->_opened) throw SocketException("[send_file] Socket not opened");

		len *= sizeof(T);
		if (len > (SOCKET_MAX_BUFFER_LEN * sizeof(T)))
		{
			stringstream error;
			error << "[receive] [len=" << len << "] Data length higher then max buffer len (" << SOCKET_MAX_BUFFER_LEN << ")";
			throw SocketException(error.str());
		}

		int ret;
		if ((ret = recv(this->_socket_id, (char*)buffer, len, 0)) == -1) throw SocketException("[send] Cannot receive");
		return ret;
	}

	void TCP::send_file(string file_name)
	{
		unsigned long long file_size;
		char chunk[SOCKET_MAX_BUFFER_LEN];
		char sync;
		fstream fp(file_name.c_str(), ios::in | ios::binary);

		if (!fp.is_open())
		{
			stringstream error;
			error << "[send_file] with [filename=" << file_name << "] Cannot open the file";
			throw SocketException(error.str());
		}

		fp.seekg(0, ifstream::end);
		file_size = fp.tellg();
		fp.seekg(0, ifstream::beg);
		this->send<unsigned long long>(&file_size, 1);

		for (unsigned long long i = 0; i < file_size / SOCKET_MAX_BUFFER_LEN; i++)
		{
			this->receive<char>(&sync, 1);
			fp.read(chunk, SOCKET_MAX_BUFFER_LEN);
			this->send<char>(chunk, SOCKET_MAX_BUFFER_LEN);
		}

		if ((file_size % SOCKET_MAX_BUFFER_LEN) != 0)
		{
			this->receive<char>(&sync, 1);
			fp.read(chunk, file_size % SOCKET_MAX_BUFFER_LEN);
			this->send<char>(chunk, file_size % SOCKET_MAX_BUFFER_LEN);
		}

		fp.close();
	}

	void TCP::receive_file(string file_name)
	{
		unsigned long long file_size;
		char chunk[SOCKET_MAX_BUFFER_LEN];
		char sync;
		fstream fp(file_name.c_str(), ios::out | ios::binary);

		if (!fp.is_open())
		{
			stringstream error;
			error << "[send_file] with [filename=" << file_name << "] Cannot open the file";
			throw SocketException(error.str());
		}

		this->receive<unsigned long long>(&file_size, 1);

		for (unsigned long long i = 0; i < file_size / SOCKET_MAX_BUFFER_LEN; i++)
		{
			this->send<char>(&sync, 1);
			this->receive<char>(chunk, SOCKET_MAX_BUFFER_LEN);
			fp.write(chunk, SOCKET_MAX_BUFFER_LEN);
		}

		if ((file_size % SOCKET_MAX_BUFFER_LEN) != 0)
		{
			this->send<char>(&sync, 1);
			this->send<char>(chunk, file_size % SOCKET_MAX_BUFFER_LEN);
			fp.write(chunk, file_size % SOCKET_MAX_BUFFER_LEN);
		}

		fp.close();
	}

	/*Tcp class end*/

}


#endif

