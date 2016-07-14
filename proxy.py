import re
# import multiprocessing
import time
from urllib.parse import urlparse#, urlunparse
# import proxy
# from multiprocessing import Process
# import ssl
# import socket
# from time import sleep
# import threading
from gevent.server import StreamServer
from gevent import sleep, socket
# monkey.patch_socket()
# monkey.patch_ssl()

def parse_header(raw_headers):
	request_lines = raw_headers.split('\r\n')
	first_line = request_lines[0].split(' ')
	method = first_line[0]
	full_path = first_line[1]
	version = first_line[2]
	# print("%s %s" % (method, full_path))
	(scm, netloc, path, params, query, fragment) \
		= urlparse(full_path, 'http')
	if method == 'CONNECT':
		address = (path.split(':')[0], int(path.split(':')[1]))
	else:
		# 如果url中有‘：’就指定端口，没有则为默认80端口
		i = netloc.find(':')
		if i >= 0:
			address = netloc[:i], int(netloc[i + 1:])
		else:
			address = netloc, 80
	return method, version, scm, address, path, params, query, fragment


host_p = re.compile('http://.+?/')
connection_p = re.compile('Connection: .+?\r\n')
proxy_p = re.compile('Proxy-.+?\n')
def make_headers(headers):
	if '\nConnection' in headers:
		headers = proxy_p.sub('', headers)
	else:
		headers = headers.replace('Proxy-', '')
	# headers = connection_p.sub('', headers)
	headers = headers.split('\n')
	headers[0] = host_p.sub('/', headers[0])
	headers = '\n'.join(headers)
	return headers


def httpsproxy(conn, addr, raw_headers):
	method, version, scm, address, path, params, query, fragment =\
		parse_header(raw_headers)	
	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	s.connect(address)
	# else:
	conn.sendall(b'HTTP/1.1 200 Connection established\r\n\r\n')
	# s.setblocking(0)
	# conn.setblocking(0)
	s.settimeout(0.1)
	conn.settimeout(0.1)
	while 1:
		try:
			for buf in iter(lambda:conn.recv(1024*8),b''):
				# print("conn:",len(buf))
				s.sendall(buf)
			# print('conn:b\'\'')
			# print('client: {} close'.format(addr))
			print('server: {} client: {} close'.format(address[0], addr) )
			return
		except socket.timeout:
			try:
				for buf in iter(lambda:s.recv(1024*8),b''):
					# print('server:',len(buf))
					conn.sendall(buf)
				# print('server:b\'\'')
				# print('server: {} close'.format(address[0]))
				print('server: {} client: {} close'.format(address[0], addr) )
				return
			except socket.timeout:
				sleep(0.1)
				continue
			except ConnectionResetError:
				print('server: {} client: {} close'.format(address[0], addr) )
				return
		except ConnectionResetError:
			print('server: {} client: {} close'.format(address[0], addr) )
			return


def httpproxy(conn, addr, headers):
	try:
		method, version, scm, address, path, params, query, fragment =\
			parse_header(headers)
	except:
		return

	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	try:
		s.connect(address)
	except socket.error:
		s.close()
		return
	else:
		print('connect {} success'.format(address[0]))
		# s.setblocking(0)
		# conn.setblocking(0)
		s.settimeout(0.1)
		conn.settimeout(0.1)
		raw_headers = headers
		headers = make_headers(headers)
		s.sendall(headers.encode())
		print(addr[0],
			  '[{}]'.format(time.strftime('%Y-%m-%d %H:%M:%S')),
			  raw_headers.split('\r\n')[0])
		while 1:
			try:
				for buf in iter(lambda:s.recv(1024*8), b''):
					# print('server:', address[0], len(buf))
					conn.sendall(buf)
					# if buf == b'':
					# 	break
				# print('server: {} close'.format(address[0]))
				print('server: {} client: {} close'.format(
					address[0], addr) )
				return
			except socket.timeout:
				try:
					# headers = ''
					while 1:
						buf = conn.recv(1024)#.decode('utf-8')
						# headers += buf
						if b'\r\n\r\n' in buf:
							# break
							# raw_headers = headers
							# headers = make_headers(headers)
							buf = buf.split(b'\r\n\r\n')
							buf[0] = make_headers(buf[0].decode('utf-8')).encode()#+b'\r\n\r\n'+ buf[1]
							buf = b'\r\n\r\n'.join(buf)
							s.sendall(buf)
							print(addr[0],
								  '[{}]'.format(time.strftime('%Y-%m-%d %H:%M:%S')),
								  raw_headers.split('\r\n')[0])
						elif buf == b'':
							# print('client: {} close'.format(addr))
							print('server: {} client: {} close'.format(address[0], addr) )
							return
						else:
							s.sendall(buf)
							# pass
					# for buf in iter(lambda:conn.recv(1024),b''):
					# 	print(buf)
					# 	conn.sendall(buf)
					# return
					# continue
				except socket.timeout:
					sleep(0.1)
					continue
			except BrokenPipeError:
				# print('client: {} close'.format(addr))
				print('server: {} client: {} close'.format(address[0], addr) )
				return

		# data = b''
		# try:
		# 	for d in iter(lambda:s.recv(1024*8), b''):
		# 		# print(d)
		# 		data += d
		# except ConnectionResetError:
		# 	return b''
		# return data


def handle(conn, addr):
	headers = ''
	# while 1:
	# 	buf = conn.recv(1).decode('utf-8')
	# 	headers += buf
	# 	# if '\r\n\r\n' in headers and len(buf) < 1024 or not buf:
	# 	if headers.endswith('\r\n\r\n') or not buf:
	# 		break
	for buf in iter( lambda:conn.recv(1).decode('utf-8','ignore'), ''):
		headers += buf
		if headers.endswith('\r\n\r\n'):
			break

	method = headers.split(' ')[0]
	# if len(headers.split('\r\n')) <= 1:
	# 	return
	# else:
	# 	pass
	# if method == 'CONNECT':
	# 	serv = headers.split('\r\n')[0].split(' ')[1].split(':')[0]
	# # print(headers)
	# else:
	# 	serv = headers.split('\r\n')[1].split(' ')[1]
									   # .replace('/', '')\
									   # .split(':')[-1]

	# print(serv)
	# print(black_list)
	# if black_list.get( serv ):
	# 	print( serv, 'black' )
	# 	childproxy(conn, addr, headers)
	if method == 'CONNECT':
		print(addr[0],
			  '[{}]'.format(time.strftime('%Y-%m-%d %H:%M:%S')),
			  headers.split('\r\n')[0])
		# resp = b''
		httpsproxy(conn, addr, headers)
		# return
	else:
		# try:
		httpproxy(conn, addr, headers)
		# except ConnectionResetError:
		# 	childproxy(conn, addr, headers)

	# conn.sendall(resp)
	# conn.close()

	
# def main1():
# 	s = socket.socket()
# 	s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
# 	s.bind(('0.0.0.0', 8087))
# 	s.listen(1500)
# 	while 1:
# 		conn, addr = s.accept()
# 		# multiprocessing.Process(target=handle,args=(conn,addr)).start()
# 		threading.Thread(target=handle,args=(conn,addr)).start()
		
# main1()
# black_list = { i.strip():True for i in open('black.dat').readlines() }
StreamServer(('0.0.0.0', 8080), handle).serve_forever()
