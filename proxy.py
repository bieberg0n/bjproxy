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
from gevent import socket, sleep
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


def conn_recv(conn,s):
	try:
		for buf in iter(lambda:conn.recv(2048), b''):
			s.sendall(buf)
	except ConnectionResetError:
		return


def httpsproxy(conn, raw_headers):
	method, version, scm, address, path, params, query, fragment =\
		parse_header(raw_headers)	
	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	try:
		s.connect(address)
	except socket.error:
		s.close()
		return b''
	else:
		conn.sendall(b'HTTP/1.1 200 Connection established\r\n\r\n')
		s.setblocking(0)
		conn.setblocking(0)
		while 1:
			try:
				for buf in iter(lambda:conn.recv(1024*8),b''):
					print("conn:",len(buf))
					s.sendall(buf)
				print('conn:b\'\'')
				return
			except socket.error:
				try:
					for buf in iter(lambda:s.recv(1024*8),b''):
						print('server:',len(buf))
						conn.sendall(buf)
					print('server:b\'\'')
					return
				except socket.error:
					sleep(0.1)
					continue


host_p = re.compile('http://.+?/')
connection_p = re.compile('Connection: .+?\r')
def get_resp_from_httpproxy(headers):
	raw_headers = headers
	headers = headers.replace(
		'Proxy-Connection: keep-alive', 'Connection: close')
	headers = connection_p.sub('Connection: Close\r', headers)
	headers = headers.split('\n')
	headers[0] = host_p.sub('/', headers[0])
	headers = '\n'.join(headers)

	try:
		method, version, scm, address, path, params, query, fragment =\
			parse_header(raw_headers)
	except:
		return b''
	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	try:
		s.connect(address)
	except socket.error:
		s.close()
		return b''
	else:
		s.sendall(headers.encode())
		data = b''
		try:
			for d in iter(lambda:s.recv(1024*8), b''):
				# print(d)
				data += d
		except ConnectionResetError:
			return b''
		return data


def handle(conn, addr):
	headers = ''
	while 1:
		buf = conn.recv(1).decode('utf-8')
		headers += buf
		if headers.endswith('\r\n\r\n') or not buf:
			break

	method = headers.split(' ')[0]
	if method == 'CONNECT':
		print(addr[0],
			  '[{}]'.format(time.strftime('%Y-%m-%d %H:%M:%S')),
			  headers.split('\r\n')[0])
		# resp = b''
		httpsproxy(conn, headers)
		return
	else:
		resp = get_resp_from_httpproxy(headers)

	conn.sendall(resp)
	print(addr[0],
		  '[{}]'.format(time.strftime('%Y-%m-%d %H:%M:%S')),
		  headers.split('\r\n')[0])
	conn.close()

	
def main1():
	s = socket.socket()
	s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
	s.bind(('0.0.0.0', 8087))
	s.listen(1500)
	while 1:
		conn, addr = s.accept()
		# multiprocessing.Process(target=handle,args=(conn,addr)).start()
		threading.Thread(target=handle,args=(conn,addr)).start()
		
# main1()
StreamServer(('0.0.0.0', 8087), handle).serve_forever()
