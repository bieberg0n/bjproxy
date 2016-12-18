import re
import json
import time
from urllib.parse import urlparse#, urlunparse
import multiprocessing
# import ssl
import socket
import socks
socks.set_default_proxy(socks.SOCKS5, '192.168.1.1', 1080)
# from time import sleep
# import threading
# from gevent.server import StreamServer
# from gevent import sleep, socket
# monkey.patch_socket()
# monkey.patch_ssl()

def parse_header(raw_headers):
	request_lines = raw_headers.split('\r\n')
	first_line = request_lines[0].split(' ')
	other_lines = request_lines[1:]
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
	headers_dict = { 'method':method, 'version':version, 'scm':scm,
					 'address':address, 'path':path, 'params':params,
					 'query':query, 'fragment':fragment }
	headers_list = [ line.split(':') for line in other_lines if line ]
	headers_dict_more = { line[0].strip():line[1].strip() for line in headers_list }
	return dict(headers_dict, **headers_dict_more)


host_p = re.compile('http://.+?/')
connection_p = re.compile('Connection: .+?\r\n')
proxy_p = re.compile('Proxy-.+?\n')
def deal_with_headers(headers):
	if '\nConnection' in headers:
		headers = proxy_p.sub('', headers)
	else:
		headers = headers.replace('Proxy-', '')
	# headers = connection_p.sub('', headers)
	headers = headers.split('\n')
	headers[0] = host_p.sub('/', headers[0])
	headers = '\n'.join(headers)
	# print(headers)
	return headers


# server_ = json.loads( open('aqua.json').read() )
# server = server_['server']
# port = server_['port']
# def childproxy(conn, headers, conn_name='', serv_name=''):
# 	s = socket.socket()
# 	s.connect( (server, port ) )
# 	s.sendall( headers.encode() )
# 	create_pipe(conn, s, conn_name, serv_name)


def httpsproxy(conn, addr, raw_headers):
	headers_dict = parse_header(raw_headers)
	# serv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	serv = socks.socksocket(socket.AF_INET, socket.SOCK_STREAM)
	try:
		serv.connect(headers_dict['address'])
	except TimeoutError:
		return
	conn.sendall(b'HTTP/1.1 200 Connection established\r\n\r\n')
	print(addr,
		  '[{}]'.format(time.strftime('%Y-%m-%d %H:%M:%S')),
		  headers_dict['method'], headers_dict['address'],
		  headers_dict['path'])
	# create_pipe(conn, s, conn_name=addr, serv_name=address[0])
	p = multiprocessing.Process(target=a_to_b, args=(conn, serv, addr[0], headers_dict['address']), daemon=True)
	p.start()
	a_to_b(serv, conn, headers_dict['address'], addr[0])
	return p.terminate()


def a_to_b(a_conn, b_conn, a_name, b_name):
	sendall = b_conn.sendall
	try:
		[ sendall(buf) for buf in iter(lambda:a_conn.recv(1024*8), b'') ]
	except (ConnectionResetError, BrokenPipeError) as e:
		print(e)
	finally:
		a_conn.close()
		b_conn.close()
		return print('{} -> {} close'.format(a_name, b_name) )


def cli_to_serv(serv, cli, serv_name, cli_name):
	try:
		while True:
			headers = get_headers(cli)
			if headers:
				headers_dict = parse_header(headers)
				headers = deal_with_headers(headers)
				# print(cli_name, headers)
				print(cli_name,
					  '[{}]'.format(time.strftime('%Y-%m-%d %H:%M:%S')),
					  headers_dict['method'], headers_dict['address'],
					  headers_dict['path'])
				serv.sendall(headers.encode())
			else:
				break
	except (ConnectionResetError, BrokenPipeError) as e:
		print(e)
	finally:
		serv.close()
		cli.close()
		return print('{} -> {} close'.format(cli_name, serv_name))


def httpproxy(cli, addr, headers):
	# socket.socket = socks.socksocket()
	serv = socks.socksocket(socket.AF_INET, socket.SOCK_STREAM)
	headers_dict = parse_header(headers)

	try:
		serv.connect(headers_dict['address'])
	except socket.gaierror as e:
		print(e, headers_dict['address'])
	print('connect {} success'.format(headers_dict['Host']))
	headers = deal_with_headers(headers)
	# print(addr,headers)
	print(addr,
		  '[{}]'.format(time.strftime('%Y-%m-%d %H:%M:%S')),
		  headers_dict['method'], headers_dict['address'],
		  headers_dict['path'])

	try:
		serv.sendall(headers.encode())
	except BrokenPipeError:
		return
	p = multiprocessing.Process(target=a_to_b, args=(serv, cli, headers_dict['Host'], addr[0],), daemon=True)
	p.start()
	# p = multiprocessing.Process(target=a_to_b, args=(serv, cli, headers_dict['Host'], addr[0],))
	# a_to_b(serv, cli, headers_dict['Host'], addr[0])
	# p.start()
	cli_to_serv(serv, cli, headers_dict['Host'], addr)
	return p.terminate()
	

def get_headers(conn):
	headers = ''
	for buf in iter( lambda:conn.recv(1).decode('utf-8','ignore'), ''):
		headers += buf
		if headers.endswith('\r\n\r\n'):
			break
	return headers


def handle(conn, cli_addr):
	# while True:
	headers = get_headers(conn)
	try:
		headers_dict = parse_header(headers)
	except (ValueError, IndexError):
		return
	if len(headers_dict.keys()) <= 1:
		return
	else:
		pass

	if headers_dict['method'] == 'CONNECT':
		# print(cli_addr[0],
		# 	  '[{}]'.format(time.strftime('%Y-%m-%d %H:%M:%S')),
		# 	  headers_dict['method'], headers_dict['cli_address'],
		# 	  headers_dict['path'])
		return httpsproxy(conn, cli_addr, headers)
		# pass
	else:
		# try:
		return httpproxy(conn, cli_addr, headers)

	
def main1():
	s = socket.socket()
	s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
	s.bind(('0.0.0.0', 8080))
	s.listen(1500)

	# pool = multiprocessing.Pool(4)
	while 1:
		conn, cli_addr = s.accept()
		# handle(conn,addr)
		multiprocessing.Process(target=handle,args=(conn, cli_addr,)).start()
# 		threading.Thread(target=handle,args=(conn,addr)).start()
		
main1()
# black_list = { i.strip():True for i in open('black.dat').readlines() }
# pre_dict = {}
# StreamServer(('0.0.0.0', 8080), handle).serve_forever()
