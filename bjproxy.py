import re
import json
import time
from urllib.parse import urlparse
import multiprocessing
# import ssl
import socket
import socks
import logging
import time
# import threading
# from gevent.server import StreamServer
# from gevent import sleep, socket
# monkey.patch_socket()
# monkey.patch_ssl()

# socks.set_default_proxy(socks.SOCKS5, '192.168.1.1', 1080)
# socket.socket = socks.socksocket()
logging.basicConfig(level=logging.INFO)


def parse_header(raw_headers):
    request_lines = raw_headers.split('\r\n')
    first_line = request_lines[0].split(' ')
    other_lines = request_lines[1:]
    method = first_line[0]
    full_path = first_line[1]
    version = first_line[2]
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
    headers_dict = {'method': method, 'version': version, 'scm': scm,
                    'address': address, 'path': path, 'params': params,
                    'query': query, 'fragment': fragment}
    headers_list = [line.split(':') for line in other_lines if line]
    headers_dict_more = {line[0].strip(): line[1].strip()
                         for line in headers_list}
    return dict(headers_dict, **headers_dict_more)


host_p = re.compile('http://.+?/')
connection_p = re.compile('Connection: .+?\r\n')
proxy_p = re.compile('Proxy-.+?\n')


def deal_with_headers(headers, conn_keep=True):
    if '\nConnection' in headers:
        headers = proxy_p.sub('', headers)
    else:
        headers = headers.replace('Proxy-', '')
    if conn_keep:
        pass
    else:
        headers = connection_p.sub('Connection: close\r\n', headers)
    headers = headers.split('\n')
    headers[0] = host_p.sub('/', headers[0])
    headers = '\n'.join(headers)
    return headers


# server_ = json.loads( open('aqua.json').read() )
# server = server_['server']
# port = server_['port']
# def childproxy(conn, headers, conn_name='', serv_name=''):
#     s = socket.socket()
#     s.connect( (server, port ) )
#     s.sendall( headers.encode() )
#     create_pipe(conn, s, conn_name, serv_name)


def httpsproxy(conn, addr, raw_headers, socks5):
    headers_dict = parse_header(raw_headers)
    if socks5:
        serv = socks.socksocket(socket.AF_INET, socket.SOCK_STREAM)
    else:
        serv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        serv.connect(headers_dict['address'])
    except TimeoutError:
        return
    conn.sendall(b'HTTP/1.1 200 Connection established\r\n\r\n')
    logging.info(str(addr) +
                 ' [{}] '.format(time.strftime('%Y-%m-%d %H:%M:%S')) +
                 headers_dict['method'] + str(headers_dict['address']) +
                 headers_dict['path'])
    # create_pipe(conn, s, conn_name=addr, serv_name=address[0])
    # p = multiprocessing.Process(target=a_to_b,
    #                             args=(conn, serv, addr[0],
    #                                   headers_dict['address']))
    # p.setDaemon(True)
    # p.start()
    # a_to_b(serv, conn, headers_dict['address'], addr[0])
    # serv.settimeout(0.1)
    # conn.settimeout(0.1)
    serv.setblocking(0)
    conn.setblocking(0)
    while 1:
        try:
            [serv.sendall(buf) for buf in iter(lambda:conn.recv(1024*16), b'')]
            return logging.debug('https close')#'server: {} client: {} close'.format(address[0], addr))
        except BlockingIOError:
            try:
                [conn.sendall(buf) for buf in iter(lambda: serv.recv(1024*16), b'')]
                return logging.debug('https close')  # 'server: {} client: {} close'.format(address[0], addr))
            except BlockingIOError:
                time.sleep(0.1)
                continue
            except ConnectionResetError:
                logging.debug('https close')  # 'server: {} client: {} close'.format(address[0], addr))
                return
        except ConnectionResetError:
            logging.debug('https close')  # 'server: {} client: {} close'.format(address[0], addr))
            return

    return  # p.terminate()


def a_to_b(a_conn, b_conn, a_name, b_name):
    b_conn_sendall = b_conn.sendall
    try:
        [b_conn_sendall(buf) for buf in iter(lambda:a_conn.recv(1024*16), b'')]
    except (ConnectionResetError, BrokenPipeError) as e:
        logging.info(e)
    finally:
        a_conn.close()
        b_conn.close()
        return logging.info('{} -> {} close'.format(a_name, b_name))


def httpproxy(cli, addr, headers, socks5=False):
    if socks5:
        serv = socks.socksocket(socket.AF_INET, socket.SOCK_STREAM)
    else:
        serv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    headers_dict = parse_header(headers)

    logging.debug('start httpproxy ' + time.ctime())
    try:
        serv.connect(headers_dict['address'])
    except socket.gaierror as e:
        logging.info('{} {}'.format(e, headers_dict['address']))
    logging.info('[{}] '.format(time.strftime('%Y-%m-%d %H:%M:%S')) +
                 ' connect {} success'.format(headers_dict['Host']))
    logging.debug('connected ' + time.ctime())
    headers = deal_with_headers(headers, conn_keep=False)
    logging.debug(headers)
    logging.info(str(addr) +
                 ' [{}] '.format(time.strftime('%Y-%m-%d %H:%M:%S')) +
                 headers_dict['method'] + str(headers_dict['address']) +
                 headers_dict['path'])

    try:
        serv.sendall(headers.encode())
    except BrokenPipeError:
        return
    # p = multiprocessing.Process(target=a_to_b,
    # args=(serv, cli, headers_dict['Host'], addr[0],), daemon=True)
    # p.start()
    # cli_to_serv(serv, cli, headers_dict['Host'], addr)
    a_to_b(serv, cli, headers_dict['address'], addr[0])
    # return p.terminate()


def get_headers(conn):
    # 针对微信朋友圈图片URL的[::ffff:ip]
    p_ip = re.compile('\[::ffff:(.+)\]')
    headers = ''
    for buf in iter(lambda: conn.recv(1).decode('utf-8', 'ignore'), ''):
        headers += buf
        if headers.endswith('\r\n\r\n'):
            break
    if '::ffff' in headers:
        headers = p_ip.sub('\\1', headers)
    return headers


def handle(cli, cli_addr, socks5):
    headers = get_headers(cli)
    try:
        headers_dict = parse_header(headers)
    except (ValueError, IndexError):
        return
    if len(headers_dict.keys()) <= 1:
        return
    else:
        pass

    if headers_dict['method'] == 'CONNECT':
        logging.debug('httpsproxy ' + time.ctime())
        return httpsproxy(cli, cli_addr, headers, socks5)
    else:
        logging.debug('proxy ' + time.ctime())
        return httpproxy(cli, cli_addr, headers, socks5)


def bjproxy(config):
    # if config['mode'] == 'multiprocessing':
    print(config['socks5'])
    if config['socks5']:
        socks5_ip, socks5_port = config['socks5'].split(':')
        socks.set_default_proxy(socks.SOCKS5, socks5_ip, int(socks5_port))
        socks5 = True
    else:
        socks5 = False
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listen_addr, listen_port = config['listen'].split(':')
    s.bind((listen_addr, int(listen_port)))
    s.listen(1500)
    logging.info('listen on {}'.format(config['listen']))

    # pool = multiprocessing.Pool(config['the_num_of_processes'])
    while True:
        cli, cli_addr = s.accept()
        logging.debug('accept ' + time.ctime())
        # handle(cli, cli_addr)
        # pool.apply_async(handle, args=(cli, cli_addr, config['mode'], ))
        multiprocessing.Process(target=handle,
                                args=(cli, cli_addr, socks5)).start()


def main():
    with open('bjproxy.json') as f:
        config = json.loads(f.read())
    bjproxy(config)


if __name__ == '__main__':
    main()
# StreamServer(('0.0.0.0', 8080), handle.serve_forever()
