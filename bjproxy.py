import asyncio
import re
import json


async def get_headers(reader):
    headers_str = ''
    # headers_list = list()
    headers = dict()
    first_line_byte = await reader.readline()
    first_line = first_line_byte.decode()
    while True:
        line_byte = await reader.readline()
        line = line_byte.decode('utf-8', 'ignore').strip('\r\n')
        if not line:  # or line == '\n':
            break
        else:
            if len(line.split(':')) > 2 and line.startswith('Host'):
                key, value, headers['port'] = line.split(':')
            else:
                line_split = line.split(':')
                key, value = line_split[0], ':'.join(line_split[1:])
            headers[key] = value.strip(' ')

    headers['method'], path, _ = first_line.split(' ')
    # print(headers)
    headers['path'] = re.sub('^.+?//.+?/', '/', path)
    if headers.get('Content-Length'):
        headers['data'] = await reader.read(int(headers.get('Content-Length')))
    else:
        headers['data'] = b''

    print(headers)

    return headers


def make_headers_str(headers):
    first_line = '{} {} HTTP/1.1\r\n'.format(headers['method'], headers['path'])
    # del headers['method'], headers[]
    headers_list = [first_line]
    for key in headers.keys():
        if key in  ('method', 'path', 'Proxy-Connection', 'data'):
            pass
        else:
            headers_list.append('{}: {}\r\n'.format(key, headers[key]))
    headers_list.append('Connection: close\r\n')
    headers_list.append('\r\n')
    # headers_list.append(headers[data])
    return ''.join(headers_list)


async def transport(reader, writer):
    while True:
        buf = await reader.read(2048)
        if not buf:
            break
        else:
            # print(buf[:200])
            writer.write(buf)
            await writer.drain()


async def httpproxy(headers, reader_c, writer_c):
    port = headers.get('port') if headers.get('port') else 80
    print(headers['Host'], port)
    reader_s, writer_s = await asyncio.open_connection(headers['Host'], port, loop=loop)
    # print(make_headers_str(headers))
    if headers['method'] == 'CONNECT':
        writer_c.write(b'HTTP/1.1 200 Connection established\r\n\r\n')
        await writer_s.drain()
        loop.create_task(transport(reader_c, writer_s))
        await transport(reader_s, writer_c)
    else:
        writer_s.write(make_headers_str(headers).encode() + headers['data'])
        await writer_s.drain()
        await transport(reader_s, writer_c)
    print(headers['Host'], headers['path'], 'close')


async def handle(reader_c, writer_c):
    print('new connection')
    headers = await get_headers(reader_c)
    # if headers['method'] == 'CONNECT':
    #     pass
    # else:
    await httpproxy(headers, reader_c, writer_c)
        # pass



with open('bjproxy.json') as f:
    cfg = json.loads(f.read())
ip, port = cfg['listen'].split(':')
port = int(port)
loop = asyncio.get_event_loop()
core = asyncio.start_server(handle, ip, port, loop=loop)
server = loop.run_until_complete(core)
loop.run_forever()
