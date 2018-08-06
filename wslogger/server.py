import asyncore
import logging
import socket
import os
import datetime
import threading
import time
import hashlib
import base64
import enum
import multiprocessing
import json


CLRF = b'\r\n'
DOUBLE_CLRF = CLRF + CLRF
DEFAULT_ENCODING = 'utf-8'
WEBSOCKETS_GUID = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11'


class WsOpCode(enum.Enum):
    Continue = 0x0
    Text = 0x1
    Binary = 0x2
    Close = 0x8
    Ping = 0x9
    Pong = 0xA


def http_date(dt):
    """Return a string representation of a date according to RFC 1123 (HTTP/1.1).
    The supplied date must be in UTC.
    """
    weekday = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"][dt.weekday()]
    month = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep",
             "Oct", "Nov", "Dec"][dt.month - 1]
    return "%s, %02d %s %04d %02d:%02d:%02d GMT" % (weekday, dt.day, month, dt.year, dt.hour, dt.minute, dt.second)


def parse_http_headers(headers_data: bytes, encoding=DEFAULT_ENCODING):
    headers = {}
    for line in headers_data.split(CLRF):
        sep = line.find(b':')
        key = line[:sep].decode(encoding).strip()
        val = line[sep + 1:].decode(encoding).strip()
        headers[key] = val
    return headers


def create_http_message(first_line, headers: dict, content: bytes=None, encoding=DEFAULT_ENCODING):
    if not isinstance(first_line, bytes):
        message = first_line.encode(encoding) + CLRF
    else:
        message = first_line + CLRF
    headers_lines = ['{0}: {1}'.format(k, v).encode(encoding) for k, v in headers.items()]
    for line in headers_lines:
        message += line + CLRF
    message += CLRF
    if content is not None:
        message += content
    return message


def parse_http_message(data: bytes, encoding=DEFAULT_ENCODING):
    header_data, content = data.split(DOUBLE_CLRF)
    sep = header_data.find(CLRF)
    first_line = header_data[:sep].decode(encoding)
    headers = parse_http_headers(header_data[sep + len(CLRF):], encoding=encoding)
    return first_line, headers, content


def create_http_response(content: bytes=b'', status=200, status_msg='OK', additional_headers=None, encoding=DEFAULT_ENCODING):
    headers = {
        'Server': 'Python WsLogger',
        'Content-Type': 'text/html',
        'Connection': 'Closed',
        'Content-Length': '{0}'.format(len(content)),
        'Date': '{0}'.format(http_date(datetime.datetime.utcnow()))
    }
    if additional_headers is not None:
        headers.update(additional_headers)
    return create_http_message('HTTP/1.1 {0} {1}'.format(status, status_msg), headers, content, encoding=encoding)


def parse_http_request(data: bytes, encoding=DEFAULT_ENCODING):
    request_line, headers, content = parse_http_message(data, encoding=encoding)
    method, uri, protocol = request_line.split(' ')
    return {'method': method, 'uri': uri, 'protocol': protocol, 'headers': headers, 'content': content}


def http_response(uri, method, headers, content, encoding=DEFAULT_ENCODING, *args, **kwargs):
    with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), 'index.html'), 'r', encoding='utf-8') as f:
        response_html = f.read()

    if method == 'GET':
        if uri == '/':
            return create_http_response(response_html.encode(encoding), 200, 'OK')
        else:
            return create_http_response(status=404, status_msg='Not Found')
    return create_http_response(status=500, status_msg='Server error')


def ws_handshake_response(request_headers, encoding=DEFAULT_ENCODING):
    ws_key = request_headers.get('Sec-WebSocket-Key', None)
    #ws_version = request_headers.get('Sec-WebSocket-Version', None)
    if ws_key is None:
        return None
    srv_key_raw = (ws_key + WEBSOCKETS_GUID).encode(encoding)
    srv_key = base64.b64encode(hashlib.sha1(srv_key_raw).digest()).decode(encoding)

    return create_http_message('HTTP/1.1 101 Switching Protocols', headers={
        'Upgrade': 'websocket',
        'Connection': 'Upgrade',
        'Sec-WebSocket-Accept': srv_key,
        #'Sec-WebSocket-Protocol': 'chat'
    })


def create_ws_dataframe(data: bytes, opcode: WsOpCode, fin=True, masking_key=None):
    fin_mask = 0b10000000 if fin else 0
    opcode_mask = 0b00001111
    first_byte = (opcode.value & opcode_mask) | fin_mask
    message = bytes([first_byte])
    data_len = len(data)
    #payload_len_bytes = int(len(data)).to_bytes(6, byteorder='little')
    payload_size = len(data)
    is_masked = 0b10000000 if masking_key is not None else 0

    if payload_size <= 125:
        message += bytes([payload_size | is_masked])
    elif 126 <= payload_size <= 655535:
        message += bytes([126 | is_masked])
        message += data_len.to_bytes(2, byteorder='big')
    else:
        message += bytes([127 | is_masked])
        message += data_len.to_bytes(8, byteorder='big')

    if masking_key is not None:
        if isinstance(masking_key, bytes):
            assert len(masking_key) == 4
        if isinstance(masking_key, int):
            masking_key = masking_key.to_bytes(4, byteorder='big')
        message += masking_key

        encoded = bytes([data[i] ^ masking_key[i % 4] for i in range(len(data))])
        message += encoded
    else:
        message += data
    return message


def parse_dataframe(data: bytes):
    if not data:
        return

    first_byte = data[0]
    fin = bool(first_byte & 0b10000000)
    opcode = WsOpCode(first_byte & 0b00001111)

    data_len_byte = data[1]
    is_masked = bool(data_len_byte & 0b10000000)
    first_len = data_len_byte & 0b01111111

    data_starts_from = 2

    if first_len < 126:
        data_len = first_len
    elif first_len == 126:
        data_starts_from += 2
        data_len = int.from_bytes(data[2:4], byteorder='big')
    elif first_len == 127:
        data_starts_from += 8
        data_len = int.from_bytes(data[2:10], byteorder='big')
    else:
        raise RuntimeError('wtf!')

    masking_key = None

    if is_masked:
        data_starts_from += 4
        masking_key = data[data_starts_from - 4:data_starts_from]
        payload = bytes([data[data_starts_from + i] ^ masking_key[i % 4] for i in range(data_len)])
    else:
        payload = data[data_starts_from:data_starts_from + data_len]
    return {
        'fin': fin,
        'opcode': opcode,
        'is_masked': is_masked,
        'masking_key': masking_key,
        'payload': payload
    }


class HttpServer(asyncore.dispatcher):
    def __init__(self, host, port, max_connections=5, *args, **kwargs):
        super().__init__(*args, **kwargs)

        asyncore.dispatcher.__init__(self)
        self.create_socket(socket.AF_INET, socket.SOCK_STREAM)
        self.set_reuse_addr()
        self.bind((host, port))
        self.listen(max_connections)

    def handle_accept(self):
        try:
            pair = self.accept()
            if pair is None:
                return
        except socket.error:
            return
        except TypeError:
            return

        sock, addr = pair
        HttpClientHandler(sock=sock)

    def handle_close(self):
        self.close()


class HttpClientHandler(asyncore.dispatcher):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.read_buffer = b''
        self.write_buffer = b''

    def handle_read(self):
        request_data = self.recv(1024)
        if not request_data:
            return
        request = parse_http_request(request_data)
        self.write_buffer = http_response(**request)

    def handle_close(self):
        self.close()

    def writable(self):
        return len(self.write_buffer) > 0

    def handle_write(self):
        sent = self.send(self.write_buffer)
        self.write_buffer = self.write_buffer[sent:]


class WsServer(asyncore.dispatcher):
    def __init__(self, host, port, max_connections=5, *args, **kwargs):
        super().__init__(*args, **kwargs)

        asyncore.dispatcher.__init__(self)
        self.create_socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.set_reuse_addr()
        self.bind((host, port))
        self.listen(max_connections)
        self.clients = []

    def handle_accept(self):
        try:
            pair = self.accept()
            if pair is None:
                return
        except socket.error:
            return
        except TypeError:
            return

        sock, addr = pair
        handler = WsHandler(self, sock=sock)
        self.clients.append(handler)

    def handle_close(self):
        self.close()


class WsHandler(asyncore.dispatcher):
    def __init__(self, srv: WsServer, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.read_buffer = b''
        self.write_buffer = b''
        self.server = srv
        self.active = False

    def handle_read(self):
        data = self.recv(1024)

        if not self.active:
            first_line, headers, content = parse_http_message(data)
            handshake_response = ws_handshake_response(headers)
            if handshake_response is not None:
                self.write_buffer = handshake_response
                self.active = True
        else:
            df = parse_dataframe(data)
            if df['opcode'] == WsOpCode.Close:
                self.close()

    def handle_close(self):
        self.active = False
        self.close()
        if self in self.server.clients:
            self.server.clients.remove(self)

    def writable(self):
        return len(self.write_buffer) > 0

    def handle_write(self):
        sent = self.send(self.write_buffer)
        self.write_buffer = self.write_buffer[sent:]

    def send_message(self, data: str):
        if self.active:
            df = create_ws_dataframe(data.encode('utf-8'), WsOpCode.Text, masking_key=None)
            self.write_buffer += df


class WebSocketsLoggingHandler(logging.Handler):
    def __init__(self, level=logging.NOTSET, websockets_port=8989, max_queue_size=100, *args, **kwargs):
        super().__init__(level)
        self.message_queue = multiprocessing.Queue(maxsize=max_queue_size)
        self.ws_port = websockets_port
        self.process = multiprocessing.Process(target=run_servers,
                                               args=(self.message_queue, ),
                                               name='WSLogger')
        self.process.daemon = True
        self.process.start()

    def emit(self, record):
        self.message_queue.put(json.dumps(record.__dict__))

    def close(self):
        if self.process is not None:
            self.process.terminate()
        super().close()


def listen_messages(queue: multiprocessing.Queue, server: WsServer):
    while True:
        msg = queue.get(block=True)
        for client in server.clients:
            if client.active:
                client.send_message(msg)


def run_servers(queue: multiprocessing.Queue):
    HttpServer('', 8988)
    wssrv = WsServer('', 8989)
    thread = threading.Thread(target=listen_messages, args=(queue, wssrv)).start()
    asyncore.loop(timeout=2)


if __name__ == '__main__':
    import numpy as np
    logger = logging.getLogger("LoggerTest")
    logger.setLevel(logging.DEBUG)
    logger.addHandler(WebSocketsLoggingHandler())

    levels = [logging.DEBUG, logging.INFO, logging.ERROR, logging.WARNING, logging.NOTSET]
    messages = [
        'The {0} is dead. Don\'t code {0}. Code {1} that is open source!',
        'For reference, for...in won\'t work in every browser as this code expects it to. It\'ll loop over all '
        'enumerable properties, which in some browsers will include arguments.length, and in others won\'t '
        'even include the arguments themselves at all. In any case',
        'String.prototype.format = function (){',
        'I also have a non-prototype version which I use more often for its Java-like syntax:',
        'ES 2015 update',
        'use a small library called String.format for JavaScript which supports most of the format string',
    ]

    while True:
        time.sleep(2)
        logger.log(level=int(np.random.choice(levels)), msg=np.random.choice(messages), extra={
            'a': 'b'
        })
