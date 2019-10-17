import inspect
import logging
import re

from logging import Formatter, Logger, StreamHandler
from socketserver import ThreadingMixIn
from typing import Dict, Union, List
from urllib.parse import urlparse, parse_qs, ParseResultBytes
from pyicap import ICAPServer, BaseICAPRequestHandler


class HttpSanitizerServer(ThreadingMixIn, ICAPServer):
    __logger: Logger = None

    def __init__(self, server_address, bind_and_activate=True):
        super().__init__(server_address, HttpSanitizerHandler, bind_and_activate)
        self.__logger = logging.getLogger(type(self).__name__)

        handler = StreamHandler()
        handler.setFormatter(Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s'))
        self.__logger.addHandler(handler)

        # Only for debug purposes
        self.__logger.setLevel(logging.DEBUG)

    def serve_forever(self, poll_interval=0.5):
        self.__logger.info('Starting HTTP Sanitizer Server...')
        try:
            super().serve_forever(poll_interval)
        except KeyboardInterrupt:
            self.__logger.info('HTTP Sanitizer Server stopped.')


class HttpSanitizerHandler(BaseICAPRequestHandler):
    # Get logger from outer scope
    __logger: Logger = logging.getLogger(HttpSanitizerServer.__name__)

    __body: str = None
    __url: ParseResultBytes = None
    __query_string: Dict[str, str] = None

    def _get_url(self) -> ParseResultBytes:
        if self.__url:
            return self.__url
        self.__url = urlparse(self.enc_req[1])
        return self.__url

    def _get_query_string(self) -> Dict[str, str]:
        if self.__query_string:
            return self.__query_string
        query_string: Dict[bytes, List[bytes]] = parse_qs(self._get_url().query)
        # Convert to ASCII
        self.__query_string = {k: [vv.decode('ascii') for vv in v]
                               for k, v in
                               {k.decode('ascii'): v for k, v in query_string.items()}.items()}
        return self.__query_string

    def _get_body(self) -> str:
        if self.__body:
            return self.__body
        body: bytes = b''
        while True:
            chunk = self.read_chunk()
            if chunk == b'':
                break
            body += chunk

        self.__body = body.decode(self.get_encoding())
        return self.__body

    def _set_body(self, body: str):
        self.__body = body

    def get_encoding(self) -> str:
        """
        Try to get encoding from Content-Type header and default to UTF-8 if not found.
        :return: The encoding.
        """
        encoding = b'utf-8'
        if b'content-type' in self.enc_res_headers:
            # Get the charset portion of the content type if present
            content_type_parts = self.enc_res_headers[b'content-type'][0].split(b'; ')
            if len(content_type_parts) > 1:
                encoding = content_type_parts[1].split(b'=')[1].lower()
        return encoding.decode('ascii')

    def res_is_html(self):
        if b'content-type' in self.enc_res_headers:
            return self.enc_res_headers[b'content-type'][0].split(b'; ')[0] == b'text/html'
        else:
            return False

    def send_body(self):
        self.set_icap_response(200)

        if self.enc_res_status is not None:
            self.set_enc_status(b' '.join(self.enc_res_status))

        for h in self.enc_res_headers:
            if h == b'content-length':
                # Fuck Python 3
                self.set_enc_header(h, to_bytes(len(self.body)))
            else:
                for v in self.enc_res_headers[h]:
                    self.set_enc_header(h, v)

        self.send_headers(True)
        self.send_chunk(self.body.encode(self.get_encoding()))

    def patch_reflection_xss(self):
        for v in self.query_string.values():
            for vv in v:
                if vv in self.body:
                    print(vv)

    body: str = property(_get_body, _set_body)
    url: ParseResultBytes = property(_get_url)
    query_string: Dict[bytes, bytes] = property(_get_query_string)

    # ---------- SERVICES ---------- #
    def default_OPTIONS(self, mode: bytes):
        self.set_icap_response(200)
        self.set_icap_header(b'Methods', mode)
        self.set_enc_header(b'Service', b'HTTP Sanitizer Server 1.0')
        self.set_icap_header(b'Preview', b'0')
        self.send_headers(False)

    def xss_auditor_OPTIONS(self):
        self.default_OPTIONS(b'RESPMOD')

    def xss_auditor_RESPMOD(self):
        if not self.res_is_html():
            self.no_adaptation_required()
            return
        self.body = self.body.replace('works', 'does not work')
        self.send_body()


def to_bytes(value: Union[str, int, float], encoding='utf-8'):
    if type(value) is str:
        return bytes(value, encoding)
    elif type(value) is int or type(value) is float:
        return bytes(str(value), encoding)


if __name__ == '__main__':
    port = 13440
    server = HttpSanitizerServer((b'', port))
    server.serve_forever()
