import inspect
import logging
import re

from logging import Formatter, Logger, StreamHandler
from socketserver import ThreadingMixIn
from typing import Dict, Union, List, Pattern
from urllib.parse import urlparse, parse_qs, ParseResult

from bs4 import BeautifulSoup, Tag, ResultSet
from pyicap import ICAPServer, BaseICAPRequestHandler
from difflib import SequenceMatcher, Match


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
    __MALICIOUS_PATTERNS: List[Pattern] = [
        r'<script>.*',
        r'javascript:.*',
    ]

    __HTML_EVENTS: List[str] = [
        'onafterprint',
        'onbeforeprint',
        'onbeforeunload',
        'onerror',
        'onhashchange',
        'onload',
        'onmessage',
        'onoffline',
        'ononline',
        'onpagehide',
        'onpageshow',
        'onpopstate',
        'onresize',
        'onstorage',
        'onunload',
        'onblur',
        'onchange',
        'oncontextmenu',
        'onfocus',
        'oninput',
        'oninvalid',
        'onreset',
        'onsearch',
        'onselect',
        'onsubmit',
        'onkeydown',
        'onkeypress',
        'onkeyup',
        'onclick',
        'ondblclick',
        'onmousedown',
        'onmousemove',
        'onmouseout',
        'onmouseover',
        'onmouseup',
        'onmousewheel',
        'onwheel',
        'ondrag',
        'ondragend',
        'ondragenter',
        'ondragleave',
        'ondragover',
        'ondragstart',
        'ondrop',
        'onscroll',
        'oncopy',
        'oncut',
        'onpaste',
        'onabort',
        'oncanplay',
        'oncanplaythrough',
        'oncuechange',
        'ondurationchange',
        'onemptied',
        'onended',
        'onerror',
        'onloadeddata',
        'onloadedmetadata',
        'onloadstart',
        'onpause',
        'onplay',
        'onplaying',
        'onprogress',
        'onratechange',
        'onseeked',
        'onseeking',
        'onstalled',
        'onsuspend',
        'ontimeupdate',
        'onvolumechange',
        'onwaiting',
        'ontoggle',
        'href'
    ]

    # Get logger from outer scope
    __logger: Logger = logging.getLogger(HttpSanitizerServer.__name__)

    __url: ParseResult = None
    __query_string: Dict[str, str] = None
    __body: str = None
    __dom: BeautifulSoup = None

    def _get_url(self) -> ParseResult:
        if self.__url:
            return self.__url
        self.__url = urlparse(self.enc_req[1].decode())
        return self.__url

    def _get_query_string(self) -> Dict[str, str]:
        if self.__query_string:
            return self.__query_string
        query_string: Dict[str, List[str]] = parse_qs(self._get_url().query)
        # Convert to ASCII
        self.__query_string = {k: [vv for vv in v]
                               for k, v in
                               {k: v for k, v in query_string.items()}.items()}
        return self.__query_string

    def _get_body(self) -> str:
        # TODO: Test
        # If modifications to the DOM have been made, write them back as string
        if self.__dom:
            self.__body = str(self.__dom)

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

    def _get_dom(self) -> BeautifulSoup:
        # TODO: Test
        # If modifications to the body have been made, write them back
        if self.__body:
            self.__dom = BeautifulSoup(self.__body)

        if self.__dom:
            return self.__dom
        self.__dom = BeautifulSoup(self.body)
        return self.__dom

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
        return encoding.decode()

    def res_is_html(self):
        if b'content-type' in self.enc_res_headers:
            return self.enc_res_headers[b'content-type'][0].split(b'; ')[0] == b'text/html'
        else:
            return False

    def get_url_path_parts(self):
        return list(filter(lambda p: len(p) != 0, self.url.path.split('/')))

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

    def find_reflected_content(self) -> List[str]:
        matches = []

        # Try to find reflected content in URL
        for part in self.get_url_path_parts():
            if self.body.find(part):
                matches.append(part)

        # Try to find a match in the query string
        for v in self.query_string.values():
            for vv in v:
                if self.body.find(vv):
                    matches.append(vv)
        return matches

    def is_malicious(self, s: str):
        for p in self.__MALICIOUS_PATTERNS:
            if re.match(p, s, flags=re.IGNORECASE):
                return True
        return False

    def get_malicious_matches(self, matches: List[str]):
        return list(filter(self.is_malicious, matches))

    def find_malicious_attributes(self, malicious_strings: List[str]):
        events_selector = ','.join(map(lambda s: f'[{s}]', self.__HTML_EVENTS))
        tags_with_events: List[Tag] = self.dom.select(events_selector)

        for tag in tags_with_events:
            for attr, val in tag.attrs.items():
                if attr in self.__HTML_EVENTS:
                    if val in malicious_strings:
                        self.__logger.info('Found malicious string')

    def patch_script_tags(self, malicious_strings: List[str]) -> List[Tag]:
        """
        Removes injected script tags from the DOM
        :return:
        """
        # Filter all script tag strings
        script_tags = list(filter(lambda s: re.match(r'<script>.*</script>', s, flags=re.IGNORECASE), malicious_strings))
        # Extract the JS source code from them
        script_tags_code = list(map(lambda s: BeautifulSoup(s).text, script_tags))

        blacklisted_tags: List[Tag] = []
        for code in script_tags_code:
            # Find corresponding tag in DOM
            tags = self.dom.find_all('script', text=code)
            # Remove the tag from the source code and add it to the blacklisted tags list
            for tag in tags:
                blacklisted_tags.append(tag.extract())
        return blacklisted_tags

    def patch_reflection_xss(self):
        malicious_strings = self.find_reflected_content()
        blacklisted_tags = self.patch_script_tags(malicious_strings)
        self.__logger.info(f'Found at least one malicious tag: {str(blacklisted_tags)}')

    url: ParseResult = property(_get_url)
    query_string: Dict[str, str] = property(_get_query_string)
    body: str = property(_get_body, _set_body)
    dom: BeautifulSoup = property(_get_dom)

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
        self.patch_reflection_xss()
        self.send_body()


def to_bytes(value: Union[str, int, float], encoding='utf-8'):
    if type(value) is str:
        return bytes(value, encoding)
    elif type(value) is int or type(value) is float:
        return bytes(str(value), encoding)


def find_longest_match(a: str, b: str) -> Match:
    seq_matcher = SequenceMatcher(None, a, b)
    return seq_matcher.find_longest_match(0, len(a), 0, len(b))


if __name__ == '__main__':
    port = 13440
    server = HttpSanitizerServer((b'', port))
    server.serve_forever()
