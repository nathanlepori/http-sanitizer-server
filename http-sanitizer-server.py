import logging
import re
from difflib import SequenceMatcher, Match
from logging import Formatter, Logger, StreamHandler
from socketserver import ThreadingMixIn
from typing import Dict, Union, List, Pattern, Set
from urllib.parse import urlparse, urlencode, parse_qs, ParseResult

import pymysql
from bs4 import BeautifulSoup, Tag
from pyicap import ICAPServer, BaseICAPRequestHandler

# Can be URL encoded, HTML or raw (for unsupported MIME types)
ParsedBody = Union[Dict[str, List[str]], BeautifulSoup, str]


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

    __HTML_EVENTS: Set[str] = [
        'onbeforecopy',
        'onbeforecut',
        'onbeforepaste',
        'oncopy',
        'oncut',
        'oninput',
        'onkeydown',
        'onkeypress',
        'onkeyup',
        'onpaste',
        'textInput',
        'onabort',
        'onbeforeunload',
        'onhashchange',
        'onload',
        'onoffline',
        'ononline',
        'onreadystatechange',
        'onreadystatechange',
        'onreadystatechange',
        'onstop',
        'onunload',
        'onreset',
        'onsubmit',
        'onclick',
        'oncontextmenu',
        'ondblclick',
        'onlosecapture',
        'onmouseenter',
        'onmousedown',
        'onmouseleave',
        'onmousemove',
        'onmouseout',
        'onmouseover',
        'onmouseup',
        'onmousewheel',
        'onscroll',
        'onmove',
        'onmoveend',
        'onmovestart',
        'ondrag',
        'ondragend',
        'ondragenter',
        'ondragleave',
        'ondragover',
        'ondragstart',
        'ondrop',
        'onresize',
        'onresizeend',
        'onresizestart',
        'onactivate',
        'onbeforeactivate',
        'onbeforedeactivate',
        'onbeforeeditfocus',
        'onblur',
        'ondeactivate',
        'onfocus',
        'onfocusin',
        'onfocusout',
        'oncontrolselect',
        'onselect',
        'onselectionchange',
        'onselectstart',
        'onafterprint',
        'onbeforeprint',
        'onhelp',
        'onerror',
        'onerror',
        'onerrorupdate',
        'onafterupdate',
        'onbeforeupdate',
        'oncellchange',
        'ondataavailable',
        'ondatasetchanged',
        'ondatasetcomplete',
        'onrowenter',
        'onrowexit',
        'onrowsdelete',
        'onrowsinserted',
        'onbounce',
        'onfinish',
        'onstart',
        'onchange',
        'onfilterchange',
        'onpropertychange',
        'onsearch',
        'onmessage',
        'CheckboxStateChange',
        'DOMActivate',
        'DOMAttrModified',
        'DOMCharacterDataModified',
        'DOMFocusIn',
        'DOMFocusOut',
        'DOMMouseScroll',
        'DOMNodeInserted',
        'DOMNodeInsertedIntoDocument',
        'DOMNodeRemoved',
        'DOMNodeRemovedFromDocument',
        'DOMSubtreeModified',
        'dragdrop',
        'dragexit',
        'draggesture',
        'overflow',
        'overflowchanged',
        'RadioStateChange',
        'underflow',
    ]

    # Minimum size for content reflected from URL or query string to be considered suspicious
    __REFLECTED_CONTENT_MIN_SIZE = 5

    # Get logger from outer scope
    __logger: Logger = logging.getLogger(HttpSanitizerServer.__name__)

    __url: ParseResult = None
    __query_string: Dict[str, str] = None
    __parsed_body: ParsedBody = None

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

    def _read_body(self) -> str:
        body: bytes = b''
        while True:
            chunk = self.read_chunk()
            if chunk == b'':
                break
            body += chunk

        return body.decode(self.get_encoding())

    def _parse_body(self, body: str):
        if self.body_is_urlencoded():
            self.__parsed_body = parse_qs(body)
        elif self.body_is_html():
            self.__parsed_body = BeautifulSoup(body, features='lxml')
        else:
            # Raw or unsupported
            self.__parsed_body = body

    def _get_parsed_body(self) -> ParsedBody:
        if self.__parsed_body:
            return self.__parsed_body
        body = self._read_body()
        self._parse_body(body)
        return self.__parsed_body

    def _get_body(self) -> str:
        if self.body_is_urlencoded():
            # Return encoded form data, preserving special characters (like "&")
            return urlencode(self.parsed_body, doseq=True)
        elif self.body_is_html():
            # Return string representation of DOM
            return str(self.parsed_body)
        else:
            return self.parsed_body

    def _set_body(self, body: str):
        self._parse_body(body)

    def get_content_type(self, request: bool = None):
        """
        Gets the content type of the current request/response. Which one to choose is determined by the ICAP command
        that's being executed, but can be changed by settings the request parameter. Returns None if Content-Type is not
        set.
        :return:
        """
        if self.command == b'REQMOD' or request:
            if b'content-type' in self.enc_req_headers:
                return self.enc_req_headers[b'content-type'][0].split(b'; ')[0]
        elif self.command == b'RESPMOD':
            if b'content-type' in self.enc_res_headers:
                return self.enc_res_headers[b'content-type'][0].split(b'; ')[0]

    def body_is_urlencoded(self, request: bool = None):
        return self.get_content_type(request) == b'application/x-www-form-urlencoded'

    def body_is_html(self, request: bool = None) -> bool:
        return self.get_content_type(request) == b'text/html'

    def get_encoding(self, request: bool = None) -> str:
        """
        Try to get encoding from Content-Type header and default to UTF-8 if not found.
        :return: The encoding.
        """
        encoding = b'utf-8'
        if self.command == b'REQMOD' or request:
            if b'content-type' in self.enc_req_headers:
                # Get the charset portion of the content type if present
                content_type_parts = self.enc_req_headers[b'content-type'][0].split(b'; ')
                if len(content_type_parts) > 1:
                    encoding = content_type_parts[1].split(b'=')[1].lower()
        else:
            if b'content-type' in self.enc_res_headers:
                # Get the charset portion of the content type if present
                content_type_parts = self.enc_res_headers[b'content-type'][0].split(b'; ')
                if len(content_type_parts) > 1:
                    encoding = content_type_parts[1].split(b'=')[1].lower()
        return encoding.decode()

    def get_url_path_parts(self):
        return list(filter(lambda p: len(p) != 0, self.url.path.split('/')))

    def send(self) -> None:
        """
        Sends the ICAP response back to the HTTP client. Calling this always copies headers and body, if any, adjusting
        the Content-Length header. Since this server only handles body adaptation so far, headers and status are copied.
        """
        self.set_icap_response(200)

        if self.command == b'REQMOD':
            # Copy request status
            if self.enc_req is not None:
                self.set_enc_request(b' '.join(self.enc_req))

            # Copy request headers
            for h in self.enc_req_headers:
                for v in self.enc_req_headers[h]:
                    self.set_enc_header(h, v)
        elif self.command == b'RESPMOD':
            # Copy response status
            if self.enc_res_status is not None:
                self.set_enc_status(b' '.join(self.enc_res_status))

            # Copy response headers
            for h in self.enc_res_headers:
                for v in self.enc_res_headers[h]:
                    self.set_enc_header(h, v)

        if self.has_body or len(self.body) > 0:
            # Request has a body, either added by the service or from the original request/response
            # Add or update the Content-Length header
            self.set_enc_header(b'content-length', to_bytes(len(self.body)))

            self.send_headers(True)
            self.send_chunk(self.body.encode(self.get_encoding()))
            self.send_chunk(b'')
        else:
            self.send_headers(False)

    def find_reflected_content(self) -> List[str]:
        matches = []

        # Try to find reflected content in URL
        for part in self.get_url_path_parts():
            if find_longest_match(self.body, part).size >= self.__REFLECTED_CONTENT_MIN_SIZE:
                matches.append(part)

        # Try to find a match in the query string
        for v in self.query_string.values():
            for vv in v:
                if find_longest_match(self.body, vv).size >= self.__REFLECTED_CONTENT_MIN_SIZE:
                    matches.append(vv)
        return matches

    def is_malicious(self, s: str):
        for p in self.__MALICIOUS_PATTERNS:
            if re.match(p, s, flags=re.IGNORECASE):
                return True
        return False

    def get_malicious_matches(self, matches: List[str]):
        return list(filter(self.is_malicious, matches))

    def patch_attributes(self, malicious_strings: List[str]):
        # First patch events (can execute JS when triggered)
        events_selector = ','.join(map(lambda s: f'[{s}]', self.__HTML_EVENTS))
        tags_with_events: List[Tag] = self.parsed_body.select(events_selector)

        blacklisted_attrs = {}
        for tag in tags_with_events:
            # Copy into list to be able to delete while iterating
            for attr in list(tag.attrs):
                if attr in self.__HTML_EVENTS:
                    v = tag.attrs[attr]
                    if v in malicious_strings:
                        del tag.attrs[attr]
                        blacklisted_attrs[attr] = v

        # Then patch these two attributes (can execute JS when prefixed with "javascript:", i.e. <a>, <iframe>, ...)
        src_attributes = ['href', 'src']
        src_selector = ','.join(map(lambda s: f'[{s}]', src_attributes))
        tags_with_src = self.parsed_body.select(src_selector)
        for tag in tags_with_src:
            # Copy into list to be able to delete while iterating
            for attr in list(tag.attrs):
                if attr in src_attributes:
                    v = tag.attrs[attr]
                    # Only filter if they contain the "javascript:" prefix
                    if 'javascript:' in v and (v in malicious_strings or f'javascript:{v}'):
                        del tag.attrs[attr]
                        blacklisted_attrs[attr] = v

        return blacklisted_attrs

    def patch_script_tags(self, malicious_strings: List[str]) -> List[Tag]:
        """
        Removes injected script tags from the DOM
        :return:
        """
        # TODO: Patch reflected script tags where the tag itself is rendered server side
        # Filter all script tag strings
        script_tags = list(
            filter(lambda s: re.match(r'.*<script>.*</script>.*', s, flags=re.IGNORECASE), malicious_strings))
        # Extract the JS source code from them
        script_tags_code = list(map(lambda s: BeautifulSoup(s, features='lxml').find('script').text, script_tags))

        blacklisted_tags: List[Tag] = []
        for code in script_tags_code:
            # Find corresponding tag in DOM
            tags = self.parsed_body.find_all('script', text=code)
            # Remove the tag from the source code and add it to the blacklisted tags list
            for tag in tags:
                blacklisted_tags.append(tag.extract())
        return blacklisted_tags

    def patch_reflection_xss(self):
        if not self.body_is_html():
            return False
        matches = self.find_reflected_content()
        blacklisted_tags = self.patch_script_tags(matches)
        blacklisted_attrs = self.patch_attributes(matches)

        patched = False
        if len(blacklisted_tags) > 0:
            self.__logger.info(f'Found at least one malicious tag: {str(blacklisted_tags)}')
            patched = True
        if len(blacklisted_attrs) > 0:
            self.__logger.info(f'Found at least one malicious attribute: {str(blacklisted_attrs)}')
            patched = True
        return patched

    def is_post_request(self):
        return self.enc_req[0] == b'POST'

    def sanitize_request_body(self):
        if self.is_post_request() and self.has_body:
            if self.body_is_urlencoded():
                escaped = False
                for k in self.parsed_body:
                    for i, v in enumerate(self.parsed_body[k]):
                        if not is_escaped(v):
                            escaped_v = pymysql.escape_string(v)
                            if escaped_v != v:
                                # If anything was actually escaped
                                self.parsed_body[k][i] = escaped_v
                                escaped = True
                if not escaped:
                    return False
                return True

    def inject_sanitizer_banner(self):
        body: Tag = self.parsed_body.find('body')
        banner = self.parsed_body.new_tag('div', attrs={
            'style': 'width: 100%; height: 50px; padding-top: 10px; text-align: center; background-color: yellow;'
        })
        banner.string = 'Some malicious content was removed by HTTP Sanitizer Server.'
        if body:
            body.insert_before(banner)
        else:
            self.parsed_body.insert(0, banner)

    url: ParseResult = property(_get_url)
    query_string: Dict[str, str] = property(_get_query_string)
    body: str = property(_get_body, _set_body)
    parsed_body: ParsedBody = property(_get_parsed_body)

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
        if self.patch_reflection_xss():
            self.inject_sanitizer_banner()
            self.send()
            return
        self.no_adaptation_required()

    def body_sanitizer_OPTIONS(self):
        self.default_OPTIONS(b'REQMOD')

    def body_sanitizer_REQMOD(self):
        if self.sanitize_request_body():
            self.send()
            return
        self.no_adaptation_required()


def to_bytes(value: Union[str, int, float], encoding='utf-8'):
    if type(value) is str:
        return bytes(value, encoding)
    elif type(value) is int or type(value) is float:
        return bytes(str(value), encoding)


def find_longest_match(a: str, b: str) -> Match:
    seq_matcher = SequenceMatcher(None, a, b)
    return seq_matcher.find_longest_match(0, len(a), 0, len(b))


def is_escaped(value: str) -> bool:
    return bool(re.match(r'\\[0\\nrZ"\']', value))


if __name__ == '__main__':
    port = 13440
    server = HttpSanitizerServer((b'', port))
    server.serve_forever()
