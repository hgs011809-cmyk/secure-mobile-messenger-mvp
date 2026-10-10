"""Container-local readiness diagnostic. Output ONLY status and fixed error code."""
import json
import socket
import urllib.error
import urllib.request

result = {'status': 0, 'error': 'UNKNOWN'}
try:
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with opener.open('http://127.0.0.1:8008/_matrix/client/versions', timeout=3) as response:
        result = {'status': response.status, 'error': 'NONE'}
except urllib.error.HTTPError as error:
    result = {'status': error.code, 'error': 'HTTP_STATUS'}
except urllib.error.URLError as error:
    if isinstance(error.reason, ConnectionRefusedError):
        result['error'] = 'ECONNREFUSED'
    elif isinstance(error.reason, (TimeoutError, socket.timeout)):
        result['error'] = 'ETIMEDOUT'
    else:
        result['error'] = 'CONNECTION_ERROR'
except (TimeoutError, socket.timeout):
    result['error'] = 'ETIMEDOUT'
except Exception:
    pass
print(json.dumps(result))
