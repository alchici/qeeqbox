'''
//  -------------------------------------------------------------
//  author        Giga
//  project       qeeqbox/honeypots
//  email         gigaqeeq@gmail.com
//  description   app.py (CLI)
//  licensee      AGPL-3.0
//  -------------------------------------------------------------
//  contributors list qeeqbox/honeypots/graphs/contributors
//  -------------------------------------------------------------
'''

from warnings import filterwarnings
filterwarnings(action='ignore', module='.*OpenSSL.*')

from OpenSSL import crypto
from cgi import FieldStorage
from requests.packages.urllib3 import disable_warnings
from tempfile import gettempdir, _get_candidate_names
from twisted.internet import reactor, ssl
from twisted.web.server import Site, NOT_DONE_YET
from twisted.web import static
from twisted.web.resource import Resource
from twisted.web.util import Redirect
from random import choice
from twisted.python import log as tlog
from subprocess import Popen
from os import path, getenv
from honeypots.helper import close_port_wrapper, get_free_port, kill_server_wrapper, server_arguments, setup_logger, disable_logger, set_local_vars, check_if_server_is_running
from uuid import uuid4
from contextlib import suppress
import requests

disable_warnings()

def get_ip():
    response = requests.get('https://api64.ipify.org?format=json', timeout=2).json()
    return response["ip"]

def geoIP(ip):
        response = requests.get(f'https://ipapi.co/{ip}/json/',timeout=2).json()
        if response['error']:
            response = requests.get(f'https://ipapi.co/{get_ip()}/json/',timeout=2).json()
        
        location = {
            "city": response["city"],
            "region": response["region"],
            "country": response["country_name"],
            "country_code": response["country_code_iso3"],
            "latitude": response["latitude"],
            "longitud": response["longitude"],
            "asn": response["asn"],
            "org": response["org"]
        }
        return location


class QHTTPSServer():
    def __init__(self, **kwargs):
        self.auto_disabled = None
        self.key = path.join(gettempdir(), next(_get_candidate_names()))
        self.cert = path.join(gettempdir(), next(_get_candidate_names()))
        self.mocking_server = choice(['Apache', 'nginx', 'Microsoft-IIS/7.5', 'Microsoft-HTTPAPI/2.0', 'Apache/2.2.15', 'SmartXFilter', 'Microsoft-IIS/8.5', 'Apache/2.4.6', 'Apache-Coyote/1.1', 'Microsoft-IIS/7.0', 'Apache/2.4.18', 'AkamaiGHost', 'Apache/2.2.25', 'Microsoft-IIS/10.0', 'Apache/2.2.3', 'nginx/1.12.1', 'Apache/2.4.29', 'cloudflare', 'Apache/2.2.22'])
        self.process = None
        self.uuid = 'honeypotslogger' + '_' + __class__.__name__ + '_' + str(uuid4())[:8]
        self.config = kwargs.get('config', '')
        if self.config:
            self.logs = setup_logger(__class__.__name__, self.uuid, self.config)
            set_local_vars(self, self.config)
        else:
            self.logs = setup_logger(__class__.__name__, self.uuid, None)
        self.ip = kwargs.get('ip', None) or (hasattr(self, 'ip') and self.ip) or '0.0.0.0'
        self.port = (kwargs.get('port', None) and int(kwargs.get('port', None))) or (hasattr(self, 'port') and self.port) or 443
        self.username = kwargs.get('username', None) or (hasattr(self, 'username') and self.username) or 'test'
        self.password = kwargs.get('password', None) or (hasattr(self, 'password') and self.password) or 'test'
        self.options = kwargs.get('options', '') or (hasattr(self, 'options') and self.options) or getenv('HONEYPOTS_OPTIONS', '') or ''
        disable_logger(1, tlog)

    def CreateCert(self, host_name, key, cert):
        pk = crypto.PKey()
        pk.generate_key(crypto.TYPE_RSA, 2048)
        c = crypto.X509()
        c.get_subject().C = 'US'
        c.get_subject().ST = 'New York'
        c.get_subject().L = 'New York'
        c.get_subject().O = 'Ivywood University'
        c.get_subject().OU = 'Ivywood University'
        c.get_subject().CN = 'www.ivy.uni.com'
        c.set_serial_number(0x0A3F2B6D7E9C48)
        before, after = (0, 60 * 60 * 24 * 365 * 2)
        c.gmtime_adj_notBefore(before)
        c.gmtime_adj_notAfter(after)
        c.set_issuer(c.get_subject())
        c.set_pubkey(pk)
        c.sign(pk, 'sha256')
        open(cert, 'wb').write(crypto.dump_certificate(crypto.FILETYPE_PEM, c))
        open(key, 'wb').write(crypto.dump_privatekey(crypto.FILETYPE_PEM, pk))

    def https_server_main(self):
        _q_s = self

        class Home(Resource):
            isLeaf = False

            allowedMethods = ('GET','POST')

            def getChild(self, name, request):
               
                request.setHeader('server', 'nginx/1.22.1')

                def check_bytes(string):
                        if isinstance(string, bytes):
                            return string.decode()
                        else:
                            return str(string)
               
                headers = {}
                client_ip = ""

                for item, value in dict(request.requestHeaders.getAllRawHeaders()).items():
                    headers.update({check_bytes(item): ','.join(map(check_bytes, value))})
                    headers.update({'method': check_bytes(request.method)})
                    headers.update({'uri': check_bytes(request.uri)})
                
                if client_ip == "":
                    client_ip = request.getClientAddress().host

                geo_test = {
                    "city": "Valencia",
                    "region": "Valencia",
                    "country": "Spain",
                    "country_code": "ESP",
                    "latitude": "33.33",
                    "longitud": "33.33",
                    "asn": "AStest",
                    "org": "Test ISP"
                }

                # _q_s.logs.info({'server': 'https_server', 'action': 'connection', 'src_ip': {"ip": client_ip, "geo": geoIP(client_ip)}, 'src_port': request.getClientAddress().port, 'dest_ip': _q_s.ip, 'dest_port': _q_s.port, 'data': headers})
                _q_s.logs.info({'server': 'https_server', 'action': 'connection', 'src_ip': {"ip": client_ip, "geo": geo_test}, 'src_port': request.getClientAddress().port, 'dest_ip': _q_s.ip, 'dest_port': _q_s.port, 'data': headers})


                if request.method == b"POST":
                    self.headers = request.getAllHeaders()  

                    if request.uri == b"/web/contact.html":
                        
                        form = FieldStorage(fp=request.content, headers=self.headers, environ={'REQUEST_METHOD': 'POST', 'CONTENT_TYPE': self.headers[b'content-type'], })

                        name_field = form['name'].value
                        email = form['email'].value
                        subject = form['subject'].value
                        message = form['message'].value

                        _q_s.logs.info({'server': 'https_server', 'action': 'contact', 'src_ip': client_ip, 'src_port': request.getClientAddress().port, 'name': name_field, 'email': email, 'subject': subject, 'message': message, 'dest_ip': _q_s.ip, 'dest_port': _q_s.port})

                        return Redirect(b"/web/contact.html")
                    
                    elif request.uri == b"/web/login.html":
                        
                        form = FieldStorage(fp=request.content, headers=self.headers, environ={'REQUEST_METHOD': 'POST', 'CONTENT_TYPE': self.headers[b'content-type'], })

                        username = form['username'].value
                        password = form['password'].value

                        _q_s.logs.info({'server': 'https_server', 'action': 'login', 'status': 'failed', 'src_ip': client_ip, 'src_port': request.getClientAddress().port, 'username': username, 'password': password, 'dest_ip': _q_s.ip, 'dest_port': _q_s.port})

                        return Redirect(b"/web/login.html")

                if name == b"":
                    return Redirect(b"/web")

                if name.decode() in self.children:
                    return self.children[name.decode()]
                
                return Redirect(b'/web/404.html')

            def render(self, request):
                return b"<html>Hello, world!</html>"

        self.CreateCert('localhost', self.key, self.cert)
        ssl_context = ssl.DefaultOpenSSLContextFactory(self.key, self.cert)


        class CustomFile(static.File):
            childNotFound = Redirect(b'/web/404.html')

        root = Home()
        root.putChild('web', CustomFile(b'./web'))
        # root = static.File(b'./webpage')
        reactor.listenSSL(self.port, Site(root), ssl_context)
        reactor.run()

    def run_server(self, process=False, auto=False):
        status = 'error'
        run = False
        if process:
            if auto and not self.auto_disabled:
                port = get_free_port()
                if port > 0:
                    self.port = port
                    run = True
            elif self.close_port() and self.kill_server():
                run = True

            if run:
                self.process = Popen(['python3', path.realpath(__file__), '--custom', '--ip', str(self.ip), '--port', str(self.port), '--username', str(self.username), '--password', str(self.password), '--options', str(self.options), '--config', str(self.config), '--uuid', str(self.uuid)])
                if self.process.poll() is None and check_if_server_is_running(self.uuid):
                    status = 'success'

            self.logs.info({'server': 'https_server', 'action': 'process', 'status': status, 'src_ip': self.ip, 'src_port': self.port, 'username': self.username, 'password': self.password, 'dest_ip': self.ip, 'dest_port': self.port})

            if status == 'success':
                return True
            else:
                self.kill_server()
                return False
        else:
            self.https_server_main()

    def close_port(self):
        ret = close_port_wrapper('https_server', self.ip, self.port, self.logs)
        return ret

    def kill_server(self):
        ret = kill_server_wrapper('https_server', self.uuid, self.process)
        return ret

    def test_server(self, ip=None, port=None, username=None, password=None):
        with suppress(Exception):
            from requests import get, post
            _ip = ip or self.ip
            _port = port or self.port
            _username = username or self.username
            _password = password or self.password
            get('https://{}:{}'.format(_ip, _port), verify=False)
            post('https://{}:{}'.format(_ip, _port), data={'username': (None, _username), 'password': (None, _password)}, verify=False)
    



if __name__ == '__main__':
    parsed = server_arguments()
    if parsed.docker or parsed.aws or parsed.custom:
        qhttpsserver = QHTTPSServer(ip=parsed.ip, port=parsed.port, username=parsed.username, password=parsed.password, options=parsed.options, config=parsed.config)
        qhttpsserver.run_server()
