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

from twisted.protocols.ftp import log, AnonUserDeniedError, ASCIIConsumerWrapper, FTPCmdError, PermissionDeniedError, toSegments, InvalidPath, BadCmdSequenceError, FTPShell, FTPAnonymousShell, FTPFactory, FTP, AUTH_FAILURE, IFTPShell, GUEST_LOGGED_IN_PROCEED, AuthorizationError, BAD_CMD_SEQ, USR_LOGGED_IN_PROCEED
from twisted.internet import reactor, defer
from twisted.cred.portal import Portal
from twisted.cred import portal, credentials, checkers
from twisted.cred.error import UnauthorizedLogin, UnauthorizedLogin, UnhandledCredentials
from twisted.cred.checkers import ICredentialsChecker, ANONYMOUS, AllowAnonymousAccess
from zope.interface import implementer
from twisted.python import filepath
from twisted.python import log as tlog
from random import choice
from subprocess import Popen
from os import path, getenv
from honeypots.helper import close_port_wrapper, get_free_port, kill_server_wrapper, server_arguments, setup_logger, disable_logger, set_local_vars, check_if_server_is_running
from uuid import uuid4
from contextlib import suppress
from tempfile import TemporaryDirectory
import requests, os

RESTART_MARKER_REPLY = "100"
SERVICE_READY_IN_N_MINUTES = "120"
DATA_CNX_ALREADY_OPEN_START_XFR = "125"
FILE_STATUS_OK_OPEN_DATA_CNX = "150"

FILE_STATUS_OK_OPEN_DATA_CNX_LIST = "150.1"
FILE_STATUS_OK_OPEN_DATA_CNX_RETR = "150.2"
FILE_STATUS_OK_OPEN_DATA_CNX_STOR = "150.3"

CMD_OK = "200.1"
TYPE_SET_OK = "200.2"
ENTERING_PORT_MODE = "200.3"
CMD_NOT_IMPLMNTD_SUPERFLUOUS = "202"
SYS_STATUS_OR_HELP_REPLY = "211.1"
FEAT_OK = "211.2"
DIR_STATUS = "212"
FILE_STATUS = "213"
HELP_MSG = "214"
NAME_SYS_TYPE = "215"
SVC_READY_FOR_NEW_USER = "220.1"
WELCOME_MSG = "220.2"
SVC_CLOSING_CTRL_CNX = "221.1"
GOODBYE_MSG = "221.2"
DATA_CNX_OPEN_NO_XFR_IN_PROGRESS = "225"
CLOSING_DATA_CNX = "226.1"
TXFR_COMPLETE_OK = "226.2"
TXFR_COMPLETE_OK_LIST = "226.3"
ENTERING_PASV_MODE = "227"
ENTERING_EPSV_MODE = "229"
USR_LOGGED_IN_PROCEED = "230.1"  # v1 of code 230
GUEST_LOGGED_IN_PROCEED = "230.2"  # v2 of code 230
REQ_FILE_ACTN_COMPLETED_OK = "250"

REQ_FILE_ACTN_COMPLETED_OK_CD = "250.1"
REQ_FILE_ACTN_COMPLETED_OK_RM = "250.2"
REQ_FILE_ACTN_COMPLETED_OK_DELE = "250.3"

PWD_REPLY = "257.1"
MKD_REPLY = "257.2"

USR_NAME_OK_NEED_PASS = "331.1"  # v1 of Code 331
GUEST_NAME_OK_NEED_EMAIL = "331.2"  # v2 of code 331
NEED_ACCT_FOR_LOGIN = "332"
REQ_FILE_ACTN_PENDING_FURTHER_INFO = "350"

SVC_NOT_AVAIL_CLOSING_CTRL_CNX = "421.1"
TOO_MANY_CONNECTIONS = "421.2"
CANT_OPEN_DATA_CNX = "425"
CNX_CLOSED_TXFR_ABORTED = "426"
REQ_ACTN_ABRTD_FILE_UNAVAIL = "450"
REQ_ACTN_ABRTD_LOCAL_ERR = "451"
REQ_ACTN_ABRTD_INSUFF_STORAGE = "452"

SYNTAX_ERR = "500"
SYNTAX_ERR_IN_ARGS = "501"
CMD_NOT_IMPLMNTD = "502.1"
OPTS_NOT_IMPLEMENTED = "502.2"
BAD_CMD_SEQ = "503"
CMD_NOT_IMPLMNTD_FOR_PARAM = "504"
NOT_LOGGED_IN = "530.1"  # v1 of code 530 - please log in
AUTH_FAILURE = "530.2"  # v2 of code 530 - authorization failure
NEED_ACCT_FOR_STOR = "532"
FILE_NOT_FOUND = "550.1"  # no such file or directory
PERMISSION_DENIED = "550.2"  # permission denied
ANON_USER_DENIED = "550.3"  # anonymous users can't alter filesystem
IS_NOT_A_DIR = "550.4"  # rmd called on a path that is not a directory
REQ_ACTN_NOT_TAKEN = "550.5"
FILE_EXISTS = "550.6"
IS_A_DIR = "550.7"
RM_FAILED = "550.8"
DELE_FAILED = "550.9"
RETR_FAILED = "550.10"
PAGE_TYPE_UNK = "551"
EXCEEDED_STORAGE_ALLOC = "552"
FILENAME_NOT_ALLOWED = "553"


RESPONSE = {
    # -- 100's --
    # TODO: this must be fixed
    RESTART_MARKER_REPLY: "110 MARK yyyy-mmmm",
    SERVICE_READY_IN_N_MINUTES: "120 service ready in %s minutes",
    DATA_CNX_ALREADY_OPEN_START_XFR: "125 Data connection already open, "
    "starting transfer",
    FILE_STATUS_OK_OPEN_DATA_CNX: "150 File status okay; about to open "
    "data connection.",

    FILE_STATUS_OK_OPEN_DATA_CNX_LIST: "150 Here comes the directory listing.",
    FILE_STATUS_OK_OPEN_DATA_CNX_RETR: "150 Opening BINARY mode data connection for %s (%s bytes).",
    FILE_STATUS_OK_OPEN_DATA_CNX_STOR: "150 Ok to send data.",
    # -- 200's --
    CMD_OK: "200 Command OK",
    TYPE_SET_OK: "200 Type set to %s.",
    ENTERING_PORT_MODE: "200 PORT OK",
    CMD_NOT_IMPLMNTD_SUPERFLUOUS: "202 Command not implemented, "
    "superfluous at this site",
    SYS_STATUS_OR_HELP_REPLY: "211 System status reply",
    FEAT_OK: ["211-Features:", "211 End"],
    DIR_STATUS: "212 %s",
    FILE_STATUS: "213 %s",
    HELP_MSG: "214 help: %s",
    NAME_SYS_TYPE: "215 UNIX Type: L8",
    WELCOME_MSG: "220 %s",
    SVC_READY_FOR_NEW_USER: "220 Service ready",
    SVC_CLOSING_CTRL_CNX: "221 Service closing control " "connection",
    GOODBYE_MSG: "221 Goodbye.",
    DATA_CNX_OPEN_NO_XFR_IN_PROGRESS: "225 data connection open, no "
    "transfer in progress",
    CLOSING_DATA_CNX: "226 Abort successful",
    TXFR_COMPLETE_OK: "226 Transfer Complete.",
    TXFR_COMPLETE_OK_LIST: "226 Directory send OK.",
    ENTERING_PASV_MODE: "227 Entering Passive Mode (%s).",
    # Where is EPSV defined in the RFCs?
    ENTERING_EPSV_MODE: "229 Entering Extended Passive Mode " "(|||%s|).",
    USR_LOGGED_IN_PROCEED: "230 Login successful.",
    GUEST_LOGGED_IN_PROCEED: "230 Login successful.",
    # i.e. CWD completed OK
    REQ_FILE_ACTN_COMPLETED_OK: "250 Requested File Action Completed " "OK",
    REQ_FILE_ACTN_COMPLETED_OK_CD: "250 Directory successfully changed.",
    REQ_FILE_ACTN_COMPLETED_OK_RM: "250 Remove directory operation successful.",
    REQ_FILE_ACTN_COMPLETED_OK_DELE: "250 Delete operation successful.",

    PWD_REPLY: '257 "%s"',
    MKD_REPLY: '257 "%s" created',
    # -- 300's --
    USR_NAME_OK_NEED_PASS: "331 Password required for %s.",
    GUEST_NAME_OK_NEED_EMAIL: "331 Please specify the password.",
    NEED_ACCT_FOR_LOGIN: "332 Need account for login.",
    REQ_FILE_ACTN_PENDING_FURTHER_INFO: "350 Requested file action pending "
    "further information.",
    # -- 400's --
    SVC_NOT_AVAIL_CLOSING_CTRL_CNX: "421 Service not available, closing "
    "control connection.",
    TOO_MANY_CONNECTIONS: "421 Too many users right now, try "
    "again in a few minutes.",
    CANT_OPEN_DATA_CNX: "425 Can't open data connection.",
    CNX_CLOSED_TXFR_ABORTED: "426 Transfer aborted.  Data " "connection closed.",
    REQ_ACTN_ABRTD_FILE_UNAVAIL: "450 Requested action aborted. " "File unavailable.",
    REQ_ACTN_ABRTD_LOCAL_ERR: "451 Requested action aborted. "
    "Local error in processing.",
    REQ_ACTN_ABRTD_INSUFF_STORAGE: "452 Requested action aborted. "
    "Insufficient storage.",
    # -- 500's --
    SYNTAX_ERR: "500 Syntax error: %s",
    SYNTAX_ERR_IN_ARGS: "501 syntax error in argument(s) %s.",
    CMD_NOT_IMPLMNTD: "502 Command '%s' not implemented",
    OPTS_NOT_IMPLEMENTED: "502 Option '%s' not implemented.",
    BAD_CMD_SEQ: "503 Incorrect sequence of commands: " "%s",
    CMD_NOT_IMPLMNTD_FOR_PARAM: "504 Not implemented for parameter " "'%s'.",
    NOT_LOGGED_IN: "530 Please login with USER and PASS.",
    AUTH_FAILURE: "530 Login incorrect.",
    NEED_ACCT_FOR_STOR: "532 Need an account for storing " "files",
    FILE_NOT_FOUND: "550 %s: No such file or directory.",
    PERMISSION_DENIED: "550 %s: Permission denied.",
    ANON_USER_DENIED: "550 Permission denied.",
    IS_NOT_A_DIR: "550 Cannot rmd, %s is not a " "directory",
    FILE_EXISTS: "550 %s: File exists",
    IS_A_DIR: "550 %s: is a directory",
    REQ_ACTN_NOT_TAKEN: "550 Requested action not taken: %s",

    RM_FAILED: "550 Remove directory operation failed.",
    DELE_FAILED: "550 Delete operation failed.",
    RETR_FAILED: "550 Failed to open file.",

    PAGE_TYPE_UNK: "551 Page type unknown",
    EXCEEDED_STORAGE_ALLOC: "552 Requested file action aborted, "
    "exceeded file storage allocation",
    FILENAME_NOT_ALLOWED: "553 Requested action not taken, file " "name not allowed",
}

# def get_ip():
#     response = requests.get('https://api64.ipify.org?format=json', timeout=2).json()
#     return response["ip"]

# def geoIP(ip):
#         response = requests.get(f'https://ipapi.co/{ip}/json/',timeout=2).json()
#         if response['error']:
#             response = requests.get(f'https://ipapi.co/{get_ip()}/json/',timeout=2).json()
        
#         location = {
#             "city": response["city"],
#             "region": response["region"],
#             "country": response["country_name"],
#             "country_code": response["country_code_iso3"],
#             "latitude": response["latitude"],
#             "longitud": response["longitude"],
#             "asn": response["asn"],
#             "org": response["org"]
#         }
#         return location

class CustomFTPAnonymousShell(FTPAnonymousShell):
    def openForReading(self, path):
        path = self._path(path)
        return defer.fail(PermissionDeniedError())


class QFTPServer():
    def __init__(self, **kwargs):
        self.auto_disabled = None
        self.mocking_server = choice(['ProFTPD 1.2.10', 'ProFTPD 1.3.4a', 'FileZilla ftp 0.9.43', 'Gene6 ftpd 3.10.0', 'FileZilla ftp 0.9.33', 'ProFTPD 1.2.8'])
        self.process = None
        self.uuid = 'honeypotslogger' + '_' + __class__.__name__ + '_' + str(uuid4())[:8]
        self.config = kwargs.get('config', '')
        if self.config:
            self.logs = setup_logger(__class__.__name__, self.uuid, self.config)
            set_local_vars(self, self.config)
        else:
            self.logs = setup_logger(__class__.__name__, self.uuid, None)
        self.ip = kwargs.get('ip', None) or (hasattr(self, 'ip') and self.ip) or '0.0.0.0'
        self.port = (kwargs.get('port', None) and int(kwargs.get('port', None))) or (hasattr(self, 'port') and self.port) or 21
        self.username = kwargs.get('username', None) or (hasattr(self, 'username') and self.username) or 'test'
        self.password = kwargs.get('password', None) or (hasattr(self, 'password') and self.password) or 'test'
        self.options = kwargs.get('options', '') or (hasattr(self, 'options') and self.options) or getenv('HONEYPOTS_OPTIONS', '') or ''
        self.temp_folder = TemporaryDirectory()
        disable_logger(1, tlog)

    def ftp_server_main(self):
        _q_s = self

        @implementer(portal.IRealm)
        class CustomFTPRealm:
            def __init__(self, anonymousRoot):
                self.anonymousRoot = filepath.FilePath(anonymousRoot)

            # def requestAvatar(self, avatarId, mind, *interfaces):
            #     for iface in interfaces:
            #         if iface is IFTPShell:
            #             avatar = FTPAnonymousShell(self.anonymousRoot)
            #             return IFTPShell, avatar, getattr(avatar, 'logout', lambda: None)
            #     raise NotImplementedError("Only IFTPShell interface is supported by this realm")
            
            def requestAvatar(self, avatarId, mind, *interfaces):
                for iface in interfaces:
                    if iface is IFTPShell:
                        if avatarId is checkers.ANONYMOUS:
                            avatar = CustomFTPAnonymousShell(self.anonymousRoot)
                        else:
                            avatar = FTPShell(filepath.FilePath("/code/user"))
                        return IFTPShell, avatar, getattr(avatar, 'logout', lambda: None)
                raise NotImplementedError("Only IFTPShell interface is supported by this realm")

        @implementer(ICredentialsChecker)
        class CustomAccess:
            credentialInterfaces = (credentials.IAnonymous, credentials.IUsernamePassword)

            def check_bytes(self, string):
                if isinstance(string, bytes):
                    return string.decode()
                else:
                    return str(string)

            def requestAvatarId(self, credentials):
                with suppress(Exception):
                    username = self.check_bytes(credentials.username)
                    password = self.check_bytes(credentials.password)
                    if username == _q_s.username and password == _q_s.password:
                        username = _q_s.username
                        password = _q_s.password
                        return defer.succeed(credentials.username)
                    elif username == "anonymous":
                        return defer.succeed(ANONYMOUS)
                return defer.fail(UnauthorizedLogin())
            

        class CustomFTPProtocol(FTP):
            
            def reply(self, key, *args):
                msg = RESPONSE[key] % args
                self.sendLine(msg)

            def check_bytes(self, string):
                if isinstance(string, bytes):
                    return string.decode()
                else:
                    return str(string)

            def connectionMade(self):
                # _q_s.logs.info({'server': 'ftp_server', 'action': 'connection', 'src_ip': {'ip': self.transport.getPeer().host, 'geo': geoIP(self.transport.getPeer().host)}, 'src_port': self.transport.getPeer().port, 'dest_ip': _q_s.ip, 'dest_port': _q_s.port})
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
                _q_s.logs.info({'server': 'ftp_server', 'action': 'connection', 'src_ip': {'ip': self.transport.getPeer().host, 'geo': geo_test}, 'src_port': self.transport.getPeer().port, 'dest_ip': _q_s.ip, 'dest_port': _q_s.port})
                self.state = self.UNAUTH
                # self.state = self.UNAUTH
                self.setTimeout(self.timeOut)
                self.reply("220.2", self.factory.welcomeMessage)

            def processCommand(self, cmd, *params):
                with suppress(Exception):
                    if "capture_commands" in _q_s.options:
                        _q_s.logs.info({'server': 'ftp_server', 'action': 'command', 'data': {"cmd": self.check_bytes(cmd.upper()), "args": self.check_bytes(params)}, 'src_ip': self.transport.getPeer().host, 'src_port': self.transport.getPeer().port, 'dest_ip': _q_s.ip, 'dest_port': _q_s.port})
                return super().processCommand(cmd, *params)

            def ftp_PASS(self, password):
                username = self.check_bytes(self._user)
                password = self.check_bytes(password)
                status = 'failed'
                if (username == _q_s.username and password == _q_s.password):
                    username = _q_s.username
                    password = _q_s.password
                    status = 'success'
                
                if username == self.factory.userAnonymous:
                    username = self.factory.userAnonymous
                    password = ''
                    status = 'success'

                _q_s.logs.info({'server': 'ftp_server', 'action': 'login', 'status': status, 'src_ip': self.transport.getPeer().host, 'src_port': self.transport.getPeer().port, 'dest_ip': _q_s.ip, 'dest_port': _q_s.port, 'username': username, 'password': password})

                if self.factory.allowAnonymous and self._user == self.factory.userAnonymous:
                    creds = credentials.Anonymous()
                    reply = GUEST_LOGGED_IN_PROCEED
                else:
                    creds = credentials.UsernamePassword(self._user, password)
                    reply = USR_LOGGED_IN_PROCEED

                del self._user

                def _cbLogin(parsed):
                    self.shell = parsed[1]
                    self.logout = parsed[2]
                    self.workingDirectory = []
                    self.state = self.AUTHED
                    return reply

                def _ebLogin(failure):
                    failure.trap(UnauthorizedLogin, UnhandledCredentials)
                    self.state = self.UNAUTH
                    raise AuthorizationError

                d = self.portal.login(creds, None, IFTPShell)
                d.addCallbacks(_cbLogin, _ebLogin)
                return d
            
            def ftp_LIST(self, path=""):
                """This command causes a list to be sent from the server to the
                passive DTP.  If the pathname specifies a directory or other
                group of files, the server should transfer a list of files
                in the specified directory.  If the pathname specifies a
                file then the server should send current information on the
                file.  A null argument implies the user's current working or
                default directory.
                """
                # XXX: why is this check different from ftp_RETR/ftp_STOR? See #4180
                if self.dtpInstance is None or not self.dtpInstance.isConnected:
                    return defer.fail(BadCmdSequenceError("must send PORT or PASV before RETR"))

                # Various clients send flags like -L or -al etc.  We just ignore them.
                if path.lower() in ["-a", "-l", "-la", "-al"]:
                    path = ""

                def gotListing(results):
                    self.reply(FILE_STATUS_OK_OPEN_DATA_CNX_LIST)
                    for (name, attrs) in results:
                        name = self._encodeName(name)
                        self.dtpInstance.sendListResponse(name, attrs)
                    self.dtpInstance.transport.loseConnection()
                    return (TXFR_COMPLETE_OK_LIST)

                try:
                    segments = toSegments(self.workingDirectory, path)
                except InvalidPath:
                    return defer.fail(FileNotFoundError(path))

                d = self.shell.list(
                    segments,
                    (
                        "size",
                        "directory",
                        "permissions",
                        "hardlinks",
                        "modified",
                        "owner",
                        "group",
                    ),
                )
                d.addCallback(gotListing)
                return d
            
            def ftp_RETR(self, path):
                """
                This command causes the content of a file to be sent over the data
                transfer channel. If the path is to a folder, an error will be raised.

                @type path: C{str}
                @param path: The path to the file which should be transferred over the
                data transfer channel.

                @rtype: L{Deferred}
                @return: a L{Deferred} which will be fired when the transfer is done.
                """
                if self.dtpInstance is None:
                    raise BadCmdSequenceError("PORT or PASV required before RETR")

                try:
                    newsegs = toSegments(self.workingDirectory, path)
                except InvalidPath:
                    return defer.fail(FileNotFoundError(path))

                # XXX For now, just disable the timeout.  Later we'll want to
                # leave it active and have the DTP connection reset it
                # periodically.
                self.setTimeout(None)

                # Put it back later
                def enableTimeout(result):
                    self.setTimeout(self.factory.timeOut)
                    return result

                # And away she goes
                if not self.binary:
                    cons = ASCIIConsumerWrapper(self.dtpInstance)
                else:
                    cons = self.dtpInstance

                def cbSent(result):
                    return (TXFR_COMPLETE_OK,)

                def ebSent(err):
                    log.msg("Unexpected error attempting to transmit file to client:")
                    log.err(err)
                    if err.check(FTPCmdError):
                        return err
                    return (CNX_CLOSED_TXFR_ABORTED,)

                def cbOpened(file):
                    # Tell them what to doooo
                    if self.dtpInstance.isConnected:
                        self.reply(FILE_STATUS_OK_OPEN_DATA_CNX_RETR, path, os.path.getsize(path))
                    else:
                        self.reply(FILE_STATUS_OK_OPEN_DATA_CNX)

                    d = file.send(cons)
                    d.addCallbacks(cbSent, ebSent)
                    return d

                def ebOpened(err):
                    if not err.check(
                        PermissionDeniedError, FileNotFoundError, IsADirectoryError
                    ):
                        log.msg("Unexpected error attempting to open file for " "transmission:")
                        log.err(err)
                    if err.check(FTPCmdError):
                        return (RETR_FAILED)
                    return (RETR_FAILED)

                d = self.shell.openForReading(newsegs)
                d.addCallbacks(cbOpened, ebOpened)
                d.addBoth(enableTimeout)

                # Pass back Deferred that fires when the transfer is done
                return d
            
            def ftp_STOR(self, path):
                """
                STORE (STOR)

                This command causes the server-DTP to accept the data
                transferred via the data connection and to store the data as
                a file at the server site.  If the file specified in the
                pathname exists at the server site, then its contents shall
                be replaced by the data being transferred.  A new file is
                created at the server site if the file specified in the
                pathname does not already exist.
                """
                if self.dtpInstance is None:
                    raise BadCmdSequenceError("PORT or PASV required before STOR")

                try:
                    newsegs = toSegments(self.workingDirectory, path)
                except InvalidPath:
                    return defer.fail(FileNotFoundError(path))

                # XXX For now, just disable the timeout.  Later we'll want to
                # leave it active and have the DTP connection reset it
                # periodically.
                self.setTimeout(None)

                # Put it back later
                def enableTimeout(result):
                    self.setTimeout(self.factory.timeOut)
                    return result

                def cbOpened(file):
                    """
                    File was open for reading. Launch the data transfer channel via
                    the file consumer.
                    """
                    d = file.receive()
                    d.addCallback(cbConsumer)
                    d.addCallback(lambda ignored: file.close())
                    d.addCallbacks(cbSent, ebSent)
                    return d

                def ebOpened(err):
                    """
                    Called when failed to open the file for reading.

                    For known errors, return the FTP error code.
                    For all other, return a file not found error.
                    """
                    if isinstance(err.value, FTPCmdError):
                        return (err.value.errorCode, "/".join(newsegs))
                    log.err(err, "Unexpected error received while opening file:")
                    return (FILE_NOT_FOUND, "/".join(newsegs))

                def cbConsumer(cons):
                    """
                    Called after the file was opended for reading.

                    Prepare the data transfer channel and send the response
                    to the command channel.
                    """
                    if not self.binary:
                        cons = ASCIIConsumerWrapper(cons)

                    d = self.dtpInstance.registerConsumer(cons)

                    # Tell them what to doooo
                    if self.dtpInstance.isConnected:
                        self.reply(FILE_STATUS_OK_OPEN_DATA_CNX_STOR)
                    else:
                        self.reply(FILE_STATUS_OK_OPEN_DATA_CNX)

                    return d

                def cbSent(result):
                    """
                    Called from data transport when transfer is done.
                    """
                    return (TXFR_COMPLETE_OK,)

                def ebSent(err):
                    """
                    Called from data transport when there are errors during the
                    transfer.
                    """
                    log.err(err, "Unexpected error received during transfer:")
                    if err.check(FTPCmdError):
                        return err
                    return (CNX_CLOSED_TXFR_ABORTED,)

                d = self.shell.openForWriting(newsegs)
                d.addCallbacks(cbOpened, ebOpened)
                d.addBoth(enableTimeout)

                # Pass back Deferred that fires when the transfer is done
                return d
            
            def ftp_CWD(self, path):
                try:
                    segments = toSegments(self.workingDirectory, path)
                except InvalidPath:
                    # XXX Eh, what to fail with here?
                    return defer.fail(FileNotFoundError(path))

                def accessGranted(result):
                    self.workingDirectory = segments
                    return (REQ_FILE_ACTN_COMPLETED_OK_CD)

                return self.shell.access(segments).addCallback(accessGranted)
            
            def ftp_RMD(self, path):
                try:
                    newsegs = toSegments(self.workingDirectory, path)
                except InvalidPath:
                    return defer.fail(FileNotFoundError(path))
                return self.shell.removeDirectory(newsegs).addCallback(
                    lambda ign: (REQ_FILE_ACTN_COMPLETED_OK_RM)
                )

            def ftp_DELE(self, path):
                try:
                    newsegs = toSegments(self.workingDirectory, path)
                except InvalidPath:
                    return defer.fail(FileNotFoundError(path))
                return self.shell.removeFile(newsegs).addCallback(
                    lambda ign: (REQ_FILE_ACTN_COMPLETED_OK,)
                )

            

        p = Portal(CustomFTPRealm("/code/user/credentials"), [CustomAccess()])
        factory = FTPFactory(p)
        p.registerChecker(AllowAnonymousAccess())
        factory.protocol = CustomFTPProtocol
        factory.welcomeMessage = "(vsFTPd 3.0.5)"
        factory.allowAnonymous = True


        reactor.listenTCP(port=self.port, factory=factory)
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

            self.logs.info({'server': 'ftp_server', 'action': 'process', 'status': status, 'src_ip': self.ip, 'src_port': self.port, 'username': self.username, 'password': self.password, 'dest_ip': self.ip, 'dest_port': self.port})

            if status == 'success':
                return True
            else:
                self.kill_server()
                return False
        else:
            self.ftp_server_main()
        return None

    def close_port(self):
        ret = close_port_wrapper('ftp_server', self.ip, self.port, self.logs)
        return ret

    def kill_server(self):
        ret = kill_server_wrapper('ftp_server', self.uuid, self.process)
        return ret

    def test_server(self, ip=None, port=None, username=None, password=None):
        with suppress(Exception):
            from ftplib import FTP as FFTP
            _ip = ip or self.ip
            _port = port or self.port
            _username = username or self.username
            _password = password or self.password
            f = FFTP()
            f.connect(_ip, _port)
            f.login(_username, _password)
            f.pwd()
            f.quit()


if __name__ == '__main__':
    parsed = server_arguments()
    if parsed.docker or parsed.aws or parsed.custom:
        ftpserver = QFTPServer(ip=parsed.ip, port=parsed.port, username=parsed.username, password=parsed.password, options=parsed.options, config=parsed.config)
        ftpserver.run_server()
