#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Copyright(C) 2001 - 2015 SUZUKI Hisao, Mitko Haralanov, Łukasz Langa, PACKenx

# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files(the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:

# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.

# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.

"""Tiny HTTP Proxy.

This module implements GET, HEAD, POST and CONNECT
methods on BaseHTTPServer.

Usage:
  httproxy [options]
  httproxy [options] <allowed-client> ...

Options:
  -h, --help                   Show this screen.
  --version                    Show version and exit.
  -H, --host HOST              Host to bind to [default: 127.0.0.1].
  -p, --port PORT              Port to bind to [default: 8080].
  -l, --logfile PATH           Path to the logfile [default: STDOUT].
  -i, --pidfile PIDFILE        Path to the pidfile [default: httproxy.pid].
  -d, --daemon                 Daemonize (run in the background). The
                               default logfile path is httproxy.log in
                               this case.
  -c, --configfile CONFIGFILE  Path to a configuration file.
  -v, --verbose                Log headers.
"""

__version__ = "1.1.0"

import atexit
from BaseHTTPServer import BaseHTTPRequestHandler, HTTPServer
import errno
import ftplib
import functools
import logging
import logging.handlers
import os
import re
import select
import signal
import socket
import SocketServer
import sys
import threading
from time import sleep
import urlparse

try:  # if ImportError use def value
    from configparser import ConfigParser
    from docopt import docopt
except ImportError:
    canoption = False
else:
    canoption = True

DEFAULT_LOG_FILENAME = "httproxy.log"

NEXT_PROXY_HOST = None                  # Only http. 'host', 80

class ProxyHandler(BaseHTTPRequestHandler):
    server_version = "TinyHTTPProxy/" + __version__
    rbufsize = 0                        # self.rfile Be unbuffered
    allowed_clients = ()
    verbose = False

    def handle(self):
        ip, port = self.client_address
        self.server.logger.log(logging.DEBUG, "Request from '%s'", ip)
        if self.allowed_clients and ip not in self.allowed_clients:
            self.raw_requestline = self.rfile.readline()
            if self.parse_request():
                self.send_error(403)
        else:
            BaseHTTPRequestHandler.handle(self)

    def _connect_to(self, netloc, soc):
        i = netloc.find(':')
        if i >= 0:
            host_port = netloc[:i], int(netloc[i + 1:])
        else:
            host_port = netloc, 80
        if self.command != 'CONNECT' and NEXT_PROXY_HOST:
            host_port = NEXT_PROXY_HOST
        self.server.logger.log(
            logging.DEBUG, "Connect to %s:%d", host_port[0], host_port[1])
        try:
            soc.connect(host_port)
        except socket.error, arg:
            try:
                msg = arg[1]
            except Exception:
                msg = arg
            self.send_error(404, msg)
            return 0
        return 1

    def do_only(self):
        scm, netloc, path, params, query, fragment = urlparse.urlparse(self.path, 'http')
        if not netloc:
            netloc = self.headers.get('Host', '')
        if scm not in ('http', 'https') or fragment or not netloc:
            self.send_error(400, "bad URL %s" % self.path)
            return
        soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            if self._connect_to(netloc, soc):
                socfile = soc.makefile('rb+',self.rbufsize)
                socfile.write("%s %s %s\r\n" % (
                    self.command, urlparse.urlunparse(
                    ('', '', path, params, query, '')),
                    self.protocol_version,))
                self.headers['Connection'] = 'close'
                del self.headers['Proxy-Connection']
                #del self.headers['Referer']
                for key_val in self.headers.items():
                    self.log_verbose("%s: %s", *key_val)
                    socfile.write("%s: %s\r\n" % key_val)
                socfile.write("\r\n")
                req_len = int(self.headers.get('Content-Length', '0'))
                if req_len:
                    self.cut_send(self.rfile, socfile, req_len)
                socfile.flush()
                length = self.finish_response_header(socfile)
                if length != 0:
                    self.cut_send(socfile, self.wfile, length)
                    self.wfile.flush()
        except socket.error, e:
            if e.errno == errno.EPIPE:
                self.close_connection = 1
                soc.close()
                raise
            else:
                raise
        finally:
            soc.close()

    def do_CONNECT(self):
        soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            if self._connect_to(self.path, soc):
                self.log_request(200)
                self.wfile.write(self.protocol_version +
                                 " 200 Connection established\r\n")
                self.wfile.write("Proxy-agent: %s\r\n" % self.version_string())
                self.wfile.write("\r\n")
                self._read_write(soc, 300)
        finally:
            soc.close()
            self.connection.close()

    def handle_one_request(self):
        try:
            BaseHTTPRequestHandler.handle_one_request(self)
        except socket.error, e:
            if e.errno == errno.ECONNRESET:
                self.close_connection = 1
                pass   # ignore the error
            elif e.errno == errno.EPIPE:
                self.close_connection = 1
                self.wfile._wbuf = None
                self.wfile.close()
                self.log_error('"%s" Broken pipe', self.raw_requestline.strip() if self.raw_requestline else '')
            else:
                raise

    def finish_response_header(self, socfile):
        try:
            codeline = socfile.readline().split(" ",2)
            code = codeline[1]
        except socket.error, e:
            if e.errno == 110:
                self.log_error('"%s" Connection timed out', self.raw_requestline.strip())
                return 0
            else:
                raise
        except ValueError, IndexError:
            return 0
        header = self.MessageClass(socfile,0)
        self.send_response(int(code))
        header['Connection'] = 'close'
        del header['Server']
        del header['Date']
        self.log_verbose("[response] %s", "".join(codeline).strip())
        for k_v in header.items():
            self.log_verbose("[response] %s: %s", *k_v)
            self.send_header(*k_v)
        self.end_headers()
        length = header.get('Content-Length', '')
        if not length:
            return -1
        else:
            return int(length)

    def cut_send(self, socin, socout, length):
        if length > 0:
            len_int = int(length / 10)
            len_oth = int(length % 10)
            while len_int:
                len_int -= 1
                socout.write(socin.read(10))
            if len_oth:
                socout.write(socin.read(len_oth))
        else:
            while True:
                body_buf = socin.read(10)
                buf_len = len(body_buf)
                if buf_len != 10:
                    if buf_len:
                        socout.write(body_buf)
                    break
                socout.write(body_buf)

    def _read_write(self, soc, max_idling=20):
        iw = [self.connection, soc]
        local_data = []
        ow = []
        count = 0
        while True:
            count += 1
            (ins, _, exs) = select.select(iw, ow, iw, 1)
            if exs:
                break
            if ins:
                for i in ins:
                    if i is soc:
                        out = self.connection
                    else:
                        out = soc
                    data = i.recv(8192)
                    if data:
                        out.send(data)
                        count = 0
            if count == max_idling:
                break

    do_GET = do_only
    do_POST = do_only
    do_HEAD = do_only

    def log_verbose(self, fmt, *args):
        if not self.verbose:
            return
        self.server.logger.log(
            logging.DEBUG, "%s %s", self.address_string(), fmt % args
        )

    def log_message(self, fmt, *args):
        self.server.logger.log(
            logging.INFO, "%s %s", self.address_string(), fmt % args
        )

    def log_error(self, fmt, *args):
        self.server.logger.log(
            logging.ERROR, "%s %s", self.address_string(), fmt % args
        )


class ThreadingHTTPServer(SocketServer.ThreadingMixIn, HTTPServer):
    def __init__(self, server_address, RequestHandlerClass, logger=None):
        HTTPServer.__init__(self, server_address, RequestHandlerClass)
        self.logger = logger


def setup_logging(filename, log_size, daemon, verbose):
    logger = logging.getLogger("TinyHTTPProxy")
    logger.setLevel(logging.DEBUG if verbose else logging.INFO)
    if not filename or filename in ('-', 'STDOUT'):
        if not daemon:
            # display to the screen
            handler = logging.StreamHandler()
        else:
            handler = logging.handlers.RotatingFileHandler(
                DEFAULT_LOG_FILENAME, maxBytes=(log_size * (1 << 20)),
                backupCount=5
            )
    else:
        handler = logging.handlers.RotatingFileHandler(
            filename, maxBytes=(log_size * (1 << 20)), backupCount=5)
    fmt = logging.Formatter("[%(asctime)-12s.%(msecs)03d] "
                            "%(levelname)-8s %(threadName)s  "
                            "%(message)s",
                            "%Y-%m-%d %H:%M:%S")
    handler.setFormatter(fmt)

    logger.addHandler(handler)
    return logger


def signal_handler(signo, frame, event=None):
    """This handler setup lets us handle one last request gracefully."""
    sys.stderr.write('Caught signal {}\n'.format(signo))
    if signo == signal.SIGALRM:
        raise StopServing("Unhang handle_request()")
    if event:
        event.set()
    sys.stderr.flush()
    signal.alarm(1)


def daemonize(logger):
    class DevNull(object):
        def __init__(self):
            self.fd = os.open(os.devnull, os.O_WRONLY)

        def write(self, *args, **kwargs):
            return 0

        def read(self, *args, **kwargs):
            return 0

        def fileno(self):
            return self.fd

        def close(self):
            os.close(self.fd)

    class ErrorLog(object):
        def __init__(self, obj):
            self.obj = obj

        def write(self, string):
            self.obj.log(logging.ERROR, string.rstrip())

        def read(self, *args, **kwargs):
            return 0

        def flush(self):
            pass

        def close(self):
            pass

    if os.fork() != 0:
        # allow the child pid to instantiate the server class
        sleep(1)
        sys.exit(0)
    os.setsid()
    fd = os.open(os.devnull, os.O_RDONLY)
    if fd != 0:
        os.dup2(fd, 0)
        os.close(fd)
    null = DevNull()
    log = ErrorLog(logger)
    sys.stdout = null
    sys.stderr = log
    sys.stdin = null
    fd = os.open(os.devnull, os.O_WRONLY)
    os.dup2(sys.stdout.fileno(), 1)
    if fd != 2:
        os.dup2(fd, 2)
    if fd not in (1, 2):
        os.close(fd)


def set_process_title(args):
    try:
        import setproctitle
    except ImportError:
        return
    proc_details = ['httproxy']
    for arg, value in sorted(args.items()):
        if value is True:
            proc_details.append(arg)
        elif value in (False, None):
            pass   # don't include false or empty toggles
        elif arg == '<allowed-client>':
            for client in value:
                proc_details.append(client)
        else:
            value = unicode(value)
            if 'file' in arg and value not in ('STDOUT', '-'):
                value = os.path.realpath(value)
            proc_details.append(arg)
            proc_details.append(value)
    setproctitle.setproctitle(" ".join(proc_details))


def handle_pidfile(pidfile, logger):
    try:
        import psutil
    except ImportError:
        return
    pid = str(os.getpid())
    try:
        with open(pidfile) as pf:
            stale_pid = pf.read()
        if pid != stale_pid:
            try:
                if psutil.pid_exists(int(stale_pid)):
                    msg = ("Pidfile `%s` exists. PID %s still running. "
                           "Exiting." % (pidfile, stale_pid))
                    logger.log(logging.CRITICAL, msg)
                    raise RuntimeError(msg)
                msg = ("Removed stale pidfile `%s` with non-existing PID %s."
                       % (pidfile, stale_pid))
                logger.log(logging.WARNING, msg)
            except ValueError:
                msg = "Pidfile `%s` exists. Exiting." % pidfile
                logger.log(logging.CRITICAL, msg)
                raise RuntimeError(msg)
    except IOError:
        with open(pidfile, 'w') as pf:
            pf.write(pid)
    atexit.register(os.unlink, pidfile)


def handle_configuration():
    default_args = docopt(__doc__, argv=(), version=__version__)
    cmdline_args = docopt(__doc__, version=__version__)
    for a in default_args:
        if cmdline_args[a] == default_args[a]:
            del cmdline_args[a]   # only keep overriden values
    del default_args['<allowed-client>']
    inifile = ConfigParser(allow_no_value=True)
    inifile.optionxform = lambda o: o if o.startswith('--') else ('--' + o)
    inifile['DEFAULT'] = default_args
    inifile['allowed-clients'] = {}
    inifile['main'] = {}
    read_from = inifile.read([
        os.sep + os.sep.join(('etc', 'httproxy', 'config')),
        os.path.expanduser(os.sep.join(('~', '.httproxy', 'config'))),
        cmdline_args.get('--configfile') or '',
    ])
    iniconf = dict(inifile['main'])
    for opt in iniconf:
        try:
            iniconf[opt] = inifile['main'].getboolean(opt)
            continue
        except (ValueError, AttributeError):
            pass   # not a boolean
        try:
            iniconf[opt] = inifile['main'].getint(opt)
            continue
        except (ValueError, TypeError):
            pass   # not an int
    iniconf.update(cmdline_args)
    if not iniconf.get('<allowed-client>'):
        # copy values from INI but don't include --port etc.
        inifile['DEFAULT'].clear()
        clients = []
        for client in inifile['allowed-clients']:
            clients.append(client[2:])
        iniconf['<allowed-client>'] = clients
    return read_from, iniconf


def defoptions():
    args = {
            '--host'           : '127.0.0.1',
            '--port'           : '8080',
            '--verbose'        : '',
            '--logfile'        : 'STDOUT',
            '--pidfile'        : 'httproxy.pid',
            '--daemon'         : '',
            '<allowed-client>' : '',}
    return '', args


class StopServing(Exception):
    """Raised by sigalrm to break blocking handle_request()."""


def main():
    max_log_size = 20
    shutdown_in_progress = threading.Event()
    if canoption:
        read_from, args = handle_configuration()
    else:
        read_from, args = defoptions()
    logger = setup_logging(
        args['--logfile'], max_log_size, args['--daemon'], args['--verbose'],
    )
    for path in read_from:
        logger.log(logging.DEBUG, 'Read configuration from `%s`.' % path)
    try:
        args['--port'] = int(args['--port'])
        if not (0 < args['--port'] < 65536):
            raise ValueError("Out of range.")
    except (ValueError, TypeError):
        msg = "`%s` is not a valid port number. Exiting." % args['--port']
        logger.log(logging.CRITICAL, msg)
        return 1
    if args['--daemon']:
        daemonize(logger)
    handler_with_event = functools.partial(signal_handler, event=shutdown_in_progress)
    signal.signal(signal.SIGHUP, handler_with_event)
    signal.signal(signal.SIGINT, handler_with_event)
    signal.signal(signal.SIGTERM, handler_with_event)
    signal.signal(signal.SIGALRM, handler_with_event)
    if args['<allowed-client>']:
        allowed = []
        for name in args['<allowed-client>']:
            try:
                client = socket.gethostbyname(name)
            except socket.error, e:
                logger.log(logging.CRITICAL, "%s: %s. Exiting." % (name, e))
                return 3
            allowed.append(client)
            logger.log(logging.INFO, "Accept: %s(%s)" % (client, name))
        ProxyHandler.allowed_clients = allowed
    else:
        logger.log(logging.INFO, "Any clients will be served...")
    ProxyHandler.verbose = args['--verbose']
    try:
        handle_pidfile(args['--pidfile'], logger)
    except RuntimeError:
        return 2
    set_process_title(args)
    server_address = socket.gethostbyname(args['--host']), args['--port']
    httpd = ThreadingHTTPServer(server_address, ProxyHandler, logger)
    sa = httpd.socket.getsockname()
    logger.info("Serving HTTP on %s:%s" % (sa[0], sa[1]))
    atexit.register(logger.log, logging.INFO, "Server shutdown")
    req_count = 0
    while not shutdown_in_progress.isSet():
        try:
            httpd.handle_request()
            req_count += 1
            if req_count == 1000:
                logger.log(
                    logging.INFO, "Number of active threads: %s",
                    threading.activeCount()
                )
                req_count = 0
        except select.error, e:
            if e[0] != 4 or not shutdown_in_progress.isSet():
                logger.log(logging.CRITICAL, "Errno: %d - %s", e[0], e[1])
        except StopServing:
            continue
    return 0


if __name__ == '__main__':
    sys.exit(main())
