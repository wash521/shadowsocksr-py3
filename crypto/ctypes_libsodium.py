#!/usr/bin/env python

# Copyright (c) 2014 clowwindy
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

from __future__ import absolute_import, division, print_function, \
    with_statement

import logging
from ctypes import CDLL, c_char_p, c_int, c_ulonglong, byref, \
    create_string_buffer, c_void_p

__all__ = ['ciphers']

libsodium = None
loaded = False

buf_size = 2048

# for salsa20 and chacha20
BLOCK_SIZE = 64


def load_libsodium():
    global loaded, libsodium, buf

    from ctypes.util import find_library
    for p in ('sodium',):
        libsodium_path = find_library(p)
        if libsodium_path:
            break
    else:
        raise Exception('libsodium not found')
    logging.info('loading libsodium from %s', libsodium_path)
    libsodium = CDLL(libsodium_path)
    libsodium.sodium_init.restype = c_int
    libsodium.crypto_stream_salsa20_xor_ic.restype = c_int
    libsodium.crypto_stream_salsa20_xor_ic.argtypes = (c_void_p, c_char_p,
                                                       c_ulonglong,
                                                       c_char_p, c_ulonglong,
                                                       c_char_p)
    libsodium.crypto_stream_chacha20_xor_ic.restype = c_int
    libsodium.crypto_stream_chacha20_xor_ic.argtypes = (c_void_p, c_char_p,
                                                        c_ulonglong,
                                                        c_char_p, c_ulonglong,
                                                        c_char_p)

    libsodium.sodium_init()

    buf = create_string_buffer(buf_size)
    loaded = True


class Salsa20Crypto(object):
    def __init__(self, cipher_name, key, iv, op):
        if not loaded:
            load_libsodium()
        cipher_name = cipher_name.decode('utf-8') \
            if isinstance(cipher_name, bytes) else cipher_name
        self.key = key
        self.iv = iv
        self.key_ptr = c_char_p(key)
        self.iv_ptr = c_char_p(iv)
        if cipher_name == 'salsa20':
            self.cipher = libsodium.crypto_stream_salsa20_xor_ic
        elif cipher_name == 'chacha20':
            self.cipher = libsodium.crypto_stream_chacha20_xor_ic
        else:
            raise Exception('Unknown cipher')
        # byte counter, not block counter
        self.counter = 0

    def update(self, data):
        global buf_size, buf
        l = len(data)

        # we can only prepend some padding to make the encryption align to
        # blocks
        padding = self.counter % BLOCK_SIZE
        if buf_size < padding + l:
            buf_size = (padding + l) * 2
            buf = create_string_buffer(buf_size)

        if padding:
            data = (b'\0' * padding) + data
        self.cipher(byref(buf), c_char_p(data), padding + l,
                    self.iv_ptr, self.counter // BLOCK_SIZE, self.key_ptr)
        self.counter += l
        # buf is copied to a str object when we access buf.raw
        # strip off the padding
        return buf.raw[padding:padding + l]


# 注意：本模块为历史遗留实现，当前工程实际使用的是 crypto/sodium.py。
ciphers = {
    'salsa20': (32, 8, Salsa20Crypto),
    'chacha20': (32, 8, Salsa20Crypto),
}


def test_salsa20():
    from shadowsocks.crypto import util

    cipher = Salsa20Crypto('salsa20', b'k' * 32, b'i' * 16, 1)
    decipher = Salsa20Crypto('salsa20', b'k' * 32, b'i' * 16, 0)

    util.run_cipher(cipher, decipher)


def test_chacha20():
    from shadowsocks.crypto import util

    cipher = Salsa20Crypto('chacha20', b'k' * 32, b'i' * 16, 1)
    decipher = Salsa20Crypto('chacha20', b'k' * 32, b'i' * 16, 0)

    util.run_cipher(cipher, decipher)


if __name__ == '__main__':
    # --- standalone bootstrap (py3 port) ---
    import os as _os
    import sys as _sys
    _d = _os.path.dirname(_os.path.realpath(__file__))
    while _d != _os.path.dirname(_d):
        if _os.path.isdir(_os.path.join(_d, 'shadowsocks')):
            if _d not in _sys.path:
                _sys.path.insert(0, _d)
            break
        _d = _os.path.dirname(_d)

    try:
        test_chacha20()
        test_salsa20()
        print('crypto/ctypes_libsodium.py: all tests passed')
    except Exception as e:
        # 本机没有 libsodium 时属于环境缺失，跳过而不是报错。
        if 'not found' in str(e):
            print('crypto/ctypes_libsodium.py: skipped, native library '
                  'missing: %s' % e)
        else:
            raise
