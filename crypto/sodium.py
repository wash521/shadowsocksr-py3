#!/usr/bin/env python
#
# Copyright 2015 clowwindy
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

from __future__ import absolute_import, division, print_function, \
    with_statement

from ctypes import c_char_p, c_int, c_ulong, c_ulonglong, byref, \
    create_string_buffer, c_void_p

if __name__ == '__main__':
    # --- standalone bootstrap (py3 port) ---
    # 直接 `python3 shadowsocks/xxx.py` 时，先把工程根目录放进 sys.path，
    # 否则模块级的 `from shadowsocks import ...` 会 ImportError。
    import os as _os
    import sys as _sys
    _d = _os.path.dirname(_os.path.realpath(__file__))
    while _d != _os.path.dirname(_d):
        if _os.path.isdir(_os.path.join(_d, 'shadowsocks')):
            if _d not in _sys.path:
                _sys.path.insert(0, _d)
            break
        _d = _os.path.dirname(_d)

from shadowsocks.crypto import util

__all__ = ['ciphers']

libsodium = None
loaded = False

buf_size = 2048

# for salsa20 and chacha20 and chacha20-ietf
BLOCK_SIZE = 64


def load_libsodium():
    global loaded, libsodium, buf

    libsodium = util.find_library('sodium', 'crypto_stream_salsa20_xor_ic',
                                  'libsodium')
    if libsodium is None:
        raise Exception('libsodium not found')

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

    try:
        libsodium.crypto_stream_chacha20_ietf_xor_ic.restype = c_int
        libsodium.crypto_stream_chacha20_ietf_xor_ic.argtypes = (c_void_p, c_char_p,
                                                        c_ulonglong,
                                                        c_char_p, c_ulong,
                                                        c_char_p)
    except Exception:
        # 旧版 libsodium 没有 chacha20-ietf，降级为不可用
        pass

    buf = create_string_buffer(buf_size)
    loaded = True


class SodiumCrypto(object):
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
        elif cipher_name == 'chacha20-ietf':
            if not hasattr(libsodium, 'crypto_stream_chacha20_ietf_xor_ic'):
                raise Exception('chacha20-ietf not supported by this libsodium')
            self.cipher = libsodium.crypto_stream_chacha20_ietf_xor_ic
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


ciphers = {
    'salsa20': (32, 8, SodiumCrypto),
    'chacha20': (32, 8, SodiumCrypto),
    'chacha20-ietf': (32, 12, SodiumCrypto),
}


def test_salsa20():
    cipher = SodiumCrypto('salsa20', b'k' * 32, b'i' * 16, 1)
    decipher = SodiumCrypto('salsa20', b'k' * 32, b'i' * 16, 0)

    util.run_cipher(cipher, decipher)


def test_chacha20():

    cipher = SodiumCrypto('chacha20', b'k' * 32, b'i' * 16, 1)
    decipher = SodiumCrypto('chacha20', b'k' * 32, b'i' * 16, 0)

    util.run_cipher(cipher, decipher)


def test_chacha20_ietf():

    cipher = SodiumCrypto('chacha20-ietf', b'k' * 32, b'i' * 16, 1)
    decipher = SodiumCrypto('chacha20-ietf', b'k' * 32, b'i' * 16, 0)

    util.run_cipher(cipher, decipher)


if __name__ == '__main__':
    try:
        test_chacha20_ietf()
        test_chacha20()
        test_salsa20()
        print('crypto/sodium.py: all tests passed')
    except Exception as e:
        # 本机没有 libsodium 时属于环境缺失，跳过而不是报错。
        if 'not found' in str(e):
            print('crypto/sodium.py: skipped, native library missing: %s' % e)
        else:
            raise
