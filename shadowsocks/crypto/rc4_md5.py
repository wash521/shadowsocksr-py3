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

import hashlib

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

from shadowsocks.crypto import openssl

__all__ = ['ciphers']


def create_cipher(alg, key, iv, op, key_as_bytes=0, d=None, salt=None,
                  i=1, padding=1):
    md5 = hashlib.md5()
    md5.update(key)
    md5.update(iv)
    rc4_key = md5.digest()
    return openssl.OpenSSLCrypto(b'rc4', rc4_key, b'', op)


ciphers = {
    'rc4-md5': (16, 16, create_cipher),
    'rc4-md5-6': (16, 6, create_cipher),
}


def test():
    from shadowsocks.crypto import util

    cipher = create_cipher('rc4-md5', b'k' * 32, b'i' * 16, 1)
    decipher = create_cipher('rc4-md5', b'k' * 32, b'i' * 16, 0)

    util.run_cipher(cipher, decipher)


if __name__ == '__main__':
    test()
