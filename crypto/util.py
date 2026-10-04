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

import os
import logging


def find_library_nt(name):
    # modified from ctypes.util
    # ctypes.util.find_library just returns first result he found
    # but we want to try them all
    # because on Windows, users may have both 32bit and 64bit version installed
    results = []
    path_env = os.environ.get('PATH', '')
    for directory in path_env.split(os.pathsep):
        if not directory:
            continue
        fname = os.path.join(directory, name)
        if os.path.isfile(fname):
            results.append(fname)
        if fname.lower().endswith(".dll"):
            continue
        fname = fname + ".dll"
        if os.path.isfile(fname):
            results.append(fname)
    return results


def find_library(possible_lib_names, search_symbol, library_name):
    import ctypes.util
    from ctypes import CDLL

    paths = []

    if type(possible_lib_names) not in (list, tuple):
        possible_lib_names = [possible_lib_names]

    lib_names = []
    for lib_name in possible_lib_names:
        lib_names.append(lib_name)
        lib_names.append('lib' + lib_name)

    for name in lib_names:
        if os.name == "nt":
            paths.extend(find_library_nt(name))
        else:
            path = ctypes.util.find_library(name)
            if path:
                paths.append(path)

    if not paths:
        # We may get here when find_library fails because, for example,
        # the user does not have sufficient privileges to access those
        # tools underlying find_library on linux.
        import glob

        for name in lib_names:
            patterns = [
                '/usr/local/lib*/lib%s.*' % name,
                '/usr/lib*/lib%s.*' % name,
                'lib%s.*' % name,
                '%s.dll' % name]

            for pat in patterns:
                files = glob.glob(pat)
                if files:
                    paths.extend(files)
    for path in paths:
        try:
            lib = CDLL(path)
            if hasattr(lib, search_symbol):
                logging.info('loading %s from %s', library_name, path)
                return lib
            else:
                logging.warning('can\'t find symbol %s in %s', search_symbol,
                                path)
        except Exception:
            if path == paths[-1]:
                raise
    return None


def run_cipher(cipher, decipher):
    from os import urandom
    import random
    import time

    BLOCK_SIZE = 16384
    rounds = 1 * 1024
    plain = urandom(BLOCK_SIZE * rounds)

    results = []
    pos = 0
    print('test start')
    start = time.time()
    while pos < len(plain):
        l = random.randint(100, 32768)
        c = cipher.update(plain[pos:pos + l])
        results.append(c)
        pos += l
    pos = 0
    c = b''.join(results)
    results = []
    while pos < len(plain):
        l = random.randint(100, 32768)
        results.append(decipher.update(c[pos:pos + l]))
        pos += l
    end = time.time()
    print('speed: %d bytes/s' % (BLOCK_SIZE * rounds // (end - start)))
    assert b''.join(results) == plain


def test_find_library():
    if os.name != 'posix':
        # 这组断言依赖 Unix 约定（libc / libcrypto 与 strcpy 符号），在
        # Windows 上本身不成立，跳过而不是误报失败。
        print('crypto/util.py: find_library test skipped '
              '(non-POSIX platform)')
        return
    assert find_library('c', 'strcpy', 'libc') is not None
    assert find_library(['c'], 'strcpy', 'libc') is not None
    assert find_library(('c',), 'strcpy', 'libc') is not None
    assert find_library('notexist', 'strcpy', 'libnotexist') is None
    assert find_library('c', 'symbol_not_exist', 'c') is None
    # 以下断言要求本机已安装 libcrypto，缺失时不做正向断言。
    if find_library(('crypto', 'eay32'), 'EVP_CipherUpdate',
                    'libcrypto') is not None:
        assert find_library(('notexist', 'c', 'crypto', 'eay32'),
                            'EVP_CipherUpdate', 'libc') is not None


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

    test_find_library()
    print('crypto/util.py: all tests passed')
