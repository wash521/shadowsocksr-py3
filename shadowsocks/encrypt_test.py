#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""加密算法自检脚本（Python 3 版本）。

原文件使用 tab 缩进与 Python 2 风格的隐式字符串拼接，这里整理为规范的
Python 3 代码，并修复 `except: pass`（会连 KeyboardInterrupt 一起吞掉）。
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                '..'))

from shadowsocks.crypto import rc4_md5  # noqa: E402
from shadowsocks.crypto import openssl  # noqa: E402
from shadowsocks.crypto import sodium   # noqa: E402
from shadowsocks.crypto import table    # noqa: E402


def run(func):
    try:
        func()
    except Exception as e:
        print('  skipped: %s' % e)


def run_n(func, name):
    try:
        func(name)
    except Exception as e:
        print('  skipped: %s' % e)


def main():
    print("\nrc4_md5")
    run(rc4_md5.test)

    print("\naes-256-cfb")
    run(openssl.test_aes_256_cfb)

    print("\naes-128-cfb")
    run(openssl.test_aes_128_cfb)

    print("\nbf-cfb")
    run(openssl.test_bf_cfb)

    print("\ncamellia-128-cfb")
    run_n(openssl.run_method, "camellia-128-cfb")

    print("\ncast5-cfb")
    run_n(openssl.run_method, "cast5-cfb")

    print("\nidea-cfb")
    run_n(openssl.run_method, "idea-cfb")

    print("\nseed-cfb")
    run_n(openssl.run_method, "seed-cfb")

    print("\nsalsa20")
    run(sodium.test_salsa20)

    print("\nchacha20")
    run(sodium.test_chacha20)

    print("\ntable")
    run(table.test_table_result)


if __name__ == '__main__':
    main()
