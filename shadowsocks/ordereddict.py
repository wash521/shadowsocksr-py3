#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Copyright 2012-2015 clowwindy
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

"""历史兼容层。

Python 2.6 及更早版本没有 collections.OrderedDict，老代码因此在本模块里
内置了一份纯 Python 实现。该实现在 Python 3 下存在若干问题（引用了已被移除
的 collections.MutableMapping、以及未定义的工具函数 _imap/_eq/_get_ident），
而且 Python 3 的 collections.OrderedDict 是 C 实现、严格更快。

这里直接把标准库实现重导出，保持 `from shadowsocks.ordereddict import
OrderedDict` 这一老式导入路径可用。
"""

from collections import OrderedDict  # noqa: F401

__all__ = ['OrderedDict']
