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

"""shadowsocksr-manyuser 核心包。

本包已从 Python 2 迁移到 Python 3（开发与验证环境 Python 3.11，兼容 3.8+）。

约定：
  * 所有网络协议数据（缓冲区、密钥、IV、地址）都是 ``bytes``；
  * 配置项与日志文本都是 ``str``；
  * 边界转换统一使用 :func:`shadowsocks.common.to_bytes` /
    :func:`shadowsocks.common.to_str`，不要再依赖隐式转换。

入口脚本：
  * ``shadowsocks/server.py``  多用户服务端
  * ``shadowsocks/local.py``   本地客户端
  * ``shadowsocks/manager.py`` 带管理接口的服务端
  * ``shadowsocks/user.py``    交互式配置向导
"""

__version__ = '3.4.0'
