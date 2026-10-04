#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""SSR 客户端配置向导（Python 3 版本）。

原文件是 Python 2 脚本（print 语句、raw_input、tab 缩进混排），这里整体重写为
Python 3，交互流程与生成的 user-config.json 格式保持不变。
"""

import base64
import re
import sys
import json

# ---- 可选：「加密方式」菜单（索引即用户输入的编号） ----
METHODS = ["", "table", "rc4", "rc4-md5", "rc4-md5-6", "aes-128-cfb",
           "aes-192-cfb", "aes-256-cfb", "aes-128-ctr", "aes-192-ctr",
           "aes-256-ctr", "bf-cfb", "camellia-128-cfb", "camellia-192-cfb",
           "camellia-256-cfb", "cast5-cfb", "des-cfb", "idea-cfb", "rc2-cfb",
           "seed-cfb", "salsa20", "chacha20", "chacha20-ietf"]

# ---- 可选：「协议插件」菜单 ----
PROTOCOLS = ["origin", "verify_simple", "verify_sha1", "auth_sha1",
             "auth_sha1_v2", "auth_sha1_v4", "auth_aes128_sha1",
             "auth_aes128_md5", "auth_chain_a", "auth_chain_b",
             "auth_chain_c", "auth_chain_d"]

# ---- 可选：「混淆插件」菜单 ----
OBFS = ["plain", "http_simple", "http_post", "tls_simple",
        "tls1.2_ticket_auth", "tls1.2_ticket_fastauth"]

_IP_RE = re.compile(r'^((25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}'
                    r'(25[0-5]|2[0-4]\d|[01]?\d\d?)$')


def add_base64_padding(s):
    """为 urlsafe base64 字符串补齐 '='。

    原实现用 `4 - len(s) % 4`，当长度已是 4 的倍数时会多补 4 个 '='；
    这里改用标准写法，长度对齐时补 0 个。
    """
    if isinstance(s, str):
        return s + '=' * (-len(s) % 4)
    return s + b'=' * (-len(s) % 4)


class miss(object):
    """保留原始类名以便沿用旧调用方式。"""

    def ssr4(self, ssrurl):
        return add_base64_padding(ssrurl)


def checkip(ip):
    """返回 True 表示输入不合法。"""
    if _IP_RE.match(ip or ''):
        return False
    print("输入错误请重新输入")
    return True


def checkport(port):
    """返回 True 表示输入不合法。"""
    try:
        value = int(port)
        if value < 0 or value > 65535:
            print("输入错误请重新输入")
            return True
        return False
    except (TypeError, ValueError):
        print("输入错误请重新输入")
        return True


def ask_ip(prompt, default=None):
    while True:
        print(prompt)
        value = input().strip()
        if not value and default is not None:
            value = default
        if not checkip(value):
            return value


def ask_port(prompt, default=None):
    while True:
        print(prompt)
        value = input().strip()
        if not value and default is not None:
            value = default
        if not checkport(value):
            return value


def parse_ssr_url(ssrhead):
    """解析 ssr:// 链接，返回 (serverip, serverport, password, method,
    protocol, obfs)。解析失败抛 ValueError。
    """
    parts = re.split('[:/]', ssrhead)
    if len(parts) < 4:
        raise ValueError('not a valid ssr url')
    payload = base64.urlsafe_b64decode(add_base64_padding(parts[3]))
    payload = payload.decode('utf-8', 'replace')
    fields = re.split('[:/?&]', payload)
    if len(fields) < 6:
        raise ValueError('not a valid ssr payload')
    serverip = fields[0]
    serverport = fields[1]
    password = base64.urlsafe_b64decode(add_base64_padding(fields[5]))
    password = password.decode('utf-8', 'replace')
    method = fields[3]
    protocol = fields[2]
    obfs = fields[4]
    return serverip, serverport, password, method, protocol, obfs


def choose(menu, title, offset=0, min_num=0):
    """打印菜单并让用户选择。

    offset 用于「协议/混淆」菜单：用户输入从 1 开始计数。
    """
    print(title)
    while True:
        try:
            num = int(input().strip())
            if num < min_num:
                raise ValueError('out of range')
            return menu[num - offset]
        except (ValueError, IndexError):
            print("输入错误，请输入正确的数字")


def build_config(serverip, serverport, localaddress, localport, password,
                 method, protocol, protocolparam, obfs, obfsparam):
    config = {
        "server": serverip,
        "server_ipv6": "::",
        "server_port": int(serverport),
        "local_address": localaddress,
        "local_port": int(localport),
        "password": password,
        "method": method,
        "protocol": protocol,
        "protocol_param": protocolparam,
        "obfs": obfs,
        "obfs_param": obfsparam,
        "speed_limit_per_con": 0,
        "speed_limit_per_user": 0,
        "additional_ports": {},
        "timeout": 120,
        "udp_timeout": 60,
        "dns_ipv6": False,
        "connect_verbose_info": 0,
        "redirect": "",
        "fast_open": False,
    }
    return config


def main():
    print('''
请输入SSR地址码
（就是ssr://XX,复制粘贴不嫌长您了就手打）
手动配置服务器信息请输入1''')

    ssrhead = None
    while True:
        ssrhead = input().strip()
        if ssrhead == "1":
            break
        try:
            serverip, serverport, password, method, protocol, obfs = \
                parse_ssr_url(ssrhead)
            break
        except Exception:
            print("导入失败，请输入正确的SSR地址或输入1手动配置")

    if ssrhead == "1":
        serverip = ask_ip("请输入服务器IP地址:\n")
        serverport = ask_port("请输入服务器端口:\n")
        localaddress = ask_ip("请输入本机代理地址，默认127.0.0.1，使用默认请回车",
                              default="127.0.0.1")
        localport = ask_port("请输入本机代理端口，默认1080，使用默认请回车",
                             default="1080")
        password = input("请输入密码:\n").strip()

        print('''
0="NONE不加密"
1="table"
2="rc4"
3="rc4-md5"
4="rc4-md5-6"
5="aes-128-cfb"
6="aes-192-cfb"
7="aes-256-cfb"
8="aes-128-ctr"
9="aes-192-ctr"
10="aes-256-ctr"
11="bf-cfb"
12="camellia-128-cfb"
13="camellia-192-cfb"
14="camellia-256-cfb"
15="cast5-cfb"
16="des-cfb"
17="idea-cfb"
18="rc2-cfb"
19="seed-cfb"
20="salsa20"
21="chacha20"
22="chacha20-ietf"

请输入对应的加密方式数字''')
        method = choose(METHODS, '', offset=0, min_num=0)

        print('''
1="origin"
2="verify_simple"
3="verify_sha1"
4="auth_sha1"
5="auth_sha1_v2"
6="auth_sha1_v4"
7="auth_aes128_sha1"
8="auth_aes128_md5"
9="auth_chain_a"
10="auth_chain_b"
11="auth_chain_c"
12="auth_chain_d"

请输入对应的协议插件数字''')
        protocol = choose(PROTOCOLS, '', offset=1, min_num=1)

        protocolparam = input("请输入协议参数，不使用参数请回车:\n").strip()

        print('''
1="plain"
2="http_simple"
3="http_post"
4="tls_simple"
5="tls1.2_ticket_auth"
6="tls1.2_ticket_fastauth"

请输入对应的混淆参数的数字''')
        obfs = choose(OBFS, '', offset=1, min_num=1)

        print('''
请输入混淆参数
示例:baidu.com (不需要加http)
不使用参数请回车''')
        obfsparam = input().strip()

    else:
        localaddress = ask_ip("请输入本机代理地址，默认127.0.0.1，使用默认请回车",
                              default="127.0.0.1")
        localport = ask_port("请输入本机代理端口，默认1080，使用默认请回车",
                             default="1080")
        protocolparam = input("请输入协议参数，不使用参数请回车:\n").strip()
        print('''
请输入混淆参数
示例:baidu.com (不需要加http)
不使用参数请回车''')
        obfsparam = input().strip()

    config = build_config(serverip, serverport, localaddress, localport,
                          password, method, protocol, protocolparam, obfs,
                          obfsparam)
    text = json.dumps(config, indent=4, ensure_ascii=False)

    with open('user-config.json', 'w', encoding='utf-8') as f:
        f.write(text)

    print(text + "\n" + "请检查输入是否有误，若需要修改请重新执行程序。\n"
          "启动ssr请在终端切换至shadowsocksr/shadowsocks目录执行"
          "python3 local.py -d start")


if __name__ == '__main__':
    sys.exit(main())
