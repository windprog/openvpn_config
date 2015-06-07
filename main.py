#!/usr/bin/python
# -*- coding: utf-8 -*-

"""
Copyright (c) 2015 netease

Author  :   windpro
E-mail  :   zzn1889@corp.netease.com
Date    :   15/6/6
Desc    :   
"""
import os
import os.path
import IPy
from collections import OrderedDict, defaultdict
import re


SERVER_NAME = 'server'
CONFIG_TEXT = "#openvpn auto config lines:"


route_config = {
    'client1': [
        # vpn访问的网络地址，需要在该网络所在机器加iptables，例如：
        # iptables -t nat -A POSTROUTING -s 10.9.0.0/24 -o eth0 -j MASQUERADE
        # 其中10.9.0.0/24 为openvpn.conf中的：server 10.9.0.0 255.255.255.0
        '192.168.0.0/16',
        # AS45062
        '106.2.32.0/19',
        '106.2.64.0/19',
        '106.2.96.0/19',
        '114.113.196.0/22',
        '114.113.200.0/22',
        '123.58.160.0/19',
        '223.252.192.0/19',
        '42.8.0.0/16',
        '60.233.0.0/16',
        # AS4808
        '123.125.0.0/16',
        '115.236.112.0/20',
        '106.108.0.0/15',
        '218.107.55.207/32',
    ],
    SERVER_NAME: [
        # vpn访问服务器的地址，有两种方式，一种是全局的：
        # iptables -t nat -A POSTROUTING -s 10.9.0.0/24 -j SNAT --to-source xxx.xxx.xxx.xxx
        # 或者按需nat
        # iptables -t nat -A POSTROUTING -s 10.9.0.0/24 -d 8.8.8.8/32 -j SNAT --to-source xxx.xxx.xxx.xxx
        '8.8.8.8/32',
        '8.8.4.4/32',
    ]
}

def get_network_address_normal(na):
    assert isinstance(na, IPy.IP)
    return "%s/%s" % (na.strFullsize(0), na.prefixlen())


class RewriteOpenvpnConfig(object):
    def __init__(self, route_config, cf_path, save_cf_path=None, save_ccd_path=None):
        self.route_config = route_config
        self.cf_path = cf_path
        if not save_cf_path:
            self.save_cf_path = cf_path
        else:
            self.save_cf_path = save_cf_path
        self.cf_text = ''
        with file(self.cf_path) as f:
            self.cf_text = f.read()
        self.cf_lines = [item for item in self.cf_text.replace('\r\n', '\n').split('\n')
                         if not item.startswith(CONFIG_TEXT)]

        self.ccd_real_path = None
        self.__save_ccd_path = save_ccd_path
        # result
        self.result_push_lines = []
        self.result_route_lines = []
        self.result_iroute_config = defaultdict(list)

    @property
    def save_ccd_path(self):
        return self.__save_ccd_path if self.__save_ccd_path else self.ccd_real_path

    def __result_route_lines(self, route_lines):
        route_na = OrderedDict()
        for line in route_lines:
            rl = self.route_line(line)
            if not rl:
                self.result_route_lines.append(line)
            else:
                ip, netmask = rl
                ipo = IPy.IP(ip).make_net(netmask)
                route_na[get_network_address_normal(ipo)] = ipo
        return route_na

    def __result_push_lines(self, push_lines):
        push_na = OrderedDict()
        for line in push_lines:
            if len(line) <= 4:
                self.result_push_lines.append(line)
                continue
            text = line[line.find('push')+4:].strip(' ')
            text = text.replace('"', '')
            rl = self.route_line(text)
            if not rl:
                self.result_push_lines.append(line)
            else:
                ip, netmask = rl
                ipo = IPy.IP(ip).make_net(netmask)
                push_na[get_network_address_normal(ipo)] = ipo
        return push_na

    def __result_iroute_config(self, iroute_config):
        assert isinstance(iroute_config, dict)
        iroute_na = {key: OrderedDict() for key in iroute_config.iterkeys()}
        for dr_name, lines in iroute_config.iteritems():
            _na = iroute_na[dr_name]
            for line in lines:
                rl = self.route_line(line)
                if not rl:
                    self.result_iroute_config[dr_name].append(line)
                else:
                    ip, netmask = rl
                    ipo = IPy.IP(ip).make_net(netmask)
                    _na[get_network_address_normal(ipo)] = ipo
        return iroute_na

    @staticmethod
    def route_line(_line):
        assert isinstance(_line, basestring)
        if len(_line) <= 5:
            return
        _text = _line[_line.find('route')+5:].strip(' ')
        _tmp = [_item for _item in _text.split(' ') if _item]
        if not len(_tmp) == 2:
            return
        _tmp = [_item for _item in _tmp if re.match('[\\d.]+', _item)]
        if not len(_tmp) == 2:
            return
        return _tmp

    def load_result_na(self, push_na, route_na, iroute_na):
        assert isinstance(push_na, OrderedDict)
        for dr_name, str_nas in self.route_config.iteritems():
            for str_na in str_nas:
                if dr_name == SERVER_NAME:
                    if str_na not in push_na:
                        push_na[str_na] = IPy.IP(str_na)
                else:
                    _nas = iroute_na[dr_name]
                    if str_na not in _nas:
                        _nas[str_na] = IPy.IP(str_na)
                    if str_na not in push_na:
                        push_na[str_na] = IPy.IP(str_na)
                    if str_na not in route_na:
                        route_na[str_na] = IPy.IP(str_na)

        self.result_push_lines.extend(
            ['push "route %s %s"' % (na.strNormal(0), na.netmask()) for na in push_na.itervalues()])

        self.result_route_lines.extend(
            ['route %s %s' % (na.strNormal(0), na.netmask()) for na in route_na.itervalues()])

        for dr_name, nas in iroute_na.iteritems():
            self.result_iroute_config[dr_name].extend(
                ['iroute %s %s' % (na.strNormal(0), na.netmask()) for na in nas.itervalues()])



    def write_config(self):
        default_lines = []

        push_lines = []
        route_lines = []
        iroute_config = {key: list() for key in self.route_config.iterkeys() if key != SERVER_NAME}

        def init_iroute(ccd_value):
            assert isinstance(ccd_value, basestring)
            path = ccd_value
            if not path.startswith('/'):
                path = os.path.join(os.path.dirname(self.cf_path), ccd_value)

            self.ccd_real_path = path

            if not os.path.exists(path):
                return
            for parent, dirnames, filenames in os.walk(path):
                for filename in filenames:
                    if filename not in iroute_config:
                        iroute_config[filename] = list()
                    with file(os.path.join(path, filename)) as _f:
                        text = _f.read()
                        iroute_ins = iroute_config[filename]
                        assert isinstance(iroute_ins, list)
                        iroute_ins.extend([item for item in text.replace('\r\n', '\n').split('\n')
                                           if not item.startswith(CONFIG_TEXT)])
                        if iroute_ins and iroute_ins[-1] == "":
                            # 清理最后一行为空
                            iroute_ins.pop(len(iroute_ins)-1)

        for line in self.cf_lines:
            assert isinstance(line, basestring)
            if line.startswith('push'):
                push_lines.append(line)
            elif line.startswith('route'):
                route_lines.append(line)
            else:
                if line.startswith('client-config-dir'):
                    cdd = unicode(line)
                    cd_kv = cdd.split(' ')
                    cd_kv = [item for item in cd_kv if item]
                    if len(cd_kv) == 2:
                        ccd = cd_kv[1]
                        init_iroute(ccd)
                default_lines.append(line)

        # result na
        push_na = self.__result_push_lines(push_lines)
        route_na = self.__result_route_lines(route_lines)
        iroute_na = self.__result_iroute_config(iroute_config)


        # start reconfig
        self.load_result_na(push_na, route_na, iroute_na)

        result = []
        if len(default_lines) and default_lines[-1] == "":
            default_lines.pop(len(default_lines)-1)
        result.extend(default_lines)
        result.append("%s push" % CONFIG_TEXT)
        result.extend(self.result_push_lines)
        result.append("%s route" % CONFIG_TEXT)
        result.extend(self.result_route_lines)
        result.append('')

        with file(self.save_cf_path, 'w+') as f:
            f.write('\n'.join(result))

        if self.ccd_real_path:
            for dr_name, lines in self.result_iroute_config.iteritems():
                if not os.path.exists(self.save_ccd_path):
                    os.mkdir(self.save_ccd_path)
                with file(os.path.join(self.save_ccd_path, dr_name), 'w+') as f:
                    r_lines = ['%s iroute' % CONFIG_TEXT]
                    r_lines.extend(lines)
                    r_lines.append('')  # 添加空行
                    f.write('\n'.join(r_lines))


if __name__ == '__main__':
    import sys

    cf_path = 'stuff/openvpn.conf'

    if len(sys.argv)>1:
        cf_path = sys.argv[1]
        assert isinstance(cf_path, basestring)
        if not cf_path.startswith('/'):
            cf_path = os.path.join(os.path.dirname(sys.argv[0]), cf_path)

    if not os.path.exists(cf_path):
        print u'请输入准确的openvpn配置路径'

    RewriteOpenvpnConfig(route_config, cf_path).write_config()