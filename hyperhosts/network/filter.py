#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Copyleft (C) 2015 - huhamhire <me@huhamhire.com>
import ipaddress
import os

from abc import ABCMeta, abstractmethod

from hyperhosts.constants import RES_PATH


class FilterBase(object):
    __metaclass__ = ABCMeta

    def __init__(self):
        super(FilterBase, self).__init__()

    @abstractmethod
    def filter(self, target):
        return False


class IPFilter(FilterBase):
    def __init__(self, is_ipv6=False):
        super(IPFilter, self).__init__()
        self._v6 = is_ipv6
        if self._v6:
            self._list_file = os.path.join(RES_PATH, 'blacklists/ipv6.conf')
        else:
            self._list_file = os.path.join(RES_PATH, 'blacklists/ipv4.conf')
        with open(self._list_file, 'r') as list_file:
            ls = list_file.readlines()
            blacklist = []
            for l in ls:
                l = l.strip()
                if len(l) == 0 or l.startswith('#'):
                    continue
                if '/' not in l:
                    l += '/32' if not self._v6 else '/128'
                blacklist.append(l)
            self._blacklist = blacklist

    def filter(self, target):
        match = False
        for ip in self._blacklist:
            n = ipaddress.ip_network(ip)
            subnet = int(n.network_address)
            mask = int(n.netmask)
            address = int(ipaddress.ip_address(target))
            match |= address & mask == subnet
            if match:
                break
        return match
