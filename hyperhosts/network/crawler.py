#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Copyleft (C) 2015 - huhamhire <me@huhamhire.com>
import os
import re
import socket
import struct

from abc import ABCMeta, abstractmethod


class CrawlerBase(object):
    __metaclass__ = ABCMeta

    def __init__(self):
        super(CrawlerBase, self).__init__()

    @abstractmethod
    def crawl(self):
        pass


class DNSQuery(CrawlerBase):

    def __init__(self, hostname, server, timeout=5, port=53, query_type="TCP",
                 is_v6_record=False, is_v6_server=False):
        super(DNSQuery, self).__init__()
        self._hostname = hostname
        self._server = server
        self._timeout = timeout
        self._port = port
        self._v6_record = is_v6_record
        if is_v6_server:
            self._family = socket.AF_INET6
        else:
            self._family = socket.AF_INET
        if query_type.upper() == "TCP":
            self._sock_type = socket.SOCK_STREAM
        else:
            self._sock_type = socket.SOCK_DGRAM

    def _create_socket(self):
        sock = socket.socket(self._family, self._sock_type)
        sock.settimeout(self._timeout)
        return sock

    def _encode_hostname(self):
        index = os.urandom(2)
        data = index + b"\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
        host_str = ''.join(chr(len(x)) + x for x in self._hostname.split('.'))
        if self._v6_record:
            # AAAA record query data
            data += bytes(host_str, 'utf8') + b"\x00\x00\x1C\x00\x01"
        else:
            # A record query data
            data += bytes(host_str, 'utf8') + b"\x00\x00\x01\x00\x01"
        return struct.pack("!H", len(data)) + data

    def _decode_results(self, sock):
        in_file = sock.makefile("rb")
        size = struct.unpack("!H", in_file.read(2))[0]
        data = in_file.read(size)
        ips = []
        if self._v6_record:
            # Find all AAAA records
            raw_ip_list = re.findall(b"\xC0.\x00\x1C\x00\x01.{6}(.{16})", data)
            for raw_ip in raw_ip_list:
                hex_str = ''.join(('%02x' % x for x in raw_ip))
                hextets = []
                for i in range(0, 32, 4):
                    hextets.append('%x' % int(hex_str[i:i+4], 16))
                ip = ":".join(self._compress_hextets(hextets))
                ips.append(ip)
        else:
            # Find all A records
            raw_ip_list = re.findall(b"\xC0.\x00\x01\x00\x01.{6}(.{4})", data)
            for raw_ip in raw_ip_list:
                ip = ".".join(str(int(x)) for x in raw_ip)
                ips.append(ip)
        return ips

    @staticmethod
    def _compress_hextets(hextets):
        """Compresses a list of hextets.

        Compresses a list of strings, replacing the longest continuous sequence
        of "0" in the list with "" and adding empty strings at the beginning or
        at the end of the string such that subsequently calling
        ``":".join(hextets)`` will produce the compressed version of the IPv6
        address.

        :param hextets: The hextets to compress.
        :type hextets: list
        :return: A list of strings.
        :rtype: list
        """
        best_start = -1
        best_length = 0
        start = -1
        length = 0
        for i, hextet in enumerate(hextets):
            if hextet == '0':
                length += 1
                if start == -1:
                    # Start of a sequence of zeros.
                    start = i
                if length > best_length:
                    # This is the longest sequence of zeros so far.
                    best_length = length
                    best_start = start
            else:
                length = 0
                start = -1

        if best_length > 1:
            best_end = best_start + best_length
            # For zeros at the end of the address.
            if best_end == len(hextets):
                hextets += ['']
            hextets[best_start:best_end] = ['']
            # For zeros at the beginning of the address.
            if best_start == 0:
                hextets = [''] + hextets
        return hextets

    def crawl(self):
        sock = self._create_socket()
        ips = []
        try:
            sock.connect((self._server, self._port))
            data = self._encode_hostname()
            sock.sendall(data)
            ips = self._decode_results(sock)
        except socket.timeout:
            pass
        except socket.error:
            # Connection Error
            pass
        except struct.error:
            # Decode Error
            pass
        finally:
            sock.close()
            return ips
