#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyleft (C) 2015 - huhamhire <me@huhamhire.com>
import array
import http.client
import os
import select
import socket
import ssl
import struct
import time

from abc import ABCMeta, abstractmethod

import hyperhosts.utilities as utils

from hyperhosts.constants import RES_PATH


class EvalMethodBase(object):
    __metaclass__ = ABCMeta

    def __init__(self):
        if utils.is_sys_win():
            self.timer = time.clock
        else:
            self.timer = time.time

    @abstractmethod
    def evaluate(self):
        pass


class CertVerify(EvalMethodBase):

    def __init__(self, ip, hostname, port=443, timeout=10):
        super(CertVerify, self).__init__()

        self._ip = ip
        self._hostname = hostname
        self._port = port
        self._timeout = timeout

        ctx = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
        ctx.verify_mode = ssl.CERT_REQUIRED
        ctx.check_hostname = True
        ctx.load_verify_locations(
            os.path.join(RES_PATH, "certs/ca-bundle.crt"),
            os.path.join(RES_PATH, "certs/ca-bundle.trust.crt")
        )
        self._ctx = ctx

    def evaluate(self):
        """

        :return:
        """
        result = False
        sock = socket.socket()
        sock.settimeout(self._timeout)
        conn = self._ctx.wrap_socket(sock, server_hostname=self._hostname)
        try:
            conn.connect((self._ip, self._port))
            result = True
        except ssl.CertificateError:
            pass
        except socket.timeout:
            pass
        finally:
            conn.close()
            return result


class ICMPEcho(EvalMethodBase):
    PACKET_SIZE = 64

    def __init__(self, ip, pack_id=0, seq=0, is_ipv6=False, timeout=3):
        super(ICMPEcho, self).__init__()
        self._ip = ip
        self._pack_id = pack_id
        self._seq = seq
        self._v6 = is_ipv6
        if self._v6:
            self._family = socket.AF_INET6
            self._pack_type = 128
        else:
            self._family = socket.AF_INET
            self._pack_type = 8
        self._timeout = timeout
        self._data = self._create_data()

    def _create_sock(self):
        if not utils.is_user_admin():
            # RAW socket need root privilege
            raise OSError("Operation not permitted")
        if self._v6:
            proto = socket.getprotobyname("ipv6-icmp")
        else:
            proto = socket.getprotobyname("icmp")
        # Create RAW socket for ping test
        sock = socket.socket(self._family, socket.SOCK_RAW, proto)
        sock.settimeout(self._timeout)
        return sock

    def _create_pack(self):
        # Create a dummy header
        # The order of header data is: TYPE, CODE, CHECKSUM, ID, SEQ
        checksum = 0
        header = struct.pack(
            'BbHHh', self._pack_type, 0, checksum, self._pack_id, self._seq)
        # Calculate the checksum
        pack = header + self._data
        if len(pack) & 1:
            pack += '\0'
        words = array.array('h', pack)
        for word in words:
            checksum += (word & 0xffff)
        checksum = (checksum >> 16) + (checksum & 0xffff)
        checksum += (checksum >> 16)
        checksum = (~checksum) & 0xffff
        # Repack ICMP packet with checksum
        header = struct.pack(
            'BbHHh', self._pack_type, 0, checksum, self._pack_id, self._seq)
        return header + self._data

    def _create_data(self):
        data = []
        start = 0x42
        for i in range(start, start + (self.PACKET_SIZE-8)):
            data += [(i & 0xff)]
        return bytes(data)

    def evaluate(self):
        pack = self._create_pack()
        try:
            sock = self._create_sock()
        except OSError:
            return -1
        # Send packet
        target = socket.getaddrinfo(
            self._ip, 0, self._family, 0, socket.SOL_IP)[0][4]
        time_send = self.timer()
        sock.sendto(pack, target)
        # Receive packet
        while True:
            timeout = self._timeout
            ready = select.select([sock], [], [], timeout)
            if not ready[0]:
                return -1
            time_received = self.timer()
            rec_packet, address = sock.recvfrom(1024)
            if not self._v6:
                header = rec_packet[20:28]
            else:
                header = rec_packet[0:8]
            rtype, code, checksum, rid, seq = struct.unpack('BbHHh', header)
            echo = time_received - time_send
            if address[0] == target[0] and rid == self._pack_id:
                return echo
            if timeout - echo < 0:
                return -1


class HttpDelay(EvalMethodBase):
    CONNECTION_RESET_CODE = 1000

    def __init__(self, ip, hostname, port=None, timeout=10, https=False):
        super(HttpDelay, self).__init__()
        self._ip = ip
        self._timeout = timeout
        if https:
            self.port = port if port else 443
            self.url = 'https://' + hostname
            self.conn = http.client.HTTPSConnection
        else:
            self.port = port if port else 80
            self.url = 'http://' + hostname
            self.conn = http.client.HTTPConnection

    def evaluate(self):
        delay, start_time, stat = -1, self.timer(), None
        conn = self.conn(host=self._ip, port=self.port, timeout=self._timeout)
        try:
            conn.request(method="GET", url=self.url)
            stat = conn.getresponse().status
            delay = self.timer() - start_time
        except socket.timeout:
            stat = http.client.REQUEST_TIMEOUT
        except ConnectionResetError:
            stat = self.CONNECTION_RESET_CODE
        finally:
            conn.close()
            return delay, stat
