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

from hyperhosts.constants import RES_PATH


class EvalMethodBase(object):
    __metaclass__ = ABCMeta

    @abstractmethod
    def eval(self):
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

    def eval(self):
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
        self._ip = ip
        self._pack_id = pack_id
        self._seq = seq
        self._v6 = is_ipv6
        if self._v6:
            self._family = socket.AF_INET6
        else:
            self._family = socket.AF_INET
        self._timeout = timeout
        self._data = self._create_data()

    def _create_sock(self):
        if self._v6:
            proto = socket.getprotobyname("ipv6-icmp")
        else:
            proto = socket.getprotobyname("icmp")
        try:
            # Create RAW socket for ping test
            sock = socket.socket(self._family, socket.SOCK_RAW, proto)
            sock.settimeout(self._timeout)
            return sock
        except socket.error:
            # RAW socket need root privilege
            raise

    def _create_pack(self):
        # Create a dummy header
        if not self._v6:
            header = struct.pack('bbHHh', 8, 0, 0, self._pack_id, 0)
        else:
            header = struct.pack('BbHHh', 128, 0, 0, self._pack_id, 0)
        # Calculate the checksum
        pack = header + self._data
        if len(pack) & 1:
            pack += '\0'
        words = array.array('h', pack)
        checksum = 0
        for word in words:
            checksum += (word & 0xffff)
        checksum = (checksum >> 16) + (checksum & 0xffff)
        checksum += (checksum >> 16)
        checksum = (~checksum) & 0xffff
        # Repack ICMP packet with checksum
        # TYPE, CODE, CHECKSUM, ID, SEQ
        if not self._v6:
            header = struct.pack('bbHHh', 8, 0, checksum, self._pack_id, 0)
        else:
            header = struct.pack('BbHHh', 128, 0, checksum, self._pack_id, 0)
        return header + self._data

    def _create_data(self):
        data = []
        start = 0x42
        for i in range(start, start + (self.PACKET_SIZE-8)):
            data += [(i & 0xff)]
        return bytes(data)

    def eval(self):
        pack = self._create_pack()
        sock = self._create_sock()
        # Send packet
        target = socket.getaddrinfo(
            self._ip, 0, self._family, 0, socket.SOL_IP)[0][4]
        time_send = time.clock()
        sock.sendto(pack, target)
        # Receive packet
        while True:
            timeout = self._timeout
            ready = select.select([sock], [], [], timeout)
            if not ready[0]:
                return -1
            time_received = time.clock()
            rec_packet, address = sock.recvfrom(1024)
            header = rec_packet[20:28]
            rtype, code, checksum, rid, seq = struct.unpack('bbHHh', header)
            echo = time_received - time_send
            if rid == self._pack_id:
                return echo
            if timeout - echo < 0:
                return -1


class HttpDelay(EvalMethodBase):
    CONNECTION_RESET_STAT = 1000

    def __init__(self, ip, hostname, port=None, timeout=10, https=False):
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

    def eval(self):
        delay, start_time, stat = -1, time.time(), None
        conn = self.conn(host=self._ip, port=self.port, timeout=self._timeout)
        try:
            conn.request(method="GET", url=self.url)
            stat = conn.getresponse().status
            delay = time.time() - start_time
        except socket.timeout:
            stat = http.client.REQUEST_TIMEOUT
        except ConnectionResetError:
            stat = self.CONNECTION_RESET_STAT
        finally:
            conn.close()
            return delay, stat

if __name__ == "__main__":
    test = ICMPEcho("10.0.5.1", 0, 0)
    print(test.eval())
