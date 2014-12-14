#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyleft (C) 2015 - huhamhire <me@huhamhire.com>
import http.client
import os
import socket
import ssl
import time

from abc import ABCMeta, abstractmethod

from hyperhosts.constants import res_path


class EvalBase(object):
    __metaclass__ = ABCMeta

    @abstractmethod
    def eval(self):
        pass


class CertVerify(EvalBase):

    def __init__(self, ip, hostname, port=443, timeout=10):
        super(CertVerify, self).__init__()

        self.ip = ip
        self.hostname = hostname
        self.port = port
        self.timeout = timeout

        ctx = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
        ctx.verify_mode = ssl.CERT_REQUIRED
        ctx.check_hostname = True
        ctx.load_verify_locations(
            os.path.join(res_path, "certs/ca-bundle.crt"),
            os.path.join(res_path, "certs/ca-bundle.trust.crt")
        )
        self._ctx = ctx

    def eval(self):
        """

        :return:
        """
        result = False
        sock = socket.socket()
        sock.settimeout(self.timeout)
        conn = self._ctx.wrap_socket(sock, server_hostname=self.hostname)
        try:
            conn.connect((self.ip, self.port))
            result = True
        except ssl.CertificateError:
            pass
        except socket.timeout:
            pass
        finally:
            conn.close()
            return result


class ICMPEcho(EvalBase):
    def eval(self):
        pass


class HttpDelay(EvalBase):
    def __init__(self, ip, hostname, port=None, timeout=10, https=False):
        self.ip = ip
        self.timeout = timeout
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
        conn = self.conn(host=self.ip, port=self.port, timeout=self.timeout)
        try:
            conn.request(method="GET", url=self.url)
            stat = conn.getresponse().status
            delay = time.time() - start_time
        except socket.timeout:
            pass
        except ConnectionResetError:
            pass
        finally:
            conn.close()
            return delay, stat

if __name__ == "__main__":
    test = HttpDelay("212.58.244.70", "www.bbc.com")
    print(test.eval())