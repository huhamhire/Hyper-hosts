#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyleft (C) 2015 - huhamhire <me@huhamhire.com>
import os
import socket
import ssl

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
    def eval(self):
        pass


if __name__ == "__main__":
    cert = CertVerify("74.125.200.197", "www.gg.com.hk")
    print(cert.eval())