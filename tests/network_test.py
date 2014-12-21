#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Copyleft (C) 2015 - huhamhire <me@huhamhire.com>
import unittest

import hyperhosts.utilities as utils

from hyperhosts.network import DNSQuery, CertVerify, ICMPEcho, HttpDelay
from tests.constants import TEST_MARK


class EvalMethodTest(unittest.TestCase):
    def test_cert_verify(self):
        test = CertVerify("110.75.142.111", "www.alipay.com")
        self.assertTrue(test.evaluate())
        test = CertVerify("110.75.142.111", "www.google.com.hk")
        self.assertFalse(test.evaluate())
        test = CertVerify("1.1.1.1", "www.google.com.hk", 443, 3)
        self.assertFalse(test.evaluate())

    def test_http_delay(self):
        test = HttpDelay("110.75.142.111", "www.alipay.com")
        delay, stat = test.evaluate()
        self.assertGreaterEqual(delay, 0)
        self.assertIsNotNone(stat)
        test = HttpDelay("110.75.142.111", "www.alipay.com", https=True)
        delay, stat = test.evaluate()
        self.assertGreaterEqual(delay, 0)
        self.assertIsNotNone(stat)
        test = HttpDelay("212.58.244.70", "www.bbc.co.uk/zhongwen/simp/")
        delay, stat = test.evaluate()
        self.assertEqual(delay, -1)

    def test_icmp_echo(self):
        test = ICMPEcho("127.0.0.1")
        echo = test.evaluate()
        if utils.is_user_admin():
            self.assertGreater(echo, 0)
            test = ICMPEcho("::1", is_ipv6=True)
            echo = test.evaluate()
            self.assertGreater(echo, 0)
            test = ICMPEcho("110.75.142.111")
            echo = test.evaluate()
            self.assertGreater(echo, 0)
        else:
            self.assertEqual(echo, -1)


class CrawlMethodTest(unittest.TestCase):
    def test_dns_query(self):
        test = DNSQuery('www.alipay.com', '8.8.4.4')
        ips = test.crawl()
        self.assertIn("110.75.142.111", ips)
        test = DNSQuery('huhamhire.com', '8.8.4.4', is_v6_record=True)
        ips = test.crawl()
        self.assertIn("2604:180:1::d54:39b9", ips)


def network_test_suite():
    eval_test = unittest.makeSuite(EvalMethodTest, TEST_MARK)
    crawl_test = unittest.makeSuite(CrawlMethodTest, TEST_MARK)
    return unittest.TestSuite((eval_test, crawl_test))

if __name__ == "__main__":
    unittest.TextTestRunner(verbosity=1).run(network_test_suite())
