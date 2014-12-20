#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyleft (C) 2015 - huhamhire <me@huhamhire.com>
import unittest

from hyperhosts.evaluate import CertVerify, ICMPEcho, HttpDelay
from test.constants import test_mark


class EvalMethodTest(unittest.TestCase):
    def test_cert_verify(self):
        test = CertVerify("110.75.142.111", "www.alipay.com")
        self.assertTrue(test.eval())
        test = CertVerify("110.75.142.111", "www.google.com.hk")
        self.assertFalse(test.eval())
        test = CertVerify("1.1.1.1", "www.google.com.hk", 443, 3)
        self.assertFalse(test.eval())

    def test_http_delay(self):
        test = HttpDelay("110.75.142.111", "www.alipay.com")
        delay, stat = test.eval()
        self.assertGreaterEqual(delay, 0)
        self.assertIsNotNone(stat)
        test = HttpDelay("110.75.142.111", "www.alipay.com", https=True)
        delay, stat = test.eval()
        self.assertGreaterEqual(delay, 0)
        self.assertIsNotNone(stat)
        test = HttpDelay("212.58.244.70", "www.bbc.co.uk/zhongwen/simp/")
        delay, stat = test.eval()
        self.assertEqual(delay, -1)


def eval_test_suite():
    eval_test = unittest.makeSuite(EvalMethodTest, test_mark)
    return unittest.TestSuite(eval_test)

if __name__ == "__main__":
    unittest.TextTestRunner(verbosity=1).run(eval_test_suite())
