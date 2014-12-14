#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyleft (C) 2015 - huhamhire <me@huhamhire.com>
import unittest

from hyperhosts.eval import CertVerify, ICMPEcho, HttpDelay
from test.constants import test_mark


class EvalMethodTest(unittest.TestCase):
    def test_cert_verify(self):
        test = CertVerify("110.75.142.111", "www.alipay.com")
        self.assertTrue(test.eval(), 'SSL cert should match')
        test = CertVerify("110.75.142.111", "www.google.com.hk")
        self.assertFalse(test.eval(), 'SSL cert should not match')
        test = CertVerify("1.1.1.1", "www.google.com.hk", 443, 3)
        self.assertFalse(test.eval(), 'SSL connection should be timed out')


def eval_test_suite():
    eval_test = unittest.makeSuite(EvalMethodTest, test_mark)
    return unittest.TestSuite(eval_test)

if __name__ == "__main__":
    unittest.TextTestRunner(verbosity=1).run(eval_test_suite())
