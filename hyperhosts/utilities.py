#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyleft (C) 2015 - huhamhire <me@huhamhire.com>
import os


def is_sys_win():
    return os.name == 'nt'


def is_sys_posix():
    return os.name == 'posix'


def is_user_admin():
    if is_sys_win():
        import ctypes
        # WARNING: requires Windows XP SP2 or higher!
        return ctypes.windll.shell32.IsUserAnAdmin()
    elif is_sys_posix():
        # Check for root on Posix
        return os.getuid() == 0
    else:
        raise NotImplementedError("Unsupported operating system: %s" % os.name)
