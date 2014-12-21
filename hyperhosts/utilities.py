#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Copyleft (C) 2015 - huhamhire <me@huhamhire.com>
import os


def is_sys_win():
    """
    Check if current OS is a Windows system.

    :return: If current operating system is Windows or not.
    :rtype: bool
    """
    return os.name == 'nt'


def is_sys_posix():
    """
    Check if current OS is a posix system.

    :return: If current operating system is posix or not.
    :rtype: bool
    """
    return os.name == 'posix'


def is_user_admin():
    """
    Check if current user is admin/root.

    :return: If current user has administrator/root privileges or not.
    :rtype: bool
    :raises NotImplementedError: If this method is used on neither Windows
        systems nor posix systems.
    """
    if is_sys_win():
        import ctypes
        # WARNING: requires Windows XP SP2 or higher!
        return ctypes.windll.shell32.IsUserAnAdmin()
    elif is_sys_posix():
        # Check for root on Posix
        return os.getuid() == 0
    else:
        raise NotImplementedError("Unsupported operating system: %s" % os.name)
