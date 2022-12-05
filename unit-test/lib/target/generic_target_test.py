"""
IOC Security Issues Scanner Project
Author: Emilien Peretti (https://github.com/EmilienPer)
License: GNU GENERAL PUBLIC LICENSE (Version 3)
IOC and Security issues scanner
 Copyright (C) 2022  Emilien Peretti

 This program is free software: you can redistribute it and/or modify
 it under the terms of the GNU General Public License as published by
 the Free Software Foundation, either version 3 of the License, or
 (at your option) any later version.

 This program is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 GNU General Public License for more details.

 You should have received a copy of the GNU General Public License
 along with this program.  If not, see <https://www.gnu.org/licenses/>.
"""
__author__ = "Emilien Peretti"
__license__ = "GPL"

import unittest

from lib.target.generic_target import OSType


class TestEscapeAnsi(unittest.TestCase):
    """Test for escape_ansi method"""
    def test_function(self):
        self.assertEqual(OSType(None).escape_ansi("[2C- Detecting OS... [41C [ DONE ]"),"- Detecting OS...  [ DONE ]")
        self.assertEqual(OSType(None).escape_ansi("[2C- Service Manager[42C [ systemd ]"),'- Service Manager [ systemd ]')
        self.assertEqual(OSType(None).escape_ansi("[4C- configuration in /etc/profile[26C [ DEFAULT ]"),'- configuration in /etc/profile [ DEFAULT ]')

class TestSanitize(unittest.TestCase):
    """Test for sanitize(self, text: str, to_remove=None)"""
    def test_function(self):
        self.assertEqual(OSType(None).sanitize("[2C- Detecting OS... [41C [ DONE ]\r\n"),
                         "- Detecting OS...  [ DONE ]")
        self.assertEqual(OSType(None).sanitize("[2C- Detecting OS...C:\WINDOWS\system32\conhost.exe [41C [ DONE ]\r\n"),
                         "- Detecting OS...  [ DONE ]")
