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

import os
import unittest
from os import listdir
from unittest.mock import patch, MagicMock, call

from lib.target.linux_target import Linux

linux = Linux(None)


class TestSendDirectory(unittest.TestCase):
    """
    Test for the send_directory method
    """

    def test(self):
        m = MagicMock(return_value=None)
        with patch("lib.target.linux_target.run", m.run, create=True):
            with patch("lib.target.linux_target.put", m.put, create=True):
                linux.send_directory(os.path.dirname(__file__), "tmp")
        m.run.assert_called_once_with('mkdir -p tmp || echo ko')
        current_dir = os.path.dirname(__file__)
        for elem in listdir(current_dir):
            m.put.assert_any_call(os.path.join(current_dir, elem), os.path.join("tmp", elem).replace("\\", "/"))


class TestInstallLynis(unittest.TestCase):
    """
    Test for install_lynis method
    """
    def test(self):
        m = MagicMock(return_value=None)
        with patch("lib.target.linux_target.Linux.send_directory", m.send_directory, create=True):
            linux.install_lynis()
        m.send_directory.assert_called_once()


class TestRemoveLynis(unittest.TestCase):
    def test(self):
        m = MagicMock(return_value=None)
        with patch("lib.target.linux_target.sudo", m.sudo, create=True):
            linux.remove_lynis()
        m.sudo.assert_called_once()


class TestRunLynis(unittest.TestCase):
    def test(self):
        m = MagicMock(return_value=None)
        with patch("lib.target.linux_target.sudo", m.sudo, create=True):
            with patch("lib.target.linux_target.run", m.run, create=True):
                with patch("lib.target.linux_target.cd", m.cd, create=True):
                    linux.run_lynis()
        m.sudo.assert_has_calls([call("chmod +x {}/lynis".format(linux.base_lynis)),
                                 call("{}/lynis audit system  --no-colors | tee {}".format(linux.base_lynis,
                                                                                           linux.lynis_report_path))],
                                any_order=True)
        m.run.assert_has_calls([call("export LANG=en;export LANGUAGE=en")])


class TestInstallLoki(unittest.TestCase):
    def test(self):
        m = MagicMock(return_value=None)
        with patch("lib.target.linux_target.sudo", m.sudo, create=True):
            with patch("lib.target.linux_target.run", m.run, create=True):
                with patch("lib.target.linux_target.cd", m.cd, create=True):
                    with patch("lib.target.linux_target.Linux.send_directory", m.send_directory, create=True):
                        linux.install_loki()
        m.sudo.assert_has_calls(
            [call("pip3 install -r {}/requirements.txt || pip install -r {}/requirements.txt".format(
                linux.base_loki, linux.base_loki))])

class TestRemoveLoki(unittest.TestCase):
    def test(self):
        m = MagicMock(return_value=None)
        with patch("lib.target.linux_target.sudo", m.sudo, create=True):
            linux.remove_loki()
        m.sudo.assert_called_once()


class TestRunLoki(unittest.TestCase):
    def test(self):
        m = MagicMock(return_value=None)
        with patch("lib.target.linux_target.sudo", m.sudo, create=True):
            linux.run_loki()
        m.sudo.assert_called_once()
