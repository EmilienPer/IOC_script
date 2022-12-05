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
from unittest.mock import patch, mock_open

from lib.reporter.json_report import to_json


class TestJsonReporter(unittest.TestCase):
    """Test for to_json"""

    def test_write_into_file(self):
        """Check if the function save a json into a file"""
        open_mock = mock_open()
        with patch("lib.reporter.json_report.open", open_mock, create=True):
            to_json("output.json", {})
        open_mock.assert_called_with("output.json", "w")
        open_mock.return_value.write.assert_called_once_with('')

    def test_format(self):
        """ Test if only json is saved """
        open_mock = mock_open()
        with patch("lib.reporter.json_report.open", open_mock, create=True):
            self.assertTrue(to_json("output.json", {}))
            self.assertTrue(to_json("output.json", {"key": "value"}))
            self.assertFalse(to_json("output.json", None))
            self.assertFalse(to_json("output.json", 1))
            self.assertFalse(to_json("output.json", object()))
