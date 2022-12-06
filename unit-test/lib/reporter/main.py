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

from lib.reporter.main import ReportFormat


class TestComputeExtraInfo(unittest.TestCase):
    """
    Tests for compute_extra_info method
    """

    def test_compute(self):
        self.assertEqual(ReportFormat({}).report_dict, {'scan_info': {}})
        self.assertEqual(ReportFormat({"loki": {}}).report_dict, {'loki': {}, 'scan_info': {'detected_ioc': 0}})
        self.assertEqual(
            ReportFormat({"loki": {"FileScan": [1, 2, 3, 4, 5, 6], "IOC": [1, 2, 3, 4, 5, 6]}}).report_dict,
            {'loki': {'FileScan': [1, 2, 3, 4, 5, 6], 'IOC': [1, 2, 3, 4, 5, 6]}, 'scan_info': {'detected_ioc': 12}})
        self.assertEqual(
            ReportFormat({"security_issues": {},
                          "loki": {"FileScan": [1, 2, 3, 4, 5, 6], "IOC": [1, 2, 3, 4, 5, 6]}}).report_dict,
            {"security_issues": {}, 'loki': {'FileScan': [1, 2, 3, 4, 5, 6], 'IOC': [1, 2, 3, 4, 5, 6]},
             'scan_info': {'detected_ioc': 12, 'detected_security_issues': 0}})
