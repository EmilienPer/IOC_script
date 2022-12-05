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

import logging
import unittest

from lib.parser.loki_parser import extract_reason_data_for_filescan, parse_filescan_line, LokiParser


logging.disable(logging.CRITICAL)


class TestExtractReasonDataForFilescan(unittest.TestCase):
    """
    Tests for the function extract_reason_data_for_filescan
    """
    def test_none_string(self):
        """
        A None should return None
        :return:
        """
        self.assertIsNone(extract_reason_data_for_filescan(None))

    def test_well_formatted_string(self):
        """
        Well formatted data should give a precise content_to_parse
        :return:
        """
        self.assertEqual(extract_reason_data_for_filescan(
            "2: File Name IOC matched PATTERN: /atexec\.py SUBSCORE: 70 DESC: Impacket default file name used for "
            "tools in the examples folder of the project https://github.com/SecureAuthCorp/impacket"),
            {'reason': 'File Name IOC matched',
             'description': 'Impacket default file name used for tools in the examples folder of the project https://github.com/SecureAuthCorp/impacket',
             'pattern': '/atexec\\.py'})
        self.assertEqual(extract_reason_data_for_filescan(
            "1: File Name IOC matched PATTERN: /wmiexec SUBSCORE: 60 DESC: Known Bad / Dual use classics"),
            {'reason': 'File Name IOC matched', 'description': 'Known Bad / Dual use classics', 'pattern': '/wmiexec'})
        self.assertEqual(extract_reason_data_for_filescan(
            "1: File Name IOC matched PATTERN: /smbrelayx SUBSCORE: 80 DESC: Relay Attack Tool Names"),
            {'reason': 'File Name IOC matched', 'description': 'Relay Attack Tool Names', 'pattern': '/smbrelayx'})

    def test_not_a_string(self):
        """
        Passing another think than a string should return None
        :return:
        """
        self.assertIsNone(extract_reason_data_for_filescan(1))
        self.assertIsNone(extract_reason_data_for_filescan(object()))
        self.assertIsNone(extract_reason_data_for_filescan({}))
        self.assertIsNone(extract_reason_data_for_filescan([]))

    def test_bad_format(self):
        """
        Bad format string should return None
        :return:
        """
        self.assertIsNone(extract_reason_data_for_filescan("this is a test"))
        self.assertIsNone(extract_reason_data_for_filescan("File Name IOC matched PATTERN: /smbrelayx SUBSCORE: 80 "
                                                           "DESC: Relay Attack Tool Names"))
        self.assertIsNone(extract_reason_data_for_filescan("1: File Name IOC matched DESC: Known Bad / Dual use "
                                                           "classics"))


class TestParseFileScanLine(unittest.TestCase):
    """
    Test for the function parse_filescan_line
    """
    def test_well_formatted_string(self):
        """
        Well formatted data should give a precise content_to_parse
        :return:
        """
        self.assertEqual(parse_filescan_line(
            "FILE: /usr/local/bin/atexec.py SCORE: 145 TYPE: UNKNOWN SIZE: 8861 FIRST_BYTES: "
            "23212f7573722f62696e2f707974686f6e0a2320 / <filter object at 0x7f2e7e315c60> MD5: "
            "451c0a3cdd385a65c549f85eb7f2e22c SHA1: 26f0221aee3c09f0523d66a53013ecab1341087e SHA256: "
            "be59f75ef064695a0515330e99999551d7215df9c4e39152f11d6ff3fd8bc698 CREATED: Thu Oct 21 15:05:45 2021 "
            "MODIFIED: Thu Oct 21 15:05:45 2021 ACCESSED: Thu Dec  1 18:56:43 2022 REASON_1: File Name IOC matched "
            "PATTERN: /atexec\.py SUBSCORE: 75 DESC: Impacket default file name used for tools in the examples folder "
            "of the project https://github.com/SecureAuthCorp/impacketREASON_2: File Name IOC matched PATTERN: "
            "/atexec\.py SUBSCORE: 70 DESC: Impacket default file name used for tools in the examples folder of the "
            "project https://github.com/SecureAuthCorp/impacket"),
            {'accessed': 'Thu Dec  1 18:56:43 2022',
             'created': 'Thu Oct 21 15:05:45 2021',
             'file_path': '/usr/local/bin/atexec.py',
             'first_byte': '23212f7573722f62696e2f707974686f6e0a2320',
             'log_type': 'UNKNOWN',
             'md5': '451c0a3cdd385a65c549f85eb7f2e22c',
             'modified': 'Thu Oct 21 15:05:45 2021',
             'reasons': [{'description': 'Impacket default file name used for tools in the '
                                         'examples folder of the project '
                                         'https://github.com/SecureAuthCorp/impacket',
                          'pattern': '/atexec\\.py',
                          'reason': 'File Name IOC matched'},
                         {'description': 'Impacket default file name used for tools in the '
                                         'examples folder of the project '
                                         'https://github.com/SecureAuthCorp/impacket',
                          'pattern': '/atexec\\.py',
                          'reason': 'File Name IOC matched'}],
             'score': '145',
             'sha1': '26f0221aee3c09f0523d66a53013ecab1341087e',
             'sha256': 'be59f75ef064695a0515330e99999551d7215df9c4e39152f11d6ff3fd8bc698',
             'size': '8861'})
        self.assertEqual(parse_filescan_line(
            "FILE: /usr/local/bin/nmapAnswerMachine.py SCORE: 70 TYPE: UNKNOWN SIZE: 36448 FIRST_BYTES: "
            "23212f7573722f62696e2f707974686f6e0a696d / <filter object at 0x7f2e7e315d80> MD5: "
            "9a6d729bbc49606f5dd61df4ab818cb6 SHA1: 2fcd85db64a2de8ccb9115bea05a69ceb8379591 SHA256: "
            "663ee9dddf704845cfa898607e80d59366eb9b7b8b4a32f1361f1d09c978856a CREATED: Thu Oct 21 15:05:45 2021 "
            "MODIFIED: Thu Oct 21 15:05:45 2021 ACCESSED: Thu Dec  1 18:56:43 2022 REASON_1: File Name IOC matched "
            "PATTERN: /nmapAnswerMachine\.py SUBSCORE: 70 DESC: Impacket default file name used for tools in the "
            "examples folder of the project https://github.com/SecureAuthCorp/impacket"),
            {'accessed': 'Thu Dec  1 18:56:43 2022',
             'created': 'Thu Oct 21 15:05:45 2021',
             'file_path': '/usr/local/bin/nmapAnswerMachine.py',
             'first_byte': '23212f7573722f62696e2f707974686f6e0a696d',
             'log_type': 'UNKNOWN',
             'md5': '9a6d729bbc49606f5dd61df4ab818cb6',
             'modified': 'Thu Oct 21 15:05:45 2021',
             'reasons': [{'description': 'Impacket default file name used for tools in the '
                                         'examples folder of the project '
                                         'https://github.com/SecureAuthCorp/impacket',
                          'pattern': '/nmapAnswerMachine\\.py',
                          'reason': 'File Name IOC matched'}],
             'score': '70',
             'sha1': '2fcd85db64a2de8ccb9115bea05a69ceb8379591',
             'sha256': '663ee9dddf704845cfa898607e80d59366eb9b7b8b4a32f1361f1d09c978856a',
             'size': '36448'})
        self.assertEqual(parse_filescan_line(
            "FILE: /usr/local/bin/netview.py SCORE: 70 TYPE: UNKNOWN SIZE: 22277 FIRST_BYTES: "
            "23212f7573722f62696e2f707974686f6e0a2320 / <filter object at 0x7f2e7e315cc0> MD5: "
            "c7bd3e874c6984b92bd96893fefe23dc SHA1: 1e07b8f6fa42ce087d15aaadec6b1546136e1421 SHA256: "
            "c84e9ad7d07d0cd4c1f83fd7e4ff04b3fa056556b0cc24fe63bf28ece9668547 CREATED: Thu Oct 21 15:05:45 2021 "
            "MODIFIED: Thu Oct 21 15:05:45 2021 ACCESSED: Thu Dec  1 18:56:43 2022 REASON_1: File Name IOC matched "
            "PATTERN: /netview\.py SUBSCORE: 70 DESC: Impacket default file name used for tools in the examples "
            "folder of the project https://github.com/SecureAuthCorp/impacket"),
            {'accessed': 'Thu Dec  1 18:56:43 2022',
             'created': 'Thu Oct 21 15:05:45 2021',
             'file_path': '/usr/local/bin/netview.py',
             'first_byte': '23212f7573722f62696e2f707974686f6e0a2320',
             'log_type': 'UNKNOWN',
             'md5': 'c7bd3e874c6984b92bd96893fefe23dc',
             'modified': 'Thu Oct 21 15:05:45 2021',
             'reasons': [{'description': 'Impacket default file name used for tools in the '
                                         'examples folder of the project '
                                         'https://github.com/SecureAuthCorp/impacket',
                          'pattern': '/netview\\.py',
                          'reason': 'File Name IOC matched'}],
             'score': '70',
             'sha1': '1e07b8f6fa42ce087d15aaadec6b1546136e1421',
             'sha256': 'c84e9ad7d07d0cd4c1f83fd7e4ff04b3fa056556b0cc24fe63bf28ece9668547',
             'size': '22277'})
        self.assertEqual(parse_filescan_line(
            "FILE: /usr/local/bin/smbexec.pyc SCORE: 70 TYPE: UNKNOWN SIZE: 13165 FIRST_BYTES: "
            "03f30d0aa96571616300000000000000000c0000 / <filter object at 0x7f2e7e315c90> MD5: "
            "ae37e3a048695a4d5f0af9db173b1b45 SHA1: f8be3329b1e0aff5f1473e7f56aadffc6ebeab1a SHA256: "
            "ed44cdebf852b23aec8da0433aad005e308069d6ef590f4464123abc1cd45dd7 CREATED: Thu Oct 21 15:05:45 2021 "
            "MODIFIED: Thu Oct 21 15:05:45 2021 ACCESSED: Thu Dec  1 18:56:43 2022 REASON_1: File Name IOC matched "
            "PATTERN: /smbexec\.py SUBSCORE: 70 DESC: Impacket default file name used for tools in the examples "
            "folder of the project https://github.com/SecureAuthCorp/impacket"),
            {'accessed': 'Thu Dec  1 18:56:43 2022',
             'created': 'Thu Oct 21 15:05:45 2021',
             'file_path': '/usr/local/bin/smbexec.pyc',
             'first_byte': '03f30d0aa96571616300000000000000000c0000',
             'log_type': 'UNKNOWN',
             'md5': 'ae37e3a048695a4d5f0af9db173b1b45',
             'modified': 'Thu Oct 21 15:05:45 2021',
             'reasons': [{'description': 'Impacket default file name used for tools in the '
                                         'examples folder of the project '
                                         'https://github.com/SecureAuthCorp/impacket',
                          'pattern': '/smbexec\\.py',
                          'reason': 'File Name IOC matched'}],
             'score': '70',
             'sha1': 'f8be3329b1e0aff5f1473e7f56aadffc6ebeab1a',
             'sha256': 'ed44cdebf852b23aec8da0433aad005e308069d6ef590f4464123abc1cd45dd7',
             'size': '13165'})
        self.assertEqual(parse_filescan_line(
            "FILE: /usr/local/bin/mimikatz.py SCORE: 70 TYPE: UNKNOWN SIZE: 9732 FIRST_BYTES: "
            "23212f7573722f62696e2f707974686f6e0a2320 / <filter object at 0x7f2e7e315d80> MD5: "
            "acefddfa22d674e09de5675298dfbcc3 SHA1: 2a146bbab8745be153a0812f6a5f8587a4f8ae18 SHA256: "
            "7fc1cfea5729317d21526c24a9551a69012be41bb72dd1eba1b4d0217c5b957c CREATED: Thu Oct 21 15:05:45 2021 "
            "MODIFIED: Thu Oct 21 15:05:45 2021 ACCESSED: Thu Dec  1 18:56:43 2022 REASON_1: File Name IOC matched "
            "PATTERN: /mimikatz\.py SUBSCORE: 70 DESC: Impacket default file name used for tools in the examples "
            "folder of the project https://github.com/SecureAuthCorp/impacket"),
            {'accessed': 'Thu Dec  1 18:56:43 2022',
             'created': 'Thu Oct 21 15:05:45 2021',
             'file_path': '/usr/local/bin/mimikatz.py',
             'first_byte': '23212f7573722f62696e2f707974686f6e0a2320',
             'log_type': 'UNKNOWN',
             'md5': 'acefddfa22d674e09de5675298dfbcc3',
             'modified': 'Thu Oct 21 15:05:45 2021',
             'reasons': [{'description': 'Impacket default file name used for tools in the '
                                         'examples folder of the project '
                                         'https://github.com/SecureAuthCorp/impacket',
                          'pattern': '/mimikatz\\.py',
                          'reason': 'File Name IOC matched'}],
             'score': '70',
             'sha1': '2a146bbab8745be153a0812f6a5f8587a4f8ae18',
             'sha256': '7fc1cfea5729317d21526c24a9551a69012be41bb72dd1eba1b4d0217c5b957c',
             'size': '9732'})
        self.assertEqual(parse_filescan_line(
            "FILE: /usr/local/bin/__pycache__/ntlmrelayx.cpython-39.pyc SCORE: 80 TYPE: UNKNOWN SIZE: 14836 "
            "FIRST_BYTES: 610d0d0a0000000027390860ca510000e3000000 / <filter object at 0x7f2e7e315ba0> MD5: "
            "bc762bb215365e019ec2bf1fd2ef1d05 SHA1: 3d4496088fef58a483682c1537daed55ce43a958 SHA256: "
            "e9f6909362cb09d08625eab8f09fee21c944da5033d43a5cb54adf4aebc5cbf5 CREATED: Wed Jan 20 15:07:36 2021 "
            "MODIFIED: Wed Jan 20 15:07:36 2021 ACCESSED: Thu Dec  1 18:56:43 2022 REASON_1: File Name IOC matched "
            "PATTERN: /ntlmrelayx SUBSCORE: 80 DESC: Relay Attack Tool Names"), {'accessed': 'Thu Dec  1 18:56:43 2022',
                                                                                 'created': 'Wed Jan 20 15:07:36 2021',
                                                                                 'file_path': '/usr/local/bin/__pycache__/ntlmrelayx.cpython-39.pyc',
                                                                                 'first_byte': '610d0d0a0000000027390860ca510000e3000000',
                                                                                 'log_type': 'UNKNOWN',
                                                                                 'md5': 'bc762bb215365e019ec2bf1fd2ef1d05',
                                                                                 'modified': 'Wed Jan 20 15:07:36 2021',
                                                                                 'reasons': [{
                                                                                                 'description': 'Relay Attack Tool Names',
                                                                                                 'pattern': '/ntlmrelayx',
                                                                                                 'reason': 'File Name IOC matched'}],
                                                                                 'score': '80',
                                                                                 'sha1': '3d4496088fef58a483682c1537daed55ce43a958',
                                                                                 'sha256': 'e9f6909362cb09d08625eab8f09fee21c944da5033d43a5cb54adf4aebc5cbf5',
                                                                                 'size': '14836'}
        )

    def test_not_a_string(self):
        """
        Passing another think than a string should return None
        :return:
        """
        self.assertIsNone(parse_filescan_line(1))
        self.assertIsNone(parse_filescan_line(object()))
        self.assertIsNone(parse_filescan_line({}))
        self.assertIsNone(parse_filescan_line([]))

    def test_bad_format(self):
        """
        Bad format string should return None
        :return:
        """
        self.assertIsNone(parse_filescan_line("test"))
        self.assertIsNone(parse_filescan_line(
            "2: File Name IOC matched PATTERN: /atexec\.py SUBSCORE: 70 DESC: Impacket default file name"))


class TestParse(unittest.TestCase):
    """
    Tests for the function parse()
    """
    def test_not_string_file(self):
        """
               should be detected and a default output should be return
               :return:
               """
        parser = LokiParser(1)
        self.assertEqual(parser.parse(), {'unclassified': []})

    def test_none_file(self):
        """
        A None file should be detected and a default output should be return
        :return:
        """
        parser = LokiParser(None)
        self.assertEqual(parser.parse(), {'unclassified': []})

    def test_empty_string(self):
        """
                A empty string should be detected and a default output should be return
                :return:
                """
        parser = LokiParser("", is_filepath=False)
        self.assertEqual(parser.parse(), {'unclassified': []})

    def test_bad_size_elem(self):
        """
        Unmanaged data should be send in unclassified
        :return:
        """
        parser = LokiParser("", is_filepath=False)
        parser.detected = [[], ["test"], ["test", "test"]]
        self.assertEqual(parser.parse(), {'unclassified': [['test'], ['test', 'test']]})

    def test_well_formed_data(self):
        data = "20221201T17:56:42Z,unit_test,WARNING,FileScan,FILE: /usr/local/share/doc/impacket/testcases/SMB_RPC/test_mimilib.py SCORE: 70 TYPE: UNKNOWN SIZE: 5073 FIRST_BYTES: 2323232323232323232323232323232323232323 / <filter object at 0x7f2e7e315c00> MD5: 63c6e93e5e5e3947ebcc95664ac47962 SHA1: 452f739314d65daa1ec067e341f896e319121b2e SHA256: a3db0756306658850b99425cc78c42eb90b2f53b8ed7f793188133cb7ebe02d0 CREATED: Thu Oct 21 15:05:45 2021 MODIFIED: Thu Oct 21 15:05:45 2021 ACCESSED: Thu Dec  1 18:56:42 2022 REASON_1: Yara Rule MATCH: Mimikatz_Memory_Rule_1 SUBSCORE: 70 DESCRIPTION: Detects password dumper mimikatz in memory (False Positives: an service that could have copied a Mimikatz executable, AV signatures) REF: - AUTHOR: Florian Roth MATCHES: Str1: sekurlsa::logonPasswords \n20221201T17:56:42Z,unit_test,ALERT,FileScan,FILE: /usr/local/bin/wmiexec.py SCORE: 130 TYPE: UNKNOWN SIZE: 16458 FIRST_BYTES: 23212f7573722f62696e2f707974686f6e0a2320 / <filter object at 0x7f2e7e315c30> MD5: 6a91aa180468eeb958cebc40510186ce SHA1: d1697c7099d505707c285d66aefa13319cc444b0 SHA256: 0dc6fc4902fc64083a977fd82596cd99a6983f6458cbfc8c92a532bc8384a8f8 CREATED: Thu Oct 21 15:05:45 2021 MODIFIED: Thu Oct 21 15:05:45 2021 ACCESSED: Thu Dec  1 18:56:42 2022 REASON_1: File Name IOC matched PATTERN: /wmiexec SUBSCORE: 60 DESC: Known Bad / Dual use classicsREASON_2: File Name IOC matched PATTERN: /wmiexec\.py SUBSCORE: 70 DESC: Impacket default file name used for tools in the examples folder of the project https://github.com/SecureAuthCorp/impacket                      \n20221201T17:56:43Z,unit_test,WARNING,FileScan,FILE: /usr/local/bin/esentutl.py SCORE: 70 TYPE: UNKNOWN SIZE: 3208 FIRST_BYTES: 23212f7573722f62696e2f707974686f6e0a2320 / <filter object at 0x7f2e7e315cc0> MD5: 25e18d62f7aa991a15db679b9036b977 SHA1: a89009afd078d63f24cbb6886387781a1e0ae68c SHA256: 6efdedfe41c0d762cc0183a8568e09f21b4452aec3beb12e2f314f5f83c9fb34 CREATED: Thu Oct 21 15:05:45 2021 MODIFIED: Thu Oct 21 15:05:45 2021 ACCESSED: Thu Dec  1 18:56:43 2022 REASON_1: File Name IOC matched PATTERN: /esentutl\.py SUBSCORE: 70 DESC: Impacket default file name used for tools in the examples folder of the project https://github.com/SecureAuthCorp/impacket                                                                                                                      \n20221201T17:56:43Z,unit_test,ALERT,FileScan,FILE: /usr/local/bin/smbrelayx.py SCORE: 220 TYPE: UNKNOWN SIZE: 52990 FIRST_BYTES: 23212f7573722f62696e2f707974686f6e0a2320 / <filter object at 0x7f2e7e315bd0> MD5: e31fda06426247fd9bf6fd828ff0447f SHA1: 57b2fa93f60921af2753c6f8bf9b2a8267d5fd32 SHA256: 2f6fa5f1e9544b9f6dc17e49bb11ae479cabc3d079d70045fc64b07b264ea8e0 CREATED: Thu Oct 21 15:05:45 2021 MODIFIED: Thu Oct 21 15:05:45 2021 ACCESSED: Thu Dec  1 18:56:43 2022 REASON_1: File Name IOC matched PATTERN: /smbrelayx SUBSCORE: 80 DESC: Relay Attack Tool NamesREASON_2: File Name IOC matched PATTERN: /smbrelayx\.py SUBSCORE: 70 DESC: Impacket default file name used for tools in the examples folder of the project https://github.com/SecureAuthCorp/impacket                      \n20221201T17:56:43Z,unit_test,WARNING,FileScan,FILE: /usr/local/bin/wmipersist.pyc SCORE: 70 TYPE: UNKNOWN SIZE: 7974 FIRST_BYTES: 03f30d0aa9657161630000000000000000080000 / <filter object at 0x7f2e7e315c90> MD5: 336ebc5563aa7e558f4d7d432194b909 SHA1: cd0b2d602d79e96f6e0bf07d227c37ceefed321c SHA256: 161e10bbfb90b9b2c6488c680fa687cb120a35fd487aba97453c3399269f29aa CREATED: Thu Oct 21 15:05:45 2021 MODIFIED: Thu Oct 21 15:05:45 2021 ACCESSED: Thu Dec  1 18:56:43 2022 REASON_1: File Name IOC matched PATTERN: /wmipersist\.py SUBSCORE: 70 DESC: Impacket default file name used for tools in the examples folder of the project https://github.com/SecureAuthCorp/impacket                                                                                                                 \n20221201T17:56:43Z,unit_test,WARNING,FileScan,FILE: /usr/local/bin/samrdump.pyc SCORE: 70 TYPE: UNKNOWN SIZE: 9141 FIRST_BYTES: 03f30d0aa96571616300000000000000000c0000 / <filter object at 0x7f2e7e315c60> MD5: a4dd870ad29cdb1a825b8e4de968927c SHA1: dcd1a5183732669d333f8231b5ac88577a56fe9c SHA256: 36437d49fbeef8958ce9cac27aa48481498040cd95072804f59b3d9bcabd8788 CREATED: Thu Oct 21 15:05:45 2021 MODIFIED: Thu Oct 21 15:05:45 2021 ACCESSED: Thu Dec  1 18:56:43 2022 REASON_1: File Name IOC matched PATTERN: /samrdump\.py SUBSCORE: 70 DESC: Impacket default file name used for tools in the examples folder of the project https://github.com/SecureAuthCorp/impacket                                                                                                                     \n20221201T17:56:43Z,unit_test,WARNING,FileScan,FILE: /usr/local/bin/lookupsid.py SCORE: 70 TYPE: UNKNOWN SIZE: 6705 FIRST_BYTES: 23212f7573722f62696e2f707974686f6e0a2320 / <filter object at 0x7f2e7e315d80> MD5: b114be8855a21000c770299a20082e69 SHA1: 3582a6ae52a070378c139c93b79d34faee57d2a8 SHA256: 6bb0633e0467d9290994974d0b43d60ca7dc9b107d65cfd1d1c36c93045329b3 CREATED: Thu Oct 21 15:05:45 2021 MODIFIED: Thu Oct 21 15:05:45 2021 ACCESSED: Thu Dec  1 18:56:43 2022 REASON_1: File Name IOC matched PATTERN: /lookupsid\.py SUBSCORE: 70 DESC: Impacket default file name used for tools in the examples folder of the project https://github.com/SecureAuthCorp/impacket                                                                                                                    \n20221201T17:56:43Z,unit_test,WARNING,FileScan,FILE: /usr/local/bin/secretsdump.py SCORE: 70 TYPE: UNKNOWN SIZE: 17779 FIRST_BYTES: 23212f7573722f62696e2f707974686f6e0a2320 / <filter object at 0x7f2e7e315c60> MD5: b4270a553308664199874bbd72999ccf SHA1: b541a0c349b14803e51be88c069d16b9d14e6192 SHA256: 9a54d529df28c8f5e2b0211aa694cf5cd279605a55ebdc42ee473088359f55c9 CREATED: Thu Oct 21 15:05:45 2021 MODIFIED: Thu Oct 21 15:05:45 2021 ACCESSED: Thu Dec  1 18:56:43 2022 REASON_1: File Name IOC matched PATTERN: /secretsdump\.py SUBSCORE: 70 DESC: Impacket default file name used for tools in the examples folder of the project https://github.com/SecureAuthCorp/impacket                                                                                                               \n20221201T17:56:43Z,unit_test,WARNING,FileScan,FILE: /usr/local/bin/rdp_check.py SCORE: 70 TYPE: UNKNOWN SIZE: 23084 FIRST_BYTES: 23212f7573722f62696e2f707974686f6e0a2320 / <filter object at 0x7f2e7e315cc0> MD5: 80a9eee2475ace913208186a2ce472bd SHA1: 745e9d351d8456fe928554313e532334f0e62b51 SHA256: 2e175ba69ce41a41ff00a266c9a35f4e95f246a577b153d2499bf898d585ae35 CREATED: Thu Oct 21 15:05:45 2021 MODIFIED: Thu Oct 21 15:05:45 2021 ACCESSED: Thu Dec  1 18:56:43 2022 REASON_1: File Name IOC matched PATTERN: /rdp_check\.py SUBSCORE: 70 DESC: Impacket default file name used for tools in the examples folder of the project https://github.com/SecureAuthCorp/impacket                                                                                                                   \n20221201T17:56:43Z,unit_test,WARNING,FileScan,FILE: /usr/local/bin/sniffer.py SCORE: 70 TYPE: UNKNOWN SIZE: 2075 FIRST_BYTES: 23212f7573722f62696e2f707974686f6e0a2320 / <filter object at 0x7f2e7e315d80> MD5: 167580108df197cc14394b543242ce02 SHA1: 69c7c2375b20a90e15ecc2cf17d13cab3bb162c4 SHA256: 688a68729c11c10b9be298ea8691935d102398917d8dd314dd3559503c2d0bc6 CREATED: Thu Oct 21 15:05:45 2021 MODIFIED: Thu Oct 21 15:05:45 2021 ACCESSED: Thu Dec  1 18:56:43 2022 REASON_1: File Name IOC matched PATTERN: /sniffer\.py SUBSCORE: 70 DESC: Impacket default file name used for tools in the examples folder of the project https://github.com/SecureAuthCorp/impacket\n20221201T17:56:43Z,unit_test,WARNING,FileScan,FILE: /usr/local/bin/ticketer.py SCORE: 70 TYPE: UNKNOWN SIZE: 38609 FIRST_BYTES: 23212f7573722f62696e2f707974686f6e0a2320 / <filter object at 0x7f2e7e315cc0> MD5: fa83ce367e5b61146cfb62b2002248bb SHA1: d1ce9546338b9d391ef89e71768eb7f451e57454 SHA256: 83c5cd09e09bf6580bf4cd5d6f8329a06cfe8a6ee7a86fd1e7c0b7e259dd17d6 CREATED: Thu Oct 21 15:05:45 2021 MODIFIED: Thu Oct 21 15:05:45 2021 ACCESSED: Thu Dec  1 18:56:43 2022 REASON_1: File Name IOC matched PATTERN: /ticketer\.py SUBSCORE: 70 DESC: Impacket default file name used for tools in the examples folder of the project https://github.com/SecureAuthCorp/impacket                                                                                                                     \n"
        parser = LokiParser(data, is_filepath=False)
        self.assertEqual(parser.parse(), {'unclassified': [['']], 'FileScan': [{'file_path': '/usr/local/share/doc/impacket/testcases/SMB_RPC/test_mimilib.py', 'score': '70', 'log_type': 'UNKNOWN', 'size': '5073', 'first_byte': '2323232323232323232323232323232323232323', 'md5': '63c6e93e5e5e3947ebcc95664ac47962', 'sha1': '452f739314d65daa1ec067e341f896e319121b2e', 'sha256': 'a3db0756306658850b99425cc78c42eb90b2f53b8ed7f793188133cb7ebe02d0', 'created': 'Thu Oct 21 15:05:45 2021', 'modified': 'Thu Oct 21 15:05:45 2021', 'accessed': 'Thu Dec  1 18:56:42 2022', 'reasons': [{'hash': 'Mimikatz_Memory_Rule_1', 'description': 'Detects password dumper mimikatz in memory (False Positives: an service that could have copied a Mimikatz executable, AV signatures)', 'reason': 'Yara Rule'}]}, {'file_path': '/usr/local/bin/wmiexec.py', 'score': '130', 'log_type': 'UNKNOWN', 'size': '16458', 'first_byte': '23212f7573722f62696e2f707974686f6e0a2320', 'md5': '6a91aa180468eeb958cebc40510186ce', 'sha1': 'd1697c7099d505707c285d66aefa13319cc444b0', 'sha256': '0dc6fc4902fc64083a977fd82596cd99a6983f6458cbfc8c92a532bc8384a8f8', 'created': 'Thu Oct 21 15:05:45 2021', 'modified': 'Thu Oct 21 15:05:45 2021', 'accessed': 'Thu Dec  1 18:56:42 2022', 'reasons': [{'pattern': '/wmiexec', 'description': 'Known Bad / Dual use classics', 'reason': 'File Name IOC matched'}, {'pattern': '/wmiexec\\.py', 'description': 'Impacket default file name used for tools in the examples folder of the project https://github.com/SecureAuthCorp/impacket', 'reason': 'File Name IOC matched'}]}, {'file_path': '/usr/local/bin/esentutl.py', 'score': '70', 'log_type': 'UNKNOWN', 'size': '3208', 'first_byte': '23212f7573722f62696e2f707974686f6e0a2320', 'md5': '25e18d62f7aa991a15db679b9036b977', 'sha1': 'a89009afd078d63f24cbb6886387781a1e0ae68c', 'sha256': '6efdedfe41c0d762cc0183a8568e09f21b4452aec3beb12e2f314f5f83c9fb34', 'created': 'Thu Oct 21 15:05:45 2021', 'modified': 'Thu Oct 21 15:05:45 2021', 'accessed': 'Thu Dec  1 18:56:43 2022', 'reasons': [{'pattern': '/esentutl\\.py', 'description': 'Impacket default file name used for tools in the examples folder of the project https://github.com/SecureAuthCorp/impacket', 'reason': 'File Name IOC matched'}]}, {'file_path': '/usr/local/bin/smbrelayx.py', 'score': '220', 'log_type': 'UNKNOWN', 'size': '52990', 'first_byte': '23212f7573722f62696e2f707974686f6e0a2320', 'md5': 'e31fda06426247fd9bf6fd828ff0447f', 'sha1': '57b2fa93f60921af2753c6f8bf9b2a8267d5fd32', 'sha256': '2f6fa5f1e9544b9f6dc17e49bb11ae479cabc3d079d70045fc64b07b264ea8e0', 'created': 'Thu Oct 21 15:05:45 2021', 'modified': 'Thu Oct 21 15:05:45 2021', 'accessed': 'Thu Dec  1 18:56:43 2022', 'reasons': [{'pattern': '/smbrelayx', 'description': 'Relay Attack Tool Names', 'reason': 'File Name IOC matched'}, {'pattern': '/smbrelayx\\.py', 'description': 'Impacket default file name used for tools in the examples folder of the project https://github.com/SecureAuthCorp/impacket', 'reason': 'File Name IOC matched'}]}, {'file_path': '/usr/local/bin/wmipersist.pyc', 'score': '70', 'log_type': 'UNKNOWN', 'size': '7974', 'first_byte': '03f30d0aa9657161630000000000000000080000', 'md5': '336ebc5563aa7e558f4d7d432194b909', 'sha1': 'cd0b2d602d79e96f6e0bf07d227c37ceefed321c', 'sha256': '161e10bbfb90b9b2c6488c680fa687cb120a35fd487aba97453c3399269f29aa', 'created': 'Thu Oct 21 15:05:45 2021', 'modified': 'Thu Oct 21 15:05:45 2021', 'accessed': 'Thu Dec  1 18:56:43 2022', 'reasons': [{'pattern': '/wmipersist\\.py', 'description': 'Impacket default file name used for tools in the examples folder of the project https://github.com/SecureAuthCorp/impacket', 'reason': 'File Name IOC matched'}]}, {'file_path': '/usr/local/bin/samrdump.pyc', 'score': '70', 'log_type': 'UNKNOWN', 'size': '9141', 'first_byte': '03f30d0aa96571616300000000000000000c0000', 'md5': 'a4dd870ad29cdb1a825b8e4de968927c', 'sha1': 'dcd1a5183732669d333f8231b5ac88577a56fe9c', 'sha256': '36437d49fbeef8958ce9cac27aa48481498040cd95072804f59b3d9bcabd8788', 'created': 'Thu Oct 21 15:05:45 2021', 'modified': 'Thu Oct 21 15:05:45 2021', 'accessed': 'Thu Dec  1 18:56:43 2022', 'reasons': [{'pattern': '/samrdump\\.py', 'description': 'Impacket default file name used for tools in the examples folder of the project https://github.com/SecureAuthCorp/impacket', 'reason': 'File Name IOC matched'}]}, {'file_path': '/usr/local/bin/lookupsid.py', 'score': '70', 'log_type': 'UNKNOWN', 'size': '6705', 'first_byte': '23212f7573722f62696e2f707974686f6e0a2320', 'md5': 'b114be8855a21000c770299a20082e69', 'sha1': '3582a6ae52a070378c139c93b79d34faee57d2a8', 'sha256': '6bb0633e0467d9290994974d0b43d60ca7dc9b107d65cfd1d1c36c93045329b3', 'created': 'Thu Oct 21 15:05:45 2021', 'modified': 'Thu Oct 21 15:05:45 2021', 'accessed': 'Thu Dec  1 18:56:43 2022', 'reasons': [{'pattern': '/lookupsid\\.py', 'description': 'Impacket default file name used for tools in the examples folder of the project https://github.com/SecureAuthCorp/impacket', 'reason': 'File Name IOC matched'}]}, {'file_path': '/usr/local/bin/secretsdump.py', 'score': '70', 'log_type': 'UNKNOWN', 'size': '17779', 'first_byte': '23212f7573722f62696e2f707974686f6e0a2320', 'md5': 'b4270a553308664199874bbd72999ccf', 'sha1': 'b541a0c349b14803e51be88c069d16b9d14e6192', 'sha256': '9a54d529df28c8f5e2b0211aa694cf5cd279605a55ebdc42ee473088359f55c9', 'created': 'Thu Oct 21 15:05:45 2021', 'modified': 'Thu Oct 21 15:05:45 2021', 'accessed': 'Thu Dec  1 18:56:43 2022', 'reasons': [{'pattern': '/secretsdump\\.py', 'description': 'Impacket default file name used for tools in the examples folder of the project https://github.com/SecureAuthCorp/impacket', 'reason': 'File Name IOC matched'}]}, {'file_path': '/usr/local/bin/rdp_check.py', 'score': '70', 'log_type': 'UNKNOWN', 'size': '23084', 'first_byte': '23212f7573722f62696e2f707974686f6e0a2320', 'md5': '80a9eee2475ace913208186a2ce472bd', 'sha1': '745e9d351d8456fe928554313e532334f0e62b51', 'sha256': '2e175ba69ce41a41ff00a266c9a35f4e95f246a577b153d2499bf898d585ae35', 'created': 'Thu Oct 21 15:05:45 2021', 'modified': 'Thu Oct 21 15:05:45 2021', 'accessed': 'Thu Dec  1 18:56:43 2022', 'reasons': [{'pattern': '/rdp_check\\.py', 'description': 'Impacket default file name used for tools in the examples folder of the project https://github.com/SecureAuthCorp/impacket', 'reason': 'File Name IOC matched'}]}, {'file_path': '/usr/local/bin/sniffer.py', 'score': '70', 'log_type': 'UNKNOWN', 'size': '2075', 'first_byte': '23212f7573722f62696e2f707974686f6e0a2320', 'md5': '167580108df197cc14394b543242ce02', 'sha1': '69c7c2375b20a90e15ecc2cf17d13cab3bb162c4', 'sha256': '688a68729c11c10b9be298ea8691935d102398917d8dd314dd3559503c2d0bc6', 'created': 'Thu Oct 21 15:05:45 2021', 'modified': 'Thu Oct 21 15:05:45 2021', 'accessed': 'Thu Dec  1 18:56:43 2022', 'reasons': [{'pattern': '/sniffer\\.py', 'description': 'Impacket default file name used for tools in the examples folder of the project https://github.com/SecureAuthCorp/impacket', 'reason': 'File Name IOC matched'}]}, {'file_path': '/usr/local/bin/ticketer.py', 'score': '70', 'log_type': 'UNKNOWN', 'size': '38609', 'first_byte': '23212f7573722f62696e2f707974686f6e0a2320', 'md5': 'fa83ce367e5b61146cfb62b2002248bb', 'sha1': 'd1ce9546338b9d391ef89e71768eb7f451e57454', 'sha256': '83c5cd09e09bf6580bf4cd5d6f8329a06cfe8a6ee7a86fd1e7c0b7e259dd17d6', 'created': 'Thu Oct 21 15:05:45 2021', 'modified': 'Thu Oct 21 15:05:45 2021', 'accessed': 'Thu Dec  1 18:56:43 2022', 'reasons': [{'pattern': '/ticketer\\.py', 'description': 'Impacket default file name used for tools in the examples folder of the project https://github.com/SecureAuthCorp/impacket', 'reason': 'File Name IOC matched'}]}]})


if __name__ == "__main__":
    unittest.main()
