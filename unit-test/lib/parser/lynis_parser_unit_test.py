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

from lib.parser.lynis_parser import get_suggestion_and_ref_from_lines, get_part_title, get_title_and_count, \
    get_suggestion_part

logging.disable(logging.CRITICAL)
content_to_parse = """
Warnings (1):
----------------------------
! Reboot of system is most likely needed [KRNL-5830] 
  - Solution : reboot
    https://cisofy.com/lynis/controls/KRNL-5830/

Suggestions (36):
----------------------------
* This release is more than 4 months old. Check the website or GitHub to see if there is an update available. [LYNIS] 
    https://cisofy.com/lynis/controls/LYNIS/

* Set a password on GRUB boot loader to prevent altering boot configuration (e.g. boot in single user mode without password) [BOOT-5122] 
    https://cisofy.com/lynis/controls/BOOT-5122
"""


class TestGetSuggestionAndRefFromLines(unittest.TestCase):
    """
    Tests for the function get_suggestion_and_ref_from_lines(elem: str)
    """

    def test_none_string(self):
        """
        None or null string should return None,None
        :return:
        """
        for line in ["", None]:
            suggestion, ref = get_suggestion_and_ref_from_lines(line)
            self.assertIsNone(suggestion)
            self.assertIsNone(ref)

    def test_bad_type(self):
        """
        Anything except a string should return None,None
        :return:
        """
        for line in [1, {}, [], object()]:
            suggestion, ref = get_suggestion_and_ref_from_lines(line)
            self.assertIsNone(suggestion)
            self.assertIsNone(ref)

    def test_well_formatted_string(self):
        suggestion, ref = get_suggestion_and_ref_from_lines("test")
        self.assertEqual(suggestion, "test")
        self.assertEqual(ref, "")
        suggestion, ref = get_suggestion_and_ref_from_lines("test\ntest_ref")
        self.assertEqual(suggestion, "test")
        self.assertEqual(ref, "test_ref")
        suggestion, ref = get_suggestion_and_ref_from_lines("test\ntest_line2\ntest_ref")
        self.assertEqual(suggestion, "test test_line2")
        self.assertEqual(ref, "test_ref")


class TestGetPartTitle(unittest.TestCase):
    """Tests for the function get_part_title(content_to_parse, title_and_count_tuple_list)"""

    def test_well_formatted(self):
        content_to_parse = """
        Warnings (1):
        ----------------------------
        ! Reboot of system is most likely needed [KRNL-5830] 
          - Solution : reboot
            https://cisofy.com/lynis/controls/KRNL-5830/
        
        Suggestions (36):
        ----------------------------
        * This release is more than 4 months old. Check the website or GitHub to see if there is an update available. [LYNIS] 
            https://cisofy.com/lynis/controls/LYNIS/
        
        * Set a password on GRUB boot loader to prevent altering boot configuration (e.g. boot in single user mode without password) [BOOT-5122] 
            https://cisofy.com/lynis/controls/BOOT-5122
        """
        self.assertEqual(get_part_title(content_to_parse, [["Warnings (1)", 1], ["Suggestions (36)", 36]]),
                         [[9, 'Warnings', '1'], [226, 'Suggestions', '36']])

    def test_not_authorized_data(self):
        """
        Test function with wrong data
        :return:
        """
        self.assertEqual(get_part_title(None, None), [])
        self.assertEqual(get_part_title("", None), [])
        self.assertEqual(get_part_title("test", "test"), [])

    def test_title_not_in_content(self):
        """
            Test with a string not in content
        """

        self.assertEqual(get_part_title(content_to_parse, [["Test (1)", 1], ["Suggestions (36)", 36]]),
                         [[266, 'Suggestions', '36']])


class TestGetTitleAndCount(unittest.TestCase):
    """
    Test for the function get_title_and_count(file_suggestion_part)
    """

    def test_not_a_string(self):
        """
        empty list should be returned is non string
        :return:
        """
        self.assertEqual(get_title_and_count(1), [])
        self.assertEqual(get_title_and_count(None), [])
        self.assertEqual(get_title_and_count(object()), [])

    def test_no_title_in_data(self):
        """
                empty list should be returned if there is no title in content
                :return:
                """
        self.assertEqual(get_title_and_count("test"), [])

    def test_well_formatted_data(self):
        """
                Test for well formatted date
                :return:
                """
        self.assertEqual(get_title_and_count(content_to_parse),[('Warnings', '1'), ('Suggestions', '36')])


class TestGetSuggestionPart(unittest.TestCase):
    def test_not_a_string(self):
        """
                None should be returned is non string
                :return:
                """
        self.assertEqual(get_suggestion_part(1),None)
        self.assertEqual(get_suggestion_part(None), None)
        self.assertEqual(get_suggestion_part(object()), None)

    def test_no_suggestion_part(self):
        """
        None should be returned if there is no interesting part
        :return:
        """
        self.assertEqual(get_suggestion_part("test"), None)

    def test_well_formatted_data(self):
        """
                        Test for well formatted date
                        :return:
                        """
        self.assertEqual(get_suggestion_part("test"+"="*80+"Good part"),"Good part")


if __name__ == "__main__":
    unittest.main()
