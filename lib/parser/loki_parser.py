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
import re


class LokiParser:
    """
    Parser for loki report
    """

    def __init__(self, filepath_or_string, is_filepath=True):
        """
        :param filepath_or_string: Local path to the loki report
        """
        self.detected = []
        try:
            if filepath_or_string is not None and len(filepath_or_string) > 0:
                if is_filepath:
                    with open(filepath_or_string, 'r') as f:
                        for line in f.readlines():
                            self.detected.append(line.rstrip().split(","))
                else:
                    for line in filepath_or_string.split("\n"):
                        self.detected.append(line.rstrip().split(","))
        except:
            logging.error('Error during initialize lokiparser with file "{}"'.format(filepath_or_string))
        finally:
            logging.debug('Detected {}'.format(self.detected))

    def parse(self) -> dict:
        """
        Parse the string from loki log
        :return:
        """
        logging.debug('start parsing loki report')
        out_dict = {"unclassified": []}
        for line in self.detected:
            if len(line) >= 4:
                if line[3] not in out_dict:
                    out_dict[line[3]] = []
                if line[3] == "FileScan":
                    line_data = parse_filescan_line(",".join(line[4:]))
                    if line_data:
                        out_dict[line[3]].append(line_data)
                else:
                    out_dict[line[3]].append(",".join(line[4:]))
            else:
                if len(line) != 0:
                    out_dict["unclassified"].append(line)
        return out_dict


def parse_filescan_line(line):
    """
    Parse the log file
    :param line:
    :return:
    """
    try:
        split_reason = line.split("REASON_")
        file_info_dict = {}
        if len(split_reason) >= 2:
            file_info = split_reason[0]
            r1 = "FILE:\s(?P<file_path>((?!SCORE).)*)\sSCORE:\s(?P<score>\d+)\sTYPE:\s(?P<log_type>\w+)\sSIZE:\s(" \
                 "?P<size>\d+)\s(FIRST_BYTES:\s(?P<first_byte>[^\s]+)(\s\/\s<filter object at .*>)?)?\s?(((MD5: (" \
                 "?P<md5>\w*))|(SHA1: (?P<sha1>\w*))|(SHA256: (?P<sha256>\w*)))\s)*\s?CREATED: (?P<created>\w+ " \
                 "\w+\s+\d+ \d+:\d+:\d+ \d+) MODIFIED: (?P<modified>\w+ \w+\s+\d+ \d+:\d+:\d+ \d+) ACCESSED: (" \
                 "?P<accessed>\w+ \w+\s+.\d+ \d+:\d+:\d+ \d+) "
            file_info_dict = re.match(r1, file_info).groupdict()
            file_info_dict["reasons"] = []
            reasons = split_reason[1:]
            for r in reasons:
                finding = extract_reason_data_for_filescan(r)
                if finding is not None:
                    file_info_dict["reasons"].append(finding)
        if file_info_dict != {}:
            return file_info_dict
        return None
    except Exception as e:
        logging.error('error during parsing loki line "{}":{}'.format(line, e))
        return None


def extract_reason_data_for_filescan(reason_str):
    """
    Extract IOC reason from string using a regex
    :param reason_str: the reason line of a IOC detected in loki report
    :return:
    """
    try:
        if "File Name IOC matched" in reason_str:
            regex = "\d+: File Name IOC matched PATTERN: (?P<pattern>[^\s]+) SUBSCORE: \d+ DESC: (?P<description>.*)"
            reason = "File Name IOC matched"
        elif "Malware Hash" in reason_str:
            regex = "\d+: Malware Hash TYPE: (?P<log_type>\w+) HASH: (?P<hash>\w+) SUBSCORE: \d+ DESC: (?P<description>.*)"
            reason = "Malware Hash"
        elif "Yara Rule" in reason_str:
            regex = "\d+: Yara Rule MATCH: (?P<hash>\w+) SUBSCORE: \d+ DESCRIPTION: (?P<description>.*) REF: .* AUTHOR: " \
                    ".* (MATCHES: .*)* "
            reason = "Yara Rule"
        else:
            logging.error('error during parsing loki line reason"{}":Unknown pattern'.format(reason_str))
            return None
        finding = re.match(regex, reason_str).groupdict()
        finding["reason"] = reason
        return finding
    except Exception as e:
        logging.error('error during parsing loki line reason"{}":{}'.format(reason_str, e))
        return None
