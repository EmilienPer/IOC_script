"""
IOC Security Issues Scanner Project
Author: Emilien Peretti (https://github.com/EmilienPer)
License: GNU GENERAL PUBLIC LICENSE (Version 3)
"""
__author__ = "Emilien Peretti"
__license__ = "GPL"

import logging
import re


class LokiParser:
    """
    Parser for loki report
    """

    def __init__(self, filepath):
        """
        :param filepath: Local path to the loki report
        """
        self.detected = []
        try:
            with open(filepath, 'r') as f:
                for line in f.readlines():
                    self.detected.append(line.split(","))
        finally:
            pass

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
                    out_dict[line[3]].append(parse_file_scan(",".join(line[4:])))
                else:
                    out_dict[line[3]].append(",".join(line[4:]))
            else:
                out_dict["unclassified"].append(line)
        return out_dict


def parse_file_scan(line):
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
                r2 = "\d+: (?P<reason>((?!(PATTERN|SUBSCORE|TYPE)).)*)\s((TYPE: (?P<log_type>\w+) HASH: (" \
                     "?P<hash>\w+) SUBSCORE: \d+ DESC: (?P<description>.*))|(SUBSCORE: \d+ DESCRIPTION: (" \
                     "?P<description2>((?!REF).)*)\s)|(PATTERN: (?P<pattern>[^\s]+) SUBSCORE: \d+ DESC: .*)) "
                file_info_dict["reasons"].append(re.match(r2, r).groupdict())
        return file_info_dict
    except Exception as e:
        logging.error('error during parsing loki line "{}":{}'.format(line, e))
        return {"error": e, "line": line}
