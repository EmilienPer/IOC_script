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


class LynisParser:
    """
        Parser for Lynis report
        """

    def __init__(self, filepath: str):
        self.filepath = filepath

    def parse(self) -> dict:
        """
        Parse the Lynis log
        :return:
        """
        logging.debug('start parsing lynis report')
        try:
            with open(self.filepath, 'r') as f:
                content = f.read()
                split = content.split("=" * 80)
                result = split[1].replace("  ", "")
                titles = re.findall("(?P<title>.+)(\s\((?P<count>\d+)\))?:\n----------------------------", result)
                index_table = []
                for title_tuple in titles:
                    t = re.match("(?P<title>.+)\s\((?P<count>\d+)\)", title_tuple[0])
                    if t:
                        title = t.groupdict()["title"]
                        count = t.groupdict()["count"]
                    else:
                        title = title_tuple[0]
                        count = 0
                    index_table.append([result.index(title_tuple[0]), title, count])
                out = {}
                for i in range(len(index_table)):
                    if index_table[i][1] != "Follow-up":
                        out[index_table[i][1]] = {"count": index_table[i][2], "data": []}
                        start = index_table[i][0]
                        if i != len(index_table) - 1:
                            end = index_table[i + 1][0]
                        else:
                            end = len(result)
                        interesting_part = result[start:end].split("-" * 28)[1][1:]
                        delimiter = interesting_part[0]
                        for elem in interesting_part.split(delimiter):
                            if len(elem) > 0:
                                elem = elem.replace("\n\n", "")[1:]
                                part = elem.split("\n")
                                if len(part) == 2:
                                    suggestion, ref = part
                                elif len(part) > 2:
                                    suggestion = " ".join(part[:-1])
                                    ref = part[-1]
                                else:
                                    suggestion = " ".join(part)
                                    ref = ""
                                out[index_table[i][1]]["data"].append({"suggestion": suggestion, "ref": ref})
                return out
        except Exception as e:
            logging.error('error during parsing lynis report :{}'.format(e))
            return {}
