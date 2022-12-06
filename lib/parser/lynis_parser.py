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


def get_suggestion_and_ref_from_lines(elem: str) -> (str, str):
    """
    Extract suggestion and reference part from string
    :param elem: the string to parse
    :return: the suggestion and the ref
    """
    if isinstance(elem, str) and len(elem) > 0:
        elem = elem.replace("\n\n", "")
        part = elem.split("\n")
        if len(part) == 2:
            suggestion, ref = part
        elif len(part) > 2:
            suggestion = " ".join(part[:-1])
            ref = part[-1]
        else:
            suggestion = " ".join(part)
            ref = ""
        return suggestion, ref
    return None, None


def get_part_title(content_to_parse, title_and_count_tuple_list):
    """
    Get a list of each title of part
    :param content_to_parse: the file content
    :param title_and_count_tuple_list: a list of tuple (title,count) to find
    :return: a list of title [index_of_title_in_result,title,number_of_elem_in_part]
    """
    index_table = []
    if isinstance(title_and_count_tuple_list, list) and isinstance(content_to_parse, str):
        for title_tuple in title_and_count_tuple_list:
            if len(title_tuple) == 2 and isinstance(title_tuple[0], str):
                t = re.match("\s+(?P<title>.+)\s\((?P<count>\d+)\)", title_tuple[0])
                if t:
                    title = t.groupdict()["title"]
                    count = t.groupdict()["count"]
                else:
                    title = title_tuple[0]
                    count = title_tuple[1]
                try:
                    index_table.append([content_to_parse.index(title_tuple[0]), title, count])
                except:
                    pass
    return index_table


def get_title_and_count(file_suggestion_part):
    """
    Extract all title and count from lynis suggestion part
    :param file_suggestion_part: the lynis suggestion part
    :return:
    """
    if isinstance(file_suggestion_part, str):
        titles_count = re.findall("(?P<title>.+)\s\((?P<count>\d+)\):\n----------------------------",
                                  file_suggestion_part)
        return titles_count
    else:
        return []


def get_suggestion_part(file_content):
    """
    Extrat the suggestion part from lynis report
    :param file_content:
    :return:
    """
    if isinstance(file_content, str):
        split = file_content.split("=" * 80)
        if len(split) >= 2:
            return split[1].replace("  ", "")
        else:
            return None


class LynisParser:
    """
        Parser for Lynis report
        """

    def __init__(self, filepath_or_content: str, is_file_path:bool=True):
        self.filepath = filepath_or_content
        if is_file_path:
            try:
                with open(self.filepath, 'r') as f:
                    self.content = f.read()
            except:
                self.content = ""
        else:
            self.content = filepath_or_content

    def parse(self) -> dict:
        """
        Parse the Lynis log
        :return:
        """
        logging.debug('start parsing lynis report')
        try:

            file_suggestion_part = get_suggestion_part(self.content)
            tuple_title_and_count_list = get_title_and_count(file_suggestion_part)
            index_table = get_part_title(file_suggestion_part, tuple_title_and_count_list)
            out = {}
            for i in range(len(index_table)):
                if index_table[i][1] != "Follow-up":
                    out[index_table[i][1]] = {"count": index_table[i][2], "data": []}
                    start = index_table[i][0]
                    if i != len(index_table) - 1:
                        end = index_table[i + 1][0]
                    else:
                        end = len(file_suggestion_part)
                    interesting_part = file_suggestion_part[start:end].split("-" * 28)[1][1:]
                    delimiter = interesting_part[0]
                    for elem in interesting_part.split(delimiter):
                        suggestion, ref = get_suggestion_and_ref_from_lines(elem[1:])
                        if suggestion is not None:
                            out[index_table[i][1]]["data"].append({"suggestion": suggestion, "ref": ref})
            return out
        except Exception as e:
            logging.error('error during parsing lynis report :{}'.format(e))
            return {}
