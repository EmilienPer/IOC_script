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

import json

from lib.tools_utils.Tool import TOOL_CONFIG_PATH


class Config:
    """
    Manage config
    """
    info = {}
    name = ""

    def __init__(self):
        try:
            with open(TOOL_CONFIG_PATH, "r") as f_in:
                self.json_obj = json.load(f_in)
        except:
            self.json_obj = {}
        with open(TOOL_CONFIG_PATH, "w") as f_out:
            if self.name not in self.json_obj:
                self.json_obj[self.name] = self.info
            json.dump(self.json_obj, f_out, indent=4, sort_keys=True, default=str)

    @staticmethod
    def write_change(tool_name, info_key, info_value):
        """
        Write change into config
        :param tool_name: the name of the tool
        :param info_key: the key of the config
        :param info_value: the value
        :return:
        """
        try:
            with open(TOOL_CONFIG_PATH, "r") as f_in:
                json_obj = json.load(f_in)
        except Exception as e:
            json_obj = {}
        with open(TOOL_CONFIG_PATH, "w") as f_out:
            if tool_name not in json_obj:
                json_obj[tool_name] = {}
            if info_key is not None:
                json_obj[tool_name][info_key] = info_value
            else:
                json_obj[tool_name] = info_value
            json.dump(json_obj, f_out, indent=4, sort_keys=True, default=str)
