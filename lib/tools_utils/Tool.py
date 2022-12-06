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
import os

TOOL_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "resources", "tools")
TOOL_CONFIG_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "config")


def get_json():
    """
    Return config as json object
    :return:
    """
    try:
        with open(TOOL_CONFIG_PATH, "r") as f:
            return json.load(f)
    except:
        return {}


class Tool:
    """
        Aims to add tool into config
    """
    name = ""
    default_config = {}

    def __init__(self, name=None, default_config=None):
        if name is not None:
            self.name = name
        if default_config is not None:
            self.default_config = default_config
        json_obj = get_json()
        if self.name not in json_obj:
            if self.name is not None and len(self.name) != 0:
                json_obj[self.name] = self.default_config
            with open(TOOL_CONFIG_PATH, "w") as f:
                json.dump(json_obj, f)

    def get(self, key, default=None):
        """
        Get config from key
        :param key: the key to search
        :param default: the default value
        :return:
        """
        try:
            with open(TOOL_CONFIG_PATH, "r") as f:
                json_obj = json.load(f)
                if isinstance(key, str):
                    return json_obj[self.name][key]
                else:
                    d = json_obj[self.name]
                    for k in key:
                        d = d[k]
                    return d
        except:
            return default

    def set(self, key, value):
        """
        Set a value in config
        :param key: the key (list or str)
        :param value: the value
        :return:
        """
        json_obj = get_json()
        if isinstance(key, str):
            json_obj[self.name][key] = value
        else:
            current = json_obj[self.name]
            for i in range(len(key)):
                k = key[i]
                if k not in current and i != len(key) - 1:
                    current[k] = {}
                else:
                    if i == len(key) - 1:
                        current[k] = value
                current = current[k]
        with open(TOOL_CONFIG_PATH, "w") as f:
            json.dump(json_obj, f)
