"""
IOC Security Issues Scanner Project
Author: Emilien Peretti (https://github.com/EmilienPer)
License: GNU GENERAL PUBLIC LICENSE (Version 3)
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
