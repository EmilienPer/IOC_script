"""
IOC Security Issues Scanner Project
Author: Emilien Peretti (https://github.com/EmilienPer)
License: GNU GENERAL PUBLIC LICENSE (Version 3)
"""
__author__ = "Emilien Peretti"
__license__ = "GPL"

import os

from lib.tools_utils.Tool import Tool, TOOL_PATH


class Lynis(Tool):
    """
    Represent Lynis in the config
    """
    name = "lynis"
    default_config = {
        "linux": {
            "workspace": "/tmp/lynis"
        }
    }
    path = os.path.join(TOOL_PATH, "lynis")
