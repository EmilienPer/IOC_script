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

import os

from lib.tools_utils.Tool import Tool, TOOL_PATH


class Loki(Tool):
    """
    Represent the tool in the config
    """
    name = "loki"
    default_config = {"windows": {
        "workspace": "loki"
    },
        "linux": {
            "workspace": "/tmp/loki"
        }
    }
    path = os.path.join(TOOL_PATH, "loki")

    def get_yara_files_list(self):
        """
        List all yara file used by Loki
        :return:
        """
        yara_path = os.path.join(self.path, "signature-base", "yara")
        return [path for path in os.listdir(yara_path) if
                os.path.isfile(os.path.join(yara_path, path)) and (path.endswith(".yar") or path.endswith(".yara"))]


if __name__ == "__main__":
    print(Loki().get_yara_files_list())
