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
import logging


def to_json(output_path: str, report_dict: dict) -> bool:
    """
    save the json into a file
    :param output_path: the path file
    :param report_dict: the json to save
    :return: True if no error
    """
    try:
        with open(output_path, "w") as f:
            json.dump(report_dict, f, indent=4, sort_keys=True, default=str)
        return True
    except Exception as e:
        logging.error('error during saving json report : {}'.format(e))
        return False
