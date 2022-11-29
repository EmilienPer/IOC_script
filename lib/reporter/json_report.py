"""
IOC Security Issues Scanner Project
Author: Emilien Peretti (https://github.com/EmilienPer)
License: GNU GENERAL PUBLIC LICENSE (Version 3)
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
