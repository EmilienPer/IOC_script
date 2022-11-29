"""
IOC Security Issues Scanner Project
Author: Emilien Peretti (https://github.com/EmilienPer)
License: GNU GENERAL PUBLIC LICENSE (Version 3)
"""
__author__ = "Emilien Peretti"
__license__ = "GPL"

import logging
import os

from lib.reporter.json_report import to_json
from lib.reporter.pdf_report import to_pdf


class ReportFormat:
    """
    Format the report of this tool
    """

    def __init__(self, report: dict):
        self.report_dict = report
        self.compute_extra_info()

    def compute_extra_info(self):
        """
            this function aims to compute extra useful information of the report
        """
        try:
            if "loki" in self.report_dict:
                count = 0
                for key in self.report_dict["loki"]:
                    count += len(self.report_dict["loki"][key])
                self.report_dict["scan_info"]["detected_ioc"] = count
            if "vulnerabilities" in self.report_dict:
                count = 0
                for key in self.report_dict["vulnerabilities"]:
                    count += int(self.report_dict["vulnerabilities"][key]["count"])
                self.report_dict["scan_info"]["detected_vulnerabilities"] = count
        except Exception as e:
            logging.error('error during compute extra data of the report : {}'.format(e))

    def generate_report(self, report_type: str, output_dir: str) -> bool:
        """
        Generate a report and save it into the output directory
        :param report_type: JSON or PDF
        :param output_dir: the path to the directory
        :return:
        """
        available_type = {
            "JSON": [to_json, "json"],
            "PDF": [to_pdf, "pdf"]
        }
        if report_type in available_type:
            file_path = os.path.join(output_dir, "report.{}".format(available_type[report_type][1]))
            return available_type[report_type][0](file_path, self.report_dict)
        logging.error('report output log_type unknown : {}'.format(report_type))
        return False
