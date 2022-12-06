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
from datetime import datetime

from fabric.operations import run
from fabric.state import env

from lib.gui.user_interface import User_interface
from lib.parser.loki_parser import LokiParser
from lib.reporter.main import ReportFormat
from lib.target.linux_target import Linux
from lib.target.windows_target import Windows


class Target:
    """
    Generic class for the target
    """
    os = None

    def __init__(self, host: str, user: str, password: str = None, key_file: str = None, port: int = 22,
                 user_interface: User_interface = None, security_issues_scan: bool = True, ioc_scan: bool = True,
                 output_type="TXT",
                 output_path=".", start_scan=True) -> None:
        """
        :param host: the IP address of the target
        :param user: The SSH user on the target
        :param password: the password of the user (use password or key file)
        :param key_file: the SSH key file path (use password or key file)
        :param port: the SSh port (default:22)
        :param user_interface: the user interface object
        :param security_issues_scan: True to start a security issues scan
        :param ioc_scan: True to start a IOC scan
        :param output_path: the path for all output
        :param output_type: the log_type of the main report (TXT,JSON,CSV,PDF,XML)
        """
        # instance variable definition
        self.host = host
        self.user = user
        self.password = password
        self.key_file = key_file
        self.port = port
        self.user_interface = user_interface
        self.output_type = output_type
        self.output_path = output_path
        env.port = port
        env.user = user
        env.port = port
        env.host_string = host
        if self.password is not None:
            env.password = password
        if self.key_file is not None:
            env.key_filename = self.key_file
        # Create output tmp directory
        self.output_tmp_path = os.path.join(self.output_path, "tmp")
        os.makedirs(self.output_tmp_path, exist_ok=True)
        if start_scan:
            self.start_scans(ioc_scan, security_issues_scan)

    def start_scans(self, ioc_scan: bool, security_issues_scan: bool) -> None:
        """
        This function is used to start the scans (IOC and vulnerability)
        :param ioc_scan: True to start a IOC scan
        :param security_issues_scan: True to start a vulnerability scan
        :return: None
        """
        # Check possibility to connect via SSH
        report = {"scan_info": {"start": datetime.now(), "target": self.host, "user": self.user}}
        if self.host is not None and self.user is not None:
            if self.password is None and self.key_file is None:
                self.log("No password/key file found", log_type="error")
            # Choice between Linux and Windows
            found_os = self.get_os()
            if found_os == "linux":
                env.use_shell = False
                self.os = Linux(outer_instance=self)
            elif found_os == "windows":
                env.shell = "cmd /c"
                self.os = Windows(self)

            if self.os is not None:
                # Add info about the target into the GUI
                report["scan_info"]["os"] = self.os.get_uname()
                report["scan_info"]["hostname"] = self.os.get_hostname()
                report["scan_info"]["ioc"] = False
                report["scan_info"]["security_issues"] = False
                self.user_interface.set_os_detected(report["scan_info"]["os"])
                self.user_interface.set_host_name(report["scan_info"]["hostname"])
                if found_os == "windows":
                    self.user_interface.error("Coming soon",
                                              "Unfortunately, we are not yet able to scan a Windows system."
                                              " Sorry for the disturb")
                    return
                if security_issues_scan:
                    self.run_security_issues_scan(report)
                # Start IOC scan
                if ioc_scan:
                    self.run_ioc_scan(report)
                report["scan_info"]["end"] = datetime.now()
                ReportFormat(report).generate_report(self.output_type, self.output_path)
                self.user_interface.info("Done!", "Scan completed successfully!")
        else:
            self.log("No host/username found", log_type="error")

    def run_security_issues_scan(self, report: dict) -> None:
        """
                Run Security issues scan
                :param report:  the report
                :return:
                """
        self.log("------- Start Security Issues Scan --------", log_type="info")
        report["scan_info"]["security_issues"] = True
        report["security_issues"] = self.os.security_issues_scan(self.output_tmp_path)

    def run_ioc_scan(self, report: dict) -> None:
        """
        Run Loki IOC scan
        :param report:  the report
        :return:
        """
        self.log("------- Start IOC Scan --------", log_type="info")
        report["scan_info"]["ioc"] = True
        if self.os.install_loki():
            self.os.run_loki()
            if self.os.get_loki_report(self.output_tmp_path):
                self.os.remove_loki()
            else:
                self.log("Unable to get loki report", log_type="error")
            report["loki"] = LokiParser(os.path.join(self.output_tmp_path, "loki.log")).parse()

    def log(self, message: str, log_type: str) -> None:
        """
        Log message into the GUI or into the console
        :param message: the message to log
        :param log_type: the log_type of message (error, debug, info, warning, ...)
        :return: None
        """

        if self.user_interface is not None:
            self.user_interface.log(message, log_type)
        else:
            now = datetime.now()
            print("[{}] {} {}".format(now.strftime("%m/%d/%Y, %H:%M:%S"), log_type, message))

    def get_os(self) -> str:
        """
        Check the operating system log_type
        :return: linux or windows string
        """
        x = run("uname")
        if "linux" in x.lower():
            return "linux"
        else:
            env.shell = "cmd /c"
            x = run("ver")
            if "windows" in x.lower():
                return "windows"
            else:
                self.log("Target not detected", log_type="error")
