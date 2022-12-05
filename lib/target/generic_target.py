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

import re

from fabric.operations import get


class OSType:
    """ Generic class for operating system"""
    loki_report_path = None

    def __init__(self, outer_instance):
        """
        :param outer_instance: the target instance
        """
        self.outer_instance = outer_instance

    def get_uname(self) -> str:
        """
        Get the name of the operating system
        :return:
        """
        self.log("Get Target name")
        os = self._get_uname()
        self.log("Detected os:{}".format(os))
        return os

    def _get_uname(self) -> str:
        """
        OS specific method to get the name of the operating system
        :return:
        """
        raise NotImplemented()

    def get_hostname(self) -> str:
        """
        Get the target name
        :return:
        """
        self.log("Get Target name")
        name = self._get_hostname()
        self.log("Hostname:{}".format(name))
        return name

    def _get_hostname(self) -> str:
        """
            OS specific method to get the target name
        """
        raise NotImplemented()

    def install_loki(self) -> bool:
        """
            Install loki on the target
        """
        raise NotImplemented()

    def run_loki(self):
        """
            Run loki on the target
        """
        raise NotImplemented()

    def remove_loki(self):
        """
        Remove loki from the target
        :return:
        """
        raise NotImplemented()

    def security_issues_scan(self, output_dir):
        """
        run a security issues scan
        :param output_dir:
        :return:
        """
        raise NotImplemented()

    def get_loki_report(self, local_path):
        """
        Get loki report from target
        :param local_path:
        :return:
        """
        try:
            get(self.loki_report_path, local_path)
            return True
        except:
            return False

    def log(self, message: str, log_type: str = "info") -> None:
        """
        Log the message
        :param message: the message to log
        :param log_type: the log_type of message (error, debug, info, warning,...)
        :return: None
        """
        if self.outer_instance is not None:
            self.outer_instance.log(message, log_type)

    @staticmethod
    def escape_ansi(line: str) -> str:
        """
        Aims to remove ansi symbol
        :param line: the string to sanitize
        :return: the string sanitized
        """
        if isinstance(line,str):
            ansi_escape = re.compile(r'((\x9B|\x1B\[)[0-?]*[ -/]*[@-~])|\x1b]0;\x07')
            return ansi_escape.sub('', line)
        return line

    def sanitize(self, text: str, to_remove=None) -> str:
        """
        Aims to remove unwanted substring into string
        :param to_remove: list all all sub string to remove
        :param text: the initial string
        :return: the string sanitized
        """
        if to_remove is None:
            to_remove = ["\r\n", 'C:\WINDOWS\system32\conhost.exe']
        out = text
        for elem in to_remove:
            out = out.replace(elem, "")
        return self.escape_ansi(out)
