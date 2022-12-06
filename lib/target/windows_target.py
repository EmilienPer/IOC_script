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
from os import listdir

from fabric.operations import run, put

from lib.target.generic_target import OSType


class Windows(OSType):
    """
    Windows operating system manager
    """
    loki_report_path = ""

    def _get_hostname(self) -> str:
        """Get the target name"""
        return self.sanitize(run("hostname"))

    def _get_uname(self) -> str:
        """Get the operating system name"""
        return self.sanitize(run("ver")).split("[")[0]

    def send_directory(self, local_path: str, remote_base: str):
        """
        Aims to send a directory from the host to the target and conserve the tree
        :param local_path: the path of the directory on the host
        :param remote_base: the destination path
        :return:None
        """
        for elem in listdir(local_path):

            l_path = os.path.join(local_path, elem)
            r_path = os.path.join(remote_base, elem).replace("/", "\\")

            if os.path.isfile(l_path):
                put(l_path, r_path)
            else:
                run("md {}".format(r_path))
                self.send_directory(l_path, r_path)
