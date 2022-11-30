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

from datetime import datetime
from tkinter import messagebox

from lib.gui.user_interface import User_interface


class CommandLine(User_interface):
    """
    Command line interface
    """

    def info(self, _, message: str) -> None:
        """
        Show info
        :param _: title
        :param message: the message
        :return:
        """
        self.log(message, "info")

    def error(self, _, message: str) -> None:
        """
        Show error
        :param _: title
        :param message: the message
        :return:
        """
        self.log(message, "error")

    @staticmethod
    def askquestion(title, message):
        """
        Ask yes or no for a question
                :param title: the title
                :param message: the message
                :return:
        """
        return messagebox.askquestion(title, message)

    def log(self, message, log_type):
        """
                print log
                :param message: the message
                :param log_type: the log_type of log (info, error, warning, debug,...)
                :return:
                """
        now = datetime.now()
        print("[{}] {} {}".format(now.strftime("%m/%d/%Y, %H:%M:%S"), log_type.upper(), message))

    def set_host_name(self, name: str) -> None:
        """
        Set the OS name
        :param name:
        :return:
        """
        self.info(None, "========> Host Name: {}".format(name))

    def set_os_detected(self, name: str) -> None:
        """
        Set the value of the target name
        :param name: the name of the target
        :return:
        """
        self.info(None, "========> Detected OS:{}".format(name))
