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

import io
import os
import sys
import tkinter
from tkinter import messagebox
from zipfile import ZipFile

import psutil
import requests

from lib.gui.user_interface import User_interface
from lib.updater.config import Config


def restart_program():
    """Restarts the current program, with file objects and descriptors
       cleanup
    """
    python = sys.executable
    os.execl(python, python, *sys.argv)


class Updater(Config):
    """
        Aims to update this program
    """
    __instance = None
    owner = "EmilienPer"
    repos = "ioc_security_issue_scanner"
    github_api = "https://api.github.com"
    repos_api = github_api + "/repos"
    release_api = "{}/{}/{}/releases".format(repos_api, owner, repos)
    name = "updater"
    already_ask = False
    info = {"id": 0, "created_at": 0, name: "", "tag_name": "", "body": "", "auto_check_update": True, "name": ""}

    def __init__(self,user_interface:User_interface=None,check_update:bool=True):
        super().__init__()
        self.user_interface=user_interface
        self.info = self.json_obj[self.name]
        if self.info["auto_check_update"] and not self.already_ask and check_update:
            self.check_release()

    def __new__(cls,user_interface, *args, **kwargs):
        if cls.__instance is None:
            cls.__instance = super(Updater, cls).__new__(cls, *args, **kwargs)
        return cls.__instance

    def check_release(self, from_script=False):
        """
            Check if a release is available
        :param from_script: True if the check come from a script call
        """
        r = requests.get("{}/latest".format(self.release_api))
        if r.status_code == 200:
            last_release = r.json()
            if "id" in last_release and self.info["id"] != last_release["id"]:
                root = tkinter.Tk()
                root.withdraw()
                if self.user_interface is not None:
                    to_update = self.user_interface.askquestion("Update available!",
                                                       "A new version of this tool is available ({})\n Do you want to "
                                                       "update now?".format(
                                                           last_release["name"]))
                else:
                    to_update=True
                self.already_ask = True
                root.destroy()
                if to_update == "yes":
                    self.update()
            elif from_script and self.user_interface is not None:
                self.user_interface.info("No update needed", "You are up to date!")
        else:
            root = tkinter.Tk()
            root.withdraw()
            if self.user_interface is not None:
                self.user_interface.error("Error", "An error occurred")
            root.destroy()

    def update(self, last_release=None):
        """
        Update the program
        :param last_release:
        :return:
        """
        if last_release is None:
            r = requests.get("{}/latest".format(self.release_api))
            if r.status_code == 200:
                last_release = r.json()

        if last_release is not None and "id" in last_release and self.info["id"] != last_release["id"]:
            for asset in last_release['assets']:
                file_name = asset['browser_download_url'].split("/")[-1]
                tmp_file = os.path.join(os.path.dirname(__file__), "tmp", file_name)
                os.makedirs(tmp_file, exist_ok=True)
                r = requests.get(asset['browser_download_url'])
                # z = zipfile.ZipFile(io.BytesIO(r.content))
                z = ZipFile(io.BytesIO(r.content))
                z.extractall(os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(__file__)))))
            self.info["id"] = last_release["id"]
            self.info["created_at"] = last_release["created_at"]
            self.info["name"] = last_release["name"]
            self.info["tag_name"] = last_release["tag_name"]
            self.info["body"] = last_release["body"]
            self.write_change(self.name, info_key=None, info_value=self.info)
            root = tkinter.Tk()
            root.withdraw()
            if self.user_interface is not None:
                restart = self.user_interface.askquestion("Update done!",
                                             "The update is complete. To apply the changes, please restart the "
                                             "program\nDo you want to restart?")
            else:
                restart=True
            root.destroy()
            if restart == "yes":
                restart_program()
