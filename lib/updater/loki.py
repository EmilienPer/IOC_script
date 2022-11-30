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
import json
import os
import shutil
import sys
import traceback
import zipfile
from datetime import datetime
from urllib.request import urlopen

from lib.tools_utils.Loki import Loki
from lib.updater.config import Config


class LogAdaptator:
    """
    Tiny class to have a generic logger
    """

    def __init__(self, logger):
        self.logger = logger

    def log(self, log_type: str, _, message: str) -> None:
        """
        Log all message
        :param log_type:
        :param _:
        :param message:
        :return:
        """
        self.logger.log(message, log_type.lower())


class LOKIUpdater(Config):
    """
    This class manage the update of Loki and the update of the signature of IOC
    """
    # Incompatible signatures
    INCOMPATIBLE_RULES = []
    # URL of signatures
    UPDATE_URL_SIGS = [
        "https://github.com/Neo23x0/signature-base/archive/master.zip",
        "https://github.com/reversinglabs/reversinglabs-yara-rules/archive/develop.zip"
    ]
    # URL of LOKI on github
    UPDATE_URL_LOKI = "https://api.github.com/repos/Neo23x0/Loki/releases/latest"

    def __init__(self, logger):
        class ConsoleLogger:
            """ This subclass aims to harmonize the ConsoleLogger display"""

            @staticmethod
            def log(log_type: str, from_where: str, message: str) -> None:
                """
                Display logs in console
                :param log_type: Type of ConsoleLogger (error, warning, debug, info, ...)
                :param from_where: The sender of the ConsoleLogger
                :param message: the message to display
                :return:
                """
                print("[{}]{} {}".format(log_type, from_where, message))

        super().__init__()
        self.debug = True
        self.application_path = Loki().path
        if logger:
            self.logger = logger
        else:
            self.logger = ConsoleLogger()

    def update_signatures(self, clean: bool = False) -> bool:
        """
        Update the signatures of the IOCs
        :param clean: true to clean directories after download
        :return: True if the update is completed
        """
        try:
            for sig_url in self.UPDATE_URL_SIGS:
                # Downloading current repository
                try:
                    self.logger.log("INFO", "Upgrader", "Downloading %s ..." % sig_url)
                    response = urlopen(sig_url)
                except:
                    if self.debug:
                        traceback.print_exc()
                    self.logger.log("ERROR", "Upgrader", "Error downloading the signature database - "
                                                         "check your Internet connection")
                    sys.exit(1)

                # Preparations
                try:
                    sig_dir = os.path.join(self.application_path, 'signature-base')
                    if clean:
                        self.logger.log("INFO", "Upgrader", "Cleaning directory '%s'" % sig_dir)
                        shutil.rmtree(sig_dir)
                    for outDir in ['', 'iocs', 'yara', 'misc']:
                        full_out_dir = os.path.join(sig_dir, outDir)
                        if not os.path.exists(full_out_dir):
                            os.makedirs(full_out_dir)
                except:
                    if self.debug:
                        traceback.print_exc()
                    self.logger.log("ERROR", "Upgrader", "Error while creating the signature-base directories")
                    sys.exit(1)

                # Read ZIP file
                try:
                    zip_update = zipfile.ZipFile(io.BytesIO(response.read()))
                    for zipFilePath in zip_update.namelist():
                        sig_name = os.path.basename(zipFilePath)
                        if zipFilePath.endswith("/"):
                            continue
                        # Skip incompatible rules
                        skip = False
                        for incompatible_rule in self.INCOMPATIBLE_RULES:
                            if sig_name.endswith(incompatible_rule):
                                self.logger.log("NOTICE", "Upgrader", "Skipping incompatible rule %s" % sig_name)
                                skip = True
                        if skip:
                            continue
                        # Extract the rules
                        self.logger.log("DEBUG", "Upgrader", "Extracting %s ..." % zipFilePath)
                        if "/iocs/" in zipFilePath and zipFilePath.endswith(".txt"):
                            target_file = os.path.join(sig_dir, "iocs", sig_name)
                        elif "/yara/" in zipFilePath and zipFilePath.endswith(".yar"):
                            target_file = os.path.join(sig_dir, "yara", sig_name)
                        elif "/misc/" in zipFilePath and zipFilePath.endswith(".txt"):
                            target_file = os.path.join(sig_dir, "misc", sig_name)
                        elif zipFilePath.endswith(".yara"):
                            target_file = os.path.join(sig_dir, "yara", sig_name)
                        else:
                            continue

                        # New file
                        if not os.path.exists(target_file):
                            self.logger.log("INFO", "Upgrader", "New signature file: %s" % sig_name)

                        # Extract file
                        source = zip_update.open(zipFilePath)
                        target = open(target_file, "wb")
                        with source, target:
                            shutil.copyfileobj(source, target)
                        target.close()
                        source.close()

                except:
                    if self.debug:
                        traceback.print_exc()
                    self.logger.log("ERROR", "Upgrader", "Error while extracting the signature files from the download "
                                                         "package")
                    sys.exit(1)

        except:
            if self.debug:
                traceback.print_exc()
            return False
        self.write_change("loki", "signatures", datetime.now())
        return True

    def update_loki(self, force_yara_version=True) -> bool:
        """
        Update loki from github
        :return: True if the update is completed
        """
        try:

            # Downloading the info for latest release
            try:
                self.logger.log("INFO", "Upgrader", "Checking location of latest release %s ..." % self.UPDATE_URL_LOKI)
                response_info = urlopen(self.UPDATE_URL_LOKI)
                data = json.load(response_info)
                # Get download URL
                zip_url = data['assets'][0]['browser_download_url']
                self.logger.log("INFO", "Upgrader", "Downloading latest release %s ..." % zip_url)
                response_zip = urlopen(zip_url)
            except:
                if self.debug:
                    traceback.print_exc()
                self.logger.log("ERROR", "Upgrader",
                                "Error downloading the loki update - check your Internet connection")
                sys.exit(1)

            # Read ZIP file
            try:
                zip_update = zipfile.ZipFile(io.BytesIO(response_zip.read()))
                for zipFilePath in zip_update.namelist():
                    if zipFilePath.endswith("/") or "/config/" in zipFilePath or "/loki-upgrader.exe" in zipFilePath:
                        continue

                    source = zip_update.open(zipFilePath)
                    target_file = os.path.join(self.application_path, *zipFilePath.split("/")[1:])

                    self.logger.log("INFO", "Upgrader", "Extracting %s ..." % target_file)

                    try:
                        # Create file if not present
                        if not os.path.exists(os.path.dirname(target_file)):
                            if os.path.dirname(target_file) != '':
                                os.makedirs(os.path.dirname(target_file))
                    except:
                        if self.debug:
                            self.logger.log("DEBUG", "Upgrader",
                                            "Cannot create dir name '%s'" % os.path.dirname(target_file))
                            traceback.print_exc()

                    try:
                        # Create target file
                        target = open(target_file, "wb")
                        with source, target:
                            shutil.copyfileobj(source, target)
                            if self.debug:
                                self.logger.log("DEBUG", "Upgrader", "Successfully extracted '%s'" % target_file)
                        target.close()
                    except:
                        self.logger.log("ERROR", "Upgrader", "Cannot extract '%s'" % target_file)
                        if self.debug:
                            traceback.print_exc()

            except:
                if self.debug:
                    traceback.print_exc()
                self.logger.log("ERROR", "Upgrader",
                                "Error while extracting the signature files from the download package")
                sys.exit(1)

        except:
            if self.debug:
                traceback.print_exc()
            return False
        req_path = os.path.join(self.application_path, "requirements.txt")

        if force_yara_version and os.path.exists(req_path):
            file = open(req_path, "r")
            replaced_content = ""
            # looping through the file
            for line in file:
                # stripping line break
                line = line.strip()
                # replacing the texts
                if line == "yara-python":
                    new_line = line.replace("yara-python", "yara-python==4.1.0")
                else:
                    new_line = line
                # concatenate the new string and add an end-line break
                replaced_content = replaced_content + new_line + "\n"

            # close the file
            file.close()
            # Open file in write mode
            write_file = open(req_path, "w")
            # overwriting the old file contents with the new/replaced content
            write_file.write(replaced_content)
            # close the file
            write_file.close()
        self.write_change("loki", "update", datetime.now())
        return True
