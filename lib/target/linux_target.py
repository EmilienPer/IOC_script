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

import logging
import os
from os import listdir

from fabric.context_managers import cd
from fabric.operations import run, get, put, sudo

from lib.parser.lynis_parser import LynisParser
from lib.target.generic_target import OSType
from lib.tools_utils.Loki import Loki
from lib.tools_utils.Lynis import Lynis


class Linux(OSType):
    """
    Linux OS manager
    """
    base_lynis = "/tmp/lynis"
    lynis_report_path = "{}/lynis.log".format(base_lynis)

    def __init__(self, outer_instance: object):
        super().__init__(outer_instance)
        self.base_loki = Loki().get(["linux", "workspace"], "/tmp/loki")
        self.loki_report_path = "{}/loki.log".format(self.base_loki)
        self.loki = Loki()
        self.lynis = Lynis()
        print(self.base_loki, self.loki_report_path)

    def _get_uname(self) -> str:
        """Get the operating system name"""
        try:
            return run("uname")
        except Exception as e:
            self.log("Unable to get uname", "error")
            logging.error('error during get uname : {}'.format(e))

    def _get_hostname(self) -> str:
        """Get the target name"""
        try:
            return run("hostname")
        except Exception as e:
            self.log("Unable to get hostname", "error")
            logging.debug('error during get hostname: {}'.format(e))

    def send_directory(self, local_path: str, remote_base: str) -> None:
        """
        Aims to send a directory from the host to the target and conserve the tree
        :param local_path: the path of the directory on the host
        :param remote_base: the destination path
        :return:None
        """
        if os.path.isdir(local_path):
            run("{} {} || echo ko".format("mkdir -p", remote_base))
        try:
            ok = True
            for elem in listdir(local_path):
                l_path = os.path.join(os.path.dirname(__file__), local_path, elem)
                r_path = os.path.join(remote_base, elem).replace("\\", "/")

                if os.path.isfile(l_path):
                    put(l_path, r_path)
                else:
                    run("{} {}".format("mkdir -p", r_path))
                    if not self.send_directory(l_path, r_path):
                        ok = False
            logging.debug("{} send to {} on remote".format(local_path, remote_base))
            return ok
        except Exception as e:
            self.log("Unable to send {} on target".format(local_path), "error")
            logging.error('error during send {} to {} : {}'.format(local_path, remote_base, e))
            return False

    def vulnerability_scan(self, output_dir: str):
        """
        run a security issues scan
        :param output_dir: the output directory for the report on the target
        :return:
        """
        self.install_lynis()
        self.run_lynis()
        get(self.lynis_report_path, output_dir)
        self.remove_lynis()
        with open(os.path.join(output_dir, "lynis.log"), "r") as f_in:
            with open(os.path.join(output_dir, "lynis_san.log"), "w") as f_out:
                f_out.write(self.sanitize(f_in.read()))
        return LynisParser(os.path.join(output_dir, "lynis_san.log")).parse()

    def install_lynis(self) -> None:
        """
        Send the lynis directory on the target
        :return: None
        """
        self.send_directory(self.lynis.path, self.base_lynis)

    def remove_lynis(self):
        """
            Remove lynis on the target
        """
        sudo('rm -R -f {}'.format(self.base_lynis))

    def run_lynis(self):
        """
                    Run lynis on the target

                    """
        try:
            sudo("chmod +x {}/lynis".format(self.base_lynis))
            self.log("Start Lynis analysis")
            run("export LANG=en;export LANGUAGE=en")
            x = sudo("{}/lynis audit system  --no-colors | tee {}".format(self.base_lynis, self.lynis_report_path))
            if "Fatal error: can't find include directory" in x:
                with cd(self.base_lynis):
                    x = run("{}/lynis audit system  --no-colors | tee {}".format(self.base_lynis,
                                                                                 self.lynis_report_path))
            self.log("End Lynis analysis")
            return x
        except:
            self.log("Unable to run Loki")
            return False

    def install_loki(self) -> bool:
        """
        Send loki on the target (in /tmp directory)
        :return: True if installation is completed
        """
        self.log("Install loki on the target")
        if self.send_directory(self.loki.path, self.base_loki):

            self.log("Install pip requirements")
            try:
                x = sudo("pip3 install -r {}/requirements.txt || pip install -r {}/requirements.txt".format(
                    self.base_loki, self.base_loki))
                self.log(x, "debug")
                return True
            except:
                self.log("Unable to install install requirements for pip", "error")
                return False
            self.log("Installation complete")
        else:
            self.log("Unable to install loki", "error")
            return False

    def remove_loki(self):
        """
        Remove the loki directory on the target (from /tmp directory)
        :return:
        """
        sudo('rm -R -f {}'.format(self.base_loki))

    def run_loki(self):
        """
        Run loki on the target and get the report
        :return: the report
        """
        try:
            self.log("Start Loki analysis")
            x = sudo("python3 {}/loki.py --vulnchecks "
                     "--intense --csv --onlyrelevant -l {}".format(self.base_loki, self.loki_report_path))
            self.log("End Loki analysis")
            return x
        except:
            self.log("Unable to run Loki")
            return False
