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
__version__ = "Alfa-0.1.1"

import argparse
import logging
import sys

from lib.gui.command_line import CommandLine
from lib.gui.main_windows import GUI
from lib.target.main import Target
from lib.updater.loki import LOKIUpdater, LogAdaptator
from lib.updater.project import Updater

logging.basicConfig(
    format='%(asctime)s,%(msecs)d %(levelname)-8s [%(pathname)s:%(lineno)d in function %(funcName)s] %(message)s',
    datefmt='%Y-%m-%d:%H:%M:%S',
    level=logging.ERROR
)
logger = logging.getLogger(__name__)
if sys.version_info[0] < 3:
    raise Exception("Python 3 or a more recent version is required.")
if len(sys.argv) == 1:
    GUI()
else:
    parser = argparse.ArgumentParser(
        description='This program aims to detect Indicator of compromise (IOC) and security issues. Main page : '
                    'https://github.com/EmilienPer/ioc_security_issue_scanner',
    )
    user_interface = CommandLine()
    group = parser.add_mutually_exclusive_group()
    group.add_argument('--update', choices=["all", "program", "loki", "sign"],
                       help="Use this option to update an element of this program")
    group.add_argument('--scan', metavar='TARGET', help="The target IP address")
    parser.add_argument("-u", "--user", required="--scan" in sys.argv, help="The Target's SSH username")
    group_secret = parser.add_mutually_exclusive_group(required="--scan" in sys.argv)
    group_secret.add_argument("-k", "--key_file", help="Path to the private key for SSH authentication")
    group_secret.add_argument("-p", "--password", help="Password for SSH authentication")
    parser.add_argument("--port", help="The Target's SSH port", default=22, type=int)
    parser.add_argument("-t", "--type", required="--scan" in sys.argv, help="The report type", choices=["PDF", "JSON"])
    parser.add_argument("-P", "--path", required="--scan" in sys.argv, help="The report output directory")
    parser.add_argument('--noioc', action='store_false', help='Do not scan for IOC', default=True)
    parser.add_argument('--noissue', action='store_false', help='Do not scan for Security issues', default=True)
    args = parser.parse_args()
    if args.update is not None:
        update_program = False
        update_loki = False
        update_loki_signature = False
        if args.update == "all":
            update_program = True
            update_loki = True
            update_loki_signature = True
        elif args.update == "program":
            update_program = True
        elif args.update == "loki":
            update_loki = True
        elif args.update == "sign":
            update_loki_signature = True
        if update_program:
            updater = Updater(user_interface=user_interface)
            updater.update()
        if update_loki:
            updater = LOKIUpdater(LogAdaptator(user_interface))
            r = updater.update_loki()
        if update_loki_signature:
            updater = LOKIUpdater(LogAdaptator(user_interface))
            r = updater.update_signatures()
    elif args.scan is not None:
        Target(host=args.scan,
               user=args.user,
               password=args.password,
               key_file=args.key_file,
               port=args.port,
               user_interface=user_interface,
               security_issues_scan=args.noissue,
               ioc_scan=args.noioc,
               output_type=args.type,
               output_path=args.path
               )
