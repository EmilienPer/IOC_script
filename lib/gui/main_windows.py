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

import _thread
import json
import logging
import tkinter
from datetime import datetime
from functools import partial
from json import JSONDecodeError
from tkinter import messagebox, ttk
from tkinter.scrolledtext import ScrolledText
from tkinter.simpledialog import askstring
from typing import Union

import _tkinter

from lib.gui.user_interface import User_interface
from lib.target.main import Target
from lib.tools_utils.Loki import Loki
from lib.tools_utils.Lynis import Lynis
from lib.tools_utils.Tool import TOOL_CONFIG_PATH
from lib.updater.loki import LOKIUpdater, LogAdaptator
from lib.updater.project import Updater


class GUI(User_interface):
    """
    The Tkinter windows of the application
    """

    log_view = None
    output_type_field = None
    output_path_field = None
    user_field = None
    host_field = None
    port_field = None
    password_field = None
    key_file_field = None
    IOC_scan = None
    security_issues_scan = None
    os_name_input = None
    os_detected_input = None

    def __init__(self) -> None:
        # Define the windows
        logging.debug('GUI initialisation')
        updater = Updater(self)
        self.windows = tkinter.Tk()

        self.windows.title("IOC Security Issue Scanner (Version:{})".format(updater.info["name"]))
        self.windows.resizable(False, False)
        try:
            self.windows.iconbitmap("logo.ico")
        except _tkinter.TclError:
            logging.debug('Logo not set')
        self.target_information_group()

        self.output_group()
        # Button
        self.button_group()
        self.log_group()
        self.create_menu_bar()
        logging.debug('GUI is ready')
        self.windows.mainloop()

    def create_menu_bar(self):
        """
        Create the menu bar of the tool
        :return:
        """
        menu_bar = tkinter.Menu(self.windows)
        menu_tools = tkinter.Menu(menu_bar, tearoff=0)
        menu_loki = tkinter.Menu(menu_tools, tearoff=0)
        menu_bar.add_cascade(label="Tools", menu=menu_tools)
        menu_tools.add_cascade(label="Loki", menu=menu_loki)
        menu_loki.add_command(label="Update Loki", accelerator="CTRL+L", command=self.update_loki)
        menu_loki.add_command(label="Update IOC signature", accelerator="CTRL+U", command=self.update_loki_signature)
        # menu_loki.add_command(label="Yara rules", accelerator="CTRL+Y", command=self.not_yet_implemented)
        menu_loki_workspace = tkinter.Menu(menu_loki, tearoff=0)
        menu_loki.add_cascade(label="Set Workspace", menu=menu_loki_workspace)
        menu_loki_workspace.add_command(label="Linux", command=partial(self.set_loki_workspace, "linux"))
        menu_loki_workspace.add_command(label="Windows", command=partial(self.set_loki_workspace, "windows"))
        menu_loki.add_command(label="About...", command=self.get_loki_info)
        menu_lynis = tkinter.Menu(menu_tools, tearoff=0)
        menu_tools.add_cascade(label="Lynis (Linux only)", menu=menu_lynis)
        menu_lynis.add_command(label="Set workspace", command=self.set_lynis_workspace)
        # menu_lynis.add_command(label="About...", command=self.get_lynis_info)
        self.windows.bind_all("<Control-l>", lambda x: self.update_loki())
        self.windows.bind_all("<Control-u>", lambda x: self.update_loki_signature())
        self.windows.bind_all("<Control-y>", lambda x: self.about())
        menu_help = tkinter.Menu(menu_bar, tearoff=0)
        menu_bar.add_cascade(label="Help", menu=menu_help)
        menu_help.add_command(label="About", command=self.about)
        menu_help.add_command(label="Check update", command=self.update)
        self.windows.config(menu=menu_bar)

    @staticmethod
    def info(title: str, message: str) -> None:
        """
        Show info in popup
        :param title: the title of the pop up
        :param message: the message
        :return: 
        """
        messagebox.showinfo(title, message)

    @staticmethod
    def error(title: str, message: str) -> None:
        """
        Show error in popup
        :param title: the title of the pop up
        :param message: the message
        :return: 
        """
        messagebox.showerror(title, message)

    @staticmethod
    def askquestion(title, message):
        """
        Ask yes or no for a question
                :param title: the title of the pop up
                :param message: the message
                :return:
        """
        return messagebox.askquestion(title, message)

    def not_yet_implemented(self) -> None:
        """
            This method show a messagebox to warm the user the functionality is not yet implemented
        """
        logging.debug('GUI not yet implemented call')
        self.error("Coming Soon", "We are sorry. This function is not yet implemented !")

    def about(self) -> None:
        """
            This method shows a messagebox with information about this tool
        """
        logging.debug('GUI about call')
        updater = Updater()
        self.info("IOC Security Issue Scanner",
                  "Current version: {}\nThis program aims to detect indicator of compromise (IOC)"
                  " and potential security issues.\n"
                  "To work, the tool uses Lynis (https://cisofy.com/lynis/) for security issues and Loki "
                  "IOC scanner (https://github.com/Neo23x0/Loki). ".format(
                      updater.info["name"]))

    @staticmethod
    def update() -> None:
        """
            This method is used to check if a new version of this tool can be downloaded
        """
        logging.debug('GUI update call')
        updater = Updater()
        updater.check_release(from_script=True)

    def log_group(self) -> None:
        """
        Define the log space into the windows
        """
        self.log_view = ScrolledText(self.windows, width=45, height=13)
        self.log_view.grid(column=0, row=3, columnspan=3, pady=20)
        self.log_view.tag_config('debug', foreground="grey")
        self.log_view.tag_config('notice', foreground="grey")
        self.log_view.tag_config('info', foreground="blue")
        self.log_view.tag_config('warning', foreground="orange")
        self.log_view.tag_config('error', foreground="red")

    def button_group(self) -> None:
        """
        Define the button
        :return:
        """
        button = tkinter.Button(self.windows, text="Start scanning", command=self.start)
        button.grid(column=0, row=2, padx=20, ipadx="140")

    def output_group(self) -> None:
        """
        Define the output group
        :return:
        """
        # Output Frame
        output_frame = tkinter.LabelFrame(self.windows, text='Output File')
        output_frame.grid(column=0, row=1, padx=20, pady=20, ipadx="10")
        # The log_type of output
        output_type_label = tkinter.Label(output_frame, text="Type", font='arial 8 bold')
        output_type_label.grid(row=0, column=0)
        self.output_type_field = ttk.Combobox(output_frame, width=7,
                                              values=[
                                                  "JSON",
                                                  "PDF"
                                              ])
        self.output_type_field.grid(row=0, column=1)
        # The output path
        output_type_label = tkinter.Label(output_frame, text="Output dir", font='arial 8 bold')
        output_type_label.grid(row=0, column=2)
        self.output_path_field = tkinter.Entry(output_frame)
        self.output_path_field.grid(row=0, column=3, ipadx="46", pady=5)

    def target_information_group(self) -> None:
        """
        Define the target information group
        :return:
        """
        # The target information group
        lf = tkinter.LabelFrame(self.windows, text='Target')
        lf.grid(column=0, row=0, padx=20, ipadx="10")
        #  - The host
        host_label = tkinter.Label(lf, text="Host IP", font='arial 8 bold')
        host_label.grid(row=0, column=0, ipadx="30", pady="5", padx="5")
        self.host_field = tkinter.Entry(lf)
        self.host_field.grid(row=0, column=1, ipadx="30", pady="5", padx="5")
        # - The user
        user_label = tkinter.Label(lf, text="Username", font='arial 8 bold')
        user_label.grid(row=1, column=0, ipadx="30", pady="5", padx="5")
        self.user_field = tkinter.Entry(lf)
        self.user_field.grid(row=1, column=1, ipadx="30", pady="5", padx="5")
        # - The password / Keyfile group
        pass_key_frame = tkinter.LabelFrame(lf, text="Password or Key File")
        pass_key_frame.grid(row=2, column=0, columnspan=3)
        # -- The password
        password_label = tkinter.Label(pass_key_frame, text="Password", font='arial 8 bold')
        password_label.grid(row=0, column=0, ipadx="30", pady="5", padx="5")
        self.password_field = tkinter.Entry(pass_key_frame, show="*")
        self.password_field.grid(row=0, column=1, ipadx="30", pady="5", padx="5")
        # -- The key file path
        key_label = tkinter.Label(pass_key_frame, text="Key File Path", font='arial 8 bold')
        key_label.grid(row=1, column=0, ipadx="30", pady="5", padx="5")
        self.key_file_field = tkinter.Entry(pass_key_frame)
        self.key_file_field.grid(row=1, column=1, ipadx="30", pady="5", padx="5")
        # - the sub option group
        line = tkinter.Frame(lf)
        line.grid(column=0, row=3, columnspan=2)
        # -- The port
        port_label = tkinter.Label(line, text="SSH port", font='arial 8 bold')
        port_label.grid(row=0, column=0, ipadx="15", pady="5", padx="5")
        self.port_field = tkinter.Entry(line, width=4)
        self.port_field.grid(row=0, column=1)
        self.port_field.insert(0, "22")
        # -- The scan group
        scan_frame = tkinter.LabelFrame(line, text='Scans')
        scan_frame.grid(row=0, column=3, ipadx="30", pady="5", padx="5")
        # --- The ioc scan
        self.IOC_scan = tkinter.IntVar()
        self.IOC_scan.set(1)
        ioc_checkbox = tkinter.Checkbutton(scan_frame, text='IOC (Loki)',
                                           variable=self.IOC_scan,
                                           onvalue=1,
                                           offvalue=0,
                                           font='arial 8 bold')
        ioc_checkbox.grid(row=0, column=0)
        # --- The vulnerability scan
        self.security_issues_scan = tkinter.IntVar()
        self.security_issues_scan.set(1)
        security_issues_checkbox = tkinter.Checkbutton(scan_frame,
                                                       text='Security issues',
                                                       variable=self.security_issues_scan,
                                                       onvalue=1,
                                                       offvalue=0,
                                                       font='arial 8 bold')
        security_issues_checkbox.grid(row=0, column=1)
        # - The Os information group
        os_frame = tkinter.Frame(line)
        os_frame.grid(column=0, row=4, columnspan=3)
        # -- The target name
        os_detected_label = tkinter.Label(os_frame, text="Target:", font='arial 8 bold')
        os_detected_label.grid(column=0, row=0)
        self.os_detected_input = tkinter.Label(os_frame, text="/")
        self.os_detected_input.grid(column=1, row=0)
        # -- The OS name
        os_name_label = tkinter.Label(os_frame, text="Name:", font='arial 8 bold')
        os_name_label.grid(column=2, row=0)
        self.os_name_input = tkinter.Label(os_frame, text="/")
        self.os_name_input.grid(column=3, row=0)

    def set_os_detected(self, name: str) -> None:
        """
        Set the value of the target name
        :param name: the name of the target
        :return:
        """
        logging.debug('GUI set os detected:{}'.format(name))
        self.os_detected_input.config(text=name, font=("Courier", 10, "bold"), fg="#0000FF")

    def _add_log(self, log: str, log_type: str = "info") -> None:
        """
        Add log into the log panel
        :param log: the message
        :param log_type: the log_type of log (info, error, warning, debug,...)
        :return:
        """
        self.log_view.insert(tkinter.END, "{}\n".format(log), log_type)
        self.log_view.see(tkinter.END)

    def log(self, message, log_type):
        """
                Add log into the log panel with a format
                :param message: the message
                :param log_type: the log_type of log (info, error, warning, debug,...)
                :return:
                """
        now = datetime.now()
        self._add_log("[{}] {}".format(now.strftime("%m/%d/%Y, %H:%M:%S"), message), log_type)

    def set_host_name(self, name: str) -> None:
        """
        Set the OS name
        :param name:
        :return:
        """
        logging.debug('GUI set host name')
        self.os_name_input.config(text=name, font=("Courier", 10, "bold"), fg="#0000FF")

    @staticmethod
    def convert_in_default_if_empty(text: Union[str, int, object], default=None):
        """
        Return the default value if the text is empty
        :param text: the text to check
        :param default: the default value
        :return:
        """
        if isinstance(text, str) and len(text) == 0:
            return default
        if text is not None:
            return text
        return default

    def update_loki(self) -> None:
        """
        Aims to update loki
        :return: None
        """
        logging.debug('GUI update loki function')

        def _update_loki():
            self.log("Start update of Loki", "info")
            updater = LOKIUpdater(LogAdaptator(self))
            r = updater.update_loki()
            self.log("End update of Loki", "info")
            if r:
                self.info("Loki Update", "Loki has been successfully updated!")
            else:
                self.error("Loki Update", "Loki update failed...")

        _thread.start_new_thread(_update_loki, ())

    @staticmethod
    def get_lynis_info() -> None:
        """
        Show lynis information
        :return:
        """
        logging.debug('GUI get lynis info')

    def get_loki_info(self) -> None:
        """
            Show loki information
        """
        logging.debug('GUI get loki info function')
        try:
            with open(TOOL_CONFIG_PATH, "r") as f:
                json_obj = json.load(f)
        except (JSONDecodeError, TypeError):
            logging.debug('impossible to parse config')
            json_obj = {}
        if "loki" in json_obj:
            if "signatures" in json_obj["loki"]:
                signature = json_obj["loki"]["signatures"]
            else:
                signature = "?"
            if "update" in json_obj["loki"]:
                update = json_obj["loki"]["update"]
            else:
                update = "?"
        else:
            update = "?"
            signature = "?"
        self.info("Loki info.", "Last update: {}\nLast signatures update: {}".format(update, signature))

    def update_loki_signature(self) -> None:
        """
        Aims to update loki signatures
        :return: None
        """
        logging.debug('GUI update loki signature')

        def _update_loki_sign():
            self.log("Start update of Loki Signatures", "info")
            updater = LOKIUpdater(LogAdaptator(self))
            r = updater.update_signatures()
            self.log("End update of Loki", "info")
            if r:
                self.info("Loki Signatures Update", "Loki signatures has been successfully updated!")
            else:
                self.error("Loki Update", "Loki signatures update failed...")

        _thread.start_new_thread(_update_loki_sign, ())

        self.log("End update of Loki", "info")

    @staticmethod
    def set_loki_workspace(os_name: str) -> None:
        """
            This function should be used to set the workspace of Loki
        :param os_name: windows or linux
        """
        logging.debug('GUI set loki workspace for {}'.format(os_name))
        loki = Loki()
        w = loki.get([os_name, "workspace"])
        new = askstring('Loki workspace', 'Current : {}\n New:'.format(w))
        if new is not None:
            loki.set([os_name, "workspace"], new)
            logging.debug('GUI set loki workspace for {} from {} to {}'.format(os_name, w, new))

    @staticmethod
    def set_lynis_workspace() -> None:
        """
                    This function should be used to set the workspace of Lynis

                """
        logging.debug('GUI set lynis workspace')
        loki = Lynis()
        w = loki.get(["linux", "workspace"])
        new = askstring('Lynis workspace', 'Current : {}\n New:'.format(w))
        if new is not None:
            loki.set(["linux", "workspace"], new)
            logging.debug('GUI set lynis workspace from {} to {}'.format(w, new))

    def start(self) -> None:
        """
        This method is called when the start button is clicked
        :return:
        """
        logging.debug("GUI start scan")

        def _start():
            logging.debug("host={};"
                          "user={};"
                          "password=*********;"
                          "key_file={};"
                          "port={};"
                          "user_interface={};"
                          "security_issues_scan={};"
                          "ioc_scan={};"
                          "output_type={};"
                          "output_path={}".format(
                self.convert_in_default_if_empty(self.host_field.get()),
                self.convert_in_default_if_empty(self.user_field.get()),
                self.convert_in_default_if_empty(self.key_file_field.get()),
                self.convert_in_default_if_empty(int(self.port_field.get()), 22),
                self,
                self.security_issues_scan.get(),
                self.IOC_scan.get(),
                self.output_type_field.get(),
                self.output_path_field.get()
            ))
            Target(host=self.convert_in_default_if_empty(self.host_field.get()),
                   user=self.convert_in_default_if_empty(self.user_field.get()),
                   password=self.convert_in_default_if_empty(self.password_field.get()),
                   key_file=self.convert_in_default_if_empty(self.key_file_field.get()),
                   port=self.convert_in_default_if_empty(int(self.port_field.get()), 22),
                   user_interface=self,
                   security_issues_scan=self.security_issues_scan.get(),
                   ioc_scan=self.IOC_scan.get(),
                   output_type=self.output_type_field.get(),
                   output_path=self.output_path_field.get()
                   )

        _thread.start_new_thread(_start, ())
