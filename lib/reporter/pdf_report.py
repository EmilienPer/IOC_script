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
from io import BytesIO

import jinja2
from xhtml2pdf import pisa


def to_pdf(output_path: str, report_dict: dict) -> bool:
    """
        generate a PDF report
        :param output_path: the path file
        :param report_dict: the json to save
        :return: True if no error
        """
    template_loader = jinja2.FileSystemLoader(searchpath="resources/templates")
    template_env = jinja2.Environment(loader=template_loader)
    template_file = "report.html"
    template = template_env.get_template(template_file)
    html = template.render(report_dict)
    result = BytesIO()
    pdf = pisa.pisaDocument(BytesIO(html.encode("ISO-8859-1", "ignore")), result)
    if pdf.err:
        logging.debug('Error during the conversion of htm to pdf for the PDF report : {}'.format(pdf.err))
        return False
    else:
        with open(output_path, "wb") as f:
            f.write(result.getvalue())
        return True
