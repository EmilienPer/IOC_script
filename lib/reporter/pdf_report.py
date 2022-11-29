"""
IOC Security Issues Scanner Project
Author: Emilien Peretti (https://github.com/EmilienPer)
License: GNU GENERAL PUBLIC LICENSE (Version 3)
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
