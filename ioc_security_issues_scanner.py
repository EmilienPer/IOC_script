import logging
import sys

from lib.gui.main_windows import GUI

logging.basicConfig(
    format='%(asctime)s,%(msecs)d %(levelname)-8s [%(pathname)s:%(lineno)d in function %(funcName)s] %(message)s',
    datefmt='%Y-%m-%d:%H:%M:%S',
    level=logging.DEBUG
)
logger = logging.getLogger(__name__)
if sys.version_info[0] < 3:
    raise Exception("Python 3 or a more recent version is required.")

GUI()
