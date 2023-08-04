from datetime import datetime
import pypackerdetect
# -*- coding: UTF-8 -*-
import logging
from argparse import ArgumentParser, RawTextHelpFormatter
from ast import literal_eval
from os.path import exists
from time import perf_counter


class PositiveInt:
    def __call__(self, string):
        try:
            n = literal_eval(string)
        except ValueError:
            raise ValueError(string)
        if not isinstance(n, int) or n < 0:
            raise ValueError(string)
        return int(n)

    def __repr__(self):
        return "positive int"


class PyDetectPacker:
    def __init__(self):
        __y = str(datetime.now().year)
        __s = "2018"

        __author__ = "Nick Cano"
        __credits__ = "Alexandre D'Hondt"
        __copyright__ = "© {} Cylance".format([__y, __s + "-" + __y][__y != __s])
        __license__ = "GPLv3 (https://www.gnu.org/licenses/gpl-3.0.fr.html)"
        __reference__ = "https://github.com/cylance/PyPackerDetect"
        __source__ = "https://github.com/dhondta/PyPackerDetect"
        __version__ = "1.1.0"

        """ Tool's main function """
        descr = "PyPackerDetect {}\n\nAuthor   : {}\nCredits  : {}\nCopyright: {}\nLicense  : {}\nReference: {}\n" \
                "Source   : {}\n\nThis tool applies multiple checks for determining if a PE file is packed or not and " \
                "reports the related findings, either as suspicions or detections.\n\n"
        descr = descr.format(__version__, __author__, __credits__, __copyright__, __license__, __reference__,
                             __source__)
        examples = "usage examples:\n- " + "\n- ".join([
            "pypackerdetect program.exe",
            "pypackerdetect program.exe -b",
            "pypackerdetect program.exe --low-imports --unknown-sections",
            "pypackerdetect program.exe --imports-threshold 5 --bad-sections-threshold 5",
        ])
        parser = ArgumentParser(description=descr, epilog=examples, formatter_class=RawTextHelpFormatter,
                                add_help=False)
        # parser.add_argument("path", type=valid_file, help="path to the portable executable")
        opt = parser.add_argument_group("optional arguments")
        opt.add_argument("--bad-ep-sections", action="store_false",
                         help="check for bad entry point sections (default: True)")
        opt.add_argument("--low-imports", action="store_false",
                         help="check for the number of imports (default: True)")
        opt.add_argument("--packer-sections", action="store_false",
                         help="check for packer sections (default: True)")
        opt.add_argument("--peid", action="store_false", help="detect with PEiD (default: True)")
        opt.add_argument("--peid-large-db", action="store_true",
                         help="use the large database for PEiD (default: False)")
        opt.add_argument("--peid-ep-only", action="store_false",
                         help="check only entry point signatures (default: True)")
        opt.add_argument("--unknown-sections", action="store_false",
                         help="check for unknown sections (default: True)")
        thrs = parser.add_argument_group("threshold arguments")
        thrs.add_argument("--bad-sections-threshold", dest="bst", type=PositiveInt, default=2,
                          help="threshold for the number of bad sections (default: 2)")
        thrs.add_argument("--imports-threshold", dest="it", type=PositiveInt, default=10,
                          help="threshold for the minimum number of imports (default: 10)")
        thrs.add_argument("--unknown-sections-threshold", dest="ust", type=PositiveInt, default=3,
                          help="threshold for the number of unknown sections (default: 3)")
        extra = parser.add_argument_group("extra arguments")
        extra.add_argument("-b", "--benchmark", action="store_true",
                           help="enable benchmarking, output in seconds (default: False)")
        extra.add_argument("-h", "--help", action="help", help="show this help message and exit")
        extra.add_argument("-v", "--verbose", action="store_true", help="display debug information (default: False)")
        self.args = parser.parse_args()
        logging.basicConfig()
        self.args.logger = logging.getLogger("pypackerdetect")
        self.args.logger.setLevel([logging.INFO, logging.DEBUG][self.args.verbose])
        code = 0

    def detect(self, path):
        t1 = perf_counter()
        r = pypackerdetect.PyPackerDetect(**vars(self.args)).detect(path)
        dt = str(perf_counter() - t1) if self.args.benchmark else ""
        # pypackerdetect.PyPackerDetect.report(path, r)
        return r["detections"]
        # if dt != "":
        #     return dt
        # return None