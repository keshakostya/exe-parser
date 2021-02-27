from argparse import ArgumentParser
import logging
from pe_parser.engine.pe_parser import PEParser
from pe_parser.engine.errors import PEParseException
from pe_parser.cli.printer import field_to_str


def parse_args():
    argument_parser = ArgumentParser(description='Python PE format engine')
    argument_parser.add_argument('-d', '--DEBUG', action='store_true',
                                 help='Print debug messages')
    argument_parser.add_argument('file', help='Exe file to parse')
    return argument_parser.parse_args().__dict__


if __name__ == '__main__':
    args = parse_args()
    log_level = logging.DEBUG if args['DEBUG'] else logging.INFO
    logging.basicConfig(level=log_level,
                        format='%(levelname)s - %(message)s')
    parser = PEParser(args['file'])
    try:
        parser.parse()
    except PEParseException as e:
        logging.error(e.message)
