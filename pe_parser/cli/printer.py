from colorama import init, Fore
from pe_parser.engine.pe_parser import PEParser


class Printer:

    def print_pretty(self, pe_parser: PEParser):
        parser_results = pe_parser.generate_info_dict()
        for name in parser_results:
            print(Fore.GREEN, name)
            if isinstance(parser_results[name], str):
                print(Fore.YELLOW, f'\t{parser_results[name]}')
            elif isinstance(parser_results[name], dict)