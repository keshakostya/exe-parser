from typing import Dict


class Printer:

    def print_pretty(self, data: Dict, ident=0):
        for key, value in data.items():
            if isinstance(value, dict):
                print('\t' * ident + key)
                self.print_pretty(value, ident + 1)
            elif isinstance(value, list):
                print('\t' * ident + key)
                for item in value:
                    if isinstance(item, dict):
                        self.print_pretty(item, ident + 1)
                    else:
                        print('\t' * (ident + 1) + item)
            else:
                print('\t' * ident + key + ': ' + value)
        print()
