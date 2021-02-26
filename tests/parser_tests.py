from pe_parser.engine.pe_parser import PEParser
from pe_parser.engine.errors import MagicSignatureError

import pytest


# не нужно?
@pytest.mark.parametrize(
    ('file_name', 'expected_lfanew'), [
        ('tests/test_exe/add_str.exe', 264),
        ('tests/test_exe/wireshark.exe', 272)
    ]
)
def test_read_dos_header(file_name, expected_lfanew):
    parser = PEParser(file_name)
    with open(parser.file_name, 'rb') as parser.file_obj:
        parser.read_dos_header()
        assert parser.dos_header.e_lfanew == expected_lfanew


def test_read_file_header():
    pass


def test_read_optional_header_standard():
    pass


def test_read_optional_header_windows_specific():
    pass


def test_read_sections():
    pass


def test_read_imported_dlls():
    pass


@pytest.mark.parametrize(
    'file_name', [
        'tests/test_exe/add_str.exe',
        'tests/test_exe/wireshark.exe'
    ]
)
def test_parse(file_name):
    pass


@pytest.mark.parametrize(
    'file_name', [
        'tests/test_exe/add_str_with_no_MZ.exe',
        'tests/test_exe/add_str_with_no_PE00.exe'
    ]
)
def test_parse_wrong_file_magic_error(file_name):
    parser = PEParser(file_name)
    with pytest.raises(MagicSignatureError):
        parser.parse()
