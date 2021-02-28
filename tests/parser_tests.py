from pe_parser.engine.pe_parser import PEParser
from pe_parser.engine.errors import MagicSignatureError

import pytest


@pytest.fixture
def parser(file_name):
    parser = PEParser(file_name)
    parser.parse()
    return parser


@pytest.mark.parametrize(
    ('file_name', 'expected_lfanew'), [
        ('tests/test_exe/add_str.exe', 264),
        ('tests/test_exe/wireshark.exe', 272)
    ]
)
def test_dos_header(parser, file_name, expected_lfanew):
    assert parser.dos_header.e_lfanew == expected_lfanew


@pytest.mark.parametrize(
    ('file_name', 'expected_file_header'), [
        ('tests/test_exe/add_str.exe', {
            'pe_magic': b'PE\x00\x00',
            'machine': 34404,
            'number_of_sections': 7,
            'time_date_stamp': 1610531106,
            'pointer_to_symbol_table': 0,
            'number_of_symbols': 0,
            'size_of_optional_headers': 240,
            'characteristics': 34
        }),
        ('tests/test_exe/wireshark.exe', {
            'pe_magic': b'PE\x00\x00',
            'machine': 34404,
            'number_of_sections': 6,
            'time_date_stamp': 1604000119,
            'pointer_to_symbol_table': 0,
            'number_of_symbols': 0,
            'size_of_optional_headers': 240,
            'characteristics': 34
        })
    ]
)
def test_file_header(parser, file_name, expected_file_header):
    for key in parser.file_header.__dict__.keys():
        assert parser.file_header.__dict__[key] == expected_file_header[key]


@pytest.mark.parametrize(
    ('file_name', 'expected_optional_header'), [
        ('tests/test_exe/add_str.exe', {
            'magic': 523,
            'major_linker_version': 14,
            'minor_linker_version': 0,
            'size_of_code': 135168,
            'size_of_initialized_data': 139264,
            'size_of_uninitialized_data': 0,
            'address_of_entry_point': 35092,
            'base_of_code': 4096,
            'base_of_data': None
        }),
        ('tests/test_exe/wireshark.exe', {
            'magic': 523,
            'major_linker_version': 14,
            'minor_linker_version': 27,
            'size_of_code': 20992,
            'size_of_initialized_data': 311808,
            'size_of_uninitialized_data': 0,
            'address_of_entry_point': 20320,
            'base_of_code': 4096,
            'base_of_data': None
        })
    ]
)
def test_optional_header_standard(parser, file_name, expected_optional_header):
    for key in parser.optional_header_standard.__dict__.keys():
        assert parser.optional_header_standard.__dict__[key] == expected_optional_header[key]


@pytest.mark.parametrize(
    ('file_name', 'expected_optional_header'), [
        ('tests/test_exe/add_str.exe', {
            'image_base': 5368709120,
            'section_alignment': 4096,
            'file_alignment': 512,
            'major_operating_system_version': 5,
            'minor_operating_system_version': 2,
            'major_image_version': 0,
            'minor_image_version': 0,
            'major_subsystem_version': 5,
            'minor_subsystem_version': 2,
            'win32_version_value': 0,
            'size_of_image': 335872,
            'size_of_headers': 1024,
            'check_sum': 0,
            'subsystem': 3,
            'dll_characteristics': 33120,
            'size_of_stack_reserve': 1048576,
            'size_of_stack_commit': 4096,
            'size_of_heap_reserve': 1048576,
            'size_of_heap_commit': 4096,
            'loader_flags': 0,
            'number_of_rva_and_sizes': 16,
        }),
        ('tests/test_exe/wireshark.exe', {
            'image_base': 5368709120,
            'section_alignment': 4096,
            'file_alignment': 512,
            'major_operating_system_version': 6,
            'minor_operating_system_version': 0,
            'major_image_version': 0,
            'minor_image_version': 0,
            'major_subsystem_version': 6,
            'minor_subsystem_version': 0,
            'win32_version_value': 0,
            'size_of_image': 352256,
            'size_of_headers': 1024,
            'check_sum': 349930,
            'subsystem': 3,
            'dll_characteristics': 49504,
            'size_of_stack_reserve': 1048576,
            'size_of_stack_commit': 4096,
            'size_of_heap_reserve': 1048576,
            'size_of_heap_commit': 4096,
            'loader_flags': 0,
            'number_of_rva_and_sizes': 16,
        })
    ]
)
def test_optional_header_windows_specific(parser, file_name, expected_optional_header):
    for key in parser.optional_header_windows_specific.__dict__.keys():
        assert parser.optional_header_windows_specific.__dict__[key] == expected_optional_header[key]


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
