import logging
import struct
from dataclasses import dataclass, field
from typing import List, Optional, IO, Tuple, Dict

from pe_parser.engine.errors import MagicSignatureError
from pe_parser.engine.structures import DOSHeader, FileHeader, OptionalHeaderStandard, OptionalHeaderWindowsSpecific, \
    DataDirectory, SectionHeader


class PEParser:
    HEADERS_FORMATS = {
        # 'DOS_HEADER': (64, '<H7LI'),
        'IMAGE_FILE_HEADER': (20, '<2H3I2H'),
        'OPTIONAL_HEADER_STANDARD': {
            'PE32': (26, '<2B6I'),
            'PE32+': (22, '<2B5I')
        },
        'OPTIONAL_HEADER_WINDOWS_SPECIFIC': {
            'PE32': (68, '<3I6H4I2H6I'),
            'PE32+': (88, '<Q2I6H4I2H4Q2I')
        },
        'DATA_DIRECTORY': (8, '<2I'),
        'SECTION_HEADER': (40, '<8s6I2HI'),
        'IMPORT_DESCRIPTOR': (20, '<5I')
    }

    def __init__(self, file_name: str):
        self.file_name: str = file_name
        self.pe_format: Optional[str] = None
        self.file_obj: Optional[IO] = None
        self.dos_header: Optional[DOSHeader] = None
        self.file_header: Optional[FileHeader] = None
        self.optional_header_standard: Optional[OptionalHeaderStandard] = None
        self.optional_header_windows_specific: \
            Optional[OptionalHeaderWindowsSpecific] = None
        self.optional_header_data_directories: List[DataDirectory] = []
        self.sections: Dict[bytes, SectionHeader] = {}

    def clear(self):
        self.file_name = ''
        if not self.file_obj.closed:
            self.file_obj.close()
        self.pe_format = None
        self.file_obj = None
        self.dos_header = None
        self.file_header = None
        self.sections.clear()

    def unpack_bytes(self, size: int, struct_format: str) -> Tuple[int, ...]:
        return struct.unpack(struct_format, self.file_obj.read(size))

    def read_dos_header(self):
        e_magic = self.file_obj.read(2)
        if e_magic != b'MZ':
            raise MagicSignatureError('MZ')
        self.file_obj.seek(60)
        e_lfanew = self.unpack_bytes(4, '<I')[0]
        self.dos_header = DOSHeader(e_magic, e_lfanew)
        logging.debug(msg='Read DOSHeader')

    def read_file_header(self):
        self.file_obj.seek(self.dos_header.e_lfanew)
        pe_magic = self.file_obj.read(4)
        if pe_magic != b'PE\x00\x00':
            raise MagicSignatureError('PE')
        self.file_header = FileHeader(pe_magic,
                                      *self.unpack_bytes(
                                          *self.HEADERS_FORMATS['IMAGE_FILE_HEADER']))
        logging.debug(msg='Read FileHeader')

    def read_optional_header(self):
        magic = self.unpack_bytes(2, 'H')[0]
        if magic == 0x10b:
            self.pe_format = 'PE32'
        elif magic == 0x20b:
            self.pe_format = 'PE32+'
        else:
            raise MagicSignatureError('optional magic')
        self.optional_header_standard = \
            OptionalHeaderStandard(magic,
                                   *self.read_optional_header_standard())
        self.optional_header_windows_specific = OptionalHeaderWindowsSpecific(
            *self.read_optional_header_windows_specific()
        )
        for _ in range(self.optional_header_windows_specific.number_of_rva_and_sizes):
            self.optional_header_data_directories.append(DataDirectory(*self.unpack_bytes(
                *self.HEADERS_FORMATS['DATA_DIRECTORY']
            )))
        logging.debug('Read OptionalHeader')

    def read_optional_header_standard(self):
        return self.unpack_bytes(
            *self.HEADERS_FORMATS['OPTIONAL_HEADER_STANDARD'][self.pe_format]
        )

    def read_optional_header_windows_specific(self):
        return self.unpack_bytes(
            *self.HEADERS_FORMATS['OPTIONAL_HEADER_WINDOWS_SPECIFIC'][self.pe_format]
        )

    def read_sections(self):
        for _ in range(self.file_header.number_of_sections):
            section = SectionHeader(*self.unpack_bytes(
                *self.HEADERS_FORMATS['SECTION_HEADER']
            ))
            self.sections[section.name] = section
        logging.debug('Read sections')

    def parse(self):
        with open(self.file_name, 'rb') as f:
            self.file_obj = f
            self.read_dos_header()
            self.read_file_header()
            self.read_optional_header()
            self.read_sections()
