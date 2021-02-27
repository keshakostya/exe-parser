import logging
import struct
from typing import List, Optional, IO, Tuple, Dict

from pe_parser.engine.errors import MagicSignatureError, UnpackingError, \
    FileReadingError
from pe_parser.engine.structures import DOSHeader, FileHeader, \
    OptionalHeaderStandard, OptionalHeaderWindowsSpecific, \
    DataDirectory, SectionHeader, ImportDescriptor


class PEParser:
    """PE format parser class"""

    FORMATS = {
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
        self.imported_dlls: List[str] = []

    def clear(self):
        self.file_name = ''
        if not self.file_obj.closed:
            self.file_obj.close()
        self.pe_format = None
        self.file_obj = None
        self.dos_header = None
        self.file_header = None
        self.sections.clear()
        self.imported_dlls.clear()

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
        self.file_header = FileHeader(
            pe_magic,
            *self.unpack_bytes(*self.FORMATS['IMAGE_FILE_HEADER']))
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
        logging.debug('Read OptionalHeader')
        for _ in range(
                self.optional_header_windows_specific.number_of_rva_and_sizes):
            self.optional_header_data_directories.append(
                DataDirectory(*self.unpack_bytes(
                    *self.FORMATS['DATA_DIRECTORY']
                )))
        logging.debug('Read data directories')

    def read_optional_header_standard(self):
        return self.unpack_bytes(
            *self.FORMATS['OPTIONAL_HEADER_STANDARD'][self.pe_format]
        )

    def read_optional_header_windows_specific(self):
        return self.unpack_bytes(
            *self.FORMATS['OPTIONAL_HEADER_WINDOWS_SPECIFIC'][self.pe_format]
        )

    def read_sections(self):
        for _ in range(self.file_header.number_of_sections):
            section = SectionHeader(*self.unpack_bytes(
                *self.FORMATS['SECTION_HEADER']
            ))
            self.sections[section.name] = section
        logging.debug('Read sections')

    def read_imported_dlls(self):
        if len(self.optional_header_data_directories) < 2 or \
                self.optional_header_data_directories[1].is_empty():
            return
        import_data_directory = self.optional_header_data_directories[1]
        import_section_name = b''
        for section in self.sections.values():
            if section.virtual_address <= import_data_directory.virtual_address \
                    <= section.virtual_address + section.virtual_size:
                import_section_name = section.name
                break
        import_section = self.sections[import_section_name]
        offset = import_section.pointer_to_raw_data + \
                 (import_data_directory.virtual_address -
                  import_section.virtual_address)
        self.file_obj.seek(offset)
        import_descriptors = []
        while True:
            import_descriptor = ImportDescriptor(*self.unpack_bytes(
                *self.FORMATS['IMPORT_DESCRIPTOR']))
            if import_descriptor.is_null():
                break
            import_descriptors.append(import_descriptor)
        for import_descriptor in import_descriptors:
            offset = import_section.pointer_to_raw_data + \
                     (import_descriptor.name - import_section.virtual_address)
            self.file_obj.seek(offset)
            chars = []
            while True:
                char = self.file_obj.read(1)
                if char == b'\x00':
                    break
                chars.append(char)
            dll_name = b''.join(chars).decode(encoding='ascii')
            self.imported_dlls.append(dll_name)

    def read_text_raw_data(self):
        code_section = self.sections[b'.text\x00\x00\x00']
        offset = code_section.pointer_to_raw_data
        self.file_obj.seek(offset)
        raw_code = self.file_obj.read(code_section.size_of_raw_data)
        print(raw_code)

    def parse(self):
        try:
            self._parse()
        except struct.error as e:
            raise UnpackingError(e)
        except (ValueError, FileNotFoundError) as e:
            raise FileReadingError(str(e))

    def _parse(self):
        with open(self.file_name, 'rb') as f:
            self.file_obj = f
            self.read_dos_header()
            self.read_file_header()
            self.read_optional_header()
            self.read_sections()
            self.read_imported_dlls()

    def generate_info_dict(self):
        info_dict = {
            'File name': self.file_name,
            'PE format': self.pe_format,
            'DOS header': self.pe_file_block_to_dict(self.dos_header),
            'File header': self.pe_file_block_to_dict(self.file_header),
            'Optional header standard': self.pe_file_block_to_dict(
                self.optional_header_standard
            ),
            'Optional header windows specific': self.pe_file_block_to_dict(
                self.optional_header_windows_specific), 'Sections': [
                self.pe_file_block_to_dict(section) for section in
                self.sections
            ],
            'Imported dlls': self.imported_dlls}
        return info_dict

    def pe_file_block_to_dict(self, field) -> Dict[str, str]:
        block_dict = {}
        for name, value in field.__dict__.items():
            pretty_name = name.replace('_', ' ')
            if isinstance(int, value):
                pretty_value = f'0x{hex(value).upper()}'
            elif isinstance(bytes, value):
                pretty_value = value.rstrip(b'\x00').decode(encoding='utf-8')
            else:
                pretty_value = str(value)
            block_dict[pretty_name] = pretty_value
        return block_dict
