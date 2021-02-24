from dataclasses import dataclass
from typing import IO, Optional, Tuple, List
import struct


@dataclass
class ImageFileHeader:
    PEMagic: bytes
    Machine: int
    NumberOfSections: int
    TimeDateStamp: int
    PointerToSymbolTable: int
    NumberOfSymbols: int
    SizeOfOptionalHeader: int
    Characteristics: int


@dataclass
class OptionalHeader:
    Magic: int
    MajorLinkerVersion: int
    MinorLinkerVersion: int
    SizeOfCode: int
    SizeOfInitializedData: int
    SizeOfUninitializedData: int
    AddressOfEntryPoint: int
    BaseOfCode: int
    BaseOfData: int
    ImageBase: int
    SectionAlignment: int
    FileAlignment: int
    MajorOperatingSystemVersion: int
    MinorOperatingSystemVersion: int
    MajorImageVersion: int
    MinorImageVersion: int
    MajorSubsystemVersion: int
    MinorSubsystemVersion: int
    Win32VersionValue: int
    SizeOfImage: int
    SizeOfHeaders: int
    CheckSum: int
    Subsystem: int
    DllCharacteristics: int
    SizeOfStackReserve: int
    SizeOfStackCommit: int
    SizeOfHeapReserve: int
    SizeOfHeapCommit: int
    LoaderFlags: int
    NumberOfRvaAndSizes: int
    DataDirectory: List[Tuple[int, int]]


class Parser:
    #     singletone
    HEADERS = {
        'DOS_HEADER': (64, '<H7LI'),
        'IMAGE_FILE_HEADER': (20, '<2H3I2H')
    }

    FILE_HEADER_SIZES = {
        'e_magic': 2,
        'dos_stuff': 60,
        'e_lfanew': 4,
        'pe_magic': 4,
        'machine': 2,
        'number_of_sections': 2,
        'time_date_stamp': 4,
        'pointer_to_symbol_table': 4,
        'number_of_symbols': 4,
        'size_of_optional_header': 2,
        'characteristics': 2
    }

    def __init__(self, file_name: str):
        self.file_name: str = file_name
        self.file_obj: Optional[IO] = None

    def unpack_bytes(self, size: int, struct_format: str):
        return struct.unpack(struct_format, self.file_obj.read(size))

    def read_file_header(self):
        e_magic = self.file_obj.read(self.FILE_HEADER_SIZES['e_magic'])
        if e_magic != b'MZ':
            raise Exception('FUCK')
        self.file_obj.seek(60)
        e_lfanew = struct.unpack('<I', self.file_obj.read(4))[0]

        self.file_obj.seek(e_lfanew)
        pe_magic = self.file_obj.read(self.FILE_HEADER_SIZES['pe_magic'])
        if pe_magic != b'PE\x00\x00':
            raise Exception('FUCK_2')
        image_file_header = ImageFileHeader(pe_magic,
                                            *self.unpack_bytes(
                                                *self.HEADERS['IMAGE_FILE_HEADER']))
        print(image_file_header)
        if image_file_header.SizeOfOptionalHeader != 0:

    #
    # machine = struct.unpack('<H',
    #                         self.file_obj.read(
    #                             self.FILE_HEADER_SIZES['machine']))[0]
    # number_of_sections = struct.unpack('<H',
    #                                    self.file_obj.read())

    def parse(self):
        with open(self.file_name, 'rb') as f:
            self.file_obj = f
            self.read_file_header()


if __name__ == '__main__':
    parser = Parser('OfficeSetup.exe')
    parser.parse()
