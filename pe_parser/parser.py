from dataclasses import dataclass, field
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
    Magic: int  # H
    MajorLinkerVersion: int  # B
    MinorLinkerVersion: int  # B
    SizeOfCode: int  # I
    SizeOfInitializedData: int  # I
    SizeOfUninitializedData: int  # I
    AddressOfEntryPoint: int  # I
    BaseOfCode: int  # I
    BaseOfData: int  # I
    ImageBase: int  # I
    SectionAlignment: int  # I
    FileAlignment: int  # I
    MajorOperatingSystemVersion: int  # H
    MinorOperatingSystemVersion: int  # H
    MajorImageVersion: int  # H
    MinorImageVersion: int  # H
    MajorSubsystemVersion: int  # H
    MinorSubsystemVersion: int  # H
    Win32VersionValue: int  # I
    SizeOfImage: int  # I
    SizeOfHeaders: int  # I
    CheckSum: int  # I
    Subsystem: int  # H
    DllCharacteristics: int  # H
    SizeOfStackReserve: int  # I
    SizeOfStackCommit: int  # I
    SizeOfHeapReserve: int  # I
    SizeOfHeapCommit: int  # I
    LoaderFlags: int  # I
    NumberOfRvaAndSizes: int  # I
    DataDirectory: List[Tuple[int, int]] = field(default_factory=list)  # I I


@dataclass
class SectionHeader:
    Name: str  # 8s
    # PhysicalAddress: int  # I
    VirtualSize: int  # I
    VirtualAddress: int  # I
    SizeOfRawData: int  # I
    PointerToRawData: int  # I
    PointerToRelocations: int  # I
    PointerToLinenumbers: int  # I
    NumberOfRelocations: int  # H
    NumberOfLinenumbers: int  # H
    Characteristics: int  # I


@dataclass
class ImportDescriptor:
    OriginalFirstThunk: int  # I
    TimeDateStump: int  # I
    ForwarderChain: int  # I
    Name: int  # I
    FirstThunk: int  # I


class Parser:
    HEADERS = {
        'DOS_HEADER': (64, '<H7LI'),
        'IMAGE_FILE_HEADER': (20, '<2H3I2H'),
        'OPTIONAL_HEADER': (96, '<H2B9I6H4I2H6I'),
        'SECTION_HEADER': (40, '<8s6I2HI'),
        'IMPORT_DESCRIPTOR': (20, '<5I')
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
        e_lfanew_raw = self.file_obj.read(4)
        print(e_lfanew_raw)
        e_lfanew = struct.unpack('<I', e_lfanew_raw)[0]
        print(e_magic, e_lfanew)
        self.file_obj.seek(e_lfanew)
        pe_magic = self.file_obj.read(self.FILE_HEADER_SIZES['pe_magic'])
        if pe_magic != b'PE\x00\x00':
            raise Exception('FUCK_2')
        image_file_header = ImageFileHeader(pe_magic,
                                            *self.unpack_bytes(
                                                *self.HEADERS['IMAGE_FILE_HEADER']))
        print(image_file_header)
        optional_header = None
        if image_file_header.SizeOfOptionalHeader != 0:
            optional_header = OptionalHeader(
                *self.unpack_bytes(
                    *self.HEADERS['OPTIONAL_HEADER']
                )
            )
            data_directories = []
            if optional_header.NumberOfRvaAndSizes != 0:
                for _ in range(optional_header.NumberOfRvaAndSizes):
                    data_directories.append(self.unpack_bytes(
                        8, '<II'
                    ))
                optional_header.DataDirectory = data_directories
            else:
                self.file_obj.seek(image_file_header.SizeOfOptionalHeader - 96, 1)
        print(optional_header)
        section_header = SectionHeader(
            *self.unpack_bytes(
                *self.HEADERS['SECTION_HEADER']))
        print(section_header)
        self.file_obj.seek(section_header.PointerToRawData)
        raw_data = self.file_obj.read(section_header.SizeOfRawData)
        print(raw_data.hex())
        hex_data = raw_data.hex()
        print(hex_data)
        with open('a.txt', 'w') as f:
            for i in range(0, section_header.SizeOfRawData, 2):
                if i == 200:
                    break
                f.write(f'{hex_data[i].upper()}{hex_data[i + 1].upper()} ')
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
    parser = Parser('hello.exe')
    parser.parse()
