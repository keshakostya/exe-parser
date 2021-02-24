from dataclasses import dataclass, field
from typing import IO, Optional, Tuple, List, Dict
import struct
from  pe_parser.engine.errors import MagicSignatureError
import logging


@dataclass
class DOSHeader:
    e_magic: bytes
    e_lfanew: int


@dataclass
class FileHeader:
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
    Name: bytes  # 8s
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


class PEParser:
    HEADERS = {
        'DOS_HEADER': (64, '<H7LI'),
        'IMAGE_FILE_HEADER': (20, '<2H3I2H'),
        # HBBIIIIIIIIIHHHHHHIIIIHHIIIIII
        'OPTIONAL_HEADER': (96, '<H2B9I6H4I2H6I'),
        'SECTION_HEADER': (40, '<8s6I2HI'),
        'IMPORT_DESCRIPTOR': (20, '<5I')
    }

    def __init__(self, file_name: str):
        self.file_name: str = file_name
        self.file_obj: Optional[IO] = None
        self.dos_header: Optional[DOSHeader] = None
        self.file_header: Optional[FileHeader] = None
        self.optional_header: Optional[OptionalHeader] = None
        self.sections: Dict[bytes, SectionHeader] = {}

    def clear(self):
        self.file_name = ''
        if not self.file_obj.closed:
            self.file_obj.close()
        self.file_obj = None
        self.dos_header = None
        self.file_header = None
        self.optional_header = None
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
                                          *self.HEADERS['IMAGE_FILE_HEADER']))
        logging.debug(msg='Read FileHeader')

    def read_optional_header(self):
        self.optional_header = OptionalHeader(
            *self.unpack_bytes(
                *self.HEADERS['OPTIONAL_HEADER']
            ))
        data_directories = []
        if self.optional_header.NumberOfRvaAndSizes != 0:
            for _ in range(self.optional_header.NumberOfRvaAndSizes):
                data_directories.append(self.unpack_bytes(
                    8, '<II'
                ))
            self.optional_header.DataDirectory = data_directories
        else:
            self.file_obj.seek(self.file_header.SizeOfOptionalHeader - 96, 1)
        logging.debug('Read OptionalHeader')

    def read_sections(self):
        for _ in range(self.file_header.NumberOfSections):
            section = SectionHeader(*self.unpack_bytes(
                *self.HEADERS['SECTION_HEADER']
            ))
            self.sections[section.Name] = section
        logging.debug('Read sections')

    def read_import(self):
        pass

    def parse(self):
        with open(self.file_name, 'rb') as f:
            self.file_obj = f
            self.read_dos_header()
            self.read_file_header()
            self.read_optional_header()
            self.read_sections()
