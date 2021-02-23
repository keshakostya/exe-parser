import ctypes
import struct
from dataclasses import dataclass

filename = 'OfficeSetup.exe'


@dataclass
class ImageFileHeaderOffsets:
    Machine = 2
    NumberOfSections = 2
    TimeDateStamp = 4
    PointerToSymbolTable = 4
    NumberOfSymbols = 4
    SizeOfOptionalHeader = 2
    Characteristics = 2


@dataclass
class ImageFileHeader:
    Machine: int
    NumberOfSections: int
    TimeDateStamp: int
    PointerToSymbolTable: int
    NumberOfSymbols: int
    SizeOfOptionalHeader: int
    Characteristics: int


def read_dos_header(f):
    mz = f.read(2)
    if mz != b'MZ':
        raise Exception('Fuck')
    print(mz)
    f.seek(60)
    e_lfanew = struct.unpack('<I', f.read(4))[0]
    print(e_lfanew)
    return e_lfanew


def read_pe_header(f, e_lfanew):
    f.seek(e_lfanew)
    pe_magic = f.read(4)
    if pe_magic != b'PE\x00\x00':
        raise Exception('Fuck_2')
    print(pe_magic)
    machine = struct.unpack('H', f.read(ImageFileHeaderOffsets.Machine))[0]
    number_of_sections = struct.unpack('H', f.read(ImageFileHeaderOffsets.NumberOfSections))[0]
    time_date_stump = struct.unpack('I', f.read(ImageFileHeaderOffsets.TimeDateStamp))[0]
    pointer_to_sym_table = struct.unpack('I', f.read(ImageFileHeaderOffsets.PointerToSymbolTable))[0]
    number_of_symbols = struct.unpack('I', f.read(ImageFileHeaderOffsets.NumberOfSymbols))[0]
    size_of_optional_header = struct.unpack('H', f.read(ImageFileHeaderOffsets.SizeOfOptionalHeader))[0]
    characteristics = struct.unpack('H', f.read(ImageFileHeaderOffsets.Characteristics))[0]
    image_file_header = ImageFileHeader(machine, number_of_sections, time_date_stump, pointer_to_sym_table,
                                        number_of_symbols, size_of_optional_header, characteristics)
    print(image_file_header)


with open(filename, 'rb') as f:
    pe_start = read_dos_header(f)
    read_pe_header(f, pe_start)
