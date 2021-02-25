from dataclasses import dataclass


@dataclass
class DOSHeader:
    e_magic: bytes
    e_lfanew: int


@dataclass
class FileHeader:
    pe_magic: bytes  # I
    machine: int  # H
    number_of_sections: int  # H
    time_date_stamp: int  # I
    pointer_to_symbol_table: int  # I
    number_of_symbols: int  # I
    size_of_optional_headers: int  # H
    characteristics: int  # H


@dataclass
class DataDirectory:
    virtual_address: int  # I
    size: int  # I


@dataclass
class OptionalHeaderStandard:
    magic: int  # H
    major_linker_version: int  # B
    minor_linker_version: int  # B
    size_of_code: int  # I
    size_of_initialized_data: int  # I
    size_of_uninitialized_data: int  # I
    address_of_entry_point: int  # I
    base_of_code: int  # I
    base_of_data: int = None  # I


@dataclass
class OptionalHeaderWindowsSpecific:
    image_base: int  # I / L
    section_alignment: int  # I
    file_alignment: int  # I
    major_operating_system_version: int  # H
    minor_operating_system_version: int  # H
    major_image_version: int  # H
    minor_image_version: int  # H
    major_subsystem_version: int  # H
    minor_subsystem_version: int  # H
    win32_version_value: int  # I
    size_of_image: int  # I
    size_of_headers: int  # I
    check_sum: int  # I
    subsystem: int  # H
    dll_characteristics: int  # H
    size_of_stack_reserve: int  # I / L
    size_of_stack_commit: int  # I / L
    size_of_heap_reserve: int  # I / L
    size_of_heap_commit: int  # I / L
    loader_flags: int  # I
    number_of_rva_and_sizes: int  # I


@dataclass
class SectionHeader:
    name: bytes  # 8s
    virtual_size: int  # I
    virtual_address: int  # I
    size_of_raw_data: int  # I
    pointer_to_raw_data: int  # I
    pointer_to_relocations: int  # I
    pointer_to_linenumbers: int  # I
    number_of_relocations: int  # H
    number_of_linenumbers: int  # H
    characteristics: int  # I
