def field_to_str(field):
    str_parts = []
    for name in field.__dict__:
        str_value = ''
        value = field.__dict__[name]
        if isinstance(value, int):
            str_value = f'0x{hex(value).upper()}'
        elif isinstance(value, bytes):
            chars = []
            for char in value:
                if char == '\x00':
                    break
                chars.append(char.to_bytes(1, 'little'))
            str_value = b''.join(chars).decode(encoding='utf-8')
        str_parts.append(f'{name}: {str_value}\n')
    return ''.join(str_parts)

