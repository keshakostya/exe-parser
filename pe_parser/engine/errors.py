class PEParseException(Exception):
    message: str


class MagicSignatureError(PEParseException):

    def __init__(self, msg):
        self.message = self.message.format(msg)

    message = 'error: signature {} is not valid'


class UnpackingError(PEParseException):

    def __init__(self, msg):
        self.message = self.message.format(msg)

    message = 'error: could not correctly unpack bytes. {}'


class FileReadingError(PEParseException):

    def __init__(self, msg):
        self.message = self.message.format(msg)

    message = 'error: could not read file. {}'
