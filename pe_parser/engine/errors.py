class PEParseException(Exception):
    message: str


class MagicSignatureError(PEParseException):

    def __init__(self, msg):
        self.message = self.message.format(msg)

    message = 'error: signature {} is not valid'
