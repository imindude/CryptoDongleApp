class Utils(object):

    @classmethod
    def str_to_ba(cls, string, pad='0'):

        if len(string) % 2:
            string += pad
        ba = bytearray()
        n = 0
        while n < len(string):
            ba.append(int(string[n] + string[n+1], 16))
            n += 2

        return ba

    @classmethod
    def ba_to_hex_str(cls, ba):

        return ''.join(map(lambda b: '{:02x}'.format(b), ba))

    @classmethod
    def ba_to_chr_str(cls, ba):

        return ''.join(map(lambda b: '{:c}'.format(b), ba))

    @classmethod
    def printable(cls, msg):

        if type(msg) == str:
            msg = cls.str_to_ba(msg)

        string = ''
        for b in msg:
            if b >= 0x20 and b <= 0x7F:
                string += '%c' % b
            else:
                string += '.'

        return string
