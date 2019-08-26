from PyCRC.CRCCCITT import CRCCCITT

class Def:

    byteorder = 'little'

    ###
    ### CIPHER version V1
    ###

    CIPHER_MAGIC_WORD               = 0x23561448
    CIPHER_SEED_SIZE                = 128
    CIPHER_MD_SIZE                  = 32
    CIPHER_BLOCK_IV_SIZE            = 16
    CIPHER_BLOCK_KEY_SIZE           = 32
    CIPHER_BLOCK_SIZE               = 2048

    CIPHER_SIGN_TAG_SEED            = 0x10
    CIPHER_SIGN_TAG_MD              = 0x11

    CIPHER_TAG_LEN_SIZE             = 3

    ###
    ### CIPHER command class
    ###

    CIPHER_CLASS                    = 0x55

    ###
    ### CIPHER command instruction
    ###  : extension of FIDO (0x40 ~ 0xBF)
    ###

    CIPHER_VERSION                  = 0x50
    CIPHER_KEY                      = 0x51
    CIPHER_ENCRYPTION               = 0x52

    ###
    ### CIPHER command param
    ###

    CIPHER_PARAM_SET                = 0x10
    CIPHER_PARAM_GET                = 0x11

    ###
    ### CIPHER command param 2
    ###

    CIPHER_PARAM_INIT               = 0x20
    CIPHER_PARAM_DO                 = 0x21
    CIPHER_PARAM_DONE               = 0x22
    CIPHER_PARAM_SIGN               = 0x23
    CIPHER_PARAM_TERM               = 0x24

    ###
    ### CIPHER status code
    ###

    CIPHER_SW_NO_ERROR              = 0x9000
    CIPHER_SW_NOT_SATISFIED         = 0x6985
    CIPHER_SW_WRONG_DATA            = 0x6A80
    CIPHER_SW_WRONG_LENGTH          = 0x6700
    CIPHER_SW_INVALID_CLA           = 0x6E00
    CIPHER_SW_INVALID_INS           = 0x6D00
    CIPHER_SW_INVALID_PARAM         = 0x6C00
    CIPHER_SW_ERR_OTHER             = 0x6F00

class Packet:

    @classmethod
    def req_version(cls):

        return bytearray([Def.CIPHER_CLASS, Def.CIPHER_VERSION])

    @classmethod
    def res_version(cls, res):

        major = 0
        minor = 0
        build = 0
        sw = 0

        if len(res) == 12:
            magic_word = res[0] << 24 | res[1] << 16 | res[2] << 8 | res[3]
            sw = cls._get_sw(res)
            if magic_word == Def.CIPHER_MAGIC_WORD and sw == Def.CIPHER_SW_NO_ERROR:
                major = res[4]
                minor = res[5]
                build = res[6] << 24 | res[7] << 16 | res[8] << 8 | res[9]
            else:
                build = magic_word

        return sw, major, minor, build

    @classmethod
    def req_key(cls, key=b''):

        key_len = len(key)
        ba = bytearray([Def.CIPHER_CLASS, Def.CIPHER_KEY])

        if key_len == 0:

            ba.append(Def.CIPHER_PARAM_GET)         # p1

        else:

            key_crc = cls._make_checksum(bytes(key))

            ba.append(Def.CIPHER_PARAM_SET)         # p1
            ba.append(0)                            # p2
            ba.append(0)                            # dat[0] - extended length encoding
            ba.append(key_len >> 8 & 0xFF)          # dat[1]
            ba.append(key_len >> 0 & 0xFF)          # dat[2]
            ba.append(key_crc >> 8 & 0xFF)          # dat[3]
            ba.append(key_crc >> 0 & 0xFF)          # dat[4]
            ba += key

        return ba

    @classmethod
    def res_key(cls, res):

        try:

            sw = cls._get_sw(res)
            key = b''

            if len(res) > 2 and res[0] == 0:

                key_len = res[1] << 8 | res[2]
                key_crc = res[3] << 8 | res[4]
                key = res[5:len(res)-2]

                if not cls._make_checksum(key) == key_crc or not len(key) == key_len:
                    key = b''

            return sw, key

        except:

            return 0, b''

    @classmethod
    def req_enc_init(cls):

        return bytearray([Def.CIPHER_CLASS, Def.CIPHER_ENCRYPTION, Def.CIPHER_PARAM_SET, Def.CIPHER_PARAM_INIT])

    @classmethod
    def res_enc_init(cls, res):

        return cls._get_sw(res) if len(res) == 2 else 0

    @classmethod
    def req_enc_do(cls, data):

        data_len = len(data)
        data_crc = cls._make_checksum(data)

        ba = bytearray([Def.CIPHER_CLASS, Def.CIPHER_ENCRYPTION, Def.CIPHER_PARAM_SET, Def.CIPHER_PARAM_DO])

        ba.append(0)                            # dat[0] - extended length encoding
        ba.append(data_len >> 8 & 0xFF)
        ba.append(data_len >> 0 & 0xFF)
        ba.append(data_crc >> 8 & 0xFF)
        ba.append(data_crc >> 0 & 0xFF)
        ba += data

        return ba

    @classmethod
    def res_enc_do(cls, res):

        try:

            sw = cls._get_sw(res)
            enc = b''

            if res[0] == 0:

                enc_len = res[1] << 8 | res[2]
                enc_crc = res[3] << 8 | res[4]
                enc = res[5:len(res) - 2]

                if cls._make_checksum(enc) != enc_crc or len(enc) != enc_len:
                    enc = b''

            return sw, enc

        except:

            return 0, b''

    @classmethod
    def req_enc_done(cls):

        return bytearray([Def.CIPHER_CLASS, Def.CIPHER_ENCRYPTION, Def.CIPHER_PARAM_SET, Def.CIPHER_PARAM_DONE])

    @classmethod
    def res_enc_done(cls, res):

        try:

            sw = cls._get_sw(res)
            enc = b''

            if res[0] == 0:

                enc_len = res[1] << 8 | res[2]
                enc_crc = res[3] << 8 | res[4]
                enc = res[5:len(res)-2]

                if cls._make_checksum(enc) != enc_crc or len(enc) != enc_len:
                    enc = b''

            return sw, enc

        except:

            return 0, b''

    @classmethod
    def req_enc_sign(cls, pubk):

        pubk_len = len(pubk)
        pubk_crc = cls._make_checksum(pubk)

        ba = bytearray([Def.CIPHER_CLASS, Def.CIPHER_ENCRYPTION, Def.CIPHER_PARAM_SET, Def.CIPHER_PARAM_SIGN])

        ba.append(0)                            # dat[0] - extended length encoding
        ba.append(pubk_len >> 8 & 0xFF)
        ba.append(pubk_len >> 0 & 0xFF)
        ba.append(pubk_crc >> 8 & 0xFF)
        ba.append(pubk_crc >> 0 & 0xFF)
        ba += pubk

        return ba

    @classmethod
    def res_enc_sign(cls, res):

        try:

            sw = cls._get_sw(res)
            k_md = b''
            sign = b''

            if res[0] == 0:

                sign_len = res[1] << 8 | res[2]
                sign_crc = res[3] << 8 | res[4]
                sign = res[5:len(res)-2]

                if cls._make_checksum(sign) != sign_crc or len(sign) != sign_len:
                    sign = b''

                k_md = sign[:Def.CIPHER_MD_SIZE]
                sign = sign[Def.CIPHER_MD_SIZE:]

            return sw, k_md, sign

        except:

            return 0, b'', b''

    @classmethod
    def req_enc_term(cls):

        return bytearray([Def.CIPHER_CLASS, Def.CIPHER_ENCRYPTION, Def.CIPHER_PARAM_SET, Def.CIPHER_PARAM_TERM])

    @classmethod
    def res_enc_term(cls, res):

        return cls._get_sw(res) if len(res) == 2 else 0

    @classmethod
    def req_dec_init(cls, meta):

        meta_len = len(meta)
        meta_crc = cls._make_checksum(meta)

        ba = bytearray([Def.CIPHER_CLASS, Def.CIPHER_ENCRYPTION, Def.CIPHER_PARAM_GET, Def.CIPHER_PARAM_INIT])

        ba.append(0)                            # dat[0] - extended length encoding
        ba.append(meta_len >> 8 & 0xFF)
        ba.append(meta_len >> 0 & 0xFF)
        ba.append(meta_crc >> 8 & 0xFF)
        ba.append(meta_crc >> 0 & 0xFF)
        ba += meta

        return ba

    @classmethod
    def res_dec_init(cls, res):

        return cls._get_sw(res) if len(res) == 2 else 0

    @classmethod
    def req_dec_do(cls, data):

        data_len = len(data)
        data_crc = cls._make_checksum(data)

        ba = bytearray([Def.CIPHER_CLASS, Def.CIPHER_ENCRYPTION, Def.CIPHER_PARAM_GET, Def.CIPHER_PARAM_DO])

        ba.append(0)                            # dat[0] - extended length encoding
        ba.append(data_len >> 8 & 0xFF)
        ba.append(data_len >> 0 & 0xFF)
        ba.append(data_crc >> 8 & 0xFF)
        ba.append(data_crc >> 0 & 0xFF)
        ba += data

        return ba

    @classmethod
    def res_dec_do(cls, res):

        try:

            sw = cls._get_sw(res)
            dec = b''

            if res[0] == 0:

                dec_len = res[1] << 8 | res[2]
                dec_crc = res[3] << 8 | res[4]
                dec = res[5:len(res) - 2]

                if cls._make_checksum(dec) != dec_crc or len(dec) != dec_len:
                    dec = b''

            return sw, dec

        except:

            return 0, b''

    @classmethod
    def req_dec_done(cls):

        return bytearray([Def.CIPHER_CLASS, Def.CIPHER_ENCRYPTION, Def.CIPHER_PARAM_GET, Def.CIPHER_PARAM_DONE])

    @classmethod
    def res_dec_done(cls, res):

        try:

            sw = cls._get_sw(res)
            dec = b''

            if res[0] == 0:

                dec_len = res[1] << 8 | res[2]
                dec_crc = res[3] << 8 | res[4]
                dec = res[5:len(res)-2]

                if cls._make_checksum(dec) != dec_crc or len(dec) != dec_len:
                    dec = b''

            return sw, dec

        except:

            return 0, b''

    @classmethod
    def req_dec_sign(cls):

        return bytearray([Def.CIPHER_CLASS, Def.CIPHER_ENCRYPTION, Def.CIPHER_PARAM_GET, Def.CIPHER_PARAM_SIGN])

    @classmethod
    def res_dec_sign(cls, res):

        return cls._get_sw(res) if len(res) == 2 else 0

    @classmethod
    def req_dec_term(cls):

        return bytearray([Def.CIPHER_CLASS, Def.CIPHER_ENCRYPTION, Def.CIPHER_PARAM_GET, Def.CIPHER_PARAM_TERM])

    @classmethod
    def res_dec_term(cls, res):

        return cls._get_sw(res) if len(res) == 2 else 0

    @classmethod
    def _check_checksum(cls, crc, ba):

        crcccitt = CRCCCITT()
        crcccitt.starting_value = Def.CIPHER_MAGIC_WORD & 0xFFFF
        ba_crc = crcccitt.calculate(bytes(ba))

        return True if ba_crc == crc else False

    @classmethod
    def _make_checksum(cls, ba):

        crcccitt = CRCCCITT()
        crcccitt.starting_value = Def.CIPHER_MAGIC_WORD & 0xFFFF
        ba_crc = crcccitt.calculate(bytes(ba))

        return ba_crc

    @classmethod
    def _get_sw(cls, ba):

        n = len(ba)
        sw = ba[n-2:]

        return sw[0] << 8 | sw[1]

    @classmethod
    def req_get_pin(cls):

        return bytearray([0x54, 0x10, 0, 0, 0])

    @classmethod
    def req_set_pin(cls):

        return bytearray([0x54, 0x11, 0, 0, 0])
