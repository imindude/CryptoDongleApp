###
# pyinstaller --add-data "res;res" --paths "C:\Program Files (x86)\Windows Kits\10\Redist\10.0.17763.0\ucrt\DLLs\x64" --icon res/CryptDongle_64.ico --windowed --onefile --clean CryptDongle.py
#
# 1M encrpytion : 2:30
###

import sys
from datetime import datetime
from PyQt5 import uic
from PyQt5.QtWidgets import QApplication, QDialog, QFileDialog
from PyQt5.QtCore import QTimer
from PyQt5.QtGui import QIcon
from HidIf import HidIf
from Utils import Utils
from Cipher import Def, Packet

test_public_key = """
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA3779CniQGlW7fX8zbvcw
HS1kM2CGIZeoekwCPiaO4LqhedKAWtK72cHhJAHsOvmKDNwi9ipGml7EIcUdN3jq
FANjb/njoSyc4GssJ0yUYNfnGFQD7DfBg1S2zZ3zu484468nBaHjo7AQR+3v4SjL
IS/WuIl0OzTOJQdjFZ7hl8O07aXXK6X9RPMcXqpBeLHqIbezuso3rLCdLnPqk7e5
rFV/QGtsXDacEO6RJvLxicV9HEKaiXr1GIlLHQ0DS8aWFKV7EqIy8AzDNP20LJF4
6PzddktK+QRfS6rEZrQ9grdrLOAItxfQ7dEDWVBy2FD9PAfLy02nosqYzKPV/uoE
AwIDAQAB
-----END PUBLIC KEY-----
"""

class CryptDongle(QDialog):

    HIDIF_POLL_MS = 500

    def __init__(self, parent=None):

        QDialog.__init__(self, parent)

        # self.hidif_ = HidIf(self.logging)
        self.hidif_ = HidIf()

        self.poll_ = QTimer()
        self.poll_.setSingleShot(True)
        self.poll_.timeout.connect(self.slot_poll_timeout)
        self.poll_.start(self.HIDIF_POLL_MS)

        self._init_ui()

    def _init_ui(self):

        self.ui_ = uic.loadUi('res/CryptDongle.ui')
        self.ui_.setWindowIcon(QIcon('res/CryptDongle_64.ico'))

        self.ui_.pushButton_Version.clicked.connect(self.slot_pushbutton_version_clicked)
        self.ui_.pushButton_SetKey.clicked.connect(self.slot_pushbutton_set_key_clicked)
        self.ui_.pushButton_GetKey.clicked.connect(self.slot_pushbutton_get_key_clicked)
        self.ui_.pushButton_Encrypt.clicked.connect(self.slot_pushbutton_encrypt_clicked)
        self.ui_.pushButton_Decrypt.clicked.connect(self.slot_pushbutton_decrypt_clicked)

        self.ui_.show()

    def slot_poll_timeout(self):

        if self.hidif_.find_device(vid=HidIf.DEF_VID, pid=HidIf.DEF_PID):
            if not self.hidif_.is_connected():
                if self.hidif_.connect(vid=HidIf.DEF_VID, pid=HidIf.DEF_PID):
                    self.logging('>> connected <<')
                else:
                    self.logging('>> disconnected <<')

        self.poll_.start(self.HIDIF_POLL_MS)

    def slot_pushbutton_version_clicked(self):

        req = Packet.req_version()
        res = self.hidif_.cmd_cipher(req)
        sw, major, minor, build = Packet.res_version(res)

        if sw == Def.CIPHER_SW_NO_ERROR:
            self.logging('>> VERSION : {}.{}.{} <<'.format(major, minor, build))
        else:
            self.logging('>> VERSION Failed : {} {} <<'.format(hex(sw), hex(build)))

    def slot_pushbutton_set_key_clicked(self):

        file_path = QFileDialog.getOpenFileName(self)

        if len(file_path[0]) > 0:

            key_file = open(file_path[0], 'rb')
            key_context = key_file.read()
            key_file.close()

            req = Packet.req_key(key_context)
            res = self.hidif_.cmd_cipher(req)
            sw, _ = Packet.res_key(res)

            self.logging('>> RESULT: {} <<'.format(hex(sw)))

        else:

            self.logging('>> USER CANCEL <<')

    def slot_pushbutton_get_key_clicked(self):

        req = Packet.req_key()
        res = self.hidif_.cmd_cipher(req)
        sw, key = Packet.res_key(res)

        if sw == Def.CIPHER_SW_NO_ERROR:
            self.logging('>> READ PUBLIC KEY:\n{}<<'.format(Utils.ba_to_chr_str(key)))
        else:
            self.logging('>> KEY Failed : {} <<'.format(hex(sw)))

    def slot_pushbutton_encrypt_clicked(self):

        file_path = QFileDialog.getOpenFileName(self)
        file_context = b''

        if len(file_path[0]) > 0:

            with open(file_path[0], 'rb') as f:
                file_context = f.read()

            if len(file_context) > 0:

                self.logging('>> ENCRYPTION FILE : {}'.format(file_path[0]))

                ciphertext, metadata = self._encryption(file_context)

                if len(ciphertext) > 0 and len(metadata) > 0:

                    with open(file_path[0] + '.cipher', 'wb') as f:
                        f.write(ciphertext)

                    with open(file_path[0] + '.meta', 'wb') as f:
                        f.write(metadata)

                else:

                    self.logging('>> ENCRYPTION Failed')

    def slot_pushbutton_decrypt_clicked(self):

        file_path = QFileDialog.getOpenFileName(self)
        file_context = b''

        if len(file_path[0]) > 0:

            with open(file_path[0], 'rb') as f:
                file_context = f.read()

            if len(file_context) > 0:

                self.logging('>> DECRYPTION FILE : {}'.format(file_path[0]))

                metadata = b''
                with open(file_path[0].replace('cipher', 'meta'), 'rb') as f:
                    metadata = f.read()

                if len(metadata) > 0:
                    plaintext = self._decryption(file_context, metadata)

                    if len(plaintext) > 0:

                        with open(file_path[0].replace('cipher', 'plain'), 'wb') as f:
                            f.write(plaintext)

    def logging(self, msg):

        if type(msg) == bytes or type(msg) == bytearray:
            msg = Utils.ba_to_hex_str(msg)
        self.ui_.plainTextEdit_Logging.appendPlainText(msg)

    def _encryption(self, text):

        ciphertext = bytearray()
        metadata = bytearray()

        ## INIT

        self.logging('>> INIT: {}'.format(datetime.now()))

        req = Packet.req_enc_init()
        res = self.hidif_.cmd_cipher(req)
        sw = Packet.res_enc_init(res)

        if sw != Def.CIPHER_SW_NO_ERROR:
            self.logging('>> ENCRYPTION INIT Failed : {} <<'.format(hex(sw)))
            return b'', b''

        ## DO

        self.logging('>> DO: {}'.format(datetime.now()))

        pos = 0
        while pos < len(text):

            send_data = text[pos:pos+Def.CIPHER_BLOCK_SIZE]

            req = Packet.req_enc_do(send_data)
            res = self.hidif_.cmd_cipher(req)
            sw, enc = Packet.res_enc_do(res)

            if sw == Def.CIPHER_SW_NO_ERROR and len(enc) > 0:
                ciphertext += enc
                pos += len(send_data)
            else:
                self.logging('>> ERROR Position: {}'.format(pos))

        ## DONE

        self.logging('>> DONE: {}'.format(datetime.now()))

        req = Packet.req_enc_done()
        res = self.hidif_.cmd_cipher(req)
        sw, enc = Packet.res_enc_done(res)

        if sw != Def.CIPHER_SW_NO_ERROR or len(enc) == 0:
            self.logging('>> ERROR')
            return b'', b''

        ciphertext += enc

        ## SIGN

        self.logging('>> SIGN: {}'.format(datetime.now()))

        req = Packet.req_enc_sign(test_public_key.encode(encoding='ascii'))
        res = self.hidif_.cmd_cipher(req)
        sw, k_md, sign = Packet.res_enc_sign(res)

        metadata = k_md + sign

        if sw != Def.CIPHER_SW_NO_ERROR or len(metadata) == 0:
            self.logging('SIGN ERROR : {}'.format(hex(sw)))
            return b'', b''

        ## TERM

        self.logging('>> TERM: {}'.format(datetime.now()))

        req = Packet.req_enc_term()
        res = self.hidif_.cmd_cipher(req)
        sw = Packet.res_enc_term(res)

        if sw != Def.CIPHER_SW_NO_ERROR:
            self.logging('TERM ERROR : {}'.format(hex(sw)))
            return b'', b''

        return ciphertext, metadata

    def _decryption(self, text, meta):

        plaintext = bytearray()

        ## INIT

        self.logging('>> INIT: {}'.format(datetime.now()))

        req = Packet.req_dec_init(meta)
        res = self.hidif_.cmd_cipher(req, 15000)
        sw = Packet.res_enc_init(res)

        if sw != Def.CIPHER_SW_NO_ERROR:
            self.logging('>> INIT ERROR : {}'.format(hex(sw)))
            return b'', b''

        ## DO

        self.logging('>> DO: {}'.format(datetime.now()))

        pos = 0
        while pos < len(text):

            send_data = text[pos:pos+Def.CIPHER_BLOCK_SIZE]

            req = Packet.req_dec_do(send_data)
            res = self.hidif_.cmd_cipher(req)
            sw, dec = Packet.res_dec_do(res)

            if sw == Def.CIPHER_SW_NO_ERROR and len(dec) > 0:
                plaintext += dec
                pos += len(send_data)
            else:
                self.logging('>> ERROR Position: {}'.format(pos))

        ## DONE

        self.logging('>> DONE: {}'.format(datetime.now()))

        req = Packet.req_dec_done()
        res = self.hidif_.cmd_cipher(req)
        sw, dec = Packet.res_dec_done(res)

        if sw != Def.CIPHER_SW_NO_ERROR or len(dec) == 0:
            self.logging('>> DONE ERROR : {} <<'.format(hex(sw)))
            return b'', b''

        plaintext += dec

        ## SIGN

        self.logging('>> SIGN: {}'.format(datetime.now()))

        req = Packet.req_dec_sign()
        res = self.hidif_.cmd_cipher(req)
        sw = Packet.res_dec_sign(res)

        if sw != Def.CIPHER_SW_NO_ERROR:
            self.logging('>> SIGN ERROR : {} <<'.format(hex(sw)))
            return b'', b''

        ## TERM

        self.logging('>> TERM: {}'.format(datetime.now()))

        req = Packet.req_dec_term()
        res = self.hidif_.cmd_cipher(req)
        sw = Packet.res_dec_term(res)

        if sw != Def.CIPHER_SW_NO_ERROR:
            self.logging('>> TERM ERROR : {} <<'.format(hex(sw)))
            return b'', b''

        return plaintext

if __name__ == '__main__':
    app = QApplication(sys.argv)
    don = CryptDongle()
    try:
        app.exec()
    except:
        pass
