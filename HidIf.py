from random import randint
from usb import core as UsbCore
from usb import util as UsbUtil
from Utils import Utils

class HidIf(object):

    byteorder = 'little'

    DEF_VID = 0x0483
    DEF_PID = 0x5150
    DEF_EPI = 0x81
    DEF_EPO = 0x01

    PROTOCOL_VERSION = 2

    PACKET_SIZE = 64
    INIT_PAYLOAD_SIZE = PACKET_SIZE - 7
    CONT_PAYLOAD_SIZE = PACKET_SIZE - 5

    CMD_INIT   = 0x06
    CMD_CIPHER = 0x55

    def __init__(self, log=None):

        self.log_ = log
        self.cid_ = 0
        self.dev_ = None
        self.epi_ = 0
        self.epo_ = 0

    def _send_hid(self, ba, timeout=1000):

        try:
            n_sent = self.dev_.write(self.epo_, ba, timeout)
        except:
            n_sent = 0

        if self.log_ != None and n_sent > 0:
            self.log_('Tx: ' + Utils.ba_to_hex_str(ba))

        return n_sent

    def _recv_hid(self, timeout=1000):

        try:
            ba = self.dev_.read(self.epi_, self.PACKET_SIZE, timeout)
        except:
            ba = b''

        if self.log_ != None and len(ba) > 0:
            self.log_('Rx: ' + Utils.ba_to_hex_str(ba))

        return ba

    def _send(self, cmd, data=b'', timeout=1000):

        ba = bytearray(self.cid_.to_bytes(4, byteorder=self.byteorder, signed=False))
        ba.append(cmd | 0x80)
        ba.append(len(data) >> 8 & 0xFF)
        ba.append(len(data) & 0xFF)

        n_sent = 0
        for _ in range(self.INIT_PAYLOAD_SIZE):
            if n_sent < len(data):
                ba.append(data[n_sent])
            else:
                ba.append(0)
            n_sent += 1

        if self._send_hid(ba, timeout) > 0:

            seq = 0
            while n_sent < len(data):

                ba = bytearray(self.cid_.to_bytes(4, byteorder=self.byteorder, signed=False))
                ba.append(seq & 0xFF)

                for _ in range(self.CONT_PAYLOAD_SIZE):
                    if n_sent < len(data):
                        ba.append(data[n_sent])
                    else:
                        ba.append(0)
                    n_sent += 1

                if self._send_hid(ba, timeout) == 0:
                    n_sent = 0
                    break

                seq += 1

        else:

            n_sent = 0

        return n_sent

    def _recv(self, timeout=1000):

        cid = 0
        cmd = 0
        packet = b''
        packet_len = 0

        ba = self._recv_hid(timeout)
        if len(ba) > 0:
            cid = ba[3] << 24 | ba[2] << 16 | ba[1] << 8 | ba[0]
            cmd = ba[4]
            if cid == self.cid_ and (cmd & 0x80) == 0x80:
                cmd = cmd & 0x7F
                packet_len = ba[5] << 8 | ba[6]
                packet = ba[7:7+packet_len]

        if packet_len > self.INIT_PAYLOAD_SIZE:
            seq = 0
            while len(packet) < packet_len:
                ba = self._recv_hid(timeout)
                if len(ba) == 0:
                    packet = b''
                    break
                cid = ba[3] << 24 | ba[2] << 16 | ba[1] << 8 | ba[0]
                if cid == self.cid_ and ba[4] == seq:
                    packet += ba[5:]
                    seq += 1
                else:
                    cmd = 0
                    packet = b''
                    break

        return cmd, packet[:packet_len] if len(packet) > 0 else b''

    def _hidcmd_init(self):

        self.cid_ = randint(1, 0xFFFFFFFE)

        nonce = bytearray()
        for _ in range(8):
            nonce.append(randint(0, 0xFF))

        if self._send(self.CMD_INIT, nonce) > 0:
            cmd, rsp = self._recv()
            if cmd == self.CMD_INIT and nonce == rsp[:8] and rsp[12] == self.PROTOCOL_VERSION:
                return True

        return False

    def find_device(self, vid=DEF_VID, pid=DEF_PID):

        dev_list = list(UsbCore.find(idVendor=vid, idProduct=pid, find_all=True))
        if len(dev_list) > 0:
            return True

        self.dev_ = None
        return False

    def connect(self, vid=DEF_VID, pid=DEF_PID, epi=DEF_EPI, epo=DEF_EPO):

        self.dev_ = None
        self.epi_ = epi
        self.epo_ = epo

        dev_list = UsbCore.find(idVendor=vid, idProduct=pid, find_all=True)

        for dev in dev_list:
            try:
                dev.reset()
                dev.set_configuration()
                self.dev_ = dev
                if self._hidcmd_init() == True:
                    break
                else:
                    self.dev_ = None
            except:
                self.dev_ = None

        return True if self.dev_ != None else False

    def is_connected(self):

        return True if self.dev_ != None else False

    def cmd_cipher(self, packet, timeout=1000):

        if self.dev_ != None:
            if self._send(self.CMD_CIPHER, packet, timeout) > 0:
                cmd, rsp = self._recv(timeout)
                if cmd == self.CMD_CIPHER:
                    return rsp

        return b''
