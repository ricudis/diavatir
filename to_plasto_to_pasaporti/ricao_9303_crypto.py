#!python3
from to_plasto_to_pasaporti import RICAO_9303_Objects
from Crypto.Cipher import AES, DES3, DES
from Crypto.Hash import CMAC, SHA1
from Crypto.Util import Padding
import logging

class RICAO_9303_Crypto:
    def __init__(self):
        self.Kenc = None
        self.Kmac = None
        self.SSC = None
        
    def set_keys(self, Kenc, Kmac, SSC=None):
        self.Kenc = Kenc
        self.Kmac = Kmac
        self.SSC = SSC
        if (Kenc is not None):
            logging.debug("Kenc/Kp    : " + self.Kenc.hex())
        if (Kmac is not None):
            logging.debug("Kmac       : " + self.Kmac.hex())
        if (SSC is not None):
            logging.debug("SSC        : " + self.SSC.hex())

    def KDF(self, K, c):
        # 9.7.1 Key Derivation Function
        #
        # The key derivation function KDF(K,c), is defined as follows:
        # Input: The following inputs are required:
        # The shared secret value K (REQUIRED)
        # A 32-bit, big-endian integer counter c (REQUIRED)
        # Output: An octet string keydata.
        # Actions: The following actions are performed:
        # keydata = H(K || c)
        # Output octet string keydata
        # The key derivation function KDF(K,c) requires a
        # suitable hash function denoted by H(), i.e
        # the bit-length of the hash function SHALL be
        # greater or equal to the bit-length of the derived
        # key. The hash value SHALL be interpreted as
        # big-endian byte output.
        Kmerged = K + bytearray([0, 0, 0, c])
        logging.debug("KDF input  : " + Kmerged.hex())
        h = SHA1.new()
        h.update(Kmerged)
        Kout = h.digest()
        logging.debug("KDF output : " + Kout.hex())
        return Kout[0:16]
        
    def RicuDES3(self, data, encrypt=True, unpad=True):
        # 9.8.6.1 Encryption
        #
        # Two key 3DES in CBC mode with zero IV 
        # (i.e. 0x00 00 00 00 00 00 00 00) according
        # to [ISO/IEC 11568-2] is used. Padding according
        # to [ISO/IEC 9797-1] padding method 2 is used.
        
        zero_iv = bytearray([0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
        
        cipher = DES3.new(self.Kenc, DES3.MODE_CBC, iv=zero_iv)
        
        if (encrypt):
            return cipher.encrypt(data)
        else:
            dec = cipher.decrypt(data)
            if (unpad):
                dec = Padding.unpad(dec, 8, style='iso7816')   
            return dec   


    def MACaroni(self, data, do_padding=True):
        # 9.8.6.2 Message Authentication
        #
        # Cryptographic checksums are calculated using
        # [ISO/IEC 9797-1] MAC algorithm 3 with block
        # cipher DES, zero IV (8 bytes), and [ISO/IEC 9797-1]
        # padding method 2. The MAC length MUST be 8 bytes.
        # After a successful authentication the datagram to
        # be MACed MUST be prepended by the Send Sequence Counter.
        
        # "[ISO/IEC 9797-1] MAC algorithm 3 with block
        # cipher DES, zero IV (8 bytes), and [ISO/IEC 9797-1]
        # padding method 2" is equivalent to CBC, trim output,
        # then do one round of EDE
        
        if (self.SSC is not None):
            ssc_int = int.from_bytes(self.SSC, 'big')
            ssc_int += 1
            self.SSC = ssc_int.to_bytes(8, 'big')
            logging.debug("SSC        : " + self.SSC.hex())
            data = self.SSC + data
        
        if (do_padding):
            data = Padding.pad(data, 8, style='iso7816')
            
        # Initialize DES contexts for MAC calculation
        
        logging.debug("MAC input  : " + data.hex())
        
        zero_iv = bytearray([0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
        mac_cipher_1 = DES.new(self.Kmac[:8], DES.MODE_CBC, iv=zero_iv)
        mac_cipher_2 = DES.new(self.Kmac[8:], DES.MODE_ECB)
        mac_cipher_3 = DES.new(self.Kmac[:8], DES.MODE_ECB)
        
        h1 = mac_cipher_1.encrypt(data)[-8:]
        h2 = mac_cipher_2.decrypt(h1)
        h3 = mac_cipher_3.encrypt(h2)
        logging.debug("MAC output : " + h3.hex())
        return h3
        
