#!python3
from to_plasto_to_pasaporti import RICAO_9303_Crypto
from Crypto.Cipher import AES, DES3, DES
from Crypto.Hash import SHA1
from Crypto.Util import Padding
from Crypto.Util.strxor import strxor
import logging

class RICAO_9303_BACaliaros:
    def __init__(self, smartcard):
        self.smartcard = smartcard
        self.crypto = RICAO_9303_Crypto()
        smartcard.set_crypto_ctx(self.crypto)
        
    def authenticate(self, password, is_mrz, appy, parsed_data):
    
        assert (is_mrz == True), "Only MRZ password can be used with BAC authentication"
        
        # Calculate the SHA-1 hash of password

        h = SHA1.new()
        h.update(bytes(password, 'ascii'))
        logging.debug("### pass   : " + password)
        logging.debug("H(pass)    : " + h.hexdigest())

        # Take the most significant 16 bytes to form the Kseed:

        Kseed = h.digest()[:16]

        Kenc = self.derive(Kseed, 1)
        Kmac = self.derive(Kseed, 2)
        self.crypto.set_keys(Kenc, Kmac, None)
        
        # Select application before doing BAC
        
        self.smartcard.cmd_select_application(appy)
    
        # Get challenge
        
        (sw, RND_IC) = self.smartcard.cmd_get_challenge()
        logging.debug("RND.IC     : " + RND_IC.hex())
    
        # Generate an 8 byte random RND.IFD and a 16 byte random Kifd.
        # Of course they're random. I copied them directly from ICAO 
        # 9303-11 standard, which says these are random.
    
        RND_IFD = bytearray([0x78, 0x17, 0x23, 0x86, 0x0C, 0x06, 0xC2, 0x26])
        Kifd = bytearray([0x0B, 0x79, 0x52, 0x40, 0xCB, 0x70, 0x49, 0xB0, 0x1C, 0x19, 0xB3, 0x3E, 0x32, 0x80, 0x4F, 0x0B])
    
        # Concatenate RND.IFD, RND.IC and Kifd:
    
        S = RND_IFD + RND_IC + Kifd
    
        logging.debug("S          : " + S.hex())
    
        # Encrypt S with 3DES key Kenc:
    
        Eifd = self.crypto.RicuDES3(S, encrypt=True)
    
        logging.debug("Eifd       : " + Eifd.hex())
    
        # Compute MAC over Eifd with 3DES key Kmac:
    
        Mifd = self.crypto.MACaroni(Eifd)

        logging.debug("Mifd       : " + Mifd.hex()) 
    
        # Concatenate Eifd and Mifd, 
        # Construct command data for EXTERNAL AUTHENTICATE and
        # send command APDU to the eMRTD’s contactless IC:

        (sw, ext_auth_resp) = self.smartcard.cmd_external_authenticate(Eifd + Mifd)
    
        # Decrypt and verify received data and compare received RND.IFD with generated RND.IFD

        # Extract Eic, Mic from EXTERNAL AUTHENTICATE response
    
        Eic = ext_auth_resp[:32]
        Mic = ext_auth_resp[32:]
    
        logging.debug("Eic        : " + Eic.hex())
        logging.debug("Mic        : " + Mic.hex())
    
        # Calculate MAC over Eic with 3DES key Kmac:
    
        Mic_calc = self.crypto.MACaroni(Eic)
    
        logging.debug("Mic_calc   : " + Mic.hex())
    
        assert (Mic == Mic_calc), "MAC error from EXTERNAL AUTHENTICATE response"
    
        logging.debug("[MAC correct]")
    
        # Decrypt Eic with DES key Kenc to obtain R, and trim
    
        R = self.crypto.RicuDES3(Eic, encrypt=False, unpad=False)
    
        logging.debug("R          : " + R.hex())
        logging.debug("IC+IFD     : " + (RND_IC + RND_IFD).hex())
    
        # Compare R with RND.IC + RND.IFD
    
        assert (R[:16] == (RND_IC + RND_IFD)), "Incorrect RND.IC / RND.IFD from EXTERNAL AUTHENTICATE response"
    
        # Calculate XOR of KIFD and KIC
    
        Kseed = strxor(Kifd, R[16:])
    
        logging.debug("Kseed      : " + Kseed.hex())
    
        # Calculate session keys (KSenc and KSmac) according to Section 9.7.1/Appendix D.1:
        #
        # 9.8.6.3 Send Sequence Counter
        #
        # For Secure Messaging following BAC, the Send Sequence Counter SHALL be
        # initialized by concatenating the four least significant bytes of RND.IC and
        # RND.IFD, respectively:
        #
        # SSC = RND.IC (4 least significant bytes) || RND.IFD (4 least significant bytes).
    
        self.init_sm(Kseed, (RND_IC[-4:] + RND_IFD[-4:]))
        
    def derive(self, Kseed, c):
        # 9.7.1.1 3DES
        #
        # To derive 128-bit (112-bit excluding parity bits)
        # 3DES [FIPS 46-3] keys the hash function SHA-1 [FIPS 180-4] SHALL be
        # used and the following additional steps MUST be performed:
        # Use octets 1 to 8 of keydata to form keydataA and octets 9 to 16
        # of keydata to form keydataB; additional octets are not used.
        # Adjust the parity bits of keydataA and keydataB to form correct
        # DES keys (OPTIONAL).

        keydata = DES3.adjust_key_parity(self.crypto.KDF(Kseed, c)[:16])
        return keydata
        
    def init_sm(self, Kseed, Initial_SSC):
        # Calculate session keys (KSEnc and KSMAC) according to Section 9.7.1/Appendix D.1:        
        # Replace Kenc and Kmac with KSenc and KSmac, and initialize SSC
        KSenc = self.derive(Kseed, 1)
        KSmac = self.derive(Kseed, 2)
        self.crypto.set_keys(KSenc, KSmac, Initial_SSC)
