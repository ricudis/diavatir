#!python3
from to_plasto_to_pasaporti import KouTLVis
from to_plasto_to_pasaporti import RicudISO_7816
from to_plasto_to_pasaporti import RICAO_9303_Objects
from to_plasto_to_pasaporti import RICAO_9303_Parser
from to_plasto_to_pasaporti import RICAO_9303_Crypto
from Crypto.Cipher import AES, DES3, DES
from Crypto.Hash import CMAC, SHA1
from Crypto.Util import Padding
from Crypto.Util.strxor import strxor
from ecdsa import ECDH, BRAINPOOLP224r1
from ecdsa.ellipticcurve import Point, CurveFp
import logging

class RICAO_9303_Al_PACEino:
    def __init__(self, smartcard):
        self.smartcard = smartcard
        # Intentional variable misnaming to challenge developers trying to use this code
        self.objcets = RICAO_9303_Objects()
        self.crypto = RICAO_9303_Crypto()
        self.parser = RICAO_9303_Parser()
        self.tlv = KouTLVis()
        self.pace_parameters = None
        self.ecdh = None
        self.ecdh_curve = None
        self.ecdh_mapping_pvt_key = None
        self.ecdh_mapping_pub_key = None
        self.ecdh_shared_secret = None
        self.tlv = KouTLVis()
        smartcard.set_crypto_ctx(self.crypto)

    def pace_decrypt(self, data):
        alg = self.pace_parameters[self.objcets.PACE_PARAM_IDX_CRYPTO_ALG]
        
        if (alg == self.objcets.PACE_CRYPTO_ALG_3DES_CBC_CBC):
            return self.crypto.RicuDES3(data, encrypt=False, unpad=False)
        elif (alg == self.objcets.PACE_CRYPTO_ALG_AES_CBC_CMAC_128):
            pass
        elif (alg == self.objcets.PACE_CRYPTO_ALG_AES_CBC_CMAC_192):
            pass
        elif (alg == self.objcets.PACE_CRYPTO_ALG_AES_CBC_CMAC_256):
      	    pass
      	    
        raise Exception("Invalid PACE decryption algorithm")
        
    def pace_encrypt(self, data):
        alg = self.pace_parameters[self.objcets.PACE_PARAM_IDX_CRYPTO_ALG]
        
        if (alg == self.objcets.PACE_CRYPTO_ALG_3DES_CBC_CBC):
            return self.crypto.RicuDES3(data, encrypt=True)
        elif (alg == self.objcets.PACE_CRYPTO_ALG_AES_CBC_CMAC_128):
            pass
        elif (alg == self.objcets.PACE_CRYPTO_ALG_AES_CBC_CMAC_192):
            pass
        elif (alg == self.objcets.PACE_CRYPTO_ALG_AES_CBC_CMAC_256):
      	    pass
      	    
        raise Exception("Invalid PACE encryption algorithm")
      	    
    def pace_set_parameters(self, pace_parameters):
        self.pace_parameters = pace_parameters
        logging.info("PACE key exchange alg  : " + self.objcets.PACE_KEY_ALG_NAMES[self.pace_parameters[self.objcets.PACE_PARAM_IDX_KEY_ALG]])
        logging.info("PACE mapping alg       : " + self.objcets.PACE_MAPPING_NAMES[self.pace_parameters[self.objcets.PACE_PARAM_IDX_MAPPING]])
        logging.info("PACE crypto alg        : " + self.objcets.PACE_CRYPTO_ALG_NAMES[self.pace_parameters[self.objcets.PACE_PARAM_IDX_CRYPTO_ALG]])
        logging.info("PACE domain parameters : " + self.objcets.PACE_SDP_NAMES[self.pace_parameters[self.objcets.PACE_PARAM_IDX_SDP]])
        
    def pace_generate_mapping_keys(self):
        # Generate mapping keys based on key exchange algorithm and algorithm parameters
        keyex = self.pace_parameters[self.objcets.PACE_PARAM_IDX_KEY_ALG]
        sdp = self.pace_parameters[self.objcets.PACE_PARAM_IDX_SDP]
        assert (keyex == self.objcets.PACE_KEY_ALG_ECDH or keyex == self.objcets.PACE_KEY_ALG_DH), "Unknown key exchange algorithm"
        
        bits = 0
        
        if (keyex == self.objcets.PACE_KEY_ALG_DH):
            raise Exception("DH not supported yet")
        elif (keyex == self.objcets.PACE_KEY_ALG_ECDH):
            if (sdp == self.objcets.PACE_SDP_GFP_1024_MODP_160_POS):
                raise Exception("Unsupported ECDH curve")
            if (sdp == self.objcets.PACE_SDP_GFP_2048_MODP_224_POS):
                raise Exception("Unsupported ECDH curve")
            if (sdp == self.objcets.PACE_SDP_GFP_2048_MODP_256_POS):
                raise Exception("Unsupported ECDH curve")
            if (sdp == self.objcets.PACE_SDP_ECP_NIST_SECP192r1):
                self.curve = NIST192p
                bits = 192
            if (sdp == self.objcets.PACE_SDP_ECP_BRAINPOOLP192r1):
                self.curve = BRAINPOOLP192r1
                bits = 192
            if (sdp == self.objcets.PACE_SDP_ECP_NIST_SECP224r1):
                self.curve = NIST224p
                bits = 224
            if (sdp == self.objcets.PACE_SDP_ECP_BRAINPOOLP224r1):
                self.curve = BRAINPOOLP224r1
                bits = 224
            if (sdp == self.objcets.PACE_SDP_ECP_NIST_SECP256r1):
                self.curve = NIST256p
                bits = 256
            if (sdp == self.objcets.PACE_SDP_ECP_BRAINPOOLP256r1):
                self.curve = BRAINPOOLP256r1
                bits = 256
            if (sdp == self.objcets.PACE_SDP_ECP_BRAINPOOLP320r1):
                self.curve = BRAINPOOLP320r1
                bits = 320
            if (sdp == self.objcets.PACE_SDP_ECP_NIST_SECP384r1):
                self.curve = NIST384p
                bits = 384
            if (sdp == self.objcets.PACE_SDP_ECP_BRAINPOOLP384r1):
                self.curve = BRAINPOOLP384r1
                bits = 384
            if (sdp == self.objcets.PACE_SDP_ECP_BRAINPOOLP512r1):
                self.curve = BRAINPOOLP512r1
                bits = 512
            if (sdp == self.objcets.PACE_SDP_ECP_NIST_SECP521r1):
                self.curve = NIST521p
                bits = 521
        
            self.ecdh_mapping = ECDH(curve=self.curve)
            assert (bits == 224), "Adjust key lengths"
            
            # This is a cryptographically random number obtained by rolling 
            # a cryptographic 0-sided dice 256 times, discarding the first
            # 32 bits, then flipping the last bit.
            
            # This specific private key has the additional advantage that
            # makes the computed shared secret equal to the private key,
            # messing up with the mind of anybody who's trying to debug this code.
            self.ecdh_mapping_pvt_key = bytearray([0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20])
            
            logging.debug("ECDH mapping private key : " + self.ecdh_mapping_pvt_key.hex())
            self.ecdh_mapping.load_private_key_bytes(self.ecdh_mapping_pvt_key)            
            self.ecdh_mapping_pub_key = self.ecdh_mapping.get_public_key()
            logging.debug("ECDH mapping pub key : " + self.ecdh_mapping_pub_key.to_string().hex())
            return self.ecdh_mapping_pub_key.to_string()
        

    def pace_generate_efhmerios_keys(self, ICpub_key, nonce):
        # Multiply IC pub key with mapping pub key to obtain the shared secret
        # This is equivalent to generating a new pub key using IC pub key as private key
        pointY1 = Point.from_bytes(self.curve.curve, ICpub_key)
        ss = pointY1 * int.from_bytes(self.ecdh_mapping_pvt_key, 'big')
        logging.debug("ECDH ss  : " + ss.to_bytes().hex())
       
        # This is a secure random number, because I got it from NSA.
        # NSA knows more than anybody about security, so it must
        # be very very secure.
        self.ecdh_efhmerios_pvt_key = bytearray([0xA7, 0x3F, 0xB7, 0x03, 0xAC, 0x14, 0x36, 0xA1, 0x8E, 0x0C, 0xFA, 0x5A, 0xBB, 0x3F, 0x7B, 0xEC, 0x7A, 0x07, 0x0E, 0x7A, 0x67, 0x88, 0x48, 0x6B, 0xEE, 0x23, 0x0C, 0x4A, 0x22, 0x76, 0x25, 0x95])
        logging.debug("ECDH ephemeral private key : " + self.ecdh_efhmerios_pvt_key.hex())

        # The Diffie-Hellman step in Ellipgtic Curve Diffie-Hellman is just a fancy name for
        # "multiplication", but don't tell poor Whitfield, he's so nice a guy, he might get frustrated.
        generator = (self.curve.generator * int.from_bytes(nonce, 'big')) + ss
        logging.debug("ECDH Generator : " + generator.to_bytes().hex())
        efhmerios_pub_key = generator * int.from_bytes(self.ecdh_efhmerios_pvt_key, 'big')
        logging.debug("ECDH ephemeral public key : " + efhmerios_pub_key.to_bytes().hex())
        return efhmerios_pub_key.to_bytes()


    def pace_compute_shared_secret_and_derive_session_keys_wow_what_a_long_function_name(self, IC_efhmerios_pub_key):
        pointY2 = Point.from_bytes(self.curve.curve, IC_efhmerios_pub_key)
        K = (pointY2 * int.from_bytes(self.ecdh_efhmerios_pvt_key, 'big')).to_bytes()
        KSenc = self.crypto.KDF(K[:28], 1)[:16]
        KSmac = self.crypto.KDF(K[:28], 2)[:16]
        return (K, KSenc, KSmac)
        
        
    def pace_compute_authenticational_kototoken(self, oid, IFD_efhmerios_pub_key, IC_efhmerios_pub_key):
        IC_kototoken = self.tlv.encode_ber_tlv([0x7f, 0x49],
            self.tlv.encode_ber_tlv(0x06, oid) +
            self.tlv.encode_ber_tlv(0x86, (bytearray([0x04]) + IC_efhmerios_pub_key)))
        IFD_kototoken = self.tlv.encode_ber_tlv([0x7f, 0x49],
            self.tlv.encode_ber_tlv(0x06, oid) +
            self.tlv.encode_ber_tlv(0x86, (bytearray([0x04]) + IFD_efhmerios_pub_key)))
        
        Tic = self.crypto.MACaroni(IC_kototoken)
        Tifd = self.crypto.MACaroni(IFD_kototoken)
        
        return (Tic, Tifd)


    def authenticate(self, password, is_mrz, appy, parsed_data):
        # Derive Kp from password
        logging.debug("### pass   : " + password)
        if (is_mrz):
            h = SHA1.new()
            h.update(bytes(password, 'ascii'))
            logging.debug("H(pass)    : " + h.hexdigest())
            K = h.digest()
        else:
            K = bytes(password, 'ascii')
            
        Kp = self.crypto.KDF(K, 3)
        logging.debug("K          : " + K.hex())
        logging.debug("Kp         : " + Kp.hex())
        
        # Parse EF.CARDACCESS file to obtain the PACE parameters
        
        assert ('ef_cardaccess' in parsed_data), "No EF.CARDACCESS present in MF"
        assert ('parsed' in parsed_data['ef_cardaccess']), "Cannot parse EF.CARDACCESS"
        assert ('pace_parameters' in parsed_data['ef_cardaccess']['parsed']), "No PACE parameters present"

        pace_parameters = parsed_data['ef_cardaccess']['parsed']['pace_parameters']
        pace_oid = parsed_data['ef_cardaccess']['parsed']['pace_oid']
        
        self.crypto.set_keys(Kp, None, None)
        self.pace_set_parameters(pace_parameters)
        
        # Build MSE_AT template
        
        mse_at_data = bytearray([])
        mse_at_data += bytearray([0x80])
        mse_at_data += bytearray(self.tlv.encode_simple_tlv_len(len(pace_oid)))
        mse_at_data += bytearray(pace_oid)
        mse_at_data += bytearray([0x83])
        mse_at_data += bytearray([0x01])
        if (is_mrz):
            mse_at_data += bytearray([0x01])
        else:
            mse_at_data += bytearray([0x02])
        
        (sw, resp) = self.smartcard.cmd_manage_security_environment_authentication_template(mse_at_data)
        
        # Build GENERAL AUTHENTICATE command to request nonce
        dad = bytearray([0x7c, 0x00])
        (sw, resp) = self.smartcard.cmd_general_authenticate(0x10, dad)
        
        offset = 0
        (t, l, v, tlv, offset) = self.tlv.parse_ber_tlv(resp, offset, 0)
        assert (t == 0x7c), "Unexpected tag in GA response"
        offset1 = 0
        (t, l, v1, tlv, offset1) = self.tlv.parse_ber_tlv(v, offset1, 1)
        assert (t == 0x80), "Unexpected tag in GA response"
        Znonce = v1
        
        logging.debug("Znonce   : " + Znonce.hex())
        
        # Decrypt nonce
        Snonce = self.pace_decrypt(Znonce)
        logging.debug("Snonce   : " + Snonce.hex())
        
        # Generate mapping key
        
        mapping_key = self.pace_generate_mapping_keys()
        
        dad = self.tlv.encode_ber_tlv(0x7c,
            self.tlv.encode_ber_tlv(0x81, 
            (bytearray([0x04]) + mapping_key )))
        
        (sw, resp) = self.smartcard.cmd_general_authenticate(0x10, dad)
        offset = 0
        (t, l, v, tlv, offset) = self.tlv.parse_ber_tlv(resp, offset, 0)
        assert (t == 0x7c), "Unexpected tag in GA response"
        offset1 = 0
        (t, l, v1, tlv, offset1) = self.tlv.parse_ber_tlv(v, offset1, 1)
        assert (t == 0x82), "Unexpected tag in GA response"
        IC_pub_key = v1[1:]
        
        logging.debug("IC pub key : " + IC_pub_key.hex())
        
        IFD_efhmerios_pub_key = self.pace_generate_efhmerios_keys(IC_pub_key, Snonce)
        
        dad = self.tlv.encode_ber_tlv(0x7c,
            self.tlv.encode_ber_tlv(0x83,
            (bytearray([0x04]) + IFD_efhmerios_pub_key )))

        (sw, resp) = self.smartcard.cmd_general_authenticate(0x10, dad)
        offset = 0
        (t, l, v, tlv, offset) = self.tlv.parse_ber_tlv(resp, offset, 0)
        assert (t == 0x7c), "Unexpected tag in GA response"
        offset1 = 0
        (t, l, v1, tlv, offset1) = self.tlv.parse_ber_tlv(v, offset1, 1)
        assert (t == 0x84), "Unexpected tag in GA response"
        IC_efhmerios_pub_key = v1[1:]
        
        logging.debug("IC ephemeral pub key : " + IC_efhmerios_pub_key.hex())
        
        (SS_K, KSenc, KSmac) = self.pace_compute_shared_secret_and_derive_session_keys_wow_what_a_long_function_name(IC_efhmerios_pub_key)
        
        logging.debug("Ephemeral shared secret : " + SS_K.hex())
        
        # Temporarily set KSmac to compute authentication token
        self.crypto.set_keys(None, KSmac, None)
        
        # Compute authentication token
        
        (Tifd, Tic) = self.pace_compute_authenticational_kototoken(pace_oid, IFD_efhmerios_pub_key, IC_efhmerios_pub_key)
        
        logging.debug("Tifd : " + Tifd.hex())
        logging.debug("Tic  : " + Tic.hex())
        
        dad = self.tlv.encode_ber_tlv(0x7c,
            self.tlv.encode_ber_tlv(0x85, Tifd))
        (sw, resp) = self.smartcard.cmd_general_authenticate(0x00, dad)
        
        offset = 0
        (t, l, v, tlv, offset) = self.tlv.parse_ber_tlv(resp, offset, 0)
        assert (t == 0x7c), "Unexpected tag in GA response"
        offset1 = 0
        (t, l, v1, tlv, offset1) = self.tlv.parse_ber_tlv(v, offset1, 1)
        assert (t == 0x86), "Unexpected tag in GA response"
        RTic = v1
        
        # Compare received and computed Tic
        
        logging.debug("RTic : " + RTic.hex() + ", please compare with Tic and press CTRL-C if they are not equal")
        
        # PACE succesful. Initialize secure messaging. 
        # When using PACE, SSC is initialized to zero. 
        
        self.crypto.set_keys(KSenc, KSmac, bytearray.fromhex("0000000000000000"))
        
        # Select application 
        
        self.smartcard.cmd_select_application(appy)
        
        return True

