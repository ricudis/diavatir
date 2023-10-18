#!python3

class RICAO_9303_Objects:
    def __init__(self):
    
        self.APPLICATION_LDS1 = bytearray([0xA0, 0x00, 0x00, 0x02, 0x47, 0x10, 0x01])
        self.APPLICATION_LDS2_TR = bytearray([0xA0, 0x00, 0x00, 0x02, 0x47, 0x20, 0x01])
        self.APPLICATION_LDS2_VR = bytearray([0xA0, 0x00, 0x00, 0x02, 0x47, 0x20, 0x02])
        self.APPLICATION_LDS2_AB = bytearray([0xA0, 0x00, 0x00, 0x02, 0x47, 0x20, 0x03])

        # Table 38. Mandatory and Optional Data Elements that Combine to Form
        # the Structure of Data Groups 1 (DG1) through 16 (DG16)
        
        self.FILE_EF_CARDACCESS = bytearray([0x01, 0x1c])       # EF.CARDACCESS
        self.FILE_EF_ATR_INFO = bytearray([0x2F, 0x01])         # EF.ATR/INFO
        self.FILE_EF_CARDSECURITY = bytearray([0x01, 0x1d])     # EF.CARDSECURITY
        self.FILE_EF_COM = bytearray([0x01, 0x1e])              # EF.COM
        self.FILE_EF_DG1 = bytearray([0x01, 0x01])              # EF.DG1
        self.FILE_EF_DG2 = bytearray([0x01, 0x02])              # EF.DG2
        self.FILE_EF_DG3 = bytearray([0x01, 0x03])              # EF.DG3
        self.FILE_EF_DG4 = bytearray([0x01, 0x04])              # EF.DG4
        self.FILE_EF_DG5 = bytearray([0x01, 0x05])              # EF.DG5
        self.FILE_EF_DG6 = bytearray([0x01, 0x06])              # EF.DG6
        self.FILE_EF_DG7 = bytearray([0x01, 0x07])              # EF.DG7
        self.FILE_EF_DG8 = bytearray([0x01, 0x08])              # EF.DG8
        self.FILE_EF_DG9 = bytearray([0x01, 0x09])              # EF.DG9
        self.FILE_EF_DG10 = bytearray([0x01, 0x0A])             # EF.DG10
        self.FILE_EF_DG11 = bytearray([0x01, 0x0B])             # EF.DG11
        self.FILE_EF_DG12 = bytearray([0x01, 0x0C])             # EF.DG12
        self.FILE_EF_DG13 = bytearray([0x01, 0x0D])             # EF.DG13
        self.FILE_EF_DG14 = bytearray([0x01, 0x0E])             # EF.DG14
        self.FILE_EF_DG15 = bytearray([0x01, 0x0F])             # EF.DG15
        self.FILE_EF_DG16 = bytearray([0x01, 0x10])             # EF.DG16
        self.FILE_EF_CVCA = bytearray([0x01, 0x1C])             # EF.CVCA
        self.FILE_EF_SOD = bytearray([0x01, 0x1D])              # EF.SOD
         
        self.DG_TAG_TO_FILE = dict()
        
        self.DG_TAG_TO_FILE[0x60] = self.FILE_EF_COM
        self.DG_TAG_TO_FILE[0x61] = self.FILE_EF_DG1
        self.DG_TAG_TO_FILE[0x75] = self.FILE_EF_DG2
        self.DG_TAG_TO_FILE[0x63] = self.FILE_EF_DG3
        self.DG_TAG_TO_FILE[0x76] = self.FILE_EF_DG4
        self.DG_TAG_TO_FILE[0x65] = self.FILE_EF_DG5
        self.DG_TAG_TO_FILE[0x66] = self.FILE_EF_DG6
        self.DG_TAG_TO_FILE[0x67] = self.FILE_EF_DG7
        self.DG_TAG_TO_FILE[0x68] = self.FILE_EF_DG8
        self.DG_TAG_TO_FILE[0x69] = self.FILE_EF_DG9
        self.DG_TAG_TO_FILE[0x6A] = self.FILE_EF_DG10
        self.DG_TAG_TO_FILE[0x6B] = self.FILE_EF_DG11
        self.DG_TAG_TO_FILE[0x6C] = self.FILE_EF_DG12
        self.DG_TAG_TO_FILE[0x6D] = self.FILE_EF_DG13
        self.DG_TAG_TO_FILE[0x6E] = self.FILE_EF_DG14
        self.DG_TAG_TO_FILE[0x6F] = self.FILE_EF_DG15
        self.DG_TAG_TO_FILE[0x70] = self.FILE_EF_DG16
        self.DG_TAG_TO_FILE[0x77] = self.FILE_EF_SOD

        self.OID_ID_PACE = bytearray([0x04, 0x00, 0x7f, 0x00, 0x07, 0x02, 0x02, 0x04])
        
        self.OID_ID_PACE_DH_GM = self.OID_ID_PACE + bytearray([0x01])
        self.OID_ID_PACE_ECDH_GM = self.OID_ID_PACE + bytearray([0x02])
        self.OID_ID_PACE_DH_IM = self.OID_ID_PACE + bytearray([0x03])
        self.OID_ID_PACE_ECDH_IM = self.OID_ID_PACE + bytearray([0x04])
        self.OID_ID_PACE_ECDH_CAM = self.OID_ID_PACE + bytearray([0x06])
        
        self.OID_ID_PACE_DH_GM_3DES_CBC_CBC = self.OID_ID_PACE_DH_GM + bytearray([0x01])
        self.OID_ID_PACE_DH_GM_AES_CBC_CMAC_128 = self.OID_ID_PACE_DH_GM + bytearray([0x02])
        self.OID_ID_PACE_DH_GM_AES_CBC_CMAC_192 = self.OID_ID_PACE_DH_GM + bytearray([0x03])
        self.OID_ID_PACE_DH_GM_AES_CBC_CMAC_256 = self.OID_ID_PACE_DH_GM + bytearray([0x04])
        
        self.OID_ID_PACE_ECDH_GM_3DES_CBC_CBC = self.OID_ID_PACE_ECDH_GM + bytearray([0x01])
        self.OID_ID_PACE_ECDH_GM_AES_CBC_CMAC_128 = self.OID_ID_PACE_ECDH_GM + bytearray([0x02])
        self.OID_ID_PACE_ECDH_GM_AES_CBC_CMAC_192 = self.OID_ID_PACE_ECDH_GM + bytearray([0x03])
        self.OID_ID_PACE_ECDH_GM_AES_CBC_CMAC_256 = self.OID_ID_PACE_ECDH_GM + bytearray([0x04])
        
        self.OID_ID_PACE_DH_IM_3DES_CBC_CBC = self.OID_ID_PACE_DH_IM + bytearray([0x01])
        self.OID_ID_PACE_DH_IM_AES_CBC_CMAC_128 = self.OID_ID_PACE_DH_IM + bytearray([0x02])
        self.OID_ID_PACE_DH_IM_AES_CBC_CMAC_192 = self.OID_ID_PACE_DH_IM + bytearray([0x03])
        self.OID_ID_PACE_DH_IM_AES_CBC_CMAC_256 = self.OID_ID_PACE_DH_IM + bytearray([0x04])
        
        self.OID_ID_PACE_ECDH_IM_3DES_CBC_CBC = self.OID_ID_PACE_ECDH_IM + bytearray([0x01])
        self.OID_ID_PACE_ECDH_IM_AES_CBC_CMAC_128 = self.OID_ID_PACE_ECDH_IM + bytearray([0x02])
        self.OID_ID_PACE_ECDH_IM_AES_CBC_CMAC_192 = self.OID_ID_PACE_ECDH_IM + bytearray([0x03])
        self.OID_ID_PACE_ECDH_IM_AES_CBC_CMAC_256 = self.OID_ID_PACE_ECDH_IM + bytearray([0x04])

        self.OID_ID_PACE_ECDH_CAM_3DES_CBC_CBC = self.OID_ID_PACE_ECDH_CAM + bytearray([0x01])
        self.OID_ID_PACE_ECDH_CAM_AES_CBC_CMAC_128 = self.OID_ID_PACE_ECDH_CAM + bytearray([0x02])
        self.OID_ID_PACE_ECDH_CAM_AES_CBC_CMAC_192 = self.OID_ID_PACE_ECDH_CAM + bytearray([0x03])
        self.OID_ID_PACE_ECDH_CAM_AES_CBC_CMAC_256 = self.OID_ID_PACE_ECDH_CAM + bytearray([0x04])

        self.PACE_KEY_ALG_DH = 1
        self.PACE_KEY_ALG_ECDH = 2

        self.PACE_MAPPING_IM = 1
        self.PACE_MAPPING_GM = 2
        self.PACE_MAPPING_CAM = 3
        
        self.PACE_CRYPTO_ALG_3DES_CBC_CBC = 1
        self.PACE_CRYPTO_ALG_AES_CBC_CMAC_128 = 2
        self.PACE_CRYPTO_ALG_AES_CBC_CMAC_192 = 3
        self.PACE_CRYPTO_ALG_AES_CBC_CMAC_256 = 4
        
        self.PACE_PARAM_IDX_KEY_ALG = 0
        self.PACE_PARAM_IDX_MAPPING = 1
        self.PACE_PARAM_IDX_CRYPTO_ALG = 2
        self.PACE_PARAM_IDX_SDP = 3
        
        self.PACE_KEY_ALG_NAMES = dict()
        self.PACE_KEY_ALG_NAMES[self.PACE_KEY_ALG_DH] = "DH"
        self.PACE_KEY_ALG_NAMES[self.PACE_KEY_ALG_ECDH] = "ECDH"

        self.PACE_MAPPING_NAMES = dict()
        self.PACE_MAPPING_NAMES[self.PACE_MAPPING_IM] = "Integrated Mapping"
        self.PACE_MAPPING_NAMES[self.PACE_MAPPING_GM] = "Generic Mapping"
        self.PACE_MAPPING_NAMES[self.PACE_MAPPING_CAM] = "Chip Access Mapping"
        
        self.PACE_CRYPTO_ALG_NAMES = dict()
        self.PACE_CRYPTO_ALG_NAMES[self.PACE_CRYPTO_ALG_3DES_CBC_CBC] = "3DES-CBC-CBC"
        self.PACE_CRYPTO_ALG_NAMES[self.PACE_CRYPTO_ALG_AES_CBC_CMAC_128] = "AES-CBC-CMAC-128"
        self.PACE_CRYPTO_ALG_NAMES[self.PACE_CRYPTO_ALG_AES_CBC_CMAC_192] = "AES-CBC-CMAC-192"
        self.PACE_CRYPTO_ALG_NAMES[self.PACE_CRYPTO_ALG_AES_CBC_CMAC_256] = "AES-CBC-CMAC-256"
                
        self.PACE_PARAMETERS = dict()
        self.PACE_PARAMETERS[self.OID_ID_PACE_DH_GM_3DES_CBC_CBC.hex()] = [self.PACE_KEY_ALG_DH, self.PACE_MAPPING_GM, self.PACE_CRYPTO_ALG_3DES_CBC_CBC]
        self.PACE_PARAMETERS[self.OID_ID_PACE_DH_GM_AES_CBC_CMAC_128.hex()] = [self.PACE_KEY_ALG_DH, self.PACE_MAPPING_GM, self.PACE_CRYPTO_ALG_AES_CBC_CMAC_128]
        self.PACE_PARAMETERS[self.OID_ID_PACE_DH_GM_AES_CBC_CMAC_192.hex()] = [self.PACE_KEY_ALG_DH, self.PACE_MAPPING_GM, self.PACE_CRYPTO_ALG_AES_CBC_CMAC_192]
        self.PACE_PARAMETERS[self.OID_ID_PACE_DH_GM_AES_CBC_CMAC_256.hex()] = [self.PACE_KEY_ALG_DH, self.PACE_MAPPING_GM, self.PACE_CRYPTO_ALG_AES_CBC_CMAC_256]
        self.PACE_PARAMETERS[self.OID_ID_PACE_ECDH_GM_3DES_CBC_CBC.hex()] = [self.PACE_KEY_ALG_ECDH, self.PACE_MAPPING_GM, self.PACE_CRYPTO_ALG_3DES_CBC_CBC]
        self.PACE_PARAMETERS[self.OID_ID_PACE_ECDH_GM_AES_CBC_CMAC_128.hex()] = [self.PACE_KEY_ALG_ECDH, self.PACE_MAPPING_GM, self.PACE_CRYPTO_ALG_AES_CBC_CMAC_128]
        self.PACE_PARAMETERS[self.OID_ID_PACE_ECDH_GM_AES_CBC_CMAC_192.hex()] = [self.PACE_KEY_ALG_ECDH, self.PACE_MAPPING_GM, self.PACE_CRYPTO_ALG_AES_CBC_CMAC_192]
        self.PACE_PARAMETERS[self.OID_ID_PACE_ECDH_GM_AES_CBC_CMAC_256.hex()] = [self.PACE_KEY_ALG_ECDH, self.PACE_MAPPING_GM, self.PACE_CRYPTO_ALG_AES_CBC_CMAC_256]
        self.PACE_PARAMETERS[self.OID_ID_PACE_DH_IM_3DES_CBC_CBC.hex()] = [self.PACE_KEY_ALG_DH, self.PACE_MAPPING_IM, self.PACE_CRYPTO_ALG_3DES_CBC_CBC]
        self.PACE_PARAMETERS[self.OID_ID_PACE_DH_IM_AES_CBC_CMAC_128.hex()] = [self.PACE_KEY_ALG_DH, self.PACE_MAPPING_IM, self.PACE_CRYPTO_ALG_AES_CBC_CMAC_128]
        self.PACE_PARAMETERS[self.OID_ID_PACE_DH_IM_AES_CBC_CMAC_192.hex()] = [self.PACE_KEY_ALG_DH, self.PACE_MAPPING_IM, self.PACE_CRYPTO_ALG_AES_CBC_CMAC_192]
        self.PACE_PARAMETERS[self.OID_ID_PACE_DH_IM_AES_CBC_CMAC_256.hex()] = [self.PACE_KEY_ALG_DH, self.PACE_MAPPING_IM, self.PACE_CRYPTO_ALG_AES_CBC_CMAC_256]
        self.PACE_PARAMETERS[self.OID_ID_PACE_ECDH_IM_3DES_CBC_CBC.hex()] = [self.PACE_KEY_ALG_ECDH, self.PACE_MAPPING_IM, self.PACE_CRYPTO_ALG_3DES_CBC_CBC]
        self.PACE_PARAMETERS[self.OID_ID_PACE_ECDH_IM_AES_CBC_CMAC_128.hex()] = [self.PACE_KEY_ALG_ECDH, self.PACE_MAPPING_IM, self.PACE_CRYPTO_ALG_AES_CBC_CMAC_128]
        self.PACE_PARAMETERS[self.OID_ID_PACE_ECDH_IM_AES_CBC_CMAC_192.hex()] = [self.PACE_KEY_ALG_ECDH, self.PACE_MAPPING_IM, self.PACE_CRYPTO_ALG_AES_CBC_CMAC_192]
        self.PACE_PARAMETERS[self.OID_ID_PACE_ECDH_IM_AES_CBC_CMAC_256.hex()] = [self.PACE_KEY_ALG_ECDH, self.PACE_MAPPING_IM, self.PACE_CRYPTO_ALG_AES_CBC_CMAC_256]
        self.PACE_PARAMETERS[self.OID_ID_PACE_ECDH_CAM_3DES_CBC_CBC.hex()] = [self.PACE_KEY_ALG_ECDH, self.PACE_MAPPING_CAM, self.PACE_CRYPTO_ALG_3DES_CBC_CBC]
        self.PACE_PARAMETERS[self.OID_ID_PACE_ECDH_CAM_AES_CBC_CMAC_128.hex()] = [self.PACE_KEY_ALG_ECDH, self.PACE_MAPPING_CAM, self.PACE_CRYPTO_ALG_AES_CBC_CMAC_128]
        self.PACE_PARAMETERS[self.OID_ID_PACE_ECDH_CAM_AES_CBC_CMAC_192.hex()] = [self.PACE_KEY_ALG_ECDH, self.PACE_MAPPING_CAM, self.PACE_CRYPTO_ALG_AES_CBC_CMAC_192]
        self.PACE_PARAMETERS[self.OID_ID_PACE_ECDH_CAM_AES_CBC_CMAC_256.hex()] = [self.PACE_KEY_ALG_ECDH, self.PACE_MAPPING_CAM, self.PACE_CRYPTO_ALG_AES_CBC_CMAC_256]
        
        # Standardized Domain Parameters ICAO 9203-11 9.5.1
        self.PACE_SDP_GFP_1024_MODP_160_POS = 0
        self.PACE_SDP_GFP_2048_MODP_224_POS = 1
        self.PACE_SDP_GFP_2048_MODP_256_POS = 2
        self.PACE_SDP_ECP_NIST_SECP192r1 = 8
        self.PACE_SDP_ECP_BRAINPOOLP192r1 = 9
        self.PACE_SDP_ECP_NIST_SECP224r1 = 10
        self.PACE_SDP_ECP_BRAINPOOLP224r1 = 11
        self.PACE_SDP_ECP_NIST_SECP256r1 = 12
        self.PACE_SDP_ECP_BRAINPOOLP256r1 = 13
        self.PACE_SDP_ECP_BRAINPOOLP320r1 = 14
        self.PACE_SDP_ECP_NIST_SECP384r1 = 15
        self.PACE_SDP_ECP_BRAINPOOLP384r1 = 16
        self.PACE_SDP_ECP_BRAINPOOLP512r1 = 17
        self.PACE_SDP_ECP_NIST_SECP521r1 = 18
        
        self.PACE_SDP_NAMES = dict()
        self.PACE_SDP_NAMES[self.PACE_SDP_GFP_1024_MODP_160_POS] = "1024-bit MODP Group with 160-bit Prime Order Subgroup 1024/160 GFP [RFC 5114]"
        self.PACE_SDP_NAMES[self.PACE_SDP_GFP_2048_MODP_224_POS] = "2048-bit MODP Group with 224-bit Prime Order Subgroup 2048/224 GFP [RFC 5114]"
        self.PACE_SDP_NAMES[self.PACE_SDP_GFP_2048_MODP_256_POS] = "2048-bit MODP Group with 256-bit Prime Order Subgroup 2048/256 GFP [RFC 5114]"
        self.PACE_SDP_NAMES[self.PACE_SDP_ECP_NIST_SECP192r1] = "NIST P-192 (secp192r1) 192 ECP [RFC 5114], [FIPS 186-4]"
        self.PACE_SDP_NAMES[self.PACE_SDP_ECP_BRAINPOOLP192r1] = "BrainpoolP192r1 192 ECP [RFC 5639]"        
        self.PACE_SDP_NAMES[self.PACE_SDP_ECP_NIST_SECP224r1] = "NIST P-224 (secp224r1) * 224 ECP [RFC 5114], [FIPS 186-4]"
        self.PACE_SDP_NAMES[self.PACE_SDP_ECP_BRAINPOOLP224r1] = "BrainpoolP224r1 224 ECP [RFC 5639]"
        self.PACE_SDP_NAMES[self.PACE_SDP_ECP_NIST_SECP256r1] = "NIST P-256 (secp256r1) 256 ECP [RFC 5114], [FIPS 186-4]"
        self.PACE_SDP_NAMES[self.PACE_SDP_ECP_BRAINPOOLP256r1] = "BrainpoolP256r1 256 ECP [RFC 5639]"
        self.PACE_SDP_NAMES[self.PACE_SDP_ECP_BRAINPOOLP320r1] = "BrainpoolP320r1 320 ECP [RFC 5639]"
        self.PACE_SDP_NAMES[self.PACE_SDP_ECP_NIST_SECP384r1] = "NIST P-384 (secp384r1) 384 ECP [RFC 5114], [FIPS 186-4]" 
        self.PACE_SDP_NAMES[self.PACE_SDP_ECP_BRAINPOOLP384r1] = "BrainpoolP384r1 384 ECP [RFC 5639]"
        self.PACE_SDP_NAMES[self.PACE_SDP_ECP_BRAINPOOLP512r1] = "BrainpoolP512r1 512 ECP [RFC 5639]"
        self.PACE_SDP_NAMES[self.PACE_SDP_ECP_NIST_SECP521r1] = "NIST P-521 (secp521r1) 521 ECP [RFC 5114], [FIPS 186-4]"
        
        self.SW_CODES_NONFATAL = [0x9000, 0x6282, 0x6A82, 0x6982, 0x6986]
        
        self.SW_CODES = dict()
        
        self.SW_CODES[0x63cf] = "Authentification failed"
        
        self.SW_CODES[0x6200] = "No information given"
        self.SW_CODES[0x6281] = "Returned data may be corrupted"
        self.SW_CODES[0x6282] = "The end of the file has been reached before the end of reading"
        self.SW_CODES[0x6283] = "Invalid DF"
        self.SW_CODES[0x6284] = "Selected file is not valid. File descriptor error"
        self.SW_CODES[0x6300] = "Authentification failed. Invalid secret code or forbidden value"
        self.SW_CODES[0x6381] = "File filled up by the last write"
        self.SW_CODES[0x6501] = "Memory failure. There have been problems in writing or reading the EEPROM. Other hardware problems may also bring this error"
        self.SW_CODES[0x6581] = "Write problem / Memory failure / Unknown mode"
        self.SW_CODES[0x6700] = "Incorrect length or address range error"
        self.SW_CODES[0x6800] = "The request function is not supported by the card"
        self.SW_CODES[0x6881] = "Logical channel not supported"
        self.SW_CODES[0x6882] = "Secure messaging not supported"
        self.SW_CODES[0x6900] = "No successful transaction executed during session"
        self.SW_CODES[0x6981] = "Cannot select indicated file, command not compatible with file organization"
        self.SW_CODES[0x6982] = "Access conditions not fulfilled"
        self.SW_CODES[0x6983] = "Secret code locked"
        self.SW_CODES[0x6984] = "Referenced data invalidated"
        self.SW_CODES[0x6985] = "No currently selected EF, no command to monitor / no Transaction Manager File"
        self.SW_CODES[0x6986] = "Command not allowed (no current EF)"
        self.SW_CODES[0x6987] = "Expected SM data objects missing"
        self.SW_CODES[0x6988] = "SM data objects incorrect"
        self.SW_CODES[0x6A00] = "Bytes P1 and/or P2 are incorrect."
        self.SW_CODES[0x6A80] = "The parameters in the data field are incorrect"
        self.SW_CODES[0x6A81] = "Card is blocked or command not supported"
        self.SW_CODES[0x6A82] = "File not found"
        self.SW_CODES[0x6A83] = "Record not found"
        self.SW_CODES[0x6A84] = "There is insufficient memory space in record or file"
        self.SW_CODES[0x6A85] = "Lc inconsistent with TLV structure"
        self.SW_CODES[0x6A86] = "Incorrect parameters P1-P2"
        self.SW_CODES[0x6A87] = "The P3 value is not consistent with the P1 and P2 values"
        self.SW_CODES[0x6A88] = "Referenced data not found"
        self.SW_CODES[0x6B00] = "Incorrect reference; illegal address; Invalid P1 or P2 parameter"
        self.SW_CODES[0x6D00] = "Command not allowed. Invalid instruction byte (INS)"
        self.SW_CODES[0x6E00] = "Incorrect application (CLA parameter of a command)"
        self.SW_CODES[0x6F00] = "Checking error"
        self.SW_CODES[0x9000] = "Command executed without error"
        self.SW_CODES[0x9100] = "Purse Balance error cannot perform transaction"
        self.SW_CODES[0x9102] = "Purse Balance error"
        self.SW_CODES[0x9202] = "Write problem / Memory failure"
        self.SW_CODES[0x9240] = "Error, memory problem"
        self.SW_CODES[0x9404] = "Purse selection error or invalid purse"
        self.SW_CODES[0x9406] = "Invalid purse detected during the replacement debit step"
        self.SW_CODES[0x9408] = "Key file selection error"
        self.SW_CODES[0x9800] = "Security Warning"
        self.SW_CODES[0x9804] = "Access authorization not fulfilled"
        self.SW_CODES[0x9806] = "Access authorization in Debit not fulfilled for the replacement debit step"
        self.SW_CODES[0x9820] = "No temporary transaction key established"
        self.SW_CODES[0x9834] = "Error, Update SSD order sequence not respected (should be used if SSD Update commands are received out of sequence)"
