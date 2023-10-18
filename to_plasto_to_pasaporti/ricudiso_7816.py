#!python3
from to_plasto_to_pasaporti.tlvikoulini import KouTLVis
from to_plasto_to_pasaporti.ricao_9303_objects import RICAO_9303_Objects
from Crypto.Util import Padding
import logging

class RicudISO_7816:
    def __init__(self, conn_ctx):
        self.conn_ctx = conn_ctx
        self.tlv = KouTLVis()
        self.objects = RICAO_9303_Objects()
        self.crypto = None
        
    def set_crypto_ctx(self, crypto_ctx):
        self.crypto = crypto_ctx

    def check_sw(self, sw):
        error = "[unknown error]"
        if (sw in self.objects.SW_CODES):
            error = "[" + self.objects.SW_CODES[sw] + "]"
        
        logging.debug("<<< SW     : " + hex(sw) + " " + error)
        
        if (sw in self.objects.SW_CODES_NONFATAL):
            if (sw == 0x9000):
                logging.debug("<<< SW     : " + hex(sw) + " " + error)
            else:
                logging.warning("<<< SW     : " + hex(sw) + " " + error)
            return
        else:
            raise Exception(error)
        
    def make_cmd(self, c1, c2, p1, p2, cmd_data, Le):
        apdu = bytearray([c1, c2, p1, p2])
        if (cmd_data is not None):
            apdu += self.tlv.encode_simple_tlv_len(len(cmd_data))
            apdu += cmd_data
        if (Le is not None):
            apdu += self.tlv.encode_simple_tlv_len(Le)
        return(apdu)

    def send_plain_cmd(self, c1, c2, p1, p2, cmd_data, Le, sw_check=True):
        apdu = self.make_cmd(c1, c2, p1, p2, cmd_data, Le)
        logging.debug(">>> CMD    : " + bytearray(apdu).hex())
        resp, sw1, sw2 = self.conn_ctx.transmit(list(apdu))
        resp = bytearray(resp)
        sw = (sw1 << 8) | sw2
        logging.debug("<<< RSP    : " + resp.hex())
        if (sw_check):
            self.check_sw(sw)
        return (sw, resp)
    
        
    def send_sm_cmd(self, c1, c2, p1, p2, cmd_data, Le):
        # Whoever devised the ISO/IEC 7816-4 Secure Messaging format
        # should be locked in jail for 0x8E consecutive lifeterms, after
        # which he should be made to ask forgiveness from whoever will
        # still be dealing with this abomination then.

        # 9.8.4 Message Structure of SM APDUs
        #
        # The SM Data Objects (see [ISO/IEC 7816-4]) MUST be used in the following order:
        #
        # Command APDU: [DO‘85’ or DO‘87’] [DO‘97’] DO‘8E’.
        # Response APDU: [DO‘85’ or DO‘87’] [DO‘99’] DO‘8E’.
        #
        # In case INS is even, DO‘87’ SHALL be used, and in case INS is odd, DO‘85’ SHALL be used.
        # All SM Data Objects MUST be encoded in BER TLV as specified in [ISO/IEC 7816-4]. 
        # The command header MUST be included in the MAC calculation, therefore the class byte 
        # CLA = 0x0C MUST be used.
        #
        # The actual value of Lc will be modified to Lc’ after application of Secure Messaging.
        # If required, an appropriate data object may optionally be included into the APDU data
        # part in order to convey the original value of Lc.        
  
        # Assert on odd INS for now so we don't have to handle DO'85'
  
        assert ((c2 & 0x01) == 0), "Even INS not supported"
        
        # Mask class byte and pad command header field to a multiple of block size
        
        c1 = (c1 | 0x0C)
        ch = Padding.pad(bytearray([c1, c2, p1, p2]), 8, style='iso7816')
        logging.debug("CH         : " + ch.hex())
        
        # If no command data field is available, leave building DO‘87’ out.
        
        do87 = bytearray([])

        if (cmd_data is not None):
            cmd_data = bytearray(cmd_data)
            
            # Pad command data field
            
            dpad = Padding.pad(cmd_data, 8, style='iso7816')
            logging.debug("dpad       : " + dpad.hex())
            
            # Encrypt command data field with KSenc
            
            denc = self.crypto.RicuDES3(dpad, encrypt=True)
            logging.debug("denc       : " + denc.hex())
            
            # Construct DO'87'
            
            do87 = self.tlv.encode_ber_tlv(0x87, bytes([0x01]) + denc)
            logging.debug("DO'87'     : " + do87.hex())
        
        # If Le is not available, leave building DO‘97’ out.
        
        do97 = bytearray([])
        
        if (Le is not None):
            
            # Construct DO'97'
            
            enc_le = self.tlv.encode_simple_tlv_len(Le)
            do97 = self.tlv.encode_ber_tlv(0x97, enc_le)
            logging.debug("DO'97'     : " + do97.hex())
        
        # Concatenate command header, DO'87' and DO'97' into M
        
        M = ch + do87 + do97
        logging.debug("M          : " + M.hex())
        
        # Increment SSC, concatenate SSC and M into N and add padding
        # All these are done in the MAC function
        
        # Calculate MAC over N with KSmac
        
        CC = self.crypto.MACaroni(M)
        logging.debug("CC         : " + CC.hex())
        
        # Construct DO'8E'
        
        do8e = self.tlv.encode_ber_tlv(0x8e, CC)
        logging.debug("DO'8E'     : " + do8e.hex())
        
        # Concatenate DO'87', DO'97' and DO'8E'
        
        papdu = do87 + do97 + do8e
        
        logging.debug("PAPDU      : " + papdu.hex())
        
        # Send protected APDU and read response

        (sw, prapdu) = self.send_plain_cmd(c1, c2, p1, p2, papdu, 0, sw_check=True)
        logging.debug("PRAPDU     : " + prapdu.hex())
        
        # Scan response APDU for DO'87', DO'8E' and DO'99'
        
        scan_offset = 0
        rdo87 = bytearray([])
        rdo87_tlv = bytearray([])
        rdo8e = bytearray([])
        rdo8e_tlv = bytearray([])
        rdo99 = bytearray([])
        rdo99_tlv = bytearray([])

        while (scan_offset < len(prapdu)):
            (t, l, v, tlv, scan_offset) = self.tlv.parse_simple_tlv(prapdu, scan_offset)
            if (t == 0x87):
                rdo87 = v
                rdo87_tlv = tlv
            if (t == 0x8e):
                rdo8e = v
                rdo8e_tlvv = tlv
            if (t == 0x99):
                rdo99 = v
                rdo99_tlv = tlv
        
        assert (rdo99), "No DO'99' in SM response"
        assert (rdo8e), "No DO'8E' in SM response"
        if (rdo87):
            assert (rdo87[0] == 0x01), "Invalid DO'87' format in SM response"
        
        # Concatenate DO'87' and DO'99' in K
        
        K = rdo87_tlv + rdo99_tlv
        logging.debug("K          : " + K.hex())
        
        # Compute MAC over K with KSmac
        
        CC1 = self.crypto.MACaroni(K)
        logging.debug("CC1        : " + CC1.hex())
        
        # Compare CC1 with DO'8E'
        
        assert (CC1 == rdo8e), "MAC CC1 doesn't match DO'8E' in SM response"
        
        logging.debug("[MAC correct]")
        
        # Extract SW1 and SW2 from DO'99'
        
        assert (len(rdo99) >= 2), "DO'99' short in SM response"
        
        sw = (rdo99[0] << 8) | rdo99[1]
        self.check_sw(sw)
        
        if (not rdo87):
            logging.debug("[No DO'87]")
            return (sw, bytearray([]))
        
        # Decrypt data of DO'87' and strip padding
        
        rapdu = self.crypto.RicuDES3(rdo87[1:], encrypt=False)
        logging.debug("RAPDU      : " + rapdu.hex())
        return (sw, rapdu)
    

    def send_cmd(self, c1, c2, p1, p2, cmd, Le):
        if (self.crypto is not None and self.crypto.SSC is not None):
            (sw, resp) = self.send_sm_cmd(c1, c2, p1, p2, cmd, Le)
        else:
            (sw, resp) = self.send_plain_cmd(c1, c2, p1, p2, cmd, Le)
        return (sw, resp)


    def cmd_select_master_file(self):
        logging.info("SELECT MASTER FILE")
        return self.send_cmd(0x00, 0xA4, 0x00, 0x0c, None, 00)   
        
        
    def cmd_select_master_file_alternative(self):
        logging.info("SELECT MASTER FILE (live edition)")
        return self.send_cmd(0x00, 0x82, 0x00, 0x00, [0x3f, 0x00], 40)
        
        
    def cmd_select_application(self, application_id):
        logging.info("SELECT APPLICATION " + application_id.hex())
        return self.send_cmd(0x00, 0xA4, 0x04, 0x0C, application_id, 00)

    
    def cmd_get_challenge(self):
        logging.info("GET CHALLENGE ")
        return self.send_cmd(0x00, 0x84, 0x00, 0x00, None, 8)
    
    
    def cmd_external_authenticate(self, ext_auth_data):
        logging.info("EXTERNAL AUTHENTICATE " + ext_auth_data.hex())
        return self.send_cmd(0x00, 0x82, 0x00, 0x00, ext_auth_data, 40)
    
    
    def cmd_select_file(self, select_file_data):
        logging.info("SELECT FILE " + select_file_data.hex())
        return self.send_cmd(0x00, 0xA4, 0x02, 0x0C, select_file_data, 00)
        
        
    def cmd_manage_security_environment_authentication_template(self, mse_at_data):
        logging.info("MANAGE SECURITY ENVIRONMENT AUTHENTICATION TEMPLATE " + mse_at_data.hex())
        return self.send_cmd(0x00, 0x22, 0xC1, 0xA4, mse_at_data, 0)
        
        
    def cmd_general_authenticate(self, c1, ga_data):
        logging.info("GENERAL AUTHENTICATE " + ga_data.hex())
        return self.send_cmd(c1, 0x86, 0x00, 0x00, ga_data, 0)
        
        
    def cmd_internal_authenticate(self, int_auth_data):
        logging.info("INTERNAL AUTHENTICATE " + int_auth_data.hex())
        return self.send_cmd(0x00, 0x88, 0x00, 0x00, int_auth_data, 0)
        
        
    def cmd_read_binary(self, offset, len):
        logging.debug("## READ BINARY " + str(offset) + " " + str(len))
        p1 = 0
        p2 = 0
        
        if (offset < 256):
            p2 = offset
        else:
            p1 = (offset & 0xFF00) >> 8 
            p2 = (offset & 0xFF)
            
        return self.send_cmd(0x00, 0xB0, p1, p2, None, len)
        
        
    def func_active_authentication(self):
        # Step 1. Generate an 8 byte random:
        RND_IFD = bytearray([0xF1, 0x73, 0x58, 0x99, 0x74, 0xBF, 0x40, 0xC6])
        # Step 2. Construct command for internal authenticate and send command APDU to the eMRTD’s contactless IC:
        (sw, resp) = self.cmd_internal_authenticate(RND_IFD)
        
        
    def func_read_tlv_file(self, select_file_data, mode=2):
        # Three methods to read files from smarcards: 
        #
        # fast_and_incorrect: The obvious one. Fails due to strange
        # interactions of pycard and extended Le indicators on large
        # files
        #
        # slow_and_correct: This one works. At least for files less
        # than 32768 bytes.
        #
        # ICAO_and_stoned: Something somebody at ICAO devised from 
        # his appendix (ICAO 9303-11 Appendix D): Read file preamble
        # of 4 bytes - enough to extract the outer object TLV - then
        # read the rest of the file using the supplied length.
        
        if (mode == 1):
            logging.debug("READ FILE (method fast_and_incorrect) " + select_file_data.hex())
        elif (mode == 2):
            logging.debug("READ FILE (method slow_and_correct) " + select_file_data.hex())
        elif (mode == 3):
            logging.debug("READ FILE (method ICAO_and_stoned) " + select_file_data.hex())
        else:
            # Intentional bug so github spectators have the chance to contribute a PR
            pass
        
        file = bytearray([])
        
        # Select the target file
        (sw, dummy) = self.cmd_select_file(select_file_data)
        
        logging.info("SELECT FILE " + select_file_data.hex() + " returned SW " + hex(sw))
        
        if (sw != 0x9000):
            return file

        if (mode == 1):
            (sw, file) = self.cmd_read_binary(0, 0)
        elif (mode == 2):
            chunksize = 100
            offset = 0
        
            sw = 0x9000
        
            while (sw == 0x9000):
                logging.debug("### ITER OFFSET " + str(offset))
                (sw, chunk) = self.cmd_read_binary(offset, chunksize)
                logging.debug("### SW " + hex(sw))
                logging.debug("### CHUNK " + chunk.hex())
                offset += chunksize
                file += chunk
        elif (mode == 3):
            # READ BINARY of 4 bytes file preamble 
            (sw, file_preamble) = self.cmd_read_binary(0, 4)
            # Extract tag and length from BER-TLV object
            (file_tag, t_class, t_constructed, t_printable, skip) = self.tlv.decode_ber_tlv_tag(file_preamble)
            (file_len, skip) = self.tlv.decode_ber_tlv_len(file_preamble[skip:])
            logging.debug("### File TLV length " + str(file_len) + " " + (file_len - 4))
            # READ BINARY of remaining bytes from offset 4:
            (sw, file_rest) = self.cmd_read_binary(4, (file_len - 4))
            file = file_preamble + file_rest

        logging.info("Sucessfully read " + str(len(file)) + " bytes : " + file.hex())
        return(file)
        
