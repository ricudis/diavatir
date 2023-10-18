#!python3
from to_plasto_to_pasaporti import RICAO_9303_Objects
from to_plasto_to_pasaporti import KouTLVis
import logging

class RICAO_9303_Parser:
    def __init__(self):
        self.objects = RICAO_9303_Objects()
        self.tlv = KouTLVis()
        
    def psalidi(self, data, lelen):
        if (len(data) < lelen):
            return (bytearray(data).hex(), [])
        return(bytearray(data[:lelen]).hex(), data[lelen:])
        
    def parse_mutsuna_biometric_data(self, data):
        logging.debug("### MUTSUNA BIOMETRICS : " + data.hex())
        
        parsed = dict()
        parsed['mutsuna'] = dict()
        
        if (len(data) < 46):
            logging.warning("### Invalid biometrics")
            return parsed
        
        # The record format of ISO/IEC 19794-5 biometrics
        # is a bit hard to find without paying for the actual
        # document. I parse and dump it here just so the next
        # person who googles it gets at least some half baked
        # code and thanks me for it. 
        
        # Also by parsing the data here (which are actually
        # mostly absent on the ICAO 9303 documents I've personally
        # managed to read), we'll get more and more conspiracy
        # theorists knowledgeable to what data they are stored
        # inside their passports. This is got to go very nicely. 
        
        tmp = data
        
        frh = dict()
        (frh['format_identifier'], tmp) = self.psalidi(tmp, 4)
        (frh['version_number'], tmp) = self.psalidi(tmp, 4)
        (frh['length_of_record'], tmp) = self.psalidi(tmp, 4)
        (frh['number_of_facial_images'], tmp) = self.psalidi(tmp, 2)
        
        nofi = int(frh['number_of_facial_images'], 16)
        
        parsed['mutsuna']['facial_record_header'] = frh
        
        facial_image_data = []
        
        for x in range(nofi):
            fi = dict()
            (fi['facial_record_data_length'], tmp) = self.psalidi(tmp, 4)
            (fi['number_of_feature_points'], tmp) = self.psalidi(tmp, 2)

            # I hope this is 0 because I can't find the length 
            # of the inner data element
            nofp = int(fi['number_of_feature_points'], 16)
        
            # This field is named "GENDER" in ISO/IEC 19794-5 standard. 
            # As we all know, gender is a social construct and has no
            # place on a biometrics data standard. It should be renamed
            # to "biological_sex". We also know that sex is not binary,
            # but we are not sure if the 1 byte allocated for it is
            # wide enough.
            #
            # Somebody ought to seriously petition ISO about all that. 
        
            (fi['gender'], tmp) = self.psalidi(tmp, 1)
            (fi['eye_colour'], tmp) = self.psalidi(tmp, 1)
            (fi['hair_colour'], tmp) = self.psalidi(tmp, 4)
            (fi['property_mask'], tmp) = self.psalidi(tmp, 3)
            (fi['expression'], tmp) = self.psalidi(tmp, 2)
            (fi['pose_angle'], tmp) = self.psalidi(tmp, 3)
            (fi['pose_angle_uncertainty'], tmp) = self.psalidi(tmp, 3)
            
            # Parse nofp Feature Point headers here
            
            ii = dict()
            (ii['face_image_type'], tmp) = self.psalidi(tmp, 1)
            (ii['image_data_type'], tmp) = self.psalidi(tmp, 1)
            (ii['width'], tmp) = self.psalidi(tmp, 2)
            (ii['height'], tmp) = self.psalidi(tmp, 2)
            (ii['image_colour_space'], tmp) = self.psalidi(tmp, 1)
            (ii['source_type'], tmp) = self.psalidi(tmp, 1)
            (ii['device_type'], tmp) = self.psalidi(tmp, 2)
            (ii['quality'], tmp) = self.psalidi(tmp, 2)
            
            facial_image_record = dict()
            facial_image_record['facial_information'] = fi
            # facial_image_record['feature_point'] = fp
            facial_image_record['image_information'] = ii
            
            facial_image_data.append(facial_image_record)
        
        parsed['mutsuna']['facial_image_data'] = facial_image_data    

        # Now we scrape all this parsing and just go to a fixed offset...
        jpeg_offset = 46
        jpeg = bytes(data[jpeg_offset:])

        if (not (jpeg[0] == 0xff and jpeg[-2] == 0xff and jpeg[-1] == 0xd9)):
            logging.warning("### Invalid JPEG format")
            return parsed
            
        parsed['mutsuna']['jpeg'] = jpeg
        return parsed

    def parse_ef_com(self, data):
        logging.debug("EF.COM     : " + data.hex())
        
        # Parse EF.COM to extract the list of DG files
    
        parsed = dict()
        parsed['dg_file_tags'] = []
        parsed['lds_version'] = None
        parsed['unicode_version'] = None
        
        parsed['tlv'] = self.tlv.print_ber_tlv(data, 0)

        offset = 0
        (t, l, v, tlv, offset) = self.tlv.parse_ber_tlv(data, offset, 0)
        assert (offset == len(data) and (t == 0x60)), "Unexpected data in EF.COM"
        
        offset = 0
        while (offset < len(v)):
            (t, l, v1, data2, offset) = self.tlv.parse_ber_tlv(v, offset, 1)
            if (t == 0x5f01):
                parsed['lds_version'] = v1.decode()
            elif (t == 0x5f36):
                parsed['unicode_version'] = v1.decode()
            elif (t == 0x5c):
                parsed['dg_file_tags'] = v1

        logging.debug("### EF.COM LDS version       :" + parsed['lds_version'])
        logging.debug("### EF.COM Unicode version   :" + parsed['unicode_version'])
        logging.debug("### EF.COM Supported DG tags :" + parsed['dg_file_tags'].hex())
        return parsed
        
    def parse_ef_dg1(self, data):
        logging.debug("EF.DG1     : " + data.hex())
        
        parsed = dict()

        parsed['tlv'] = self.tlv.print_ber_tlv(data, 0)        
    
        offset = 0
        (t, l, v, tlv, offset) = self.tlv.parse_ber_tlv(data, offset, 0)
        assert (offset == len(data) and (t == 0x61)), "Unexpected data in DG1"
        
        offset = 0
        (t, l, v1, tlv1, offset) = self.tlv.parse_ber_tlv(v, offset, 2)
        assert (offset == len(v) and (t == 0x5f1f)), "Unexpected data in DG1"
        
        parsed['MRZ'] = v1.decode()
        
        logging.debug("### DG1.COM MRZ              :" + parsed['MRZ'])
        return parsed
        

    def parse_ef_dg2(self, data):
        logging.debug("EF.DG2     : " + data.hex())
        
        parsed = dict()
        
        parsed['tlv'] = self.tlv.print_ber_tlv(data, 0)
        
        offset = 0
        (t, l, v, tlv, offset) = self.tlv.parse_ber_tlv(data, offset, 0)
        assert (offset == len(data) and (t == 0x75)), "Unexpected data in DG2 1"
        
        offset = 0
        (t, l, v1, tlv, offset) = self.tlv.parse_ber_tlv(v, offset, 1)
        assert (offset == len(v) and (t == 0x7f61)), "Unexpected data in DG2 2"
        
        v3 = []
        offset1 = 0
        while (offset1 < len(v1)):
            (t, l, v2, tlv, offset1) = self.tlv.parse_ber_tlv(v1, offset1, 2)
            if (t == 0x02):
                parsed['instances'] = v2
            elif (t == 0x7f60):
                offset2 = 0
                while (offset2 < len(v2)):
                    (t, l, v3, tlv, offset2) = self.tlv.parse_ber_tlv(v2, offset2, 3)
                    if (t == 0x5f2e):
                        parsed['biometric_data_5f2e'] = self.parse_mutsuna_biometric_data(v3)
                    elif (t == 0x7f2e):
                        parsed['biometric_data_7f2e'] = self.parse_mutsuna_biometric_data(v3)
                    elif (t == 0xa1):
                        offset3 = 0
                        while (offset3 < len(v3)):
                            (t, l, v4, tlv, offset3) = self.tlv.parse_ber_tlv(v3, offset3, 4)
                            if (t == 0x80):
                                parsed['ICAO_header_version'] = v4
                            elif (t == 0x81):
                                parsed['biometric_type'] = v4
                            elif (t == 0x82):
                                parsed['biometric_subtype'] = v4
                            elif (t == 0x83):
                                parsed['creation_datetime'] = v4
                            elif (t == 0x85):
                                parsed['validity_period'] = v4
                            elif (t == 0x86):
                                parsed['creator_of_reference_data'] = v4
                            elif (t == 0x87):
                                parsed['format_owner'] = v4
                            elif (t == 0x88):
                                parsed['format_type'] = v4
        return parsed
        
    def parse_ef_dg3(self, data):
        logging.debug("EF.DG3     : " + data.hex())
        
        parsed = dict()
        
        parsed['tlv'] = self.tlv.print_ber_tlv(data, 0)
        
        offset = 0
        (t, l, v, tlv, offset) = self.tlv.parse_ber_tlv(data, offset, 0)
        assert (offset == len(data) and (t == 0x63)), "Unexpected data in DG3 1"
        
        offset = 0
        (t, l, v1, tlv, offset) = self.tlv.parse_ber_tlv(v, offset, 1)
        assert (offset == len(v) and (t == 0x7f61)), "Unexpected data in DG3 2"
        
        v3 = []
        offset1 = 0
        while (offset1 < len(v1)):
            (t, l, v2, tlv, offset1) = self.tlv.parse_ber_tlv(v1, offset1, 2)
            if (t == 0x02):
                parsed['instances'] = v2
            elif (t == 0x7f60):
                offset2 = 0
                while (offset2 < len(v2)):
                    (t, l, v3, tlv, offset2) = self.tlv.parse_ber_tlv(v2, offset2, 3)
                    if (t == 0x5f2e):
                        parsed['biometric_data_5f2e'] = v3
                        parsed['biometric_data_5f2e'] = self.parse_mutsuna_biometric_data(v3)
                    elif (t == 0x7f2e):
                        parsed['biometric_data_7f2e'] = v3
                        parsed['biometric_data_7f2e'] = self.parse_mutsuna_biometric_data(v3)
                    elif (t == 0xa1):
                        offset3 = 0
                        while (offset3 < len(v3)):
                            (t, l, v4, tlv, offset3) = self.tlv.parse_ber_tlv(v3, offset3, 4)
                            if (t == 0x80):
                                parsed['ICAO_header_version'] = v4
                            elif (t == 0x81):
                                parsed['biometric_type'] = v4
                            elif (t == 0x82):
                                parsed['biometric_subtype'] = v4
                            elif (t == 0x83):
                                parsed['creation_datetime'] = v4
                            elif (t == 0x85):
                                parsed['validity_period'] = v4
                            elif (t == 0x86):
                                parsed['creator_of_reference_data'] = v4
                            elif (t == 0x87):
                                parsed['format_owner'] = v4
                            elif (t == 0x88):
                                parsed['format_type'] = v4
        return parsed
        
    def parse_ef_dg14(self, data):
        logging.debug("EF.DG14    : " + data.hex())
        
        parsed = dict()
        
        parsed['tlv'] = self.tlv.print_ber_tlv(data, 0)
        
        offset = 0
        (t, l, v, tlv, offset) = self.tlv.parse_ber_tlv(data, offset, 0)
        assert (offset == len(data) and (t == 0x6e)), "Unexpected data in DG14"
        
        return parsed
        
    def parse_ef_dg15(self, data):
        logging.debug("EF.DG15    : " + data.hex())
        
        parsed = dict()

        parsed['tlv'] = self.tlv.print_ber_tlv(data, 0)        
        
        offset = 0
        (t, l, v, tlv, offset) = self.tlv.parse_ber_tlv(data, offset, 0)
        assert (offset == len(data) and (t == 0x6f)), "Unexpected data in DG15"
        
        return parsed
        
    def parse_ef_sod(self, data):
        logging.debug("EF.SOD    : " + data.hex())
        
        parsed = dict()

        parsed['tlv'] = self.tlv.print_ber_tlv(data, 0)
        
        return parsed
        
    def parse_ef_cardaccess(self, data):
        logging.debug("EF.CARDACCESS    : " + data.hex())
        
        parsed = dict()
        
        parsed['tlv'] = self.tlv.print_ber_tlv(data, 0)

        # There's a possible conflict between EF.CARDACCESS and EF.CVCA

        offset1 = 0
        (t, l, v1, tlv, offset1) = self.tlv.parse_ber_tlv(data, offset1, 0)
        if (t == 0x42):
            logging.warning("Got EF.CVCA instead of EF.CARDACCESS")
            return parsed
        assert (t == 0x31), "Unexpected tag in EF.CARDACCESS"
        
        offset2 = 0
        (t, l, v2, tlv, offset2) = self.tlv.parse_ber_tlv(v1, offset2, 1)
        assert (t == 0x30), "Unexpected tag in EF.CARDACCESS"
        
        offset3 = 0
        (t, l, v3, tlv, offset3) = self.tlv.parse_ber_tlv(v2, offset3, 2)
        assert (t == 0x06), "Unexpected tag in EF.CARDACCESS"
        parsed['pace_oid'] = v3
        logging.debug("PACE OID : " + parsed['pace_oid'].hex())
        
        (t, l, v3, tlv, offset3) = self.tlv.parse_ber_tlv(v2, offset3, 2)
        assert (t == 0x02), "Unexpected tag in EF.CARDACCESS"
        parsed['version'] = v3
        logging.debug("VERSION : " + parsed['version'].hex())
        
        parameterId = None
        
        if (offset3 < len(v2)):
            (t, l, v3, tlv, offset3) = self.tlv.parse_ber_tlv(v2, offset3, 2)
            assert(t == 0x02), "Unexpected tag in EF.CARDACCESS"
            parameterId = v3[0]
            logging.debug("PACE parameterId : " + hex(parameterId))
        
        assert (parsed['pace_oid'].hex() in self.objects.PACE_PARAMETERS), "Unknown PACE OID in EF.CARDACCESS"
        
        parsed['parameterId'] = parameterId
        parsed['pace_parameters'] = self.objects.PACE_PARAMETERS[parsed['pace_oid'].hex()]
        parsed['pace_parameters'].append(parameterId)
        logging.debug("PACE PARAMETERS : " + str(parsed['pace_parameters']))
        
        return parsed
        
    def parse_ef_atr_info(self, data):
        logging.debug("EF.ATR/INFO    : " + data.hex())
        
        parsed = dict()

        parsed['tlv'] = self.tlv.print_ber_tlv(data, 0)        
        
        return parsed
        
    def parse_ef_cvca(self, data):
        logging.debug("EF.CVCA            : " + data.hex())
        
        parsed = dict()
        
        parsed['tlv'] = self.tlv.print_ber_tlv(data, 0)
        
        return parsed
        
    def parse_unknown(self, data):
        logging.debug("UNKNOWN FILE       : " + data.hex())
        
        parsed = dict()
        
        # Better safe than sorry
        
        try:
            parsed['tlv'] = self.tlv.print_ber_tlv(data, 0)
        except:
            pass
            
        return parsed
        
    def parse_file(self, file_id, data):
        if (not data):
            logging.debug("### Empty data, nothing to parse")
            return(dict())
            
        d = dict()
        d['hex'] = bytearray(data).hex()
    
        if (file_id == self.objects.FILE_EF_COM):
            d['parsed'] = self.parse_ef_com(data)
        elif (file_id == self.objects.FILE_EF_DG1):
            d['parsed'] = self.parse_ef_dg1(data)
        elif (file_id == self.objects.FILE_EF_DG2):
            d['parsed'] = self.parse_ef_dg2(data)
        elif (file_id == self.objects.FILE_EF_DG3):
            d['parsed'] = self.parse_ef_dg3(data)
        elif (file_id == self.objects.FILE_EF_DG14):
            d['parsed'] = self.parse_ef_dg14(data)
        elif (file_id == self.objects.FILE_EF_DG15):
            d['parsed'] = self.parse_ef_dg15(data)
        elif (file_id == self.objects.FILE_EF_SOD):
            d['parsed'] = self.parse_ef_sod(data)
        elif (file_id == self.objects.FILE_EF_CARDACCESS):
            d['parsed'] = self.parse_ef_cardaccess(data)
        elif (file_id == self.objects.FILE_EF_ATR_INFO):
            d['parsed'] = self.parse_ef_atr_info(data)
        elif (file_id == self.objects.FILE_EF_CVCA):
            d['parsed'] = self.parse_ef_cvca(data)
        else:
            logging.warning("Trying to speculatively parse unknown file " + bytearray(file_id).hex())
            d['parsed'] = self.parse_unknown(data)
        
        return d
