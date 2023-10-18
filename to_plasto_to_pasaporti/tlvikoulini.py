#!python3
import logging

class KouTLVis:
    def __init__(self):
        pass
        
    def chunks(self, lst, n):
        for i in range(0, len(lst), n):
            yield lst[i:i + n]
        
    def encode_simple_tlv_len(self, len):
        assert (len < 65536), "SIMPLE-TLV support lengths up to 65535"
        if (len < 255):
            return bytearray([len])
        return bytearray([0xFF, (len & 0xFF00) >> 8, (len & 0xFF)])
        
    def encode_ber_tlv_len(self, data):
        lelelen = len(data)
        lenbytes = bytearray([])
        while lelelen > 0:
            lenbyte = lelelen & 0xFF
            lelelen = lelelen >> 8
            lenbytes.append(lenbyte)
        if (len(lenbytes) > 1):
            lenbytes.insert(0,(len(lenbytes) | 0x80))
        return lenbytes
        
    def decode_simple_tlv_len(self, data):
        if (data[0] != 0xFF):
            return (data[0], 1)
        return (((data[1] << 8) | data[2]), 3)
    
    
    def decode_ber_tlv_tag(self, data):
        tag = data[0]
        tag_class = tag & 0xc0
        tag_constructed = tag & 0x20
        tag_printable = False
        tag_masked = tag & 0x1f
        if (not tag_constructed and tag_class == 0x00 and
            (tag_masked in [ 4, 12, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34 ])):
                tag_printable = True
        
        if (tag_masked != 0x1f):
            return (tag, tag_class, tag_constructed, tag_printable, 1)
        
        offset = 1
        while ((data[offset] & 0x80) == 0x80):
            tag = (tag << 8) | data[offset]
            offset += 1
        tag = (tag << 8) | data[offset]
        return (tag, tag_class, tag_constructed, tag_printable, (offset + 1))
                
    def decode_ber_tlv_len(self, data):
        if (data[0] & 0x80 == 0):
            return(data[0], 1)
        len_of_len = data[0] & 0x7f
        len = 0
        for i in range(len_of_len):
            len = len << 8 | data[1 + i]
        return(len, (1 + len_of_len))
        
    def is_padding(self, data, offset):
        for i in data[offset:]:
            if (i != 0x00):
                return False
        return True

    def print_ber_tlv(self, data, level=0, goffset=0):
        offset = 0
        tlv_list = []
        while (offset < len(data)):
            if (self.is_padding(data, offset)):
                logging.debug("### TLV-BER: Skipping zero-padding after offset " + str(offset))
                break
            (t, t_class, t_constructed, t_printable, skip1) = self.decode_ber_tlv_tag(data[offset:])
            offset += skip1
            
            (l, skip2) = self.decode_ber_tlv_len(data[offset:])
            offset += skip2

            v = data[offset:(offset + l)]
            tlv = data[:(offset + l)]
            
            v_repr = None
            if (t_printable):
                try:
                    v_repr = v.decode()
                except UnicodeDecodeError:
                    v_repr = None
            
            if (v_repr):
                v_repr1 = " = [" + v_repr + "]"
            else:
                v_repr1 = ""
            
            logging.debug("### TLV-BER: [" + str(level).zfill(3) + " @ " + str(goffset).zfill(5) + "] " +
                         ("  " * level) + 
                         "T [" + hex(t) + "] L [" + str(l) + "] V [" + v.hex() + "]" + 
                         v_repr1)
            
            goffset += (skip1 + skip2)
                         
            tlv_dict = dict()
            tlv_dict['tag'] = hex(t)
            tlv_dict['length'] = l
            
            if (v_repr):
                tlv_dict['v_repr'] = v_repr
            elif (t_constructed):
                tlv_dict['v_const'] = self.print_ber_tlv(v, level=level+1, goffset=goffset)
            else:
                tlv_dict['v_hex'] = v.hex()
                
            offset += l
            goffset += l
            
            tlv_list.append(tlv_dict)
            
        return tlv_list
  
    
    def parse_ber_tlv(self, data, offset, level=0):
        starting_offset = offset
        
        (t, t_class, t_constructed, t_printable, skip) = self.decode_ber_tlv_tag(data[offset:])
        offset += skip
        
        (l, skip) = self.decode_ber_tlv_len(data[offset:])
        offset += skip
        
        v = data[offset:(offset + l)]
        tlv = data[starting_offset:(offset + l)]
        
        return (t, l, v, tlv, (offset + l))

    def parse_simple_tlv(self, data, offset, level=0):
        starting_offset = offset
        
        t = data[offset]
        offset += 1
        
        (l, skip) = self.decode_simple_tlv_len(data[offset:])
        offset += skip

        v = data[offset:(offset + l)]
        tlv = data[starting_offset:(offset + l)]        
        
        logging.debug("TLV-SIMPLE : " + ("  " * level) + "T [" + hex(t) + "] L [" + str(l) + "] V [" + v.hex() + "]") 
        
        return (t, l, v, tlv, (offset + l))
        
    def encode_simple_tlv(self, tag, data):
        return bytearray([tag]) + self.encode_simple_tlv_len(data) + bytearray(data)
        
    def encode_ber_tlv(self, tag, data):
        if (isinstance(tag, list)):
            t = tag
        else:
            t = [tag]

        return bytearray(t) + self.encode_ber_tlv_len(data) + bytearray(data)
        
