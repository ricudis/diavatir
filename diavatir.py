#!/usr/bin/python3
from to_plasto_to_pasaporti import KouTLVis
from to_plasto_to_pasaporti import RicudISO_7816
from to_plasto_to_pasaporti import RICAO_9303_Objects
from to_plasto_to_pasaporti import RICAO_9303_Parser
from to_plasto_to_pasaporti import RICAO_9303_Crypto
from to_plasto_to_pasaporti import RICAO_9303_BACaliaros
from to_plasto_to_pasaporti import RICAO_9303_Al_PACEino
from smartcard.CardConnection import CardConnection
from smartcard.System import readers
from smartcard.Exceptions import NoCardException

try:
    from wand.image import Image
except ImportError:
    Image = None

HIPSTER_MODE = False
try:
    from colorlog import ColoredFormatter
    HIPSTER_MODE = True
except ImportError:
    pass
     
import argparse
import sys
from logging import Formatter
import logging
import json

def skatypefix(obj):
    #
    # Python sucks sometimes
    #
    if (isinstance(obj, dict)):
        d = dict()
        for k in obj.keys():
            v = obj[k]
            if (isinstance(v, bytearray) or isinstance(v, bytes)):
                d[k] = v.hex()
            else:
                d[k] = skatypefix(v)
        return d
    elif (isinstance(obj, list)):
        l = []
        for v in obj:
            v = skatypefix(v)
            l.append(v)
        return l
    else:
        return obj

def main(args):
    conn_ctx = None
    objects = RICAO_9303_Objects()
    parser = RICAO_9303_Parser()
    parsed_data = dict()

    smartcard = None
    logging.info("Waiting for card")
    while (not smartcard):
        try:
            rdr = readers()
            conn_ctx = rdr[args.reader].createConnection()
            conn_ctx.connect(CardConnection.T1_protocol)
            logging.info("Initialized card reader " + str(rdr))
            logging.info("ATR: " + bytearray(conn_ctx.getATR()).hex())
            smartcard = RicudISO_7816(conn_ctx)
        except NoCardException:
            pass
        
    if (args.mrz):
        password = args.mrz
        is_mrz = True
    else:
        password = args.can
        is_mrz = False
    
    use_bac = args.bac
    use_pace = args.pace
    
    (sw, dummy) = smartcard.cmd_select_master_file()
    
    # Read EF.ATR/INFO file
    
    logging.info("Reading file EF.ATR/INFO")
    
    ef_atr_info_data = smartcard.func_read_tlv_file(objects.FILE_EF_ATR_INFO)
    parsed_data['atr_info'] = parser.parse_file(objects.FILE_EF_ATR_INFO, ef_atr_info_data)
    
    # Read EF.CARDACCESS file
    
    logging.info("Reading file EF.CARDACCESS")
    
    ef_cardaccess_data = smartcard.func_read_tlv_file(objects.FILE_EF_CARDACCESS)
    parsed_data['ef_cardaccess'] = parser.parse_file(objects.FILE_EF_CARDACCESS, ef_cardaccess_data) 

    if (use_bac or use_pace):
        if (use_bac):
            logging.info("Using BAC authentication")            
            icao_auth = RICAO_9303_BACaliaros(smartcard)
        if (use_pace):
            logging.info("Using PACE authentication")
            icao_auth = RICAO_9303_Al_PACEino(smartcard)
        
        icao_auth.authenticate(password, is_mrz, objects.APPLICATION_LDS1, parsed_data)
    else:
        smartcard.cmd_select_application(objects.APPLICATION_LDS1)

    # Read EF.COM file
    # 4.6.1 Header and Data Group Presence Information EF.COM (MANDATORY)
    
    logging.info("Reading file EF.COM")
    
    ef_com_data = smartcard.func_read_tlv_file(objects.FILE_EF_COM)
    
    # Parse EF.COM to extract the list of DG files
    
    parsed_data['ef_com'] = parser.parse_file(objects.FILE_EF_COM, ef_com_data)
    
    # Read EF.SOD file
    # 4.6.2 Document Security Object EF.SOD (MANDATORY)
    
    logging.info("Reading file EF.SOD")
    
    ef_sod_data = smartcard.func_read_tlv_file(objects.FILE_EF_SOD)
    parsed_data['ef_sod'] = parser.parse_file(objects.FILE_EF_SOD, ef_sod_data)
    
    # Iterate over all DG files listed in EF.COM as a good boy
    
    parsed_data['DG'] = dict()
    
    for dg_tag in parsed_data['ef_com']['parsed']['dg_file_tags']:
        if not dg_tag in objects.DG_TAG_TO_FILE:
            logging.warning("### EF.COM DG tag " + hex(dg_tag) + "unknown")
            continue
        file_id = objects.DG_TAG_TO_FILE[dg_tag]
        logging.info("Reading DG file id " + bytearray(file_id).hex() + " with tag " + hex(dg_tag))
            
        dg_data = smartcard.func_read_tlv_file(file_id)
        parsed_data['DG'][bytearray(file_id).hex()] = parser.parse_file(file_id, dg_data)
    
    if ('0101' in parsed_data['DG']):
        logging.critical("DG1 MRZ information : " + parsed_data['DG']['0101']['parsed']['MRZ'])
    
    # Now that we're done with this, iterate over all possible files like a kwlopaido
    if (args.et_tu_brute):
        try:
            parsed_data['brute'] = dict()
            for file_id_high in range(0xff + 1):
                for file_id_low in range(0xff + 1):
                    if (file_id_low == 0x3f and file_id_low == 0x00):
                        # This selects the MF. Don't do that, Phaedon!
                        logging.debug("Skipping master file")
                        continue
                    file_id = bytearray([file_id_high, file_id_low])
                    logging.info("Bruteforce reading file id " + bytearray(file_id).hex())
                    file_data = smartcard.func_read_tlv_file(file_id)
                    parsed_data['brute'] = parser.parse_file(file_id, file_data)
        except:
            pass
    
    # Output data
    
    json_object = json.dumps(skatypefix(parsed_data), indent = 4)
    
    if (args.friday13):
        outfile = args.mrz + '-data.json'
        logging.critical("Dumping information to " + outfile)
        with open(outfile, 'w') as f:
            f.write(json_object)

    if ('0102' in parsed_data['DG']):
        outfile = args.mrz + '-mutsuna.jpeg'
        mutsuna = parsed_data['DG']['0102']['parsed']['biometric_data_5f2e']['mutsuna']['jpeg']
        logging.critical("DG2 Photomuri saved to " + outfile)
        with open(outfile, 'wb') as f:
            f.write(mutsuna)
            
        if (Image is not None):
            outfile = args.mrz + '-mutsuna.png'

            logging.critical("DG2 Photomuri also saved to " + outfile + " because you peasants might not know what to do with a JPEG2000 file")

            pngimage = Image(blob = mutsuna)
            pngimage.save(filename=outfile)

            if (args.sexel):
                logging.critical("DG2 Photomuri output in sixel mode)")
                sixelimage = Image(blob = mutsuna).make_blob('sixel')
                sys.stdout.write('\n')
                sys.stdout.buffer.write(sixelimage)
                sys.stdout.write('\n')

    if (args.alchoolics_anonymous):
        smartcard.func_active_authentication()

if __name__ == '__main__':
    argument_paparser = argparse.ArgumentParser()
    passgroup = argument_paparser.add_mutually_exclusive_group(required=True)
    passgroup.add_argument("--mrz", help="MRZ information")
    passgroup.add_argument("--can", help="CAN number")
    argument_paparser.add_argument("--verbose", action="count", default=0)
    argument_paparser.add_argument("--boomer", action="store_true", help="Disable hipster mode")
    argument_paparser.add_argument("--friday13", action="store_true", help="JSON output")
    argument_paparser.add_argument("--sexel", action="store_true", help="SIXEL output")
    argument_paparser.add_argument("--et_tu_brute", action="store_true", help="Bruteforce retrieve all files in each application")
    argument_paparser.add_argument("--alchoolics_anonymous", action="store_true", help="Do Active Authentication")
    argument_paparser.add_argument("--reader", type=int, default=0)
    authgroup = argument_paparser.add_mutually_exclusive_group()
    authgroup.add_argument("--bac", action="store_true", help="Use only BAC authentication")
    authgroup.add_argument("--pace", action="store_true", help="Use only PACE authentication")
    
    args = argument_paparser.parse_args()

    # We deliberately use timestamps in logs to make it spastical to diff log files
    formatter = Formatter("%(asctime)s  %(levelname)-8s | %(message)s")

    if (not args.boomer and HIPSTER_MODE):
        formatter = ColoredFormatter("%(blue)s%(asctime)s  %(log_color)s%(levelname)-8s%(reset)s | %(log_color)s%(message)s%(reset)s")
    
    stream = logging.StreamHandler(sys.stdout)
    stream.setFormatter(formatter)
    logging.root.addHandler(stream)
    logging.root.setLevel(logging.INFO)    

    if (args.verbose == 1):
        logging.root.setLevel(logging.DEBUG)
    
    main(args)

