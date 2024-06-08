import io
import struct
from enum import Enum
from typing import Callable, Optional

from Crypto.Cipher import AES
from Crypto.Hash import CMAC

import config
from lrp import LRP
import ctypes
import os
import binascii

import platform

# Determine the correct shared library based on the OS
if platform.system() == "Windows":
    lib_name = "uFCoder-x86_64.dll"
    os_name = "windows"
    arch_type = "x86_64"
elif platform.system() == "Linux":
    lib_name = "libuFCoder-x86_64.so"
    os_name = "linux"
    arch_type = "x86_64"
elif platform.system() == "Darwin":
    lib_name = "libdecrypt.dylib"
    os_name = "macos"
    arch_type = "universal"
else:
    raise RuntimeError("Unsupported OS")
    
    
# Load the uFCoder shared library for macOS
lib_path = os.path.join(os.path.dirname(__file__), 'ufr-lib', os_name, arch_type, lib_name)
#lib_path = os.path.join(os.path.dirname(__file__), lib_name)
print(f"Loading library from: {lib_path}")

# Verify the library path
if not os.path.isfile(lib_path):
    raise FileNotFoundError(f"The specified library file does not exist: {lib_path}")

ufcoder = ctypes.CDLL(lib_path)

# Define DL_STATUS enum
class DL_STATUS:
    UFR_OK = 0x00
    # Define other statuses as needed

# Define necessary functions from the library
ufcoder.nt4h_decrypt_sdm_enc_file_data.argtypes = [
    ctypes.c_uint32,  # smd_read_counter
    ctypes.POINTER(ctypes.c_uint8),  # uid
    ctypes.POINTER(ctypes.c_uint8),  # auth_key
    ctypes.POINTER(ctypes.c_uint8),  # enc_file_data
    ctypes.c_uint8   # enc_file_data_len
]
ufcoder.nt4h_decrypt_sdm_enc_file_data.restype = ctypes.c_int

ufcoder.nt4h_decrypt_picc_data.argtypes = [
    ctypes.POINTER(ctypes.c_uint8),  # enc_picc_data
    ctypes.POINTER(ctypes.c_uint8),  # meta_data_aes_key
    ctypes.POINTER(ctypes.c_uint8),  # picc_data_tag
    ctypes.POINTER(ctypes.c_uint8),  # uid
    ctypes.POINTER(ctypes.c_uint32)  # sdm_read_cnt
]
ufcoder.nt4h_decrypt_picc_data.restype = ctypes.c_int

# Helper function to convert hex string to byte array
def hex_string_to_byte_array(hex_string):
    return bytes.fromhex(hex_string)



class EncMode(Enum):
    AES = 0
    LRP = 1

class ParamMode(Enum):
    SEPARATED = 0
    BULK = 1

class InvalidMessage(RuntimeError):
    pass

def decrypt_file_data1(smd_read_counter,uid_hex,auth_key_bytes,enc_file_data_hex):
    #data = request.json
    try:
        #smd_read_counter = data['smd_read_counter']
        #uid_hex = data['uid_hex']
        #auth_key_hex = data['auth_key_hex']
        #enc_file_data_hex = data['enc_file_data_hex']
        print("counter : ", type(smd_read_counter)) 
        enc_file_data_len = len(enc_file_data_hex) // 2
        print("len : ", type(enc_file_data_len)) 

        # Convert hex strings to byte arrays
        uid_bytes = hex_string_to_byte_array(uid_hex)
        #auth_key_bytes = hex_string_to_byte_array(auth_key_hex)
        enc_file_data_bytes = hex_string_to_byte_array(enc_file_data_hex)

        # Convert byte arrays to ctypes
        uid_c = (ctypes.c_uint8 * len(uid_bytes))(*uid_bytes)
        auth_key_c = (ctypes.c_uint8 * len(auth_key_bytes))(*auth_key_bytes)
        enc_file_data_c = (ctypes.c_uint8 * len(enc_file_data_bytes))(*enc_file_data_bytes)
        # Perform decryption
        status = ufcoder.nt4h_decrypt_sdm_enc_file_data(
            smd_read_counter,
            uid_c,
            auth_key_c,
            enc_file_data_c,
            enc_file_data_len
        )

        print("status : ", status)

        # Check status
        if status != DL_STATUS.UFR_OK:
            print("status if : ", status)
            return {"decrypted_message": "", "error": f"Decryption failed with status: {status}"}
        else:
            decrypted_message = bytes(enc_file_data_c).rstrip(b'\x00').decode('utf-8')
            print("status 2: ", status,decrypted_message)
            return {"decrypted_message": decrypted_message, "error":""}

    except Exception as e:
        return {"error": str(e)}



def decrypt_data1(enc_picc_data_hex,file_data,meta_data_aes_key_bytes,cmac):
    #data = request.json
    try:
        #enc_picc_data_hex = data['enc_picc_data_hex']
        #meta_data_aes_key_hex = data['meta_data_aes_key_hex']
        print(type(enc_picc_data_hex))
        print(type(meta_data_aes_key_bytes))
        # Convert hex strings to byte arrays
        enc_picc_data_bytes = hex_string_to_byte_array(enc_picc_data_hex)
        #meta_data_aes_key_bytes = hex_string_to_byte_array(meta_data_aes_key_hex)

        # Prepare output variables
        picc_data_tag = ctypes.c_uint8()
        uid = (ctypes.c_uint8 * 7)()
        sdm_read_cnt = ctypes.c_uint32()

        # Convert byte arrays to ctypes
        enc_picc_data_c = (ctypes.c_uint8 * len(enc_picc_data_bytes))(*enc_picc_data_bytes)
        meta_data_aes_key_c = (ctypes.c_uint8 * len(meta_data_aes_key_bytes))(*meta_data_aes_key_bytes)



        # Perform decryption
        status = ufcoder.nt4h_decrypt_picc_data(
            enc_picc_data_c,
            meta_data_aes_key_c,
            ctypes.byref(picc_data_tag),
            uid,
            ctypes.byref(sdm_read_cnt)
        )

        # Check status
        if status != DL_STATUS.UFR_OK:
            return {"error": f"PICC data decryption failed with status: {status}"}
        else:
            uid_str = ''.join(f'{byte:02X}' for byte in uid)
            sdm_read_cnt_str = sdm_read_cnt.value
            #print("Validate : ",validate_plain_sun(uid,sdm_read_cnt,cmac,meta_data_aes_key_bytes,None))
            ascii_mac_in = (ctypes.c_uint8*256)()
            mac_in_len = 0
            #print("Validate using uFCoder : ", ufcoder.nt4h_check_sdm_mac(sdm_read_cnt, uid, meta_data_aes_key_bytes, ascii_mac_in , mac_in_len, cmac))
            #print("validating mac with python code :",verify_mac(sdm_read_cnt_str,uid_str,meta_data_aes_key_bytes,file_data,"70",cmac))
            print("sdm_read_cnt_str",sdm_read_cnt_str,uid_str,file_data,cmac)
            print("validating mac with python code 1:",verify_mac(sdm_read_cnt_str,uid_str,"00000000000000000000000000000000",file_data,"70",cmac))

            macVerified, message = verify_mac(sdm_read_cnt_str,uid_str,"00000000000000000000000000000000",file_data,"70",cmac)
            if macVerified:
                response = {"cmac_status" : "MAC is Correct"}
            else:
                response = {"cmac_status" : "MAC is Incorrect"}
            if file_data:
                ret = decrypt_file_data1(sdm_read_cnt_str,uid_str,meta_data_aes_key_bytes,file_data)
                print("first ret : ", ret)
                response["uid"] = uid_str
                response["sdm_read_cnt"] = sdm_read_cnt_str
                if ret["error"]:
                    print("ret : ", ret)
                    return ret
                else:
                    print("ret 1: ", ret)
                    response["decrypted_encfiledata"] = ret["decrypted_message"]
                    #return {"uid": uid_str, "sdm_read_cnt": sdm_read_cnt_str, "decrypted_encfileData": ret["decrypted_message"]}
                    return response

            return response

    except Exception as e:
        return {"error": str(e)}

# Helper function to get ASCII input data or 256 bytes of zeros if input is empty
def get_ascii_mac_input_data(input):
    if not input:
        return bytearray(256)  # default to 256 bytes of zeros
    else:
        ascii_bytes = bytearray(input.encode('utf-8'))
        ascii_bytes.extend([0] * (256 - len(ascii_bytes)))
        return ascii_bytes

# Helper function to convert string to byte
def convert_to_byte(input):
    try:
        return int(input)
    except ValueError:
        raise ValueError("Invalid byte conversion.")

def verify_mac(read_counter_text, uid_text, auth_key_text , mac_input_data_text, mac_length_text, mac_text):
    try:
        # Convert readCounter to uint
        sdm_read_cnt = int(read_counter_text)

        # Convert hex strings to byte arrays
        uid = hex_string_to_byte_array(uid_text)
        file_data_aes_key = hex_string_to_byte_array(auth_key_text)
        ascii_mac_in = get_ascii_mac_input_data(mac_input_data_text)
        mac_in_len = 0 if not mac_input_data_text else convert_to_byte(mac_length_text)
        mac = hex_string_to_byte_array(mac_text)

        # Convert byte arrays to ctypes
        uid_c = (ctypes.c_uint8 * len(uid))(*uid)
        file_data_aes_key_c = (ctypes.c_uint8 * len(file_data_aes_key))(*file_data_aes_key)
        ascii_mac_in_c = (ctypes.c_uint8 * len(ascii_mac_in))(*ascii_mac_in)
        mac_c = (ctypes.c_uint8 * len(mac))(*mac)

        # Perform MAC verification
        status = ufcoder.nt4h_check_sdm_mac(
            sdm_read_cnt,
            uid_c,
            file_data_aes_key_c,
            ascii_mac_in_c,
            mac_in_len,
            mac_c
        )

        if status != DL_STATUS.UFR_OK:
            return False, f"MAC is not correct. Error: {status}"
        else:
            return True, "MAC is correct"

    except Exception as ex:
        return False, f"An error occurred: {ex}"

