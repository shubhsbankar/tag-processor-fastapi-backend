import binascii
from decryptor import ParamMode, InvalidMessage, decrypt_data1
from fastapi import HTTPException
from derive import derive_undiversified_key, derive_tag_key
from config import (
    CTR_PARAM,
    ENC_FILE_DATA_PARAM,
    ENC_PICC_DATA_PARAM,
    REQUIRE_LRP,
    SDMMAC_PARAM,
    UID_PARAM,
    DERIVE_MODE
)
from utils import get_secret

secrets = get_secret("masterKey")
#print("secrets : ", secrets)
MASTER_KEY = bytes.fromhex(secrets['MasterKey'])
def decryptData(picc_data,enc_file_data,cmac):
    # Placeholder for actual decryption logic
    print(type(picc_data))
    print(type(cmac))
    try:
        enc_picc_data_b = binascii.unhexlify(picc_data)
        enc_file_data_b = binascii.unhexlify(enc_file_data) if enc_file_data else None
        sdmmac_b = binascii.unhexlify(cmac)
    except binascii.Error:
        raise HTTPException(status_code=400, detail="Failed to decode parameters.")

    param_mode = ParamMode.SEPARATED

    try:
        meta_data_aes_key_bytes=derive_undiversified_key(MASTER_KEY, 1)
        result1 = decrypt_data1(picc_data,enc_file_data,meta_data_aes_key_bytes,cmac)
        print("result1 : ",result1)
    except InvalidMessage:
        raise HTTPException(status_code=400, detail="Invalid message (most probably wrong signature).")

    if REQUIRE_LRP and result['encryption_mode'] != EncMode.LRP:
        raise HTTPException(status_code=400, detail="Invalid encryption mode, expected LRP.")

    
    return result1

def validateCmac(data, expected_cmac):
    # Placeholder for actual CMAC validation logic
    # Here we'll just return True as a placeholder
    return True

def parseEncryptedData(encrypted_data):
    encrypted_data = encrypted_data.replace(" ", "")
    # Template 1: EC (24 bytes: 16 bytes PICC + 8 bytes CMAC)
    if len(encrypted_data) == 48:
        picc_data = encrypted_data[:32]
        cmac = encrypted_data[32:]
        return picc_data, None, cmac
    # Template 2: EEC (variable length)
    elif len(encrypted_data) > 48:
        picc_data = encrypted_data[:32]
        cmac = encrypted_data[-16:]
        enc_file_data = encrypted_data[32:-16]
        return picc_data, enc_file_data, cmac
    else:
        raise ValueError("Invalid encrypted data format")

def process_tag_data(encrypted_data):
    try:
        picc_data, enc_file_data, cmac = parse_encrypted_data(encrypted_data)
        decrypted_picc_data = decrypt_data(picc_data)
        if enc_file_data:
            decrypted_file_data = decrypt_data(enc_file_data)
        else:
            decrypted_file_data = None
        
        if validate_cmac(decrypted_picc_data + (decrypted_file_data or b""), cmac):
            cmac_status = "MAC is Correct"
        else:
            cmac_status = "MAC is Incorrect"
        
        response = {
            "decrypted_picc_data": decrypted_picc_data,
            "decrypted_file_data": decrypted_file_data,
            "cmac_status": cmac_status
        }
        
        return response
    except ValueError as e:
        return {"error": str(e)}

