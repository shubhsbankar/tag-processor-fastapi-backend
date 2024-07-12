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
import hashlib
secrets = get_secret("masterKey")
print("secrets : ", secrets)
MASTER_KEY = bytes.fromhex(secrets['MasterKey'])
print(type(MASTER_KEY),MASTER_KEY)
def decryptData(kv,salt,picc_data,enc_file_data,cmac):
    # Placeholder for actual decryption logic
    print(type(picc_data))
    print(type(cmac))
    print('kv',kv)
    #try:
        #enc_picc_data_b = binascii.unhexlify(picc_data)
        #print("enc_picc_data_b", enc_picc_data_b)
        #enc_file_data_b = binascii.unhexlify(enc_file_data) if enc_file_data else None
        #print("enc_file_data_b", enc_file_data_b)
        #sdmmac_b = binascii.unhexlify(cmac)
        #print("sdmmac_b", sdmmac_b)
    #except binascii.Error:
        #raise HTTPException(status_code=400, detail="Failed to decode parameters.")

    param_mode = ParamMode.SEPARATED

    try:
        #meta_data_aes_key_bytes=derive_undiversified_key(MASTER_KEY, 1)
        secret = get_secret(f"SuperMasterKey{kv}")
        print("secret", secret)
        #MASTER_KEY = secret[f"SuperMasterKey{kv}"].encode()
        print("master_key",MASTER_KEY)
        #master_key = secret[f"SuperMasterKey{kv}"]
        master_key = derive_key(kv,salt,0)
        derived_keys = [derive_key(kv,salt, index) for index in range(5)]
        print("master_key1",master_key)
        print("derived_keys",derived_keys)
        result1 = decrypt_data1(kv,picc_data,enc_file_data,derived_keys[0],cmac)
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
    print("encrypted_data",encrypted_data)
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
        print(picc_data)
        print(cmac)
        print(enc_file_data)
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
def kdf(uid : str):
        salt = hashlib.sha256(uid.encode()).digest()
        n = 2**14
        r = 8
        p = 1
        dklen = 64  # 64 bytes = 512 bits (for four 128-bit keys)

        # Use hashlib's scrypt function
        derived_key = hashlib.scrypt(secrets['MasterKey'].encode(), salt=salt, n=n, r=r, p=p, dklen=dklen)
        keys = [derived_key[i:i+16].hex() for i in range(0, len(derived_key), 16)]
        print(keys)
        # Convert to dictionary array
        dict_array = {f'key{i}': value for i, value in enumerate(keys)}

        # Print the resulting dictionary
        print(dict_array)
        return dict_array
def derive_key(kv, salt, index, length=16):  # length=16 to get 32-character hex key
    # Create a unique salt for each key based on the index
    master_key = get_secret(f"SuperMasterKey{kv}")
    print(master_key)
    print("salt is : ",salt)
    unique_salt = (salt + str(index)).encode()
    key = hashlib.scrypt(
    master_key.encode(),
            salt=unique_salt,
            n=2**14,
            r=8,
            p=1,
            dklen=length  # dklen=16 to get 16 bytes
    )
    return binascii.hexlify(key).decode()
