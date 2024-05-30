from database import getTagDataFromPostgres, updateTagTable
from derive import derive_undiversified_key
from config import (
    MASTER_KEY
)
from decryptor import decrypt_file_data1
def verifyData(uid,counter,filedata,macVerified):
    # Implement your verification logic here
    data = getTagDataFromPostgres(uid)
    print("got data form database : ",data)
    if data == None:
       print("No entry in database")
       return {"score": 0, "isBlacklisted": False, "error": "No entry in database"}
    for key, value in data.items():
            print(f"{key}: {value}")
    score = 0
    error = ""
    isBlacklisted = False
    if macVerified:
        score += 5
    else:
        print("mac verification failed")
        error = "mac verification failed"
        score -= 5
        isBlacklisted = True
    isUidVerified = verifyUid(data['uid'],data) 
    if isUidVerified: # Placeholder
        score += 4
    else:
        print("uid verification failed")
        error = "uid verification failed"
        score -= 3
        isBlacklisted = True
    
    ret = verifyCounter(data['counter'],data) 
    if ret == 1:
        score += 4
    elif ret == 2:
        score += 2
    elif ret == -1:
        score -= 3
        isBlacklisted = True
    else:
        print("read counter verification failed")
        error = "sdm read counter verification failed"
        score -= 5


    if verifyEncFileData(filedata, data):
        score += 2
    else:
        print("encFileData verification failed")
        error = "encrypted file data verification failed"
        score -= 2
        isBlacklisted = True
    
    if isBlacklisted and isUidVerified:
        data['blacklistvalue'] = True
        updateTagTable(data)
    #if verify_counter_in_database(co)
    print("score : ",score)
    return {"score" : score, "isBlacklisted": isBlacklisted, "error": error}

def verifyUid(uid, data):
    return uid == data['uid']

def verifyCounter(counter, data):
    if counter < data["counter"]:
        return -1
    if counter <= data['counter'] + 5:
        return 1
    elif counter <= data['counter'] + 8:
        return 2
    else :
        return 0

def verifyEncFileData(filedata, data):
    meta_data_aes_key_bytes=derive_undiversified_key(MASTER_KEY, 1)
    print("database counter type",type(data["counter"]))
    ret = decrypt_file_data1(data["counter"],data["uid"],meta_data_aes_key_bytes,data["encryptedfiledata"])
    if ret["error"]:
        print("ret : ", ret)
        return False
    else:
        print("ret 1: ", ret)
        decryptedMessage = ret["decrypted_message"]
        print("decrypted database message",decryptedMessage)
                 
    return filedata == decryptedMessage


