from database import getTagDataFromPostgres, updateTagTable
from derive import derive_undiversified_key
from config import (
    MASTER_KEY
)
from decryption import derive_key
from decryptor import decrypt_file_data1
def verifyData(kv,salt,uid,counter,filedata,macVerified):
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
        print("macVerified score + 5",score)
        score += 5
    else:
        print("mac verification failed")
        error = "mac verification failed"
        score -= 5
        isBlacklisted = True
    isUidVerified = verifyUid(data['uid'],data) 
    if isUidVerified: # Placeholder
        print("isUidVerified score + 4",score)
        score += 4
    else:
        print("uid verification failed")
        error = "uid verification failed"
        score -= 3
        isBlacklisted = True
    
    ret = verifyCounter(counter,data) 
    if ret == 1:
        print("verifyCounter score + 4",score)
        score += 4
        data['sdmreadcnt'] = counter
        print("ret = 1 Data before saving in db", data)
        updateTagTable(data,"sdmreadcnt")
        verifyProccessedcnt(data)
    elif ret == 2:
        print("verifyCounter score + 2",score)
        score += 2
        data['sdmreadcnt'] = counter
        print("ret = 2 Data before saving in db", data)
        updateTagTable(data,"sdmreadcnt")
        verifyProccessedcnt(data)
    elif ret == 3:
        print("verifyCounter ret=3  score + 2",score)
        score += 2
        data['sdmreadcnt'] = counter
        print("ret = 3 Data before saving in db", data)
        updateTagTable(data,"sdmreadcnt")
        verifyProccessedcnt(data)
    elif ret == 4:
        print("verifyCounter ret=4 score + 0",score)
        score += 0
        verifyProccessedcnt(data)
        print("Already processed tag")
    elif ret == -1:
        print("verifyCounter ret=-1 score - 3",score)
        score -= 3
        isBlacklisted = True
    else:
        print("read counter verification failed")
        error = "sdm read counter verification failed"
        score -= 5


    if verifyEncFileData(kv,salt,filedata, data):
        print("verifyEncFileData score + 2",score)
        score += 2
    else:
        print("encFileData verification failed")
        error = "encrypted file data verification failed"
        score -= 2
        isBlacklisted = True
    
    if isBlacklisted and isUidVerified and data['blacklistvalue'] == False:
        data['blacklistvalue'] = True
        print("Data before saving in db", data)
        updateTagTable(data,"blacklistvalue")
    if data['blacklistvalue'] == True and isBlacklisted == False:
        isBlacklisted = True
    #if verify_counter_in_database(co)
    print("score : ",score)
    return {"score" : score, "isBlacklisted": isBlacklisted, "error": error}

def verifyUid(uid, data):
    return uid == data['uid']

def verifyCounter(counter, data):
    print("Counter",counter,data['sdmreadcnt'])
    if counter == data['sdmreadcnt'] and data['proccessedcnt'] == 2:
        return -1
    if counter == data['sdmreadcnt'] and data['proccessedcnt'] == 1:
        return 4
    if counter < data["sdmreadcnt"]:
        return -1
    if counter <= data['sdmreadcnt'] + 5:
        return 1
    elif counter <= data['sdmreadcnt'] + 8:
        return 2
    elif counter <= data['sdmreadcnt'] + 10:
        return 3
    else :
        return 0

def verifyEncFileData(kv,salt,filedata, data):
    master_key = derive_key(kv,salt,0)
    derived_keys = [derive_key(kv,salt, index) for index in range(5)]
    #meta_data_aes_key_bytes=derive_undiversified_key(MASTER_KEY, 1)
    print("database counter type",type(data["counter"]))
    ret = decrypt_file_data1(data["counter"],data["uid"],bytes.fromhex(derived_keys[0]),data["encryptedfiledata"])
    if ret["error"]:
        print("ret : ", ret)
        return False
    else:
        print("ret 1: ", ret)
        decryptedMessage = ret["decrypted_message"]
        print("decrypted database message",decryptedMessage)
                 
    return filedata == decryptedMessage

def verifyProccessedcnt(data):
   cnt = data['proccessedcnt']
   if cnt == 2:
      cnt = 1
   elif cnt < 2:
      cnt += 1
   data['proccessedcnt'] = cnt
   updateTagTable(data,"proccessedcnt")

