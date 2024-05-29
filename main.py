from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from decryption import decrypt_data, validate_cmac, parse_encrypted_data
from verification import verify_data

app = FastAPI()

class TagData(BaseModel):
    encryptedData: str
    deviceId: str

@app.post('/read_tag')
async def read_tag(tag_data: TagData):
    try:
        encrypted_data = tag_data.encryptedData
        #picc_data, enc_file_data, cmac = parse_encrypted_data(encrypted_data)
        response = decrypt_data(encrypted_data)
        #verify_data(response['uid'])
        # if enc_file_data:
            # decrypted_file_data = decrypt_data(enc_file_data)
        # else:
            # decrypted_file_data = None
        
        # if validate_cmac(decrypted_picc_data + (decrypted_file_data or b""), cmac):
            # cmac_status = "MAC is Correct"
        # else:
            # cmac_status = "MAC is Incorrect"
        
        # response = {
            # "decrypted_picc_data": decrypted_picc_data.hex(),
            # "decrypted_file_data": decrypted_file_data.hex() if decrypted_file_data else None,
            # "cmac_status": cmac_status
        # }
        
        return response
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

if __name__ == '__main__':
    import uvicorn
    uvicorn.run(app, host='127.0.0.1', port=8000)
