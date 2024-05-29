import binascii

DERIVE_MODE = "legacy"
MASTER_KEY = binascii.unhexlify("00000000000000000000000000000000")

ENC_PICC_DATA_PARAM = "picc_data"
ENC_FILE_DATA_PARAM = "enc"

UID_PARAM = "uid"
CTR_PARAM = "ctr"

SDMMAC_PARAM = "cmac"

REQUIRE_LRP = False
