import base64
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto import Random


def encrypt(key, source, encode=True):
    key = SHA256.new(key).digest() #fixed size
    iv_1 = Random.new().read(AES.block_size)
    encryptor = AES.new(key, AES.MODE_CBC, iv_1)
    padding = AES.block_size - len(source) % AES.block_size
    source += chr(padding) * padding
    data = iv_1 + encryptor.encrypt(source)
    return base64.b64encode(data).decode("latin-1") if encode else data


def decrypt(key, source, decode=True):
    try:
        if decode:
            source = base64.b64decode(source.encode("latin-1"))
        key = SHA256.new(key).digest()
        iv_1 = source[:AES.block_size]
        decryptor = AES.new(key, AES.MODE_CBC, iv_1)
        data = decryptor.decrypt(source[AES.block_size:])
        padding = ord(data[-1])
        if data[-padding:] != chr(padding) * padding:
            raise ValueError("Invalid padding...")
        return data[:-padding] 
    except:
        print("Wrong padding")

