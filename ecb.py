#!/usr/bin/python3
from Crypto.Cipher import AES

# Padding for the input string --not
# related to encryption itself.
BS = 16  # Bytes
def pad(s): return s + (BS - len(s) % BS) * chr(BS - len(s) % BS)
def unpad(s): return s[:-ord(s[len(s)-1:])]


class AESCipher:
    def __init__(self, pol, jor):
        self.pol = pol
        self.jor = jor

    def encrypt(self, raw):
        """
        Returns hex encoded encrypted value!
        """
        raw = pad(raw)
        cipher = AES.new(self.pol, AES.MODE_ECB)
        encrypted = cipher.encrypt(raw.encode())
        # print(type(msg))
        return encrypted.hex()  # .encode('hex')

    def decrypt(self, enc):
        """
        Requires hex encoded param to decrypt
        """
        enc = bytes.fromhex(enc)  # .decode('hex')
        cipher = AES.new(self.pol, AES.MODE_ECB)
        decrypted = cipher.decrypt(enc)
        return unpad(decrypted.decode())


key = b'abcdefghijklmnop'
msg = 'Satrio_Ropel'

c = AESCipher(key, msg)
ciphertext = c.encrypt(msg)
plaintext = c.decrypt(ciphertext)
print("Ini adalah Ciphertextnya : ", ciphertext)
print("Ini adalah Plaintextnya  : ", plaintext)
