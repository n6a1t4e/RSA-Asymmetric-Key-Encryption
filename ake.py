from Crypto.Util import number, asn1
from codecs import encode, decode
from binascii import hexlify, unhexlify

#Created By: R. Nathan Lewis
#Date:       03/13/2019

class Key:
    def __init__(self,N):

        k = self.generateKeys(N)
        self.pub = hexlify(asn1.DerSetOf((k['n'],k['e'])).encode()).decode()
        self.pri = hexlify(asn1.DerSetOf((k['n'],k['d'])).encode()).decode()
        self.data = {"pub":self.pub, "sig":"0"}
        

    def generateKeys(self,N):
        p = number.getPrime(N//2-1)
        q = number.getPrime(N//2-1)
        n = p*q
        phi = (p-1)*(q-1)

        e = 65537
        d = number.inverse(e,phi)

        return {'e':e,'d':d,'n':n}

    def encrypt(self,M):
        pub = self.decodePub(self.data)
        return hex(pow(int(encode(M.encode(), "hex"),16),
                       pub[1], pub[0]))[2:]

    def decrypt(self,C):
        pri = self.decodePri()
        return bytes.fromhex(hex(pow(int(C,16),
                                     pri[1], pri[0]))[2:]).decode()

    def signature(self,sig):
        pri = self.decodePri()
        signature = hex(pow(int(encode(sig.encode(), "hex"),16),
                       pri[1], pri[0]))[2:]
        self.sig = signature
        self.data["sig"] = signature
        return signature

    def decryptSig(self,data):
        pub = self.decodePub(data)
        return bytes.fromhex(hex(pow(int(data["sig"],16),
                                     pub[1],pub[0]))[2:]).decode()

    def decodePub(self,data):
        eData = asn1.DerSetOf()
        pub = [ i for i in eData.decode(unhexlify(data["pub"]))[::-1]]
        return pub

    def decodePri(self):
        eData = asn1.DerSetOf()
        pri = [ i for i in eData.decode(unhexlify(self.pri))[::-1]]
        return pri


def example():
    K = Key(1024)
    print("Public Key:")
    print(K.pub + "\n")
    print("Private Key:")
    print(K.pri + "\n")
    
    K.sig = K.signature("Bob")
    print("Encrypted Signature w/ Private Key:")
    print(K.sig + "\n")
    print("Decrypted Signature w/ Public Key:")
    print(K.decryptSig(K.data) + "\n")

    M = "Hello World!"
    print("Message:")
    print(M + "\n")
    print("Encrypted:")
    C = K.encrypt(M)
    print(C+"\n")
    print("Decrypted:")
    D = K.decrypt(C)
    print(D)
    
#example()
