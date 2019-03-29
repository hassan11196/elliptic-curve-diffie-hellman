from elliptic import *
from finitefield.finitefield import FiniteField
import random
from Crypto import Random
from Crypto.Cipher import AES
import base64
from cryptography.fernet import Fernet


import os


def generateSecretKey(numBits):
   return int.from_bytes(os.urandom(numBits // 8), byteorder='big')


def sendDH(privateKey, generator, sendFunction):
   print("Public Key = " + str(privateKey * generator))
   return sendFunction(privateKey * generator)


def receiveDH(privateKey, receiveFunction):
   return privateKey * receiveFunction()


def slowOrder(point):
   Q = point
   i = 1
   while True:
      if type(Q) is Ideal:
         return i
      else:
         Q = Q + point
         i += 1


if __name__ == "__main__":
   
   # NIST Approved Curve
   curve_name = 'secp256k1'
    # Field characteristic.
   p=0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f
   # Curve coefficients.
   a=0
   b=7
   # Base point.
   g=(0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798,
      0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8)
   # Subgroup order.
   n=0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141
   # Subgroup cofactor.
   h=1

   F = FiniteField(p, 1)

   curve = EllipticCurve(a=F(a), b=F(b))

   basePoint = Point(curve, F(g[0]), F(g[1]))
   print(basePoint)

   aliceSecretKey = generateSecretKey(32)
   bobSecretKey = generateSecretKey(32)

   print('Secret keys are %d, %d' % (aliceSecretKey, bobSecretKey))

   alicePublicKey = sendDH(aliceSecretKey, basePoint, lambda x:x)
   bobPublicKey = sendDH(bobSecretKey, basePoint, lambda x:x)

   sharedSecret1 = receiveDH(bobSecretKey, lambda: alicePublicKey)
   sharedSecret2 = receiveDH(aliceSecretKey, lambda: bobPublicKey)
   print('Shared secret is %s == %s' % (sharedSecret1, sharedSecret2))

   print('extracing x-coordinate to get an integer shared secret: %d' % (sharedSecret1.x.n))

   key = sharedSecret1.x.n
   key2 = sharedSecret1.x.n.to_bytes(32, byteorder='big')
   
   # String to sent from A to B
   st = b'This is a Message from Alice to Bob.'
   key_bytes = (key).to_bytes(32, byteorder='big')
   f = Fernet(base64.b64encode(key2))
   print("Before Encryption At Alice's End Text: " + str(st))
   encrypted = f.encrypt(st)
   print("After Encryption At Alice's End Text: " + str(encrypted))
   decrypted = f.decrypt(encrypted)
   print("After Decryption At Bob's End Text: " + str(decrypted))




   



