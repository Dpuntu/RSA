# -*- coding: utf-8 -*-

import socket
import subprocess
import fileutils
import rsa
from Crypto.Hash import SHA256
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Cipher import PKCS1_v1_5 as Cipher_pkcs1_v1_5
from Crypto.PublicKey import RSA
import base64
import frame


class Conn:
    def __init__(self):
        self.isConn = False

    def IsConn(self):
        return self.isConn

    def SendParams(self, param):
        if self.isConn:
            print self.values.get(param)
            if self.values.get(param):
                sendMsg = param + ":" + self.values.get(param)
                with open('public.pem') as f:
                    key = f.read().encode("utf-8")
                    rsakey = RSA.importKey(key)
                    cipher = Cipher_pkcs1_v1_5.new(rsakey)
                    cipher_text = base64.b64encode(cipher.encrypt(sendMsg.encode("utf-8")))
                    self.sk.send(cipher_text)
                    ret_bytes = self.sk.recv(1024)
                    ret_str = str(ret_bytes)
                    return ret_str
            else:
                return 'OK'

    def WritePem(self):
        with open('public.pem', 'w+') as f:
            f.write("-----BEGIN RSA PUBLIC KEY-----")
            f.write("\r\n")
            f.write(self.pubKey.encode("utf-8"))
            f.write("\r\n")
            f.write("-----END RSA PUBLIC KEY-----")

    def ReadPem(self):
        with open('public.pem', 'r') as f:
            publicKey = rsa.PublicKey.load_pkcs1(f.read().encode())
        return publicKey
