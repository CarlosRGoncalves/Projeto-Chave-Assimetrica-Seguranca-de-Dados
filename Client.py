#! /usr/bin/env python

import socket
import sys
import time
import threading
import select
import traceback
import base64
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature
from cryptography.fernet import Fernet
import warnings

warnings.filterwarnings("ignore")

class Server(threading.Thread):
    def initialise(self, receive):
        self.receive = receive

    def variaveis_iniciais(self):# Gerar variaveis de armazenamento de chaves e controle de codigo
        self.chave_privada = rsa.generate_private_key(public_exponent=65537, key_size=2048)#chave privada
        self.chave_publica_gerada = self.chave_privada.public_key()#chave publica 
        self.chave_publica_gerada_bytes = self.chave_publica_gerada.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)
        # public em formato de bytes para mandar em bytes
        self.chave_publica_client_2 = None #armazena a chave publica recebida
        self.chave_publica_bytes_client_2 = None #armazena a chave publica recebida em bytes
        self.chegou_chave_pub = False #variavel para saber se chegou a chave publica
        self.chegou_assinatura = False #variavel para saber se chegou a assinatura
        self.enviou_sim = False #variavel para saber se ja chegou a chave simetrica
        self.chave_simetrica_my_client = None #variavel que armazena a chave simetrica do client
        self.chave_simetrica_client_2 = None #variavel que armazena a chave simetrica recebida 


    def run(self):
        lis = []
        lis.append(self.receive)
        while 1:
            read, write, err = select.select(lis, [], [])
            for item in read:
                try:
                    s = item.recv(1024)
                    if s != '':
                        chunk = s # Atualiza cada vez que recebo do server
                        decodifica_bytes = chunk.decode('unicode_escape')#decodifica o formato de bytes
                        chave_comeca = '-----BEGIN PUBLIC KEY-----'# pq o 2 cliente envia 2 vezes a chave publica
                        if decodifica_bytes.startswith(chave_comeca) and self.chave_publica_bytes_client_2 is None:#Nao recebeu  chave 
                            # if que recebe a chave pública do outro cliente
                            self.chave_publica_bytes_client_2 = chunk
                            self.chave_publica_client_2 = load_pem_public_key(self.chave_publica_bytes_client_2)# pega mng em formato de bytes, e Be.. e final End
                            print(decodifica_bytes)
                        #NAO É CHAVE PUBLICA
                        elif not decodifica_bytes.startswith(chave_comeca) and self.chave_simetrica_client_2 is None:#Nao trocaram chave simetrica ainda
                            # se ainda não tivermos a chave simétrica, então precisamo decriptá-la
                            self.chave_simetrica_client_2 = self.chave_privada.decrypt(chunk, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))

                        elif not self.chegou_assinatura and self.chave_simetrica_client_2 is not None:
                            try:
                                #Comparo a assinatura que recebi com a chave simetrica que acabei de decripta
                                self.chave_publica_client_2.verify(chunk, self.chave_simetrica_client_2, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())
                                self.chegou_assinatura = True

                            except InvalidSignature:
                                print('Assinatura Inválida!')
                                break

                        elif self.chegou_assinatura:
                            f = Fernet(self.chave_simetrica_client_2)
                            print(f.decrypt(chunk).decode() + "\n>>")
                            self.chegou_assinatura = False

                except:
                    traceback.print_exc(file=sys.stdout)
                    break
                


class Client(threading.Thread):
    def connect(self, host, port):
        self.sock.connect((host, port))

    def client(self, host, port, msg, srv):
        if not srv.chegou_chave_pub and srv.chave_publica_bytes_client_2 is not None:# Recebeu Public do Outro
            # função para enviar chave para outro cliente
            # ele tenta enviar a chave para o outro cliente até que a variavel de controle mude
            self.sock.send(srv.chave_publica_gerada_bytes)
            srv.chegou_chave_pub = True
            time.sleep(0.5)

        elif srv.chegou_chave_pub: #Seg rodada, msg
            # verifica se a chave pública de cliente já foi enviada e se a do outro foi recebida
            if not srv.enviou_sim:
                srv.chave_simetrica_my_client = Fernet.generate_key()# chave simetrica alfabeto
                chave_simetrica_encriptada = srv.chave_publica_client_2.encrypt(srv.chave_simetrica_my_client , padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
                self.sock.send(chave_simetrica_encriptada) # envia a chave simétrica por um meio não seguro (seguro), porém com a chave encriptada por meio da chave pública do outro cliente
                srv.enviou_sim =True
                time.sleep(0.5)
            f = Fernet(srv.chave_simetrica_my_client)#Chave simetrica encryptada
            #assina a chave, com a unica coisa que tem a chave privada
            assinatura = srv.chave_privada.sign(srv.chave_simetrica_my_client, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256()) # assina a chave simétrica (desencriptada)
            self.sock.send(assinatura)
            time.sleep(0.5)
            mensagem = self.sock.send(f.encrypt(msg))# Mensagem ultimo passo

    def run(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        host = '127.0.0.1'#fixo
        port = 5535
        print("Connecting\n")
        s = ''
        self.connect(host, port)
        print("Connected\n")
        user_name = input("Enter the User Name to be Used\n>>")
        receive = self.sock
        time.sleep(1)
        srv = Server()
        srv.initialise(receive)
        srv.daemon = True
        print("Starting service")
        srv.variaveis_iniciais()#Gerar variaveis de controle
        srv.start()# start servidor
        self.sock.send(srv.chave_publica_gerada_bytes) #manda a chave publica pro server/passo 1
        time.sleep(0.5)# infinito buga 
        while not srv.chegou_chave_pub: #Fica mandando pra funcao Client até tiver outro Client
            time.sleep(0.5)
            self.client(host, port, b'', srv)
        while 1:
            # print "Waiting for message\n"
            msg = input('>>')
            if msg == 'exit':
                break
            if msg == '':
                continue
            # print "Sending\n"
            msg = user_name + ': ' + msg 
            data = msg.encode()# tranformando em bytes
            self.client(host, port, data, srv)

        return (1)


if __name__ == '__main__':
    print("Starting client")
    cli = Client()
    cli.start()