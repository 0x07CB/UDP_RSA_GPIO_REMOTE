#coding: utf-8

import rsa
import socket

import time
from copy import deepcopy
import  argparse
argparser = argparse.ArgumentParser()


# add argument. Host with default value of "127.0.0.1", is not required
argparser.add_argument("-H", "--host", nargs="?", default="127.0.0.1",
                       help="Host to bind to. Default is '127.0.0.1'")

# add argument. Port with default value of 12345, is not required
argparser.add_argument("-P", "--port", nargs="?", default=12345, type=int,
                       help="Port to bind to. Default is 12345")

# parse the arguments
args = argparser.parse_args()



def isAlive(p):
    try:
        if p.is_alive():
            return True
        else:
            return False
    except:
        return False


class UDP_Server:
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # I want detect if the server is down
        self.sock.setblocking(0) # non-blocking socket
        self.sock.settimeout(10) # 15 seconds timeout

    def close(self):
        self.sock.close()
        return self

    def shutdown_socket(self):
        self.sock.shutdown(socket.SHUT_RDWR)
        self.sock.close()
        return self
    
    def set_blocking(self, blockingconn=None):
        if (blockingconn != None):
            self.sock.setblocking(blockingconn)
        return self
    
    def set_timeout(self, timeout=None):
        if (timeout != None):
            self.sock.settimeout(timeout)
        return self

    def send_data(self, data, address, blockingconn=None, timeout=None):
        if (blockingconn != None):
            self.sock.setblocking(blockingconn)
            
        if (timeout != None):
            self.sock.settimeout(timeout)

        # I want do: `self.sock.sendto(data, address)`
        # but I want detect if the server is down so I use try/except
        try:
            self.sock.sendto(data, address)
        except socket.timeout:
            self.shutdown_socket()
            # raise a socket.timeout exception
            raise socket.timeout
        return self

    def recv_data(self, size, blockingconn=None, timeout=None):
        if (blockingconn != None):
            self.sock.setblocking(blockingconn)
            
        if (timeout != None):
            self.sock.settimeout(timeout)

        # I want do: `recv_data = self.sock.recvfrom(size)`
        # but I want detect if the server is down so I use try/except
        try:
            recv_data, recv_address = self.sock.recvfrom(size)
            return recv_data, recv_address
        except socket.timeout:
            self.shutdown_socket()
            # raise a socket.timeout exception
            raise socket.timeout
            
    def bind(self):
        self.sock.bind((self.host, self.port))
        return self


class RSA_Communication:
    def __init__(self, key_size=512):
        self.pubkey, self.privkey = rsa.newkeys(key_size)

    def get_pubkey_PEM(self):
        return self.pubkey.save_pkcs1('PEM')

    def get_privkey_PEM(self):
        return self.privkey.save_pkcs1('PEM')

    def load_pubkey_PEM(self, keydata):
        self.pubkey = rsa.PublicKey.load_pkcs1(keydata)
        return self

    def load_privkey_PEM(self, keydata):
        self.privkey = rsa.PrivateKey.load_pkcs1(keydata)
        return self

    def encrypt(self, data):
        if ( type(data) != bytes ):
            data = data.encode('utf-8') 
        return rsa.encrypt(data, self.pubkey)

    def decrypt(self, data):
        try:
            if ( type(data) != bytes ):
                data = data.encode('utf-8')
            return rsa.decrypt(data, self.privkey)
        except rsa.pkcs1.DecryptionError:
            return [None, b"DecryptionError"]
            

class RSA_Signature:
    def __init__(self, hash_method='SHA-1', key_size=512):
        self.hash_method = hash_method
        self.key_size = key_size

    def sign(self, data, privkey):
        if ( type(data) != bytes ):
            data = data.encode('utf-8')
        return rsa.sign(data, rsa.PrivateKey.load_pkcs1(privkey), self.hash_method)

    def verify(self, data, signature, pubkey):
        if ( type(data) != bytes ):
            data = data.encode('utf-8')
        return rsa.verify(data, signature, rsa.PublicKey.load_pkcs1(pubkey))

    def check_signature(self, data, signature, pubkey):
        if ( type(data) != bytes ):
            data = data.encode('utf-8')
        try:
            check_hash_algo = self.verify(data, signature, pubkey)
            if ( check_hash_algo == self.hash_method ):
                return True
            else:
                return False

        except rsa.pkcs1.VerificationError:
            return False


def broken_close(client_pubkey, client_address, server, address):
    if ( ( client_pubkey != None ) and ( address == client_address ) ):
        server.shutdown_socket()
        server.close()
        # raise a socket.timeout exception
        raise socket.timeout
    
last_command = None
    
def main():
    global last_command
    server = UDP_Server(args.host, args.port)
    server.bind()
    rsa_comm = RSA_Communication()
    pubkey = rsa_comm.get_pubkey_PEM()
    client_pubkey = None
    client_address = None

    print("Serveur en attente de connexion...")
    client_pubkey, client_address = server.recv_data(1024)
    #broken_close(client_pubkey, client_address, server, args.host)

    print("Tentative de connexion entrante de: ", client_address)
    print("Clé publique du client reçue.")
    if ( type(client_pubkey) != bytes ):
        client_pubkey = client_pubkey.encode('utf-8')

    print("Connexion établie avec le client: ", client_address)

    server.send_data(pubkey, client_address)


    
    while True:
        wait_for_client = True
        while wait_for_client:
            try:
                data,addr_ = server.recv_data(1024, blockingconn=False, timeout=15)
                if 'READY' in data.decode():
                    wait_for_client = False
                    if last_command == None:
                        remote_command = input("?: >> ")
                        last_command = deepcopy(remote_command)
                    else:
                        remote_command = deepcopy(last_command)      
                else:
                    continue
            except socket.timeout:
                time.sleep(1)
                continue

        
        auth_sign = RSA_Signature('SHA-1',512)
        if 'terminate' in remote_command:
            terminate = True
        else:
            terminate = False

        if type(remote_command) != bytes:
            remote_command = remote_command.encode('utf-8')

        remote_command_signature = auth_sign.sign(remote_command,rsa_comm.get_privkey_PEM())
        server.send_data(rsa.encrypt(remote_command, rsa.PublicKey.load_pkcs1(client_pubkey)), client_address)
        server.send_data(remote_command_signature, client_address)
        if terminate:
            server.close()
            break

        crypt_remote_stdout, address = server.recv_data(1024)
        #broken_close(client_pubkey, client_address, server, args.host)
        signature_remote_stdout, address = server.recv_data(1024)
        #broken_close(client_pubkey, client_address, server, args.host)

        remote_stdout = rsa_comm.decrypt(crypt_remote_stdout)
        if ( type(remote_stdout) == list ):
            if ( remote_stdout[1] == b"DecryptionError" ):
                pubkey = rsa_comm.get_pubkey_PEM()
                server.send_data("[ERROR:DecryptionError]:(pubkey)".encode('utf-8'), client_address)
                server.send_data(pubkey, client_address)
                client_confirmation, client_address = server.recv_data(1024)
                if ( type(client_confirmation) != bytes ):
                    client_confirmation = client_confirmation.encode('utf-8')

                if ( client_confirmation == b"OK" ):
                    last_command = None
                    continue
                else:
                    server.shutdown_socket()
                    break

        if ( auth_sign.check_signature(remote_stdout, signature_remote_stdout, client_pubkey) == True ):
            last_command = None
            print(remote_stdout.decode())
                



def main_loop():
    process_1 = None

    while True:
        try:
            main()
        except socket.timeout:
            print("Server is down.")
            time.sleep(1)
        except OSError:
            print("Transport endpoint is not connected.")
            time.sleep(1)
        except KeyboardInterrupt:
            print("The program was interrupted by the user.")
            exit(0)


if __name__ == "__main__":
    main_loop()

