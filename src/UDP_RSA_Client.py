#coding: utf-8

import rsa
import select
import socket

import time
import gpiod
from gpiod.line import Direction, Value

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


class UDP_Client:
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # I want detect if the server is down
        self.sock.setblocking(0) # non-blocking socket
        self.sock.settimeout(3) # 15 seconds timeout
        # Documentation: https://docs.python.org/3/library/socket.html
        print("Client is running on", self.host, ":", self.port)

    def check_server_status(self, data_=b''):
        try:
            self.sock.sendto(data_, (self.host, self.port))
            self.sock.recvfrom(1024)
            return True
        except socket.timeout:
            return False

    def close(self):
        self.sock.close()
        return self
    
    def shutdown_socket(self):
        print("Shutdown socket")
        self.sock.shutdown(socket.SHUT_RDWR)
        print("Close socket")
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
        
        # I want do: `self.sock.recvfrom(size)`
        # but I want detect if the server is down so I use try/except
        try:
            recv_data, recv_address = self.sock.recvfrom(size)
            return recv_data, recv_address
        except socket.timeout:
            self.shutdown_socket()
            # raise a socket.timeout exception
            raise socket.timeout
        



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
        if ( type(data) != bytes ):
            data = data.encode('utf-8')
        return rsa.decrypt(data, self.privkey)

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

def set_gpiod_output(LINE = 12, VALUE = True, CHIP="/dev/gpiochip0"):
    if (VALUE == True):
        V_ = Value.ACTIVE
    else:
        V_ = Value.INACTIVE

    with gpiod.request_lines(
        CHIP,
        consumer="blink-example",
        config={
            LINE: gpiod.LineSettings(
                direction=Direction.OUTPUT, output_value=V_
            )
        },
    ) as request:
        request.set_value(LINE, V_)

def main():
    RELAY_LINES = {
        'relay1': 12,
        'relay2': 6
    }
    rsa_comm = RSA_Communication()
    pubkey = rsa_comm.get_pubkey_PEM()

    client = UDP_Client(args.host, args.port)
    client.send_data(pubkey, (args.host, args.port))
    
    server_pubkey, server_address = client.recv_data(1024)
    while server_pubkey == b'[ERROR:DecryptionError]:(pubkey)':
        print("Server's public key is not valid")
        server_pubkey, server_address = client.recv_data(1024)
        client.send_data(b'OK', server_address)

    while True:
        auth_sign = RSA_Signature('SHA-1',512)

        
        while server_pubkey == b'[ERROR:DecryptionError]:(pubkey)':
            print("Server's public key is not valid")
            server_pubkey, server_address = client.recv_data(1024)
            client.send_data(b'OK', server_address)

        client.send_data(b'READY', server_address, blockingconn=True, timeout=None)

        encrypted_command, server_address = client.recv_data(1024, blockingconn=True, timeout=None)
        
        

        command = rsa_comm.decrypt(encrypted_command).decode('utf-8')
        signature_command, server_address_ = client.recv_data(1024)
        if (server_address_ == server_address):
            if ( auth_sign.check_signature(command, signature_command, server_pubkey) == True ):
                if 'terminate' in command:
                    client.close()
                    break
                else:
                    if 'relay1' in command:
                        if ':on' in command:
                            set_gpiod_output(RELAY_LINES['relay1'], True)
                        elif ':off' in command:
                            set_gpiod_output(RELAY_LINES['relay1'], False)
                    elif 'relay2' in command:
                        if ':on' in command:
                            set_gpiod_output(RELAY_LINES['relay2'], True)
                        elif ':off' in command:
                            set_gpiod_output(RELAY_LINES['relay2'], False)


                    clear_stdout = "OK".encode()
                    encrypted_stdout = rsa.encrypt(clear_stdout, rsa.PublicKey.load_pkcs1(server_pubkey,'PEM'))

                    signature_message = auth_sign.sign(clear_stdout,rsa_comm.get_privkey_PEM())
                    client.send_data(encrypted_stdout, server_address)
                    client.send_data(signature_message, server_address)


def main_loop():
    while True:
        try:
            main()
        except socket.timeout:
            print("Server is offline. Trying to reconnect...")
        except OSError:
            print("Transport endpoint is not connected. Trying to reconnect...")
        except KeyboardInterrupt:
            print("The program was interrupted by the user.")
            exit(0)

if __name__ == "__main__":
    main_loop()


