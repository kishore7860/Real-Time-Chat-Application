import socket
import select
import queue
from Crypto.Cipher import AES
import os


HEADER_LENGTH = 8192
IP = '127.0.0.1'
PORT = 1234

server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

server_socket.bind((IP, PORT))

server_socket.listen()

sockets_list = [server_socket]

clients = {}
print("Server is running...")
message_queues = {} 

def receive_message(client_socket):
    try:
        message_header = client_socket.recv(HEADER_LENGTH)
        if not len(message_header):
            return False
        message_length = int(message_header.decode('utf-8').strip())
        return {'header': message_header, 'data': client_socket.recv(message_length)}
    except:
        return False

def encrypt_message(message, key):
    cipher = AES.new(key, AES.MODE_CBC)
    ciphertext = cipher.encrypt(message)
    return ciphertext, cipher.iv

def decrypt_message(ciphertext, iv, key):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = cipher.decrypt(ciphertext)
    return plaintext.rstrip(b"\0")

def generate_key(length):
    return os.urandom(length)

while True:
    read_sockets, _, exception_sockets = select.select(sockets_list, [], sockets_list)

    for notified_socket in read_sockets:
        if notified_socket == server_socket:
            client_socket, client_address = server_socket.accept()
            user = receive_message(client_socket)
            encryption_key = generate_key(32) 
            if user is False:
                continue
            sockets_list.append(client_socket)
            clients[client_socket] = user
            message_queues[client_socket] = queue.PriorityQueue()
            print(
                f"Accepted new connection from {client_address[0]}:{client_address[1]} username:{user['data'].decode('utf-8')}")
        else:
            message = receive_message(notified_socket)
            if message is False:
                print(f"Closed Connection from {clients[notified_socket]['data'].decode('utf-8')}")
                sockets_list.remove(notified_socket)
                del clients[notified_socket]
                del message_queues[notified_socket]
                continue
            user = clients[notified_socket]
            print(f'Received message from {user["data"].decode("utf-8")}:{message["data"].decode("utf-8")}')
            plaintext = decrypt_message(message['data'], message['iv'], encryption_key)
            print(f'Decrypted message: {plaintext.decode("utf-8")}')
            is_real_time = True 
            if is_real_time:
                message_queues[notified_socket].put((-1, message)) 
            else:
                message_queues[notified_socket].put((0, message))
            for client_socket in clients:
                if client_socket != notified_socket:
                    client_socket.send(user['header'] + user['data'] + message['header'] + message['data'])

    for notified_socket in exception_sockets:
        sockets_list.remove(notified_socket)
        del clients[notified_socket]
    for client_socket, message_queue in message_queues.items():
        if not message_queue.empty():
            _, message = message_queue.get()
            for client_socket in clients:
                if client_socket != notified_socket:
                    client_socket.send(user['header'] + user['data'] + message['header'] + message['data'])
