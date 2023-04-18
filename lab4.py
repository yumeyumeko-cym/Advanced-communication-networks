#!/usr/bin/env python3

########################################################################

import socket
import argparse
import sys
import time
import struct
import ipaddress
from threading import Thread
import json
import signal



CLIENT_TO_CRD_CMDS = {
    "getdir"        : 1,
    "makeroom"      : 2,
    "deleteroom"    : 3
}

CLIENT_CMDS = ["connect", "bye", "name", "chat"]


########################################################################
# Server
########################################################################

class Server:

    HOSTNAME = socket.gethostname()

    CRDS_address_port = (HOSTNAME, 50000)

    RECV_SIZE = 256
    
    MSG_ENCODING = "utf-8"

    chat_rooms = []

    def __init__(self):
        self.socket_create()
        self.accept_clients_forever()

    def socket_create(self):
        try:
            # Create an IPv4 UDP and TCP sockets.
            self.CRDS_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            # Get socket layer socket options.
            self.CRDS_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

            # Bind socket to socket address, i.e., IP address and port.
            self.CRDS_socket.bind( Server.CRDS_address_port )
        except Exception as msg:
            print(msg)
            sys.exit(1)

    def accept_clients_forever(self):
        self.CRDS_socket.listen(10)
        print("Chat Room Directory Server: Listening on port {} ...".format(Server.CRDS_address_port[1]))
        try:
            while True:
                # The program will be blocked while waiting to accept incoming connections.
                client = self.CRDS_socket.accept()
                client_thread = Thread(target=self.connection_handler, args=[client])
                client_thread.daemon = True
                client_thread.start()
        except Exception as msg:
            print(msg)
        except KeyboardInterrupt:
            print()
        finally:
            self.CRDS_socket.close()
            sys.exit(1)

    def connection_handler(self, client):
        connection, address = client
        print("-" * 72)
        print("We have received connection from {}.".format(address))

        while (True):        
            # From here we obtain the command ID
            cmd_field = connection.recv(1)
            # If the read fails, giving up.
            if len(cmd_field) == 0:
                print("Connection is closing...")
                connection.close()
                return
            # Convert the command to the byte order of our system
            command = int.from_bytes(cmd_field, byteorder='big')
            if command in CLIENT_TO_CRD_CMDS.values():
                if CLIENT_TO_CRD_CMDS["getdir"] == command:
                    # send client the list of chat rooms
                    connection.send(json.dumps(self.chat_rooms).encode(Server.MSG_ENCODING))
                
                elif CLIENT_TO_CRD_CMDS["makeroom"] == command:
                    # Obtain additional bytes including the name of the chatroom, also the multicast IP address and port.
                    chatroom_name_byte_len = int.from_bytes(connection.recv(1), byteorder='big')
                    chatroom_name = connection.recv(chatroom_name_byte_len).decode(Server.MSG_ENCODING)

                    multicast_ip = socket.inet_ntoa(connection.recv(4))
                    multicast_port = connection.recv(Server.RECV_SIZE).decode(Server.MSG_ENCODING)

                    for room in self.chat_rooms:
                        if list(room['addr_port']) == [multicast_ip, multicast_port]:
                            resp = 0
                            break
                    else:
                        self.chat_rooms.append({'name': chatroom_name, 'addr_port': (multicast_ip, multicast_port)})
                        print("Added Chatroom to Directory: ", self.chat_rooms[-1])
                        resp = 1

                    connection.send(resp.to_bytes(1, byteorder='big'))

                elif CLIENT_TO_CRD_CMDS["deleteroom"] == command:
                    # Receive additional bytes in order to retrieve the chatroom name.
                    chatroom_del_byte_len = int.from_bytes(connection.recv(1), byteorder='big')
                    chatroom_del = connection.recv(chatroom_del_byte_len).decode(Server.MSG_ENCODING)
                    print("Chat room" + chatroom_del + "deleted.")
                    for room in self.chat_rooms:
                        if room['name'] == chatroom_del:
                            self.chat_rooms.remove(room)
            else:
                print("Unrecognized command received. Closing connection ...")
                connection.close()
                return 

            


########################################################################
# Multicast Client 
########################################################################

# MULTICAST_ADDRESS = "239.0.0.10"

RX_BIND_ADDRESS = "0.0.0.0"

########################################################################

# exitChat = 0 

# def signal_handler(sig, frame):
# 	print('You pressed Ctrl+C, exiting chat.')
# 	global exitChat
# 	exitChat = 1
# 	#sys.exit(0)

#signal.signal(signal.SIGINT, signal_handler)
#print('Press Ctrl+C')
#signal.pause()

class Client:

    RECV_SIZE = 256
        
    # Create a 1-byte maximum hop count byte used in the multicast
    # packets (i.e., TTL, time-to-live).
    TTL = 1 # Hops
    TTL_SIZE = 1 # Bytes
    TTL_BYTE = TTL.to_bytes(TTL_SIZE, byteorder='big')

    def __init__(self):
        self.dir_list = None
        self.socket_create()
        # signal.signal(signal.SIGINT, signal_handler)
        self.handle_console_input_forever()
        
        

    def multicast_group_registration(self, multicast_addr_port): 
            self.multicast_addr_port = multicast_addr_port

            # Sender
            self.multicast_send = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.multicast_send.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, Client.TTL_BYTE) 

            # Receiver and Registration
            self.multicast_rec = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.multicast_rec.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, True)
            self.multicast_rec.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, Client.TTL_BYTE)
            self.multicast_rec.bind((RX_BIND_ADDRESS, int(multicast_addr_port[1])))           

            multicast_group_bytes = socket.inet_aton(multicast_addr_port[0])
            print("Multicast Group: ", multicast_addr_port[0])

            # Set up the interface
            multicast_if_bytes = socket.inet_aton(RX_BIND_ADDRESS)

            # Form the multicast request.
            multicast_request = multicast_group_bytes + multicast_if_bytes
            print("multicast_request = ", multicast_request)

            # Issue the Multicast IP and add Membership request
            print("Adding membership (address/interface): ", multicast_addr_port[0],"/", multicast_addr_port[1])
            self.multicast_rec.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, multicast_request)

    def socket_create(self):
        try:
            self.CRDS_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        
        except Exception as msg:
            print(msg)
            sys.exit(1)

    def server_connection(self):
        self.CRDS_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM) # recreate socket - allows for multiple "connect"/"bye" cmds in one session
        print("Connecting to:", Server.CRDS_address_port)
        try:
            # Connect to the server using its socket address tuple.
            self.CRDS_socket.connect( Server.CRDS_address_port )
        except Exception as msg:
            print(msg)
            sys.exit(1)

    def send_chat_msg(self):
        while True:
            try:
                if exitChat:
                    return
                if self.send_thread_kill:
                    return
                    
                msg = input()
                msg_bytes = f'{self.name}: {msg}'.encode(Server.MSG_ENCODING)
                addr_port = (self.multicast_addr_port[0], int(self.multicast_addr_port[1]))
                print(addr_port)
                self.multicast_send.sendto(msg_bytes, addr_port)
            except:
                self.recv_thread_kill = True
                return

    def receive_chat_msg(self):
        try:
            while True:
                if exitChat:
                    return
                if self.recv_thread_kill:
                    return
                
                chat_msg_bytes, ret_addr = self.multicast_rec.recvfrom(Client.RECV_SIZE)
                chat_msg = chat_msg_bytes.decode(Server.MSG_ENCODING)

                print(">>", chat_msg)

        except:
            self.send_thread_kill = True
            return

    def enter_chat_room(self, chatroom):
        try:
            global exitChat
            exitChat = 0
            for room in self.dir_list:
                print(room['name'], chatroom)
                if room['name'] == chatroom:
                    address = room["addr_port"][0]
                    port = room["addr_port"][1]
                    self.multicast_group_registration((address, port))
                    self.chatroom_name = room['name']
                    break
            else:
                print("No room by that name...")
                return
            
            send_thread = Thread(target=self.send_chat_msg)
            recv_thread = Thread(target=self.receive_chat_msg)

            self.recv_thread_kill = False
            self.send_thread_kill = False
            recv_thread.daemon = True
            send_thread.daemon = True

            send_thread.start()
            recv_thread.start()

            send_thread.join()
            recv_thread.join()
        except:
            pass
	
        print("Chat exited")
        #close the connection
        #self.CRDS_socket.close()

    def getdir(self):
        cmd_field = CLIENT_TO_CRD_CMDS["getdir"].to_bytes(1, byteorder='big')
        self.CRDS_socket.send(cmd_field)

        dir = self.CRDS_socket.recv(Client.RECV_SIZE)
        if len(dir) == 0:
            self.CRDS_socket.close()
            return
        self.dir_list = json.loads(dir.decode(Server.MSG_ENCODING))
        print(self.dir_list)

    def deleteroom(self, delroompass):
        cmd_field = CLIENT_TO_CRD_CMDS["deleteroom"].to_bytes(1, byteorder='big')
        del_len_bytes = len(delroompass).to_bytes(1, byteorder='big')
        del_bytes = delroompass.encode(Server.MSG_ENCODING)
        pkt = cmd_field + del_len_bytes + del_bytes
        self.CRDS_socket.send(pkt)
        

    def send_room_info(self, room_info):
        cmd_field = CLIENT_TO_CRD_CMDS["makeroom"].to_bytes(1, byteorder='big')

        name_len_bytes = len(room_info['name']).to_bytes(1, byteorder='big')
        name_bytes = room_info['name'].encode(Server.MSG_ENCODING)

        address_bytes = socket.inet_aton(room_info['addr_port'][0])
        port_str_bytes = room_info['addr_port'][1].encode(Server.MSG_ENCODING)

        pkt = cmd_field + name_len_bytes + name_bytes + address_bytes + port_str_bytes

        self.CRDS_socket.send(pkt)

        print("Server resp:", int.from_bytes(self.CRDS_socket.recv(1), byteorder='big'))

    def handle_console_input_forever(self):
        while True:
            try:
                self.input_text = input("Enter Command: ")
                if self.input_text != "":
                    print("Command Entered:", self.input_text)

                    if self.input_text == "connect":
                        print("Conneting to CRDS...")
                        self.server_connection()

                    elif self.input_text == "bye":
                        print("Server connection closing...")
                        self.CRDS_socket.close()

                    elif self.input_text.split()[0] == "name":
                        self.name = self.input_text.split()[1:]

                    elif self.input_text.split()[0] == "chat":
                        self.enter_chat_room(' '.join(self.input_text.split()[1:]))

                    elif self.input_text.split()[0] == "makeroom":
                        cmd_params = self.input_text.split()[1:]
                        port = cmd_params[-1]
                        address = cmd_params[-2]
                        chatroom_name = ' '.join(cmd_params[:-2])

                        room = {"name": chatroom_name, "addr_port": (address, port)}
                        self.send_room_info(room)

                        print("Chatroom: ", chatroom_name, address, port)

                    elif self.input_text.split()[0] == "deleteroom":
                        delroom = self.input_text.split()[1:]
                        self.deleteroom(delroom[0])

                    elif self.input_text == "getdir":
                        self.getdir()

                    else:
                        print("Unrecongized command received..")
                        continue

            except (KeyboardInterrupt, EOFError):
                print()
                print("Server connection is closing  ...")
                self.CRDS_socket.close()
                sys.exit(1)


########################################################################
# Process command line arguments if run directly.
########################################################################

if __name__ == '__main__':
    roles = {'client': Client,'server': Server}
    parser = argparse.ArgumentParser()

    parser.add_argument('-r', '--role',
                        choices=roles, 
                        help='server or client role',
                        required=True, type=str)

    args = parser.parse_args()
    roles[args.role]()

########################################################################
