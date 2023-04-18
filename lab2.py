import argparse
from collections import defaultdict
from cryptography.fernet import Fernet
import socket
import sys

## Commands
GET_MIDTERM_AVG_CMD = "GMA"
GET_LAB_1_AVG_CMD = "GL1A"
GET_LAB_2_AVG_CMD = "GL2A"
GET_LAB_3_AVG_CMD = "GL3A"
GET_LAB_4_AVG_CMD = "GL4A"
GET_EXAM_1_AVG_CMD = "GE1A"
GET_EXAM_2_AVG_CMD = "GE2A"
GET_EXAM_3_AVG_CMD = "GE3A"
GET_EXAM_4_AVG_CMD = "GE4A"
GET_GRADES_CMD = "GG"

COMMAND_LIST = [GET_MIDTERM_AVG_CMD, GET_LAB_1_AVG_CMD, GET_LAB_1_AVG_CMD, GET_LAB_2_AVG_CMD, GET_LAB_3_AVG_CMD,
                GET_LAB_4_AVG_CMD, GET_EXAM_1_AVG_CMD, GET_EXAM_2_AVG_CMD, GET_EXAM_3_AVG_CMD, GET_EXAM_4_AVG_CMD,
                GET_GRADES_CMD]


## Student class
class Student:

    def __init__(self, data, headers):
        self.data = {headers[i]: data[i] for i in range(len(headers))}

    def get(self, field):
        return self.data[field]


# Server Class
class Server:
    HOSTNAME = "0.0.0.0"
    PORT = 50000
    RECV_BUFFER_SIZE = 1024
    MAX_CONNECTION_BACKLOG = 10
    MSG_ENCODING = "utf-8"
    SOCKET_ADDRESS = (HOSTNAME, PORT)

    def __init__(self):
        self.parse_csv("course_grades_2023.csv")
        self.create_listen_socket()
        self.keep_processing_connections()

    # pre-process messages ready to be sent
    def parse_csv(self, filename):
        self.students = {}
        with open(filename, "r") as f:
            print("Data read from CSV file:")

            headers = f.readline()
            print(headers.strip())
            headers = headers.strip().split(',')
            lines = f.readlines()
            students_raw = []
            for line in lines:
                print(line.strip())
                students_raw = (line.strip().split(','))
                student_dict = {}
                for i in range(len(headers)):
                    student_dict[headers[i]] = students_raw[i]
                self.students[student_dict["ID Number"]] = student_dict
            # pre-compute all the averages
            self.grade = defaultdict(lambda: 0)
            num_students = len(self.students)
            for s in self.students.values():  ## values
                self.grade[GET_MIDTERM_AVG_CMD] += float(s.get("Midterm")) / num_students
                self.grade[GET_LAB_1_AVG_CMD] += float(s.get("Lab 1")) / num_students
                self.grade[GET_LAB_2_AVG_CMD] += float(s.get("Lab 2")) / num_students
                self.grade[GET_LAB_3_AVG_CMD] += float(s.get("Lab 3")) / num_students
                self.grade[GET_LAB_4_AVG_CMD] += float(s.get("Lab 4")) / num_students
                self.grade[GET_EXAM_1_AVG_CMD] += float(s.get("Exam 1")) / num_students
                self.grade[GET_EXAM_2_AVG_CMD] += float(s.get("Exam 2")) / num_students
                self.grade[GET_EXAM_3_AVG_CMD] += float(s.get("Exam 3")) / num_students
                self.grade[GET_EXAM_4_AVG_CMD] += float(s.get("Exam 4")) / num_students

    ##################################################################
    def create_listen_socket(self):
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

            self.socket.bind(Server.SOCKET_ADDRESS)

            self.socket.listen(Server.MAX_CONNECTION_BACKLOG)
            print("Listening on port {}...".format(Server.PORT))

        except Exception as msg:
            print(msg)
            sys.exit(1)

    def keep_processing_connections(self):
        try:
            while True:
                self.server_helper(self.socket.accept())
        except Exception as msg:
            print(msg)
        except KeyboardInterrupt:
            print()
        finally:
            self.socket.close()
            sys.exit(1)

    ##################################################################
    # 1. Identify clinet's command
    # 2. Create variables from parse_csv
    # 3. Encryption

    def process_cmd(self, cmd_str):
        split_string = cmd_str.split(',')  # return array split with "ID, cmd"
        id = split_string[0]
        cmd = split_string[1]

        if id in self.students:
            print("User Found.")
            if cmd in COMMAND_LIST:
                if cmd == GET_GRADES_CMD:
                    print("Good Cmd")
                    s = self.students.get(id)
                    print("Received {} command from user.".format(cmd))
                    grades_dict = {k: v for k, v in s.items() if k not in ['ID Number', 'Key']}
                    my_string = str(grades_dict)
                    
                    # encryption
                    message = my_string
                    message_bytes = message.encode('utf-8')
                    encryption_key = s.get('Key')
                    encryption_key_bytes = encryption_key.encode('utf-8')
                    fernet = Fernet(encryption_key_bytes)
                    encrypted_message_bytes = fernet.encrypt(message_bytes)
                    separator = "--"
                    message_sent = separator.join([str(encryption_key_bytes), str(encrypted_message_bytes)])
                    return message_sent
                
                else:
                    print("Good Cmd and not GG")
                    s = self.students.get(id)
                    print("Received {} command from the user".format(cmd))
                    my_string = str(self.grade[cmd])

                    # encryption            
                    message = my_string
                    message_bytes = message.encode('utf-8')
                    encryption_key = s.get('Key')
                    encryption_key_bytes = encryption_key.encode('utf-8')
                    fernet = Fernet(encryption_key_bytes)
                    encrypted_message_bytes = fernet.encrypt(message_bytes)
                    separator = "--"
                    message_sent = separator.join([str(encryption_key_bytes), str(encrypted_message_bytes)])
                    return message_sent
                    
                    
                    
            else:
                print("Bad Cmd")
                return "Bad Cmd"
                # s = self.students.get(id)
                # print("Received {GG} command from the user.")
                # grades_dict = {key: value for key, value in s.data.items()}
                # my_string = str(grades_dict)
                # encryption_key = grades_dict.get('Key')

            # elif cmd in self.grade:
            # s = self.students.get(id)
            # print("Received {cmd} command from the user.")
            # my_string = str(self.grade[cmd])
            # encryption_key = s.get('Key')
            # else:
            # print("Wrong input commands.")

        else:
            print("User not Found!!")
            return "User not Found!!"
        

    def server_helper(self, client):  #
        socket, port_num = client
        print("#" * 64)
        print("Connection received from {}.".format(port_num))

        while True:
            try:
                recv_bytes = socket.recv(Server.RECV_BUFFER_SIZE)

                if len(recv_bytes) == ",":
                    print("Closing client connection ... ")
                    socket.close()
                    break

                recv_str = recv_bytes.decode(Server.MSG_ENCODING)
                response_str = self.process_cmd(recv_str)

                if len(response_str) == Client.RECV_BUFFER_SIZE:
                    response_str += " "

                sending_bytes = response_str.encode(Server.MSG_ENCODING)
                socket.sendall(sending_bytes)
                # print("Sent Message: {}".format(sending_bytes))

            except KeyboardInterrupt:
                print()
                print("Closing client connections !!!")
                socket.close()
                break


##################################################################


# Clinet Class
class Client:
    SERVER_HOSTNAME = socket.gethostname()
    RECV_BUFFER_SIZE = 1024

    def __init__(self):
        self.get_socket()
        self.connect_server()
        self.keep_sending_console_input()

    def get_socket(self):
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        except Exception as msg:
            print(msg)
            sys.exit(1)

    def connect_server(self):
        try:
            self.socket.connect((Client.SERVER_HOSTNAME, Server.PORT))

        except Exception as msg:
            print(msg)
            sys.exit(1)

    def get_console_input(self):
        while True:
            self.input_text_ID = input("Please Enter ID: ")
            self.input_text_CMD = input("Please Enter Command: ")
            separator = ","
            self.input_text = separator.join([self.input_text_ID, self.input_text_CMD])
            if self.input_text != ",":
                print("Welcome User: ", self.input_text_ID)
                print()
                print("Command Verification: ", self.input_text)
                print()

                if self.input_text_CMD == GET_GRADES_CMD:  # Command GG
                    print_str = "Fetching Private Grade"
                elif self.input_text_CMD == GET_MIDTERM_AVG_CMD:
                    print_str = "Fetching Midterm Average"
                elif self.input_text_CMD == GET_LAB_1_AVG_CMD:
                    print_str = "Fetching Lab 1 Average"
                elif self.input_text_CMD == GET_LAB_2_AVG_CMD:
                    print_str = "Fetching Lab 2 Average"
                elif self.input_text_CMD == GET_LAB_3_AVG_CMD:
                    print_str = "Fetching Lab 3 Average"
                elif self.input_text_CMD == GET_LAB_4_AVG_CMD:
                    print_str = "Fetching Lab 4 Average"
                elif self.input_text_CMD == GET_EXAM_1_AVG_CMD:
                    print_str = "Fetching Exam 1 Average"
                elif self.input_text_CMD == GET_EXAM_2_AVG_CMD:
                    print_str = "Fetching Exam 2 Average"
                elif self.input_text_CMD == GET_EXAM_3_AVG_CMD:
                    print_str = "Fetching Exam 3 Average"
                elif self.input_text_CMD == GET_EXAM_4_AVG_CMD:
                    print_str = "Fetching Exam 4 Average"
                else:
                    print("Unrecongized Commands")
                    continue
                print(print_str)
                break

    def keep_sending_console_input(self):
        while True:
            try:
                self.get_console_input()
                self.connection_send()
                self.connection_recv()

            except (KeyboardInterrupt, EOFError):
                print("/n Server closed connection !!")
                self.socket.close()
                sys.exit(1)

    def connection_send(self):
        try:
            self.socket.sendall(self.input_text.encode(Server.MSG_ENCODING))
        except Exception as msg:
            print(msg)
            sys.exit(1)

    def connection_recv(self):
        try:
            recv_bytes = self.socket.recv(Client.RECV_BUFFER_SIZE)
            if len(recv_bytes) == 0:
                print("Closing server connection ... ")
                self.socket.close()
                sys.exit(1)

            recv_msg = recv_bytes.decode(Server.MSG_ENCODING)
            print("Received message bytes and key bytes at client {}".format(recv_msg))
            split_string = recv_msg.split('--')  # return array split with "ID, cmd"
            encryption_key_bytes = split_string[0][2:-1].encode('utf-8')
            encrypted_message_bytes = split_string[1][2:-1].encode('utf-8')
            fernet = Fernet(encryption_key_bytes)
            # Decrypt the message after reception at the client
            decrypted_message_bytes = fernet.decrypt(encrypted_message_bytes)
            decrypted_message = decrypted_message_bytes.decode('utf-8')
            print("decrypted_message = ", decrypted_message)

        except Exception as msg:
            print(msg)
            sys.exit(1)

        # Program Entry


if __name__ == '__main__':
    roles = {'client': Client, 'server': Server}
    parser = argparse.ArgumentParser()

    parser.add_argument('-r', '--role',
                        choices=roles,
                        help='server or client role',
                        required=True,
                        type=str,
                        default='client')

    args = parser.parse_args()
    roles[args.role]()
