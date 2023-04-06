
'''
Server, Daniel Sapojnikov.
Have a nice day, Eran :)
'''

import os
import string
import random
import time
from datetime import datetime
import tkinter as tk
import tkinter.ttk as ttk   
import sqlite3 as sl
from scapy.all import *
from scapy.all import conf
import subprocess, re, select
from threading import Thread
from socket import *

# globals
global SENT
global SERVER_SHUT_DOWN
SERVER_SHUT_DOWN = False
SENT = False

# Avoid scapy problems.
conf.verbose = 0
conf.sniff_promisc = 0

# important variables
PATH = os.path.dirname(os.path.realpath(__file__))
FILE_REG = r'^/(?:create|run|edit)\s+(\w+\.py)$'
KICKED, FILES = [], []
INACTIVE_GAP = 120
BUFSIZE = 1024
SIGNET = 'I AM LOOKING FOR A SERVER'
SIGNET_LEN = len(SIGNET)
FILTER_REG = r'[^\w\n|.]'
IP_REG = r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(?=\s|\Z)'
     
def init_gui():
     
    '''
    :init_gui, initializes the gui.
    :server side -> Has a TreeView Widget.
    :RETURNS: every widget on the WINDOW.
    '''
     
    WINDOW = tk.Tk()
    WINDOW.title("Server / Admin - Daniel Sapojnikov")

    # Responsive GUI
    tk.Grid.columnconfigure(WINDOW, 0, weight=1)
    tk.Grid.rowconfigure(WINDOW, 1, weight=1)

    # Set up colors
    bg_color = "#111111"
    fg_color = "#FFFFFF"
    table_color = "#222222"
    table_heading_color = "#555555"

    full_width = int(WINDOW.winfo_screenwidth()) 
    full_height = int(WINDOW.winfo_screenheight())

    width = int(full_width // 1.8)
    height = int(full_height // 1.8)
    WINDOW.geometry(f'{width}x{height}')

    style = ttk.Style()
    style.theme_use("alt")  # Use the "clam" theme
    
    # Admin label & centering.
    label = tk.Label(
        WINDOW,
        padx=10,
        pady=10,
        text='ADMIN PAGE',
        justify=tk.CENTER,
        font=('Open Sans', 15, 'bold'),
    )
    label.grid(row=0, column=0, sticky='news')
    
    # configure the style of the table.
    style.configure("TableStyle.Treeview",
                background="#333333",  # Set the background color
                foreground="white",    # Set the text color
                fieldbackground="#333333",  # Set the background color for the table cells
                bordercolor="#666666", # Set the border color
                borderwidth=1          # Set the border width
        )
    
    # set the color of the table when selected.
    style.map("TableStyle.Treeview",
          background=[("selected", "#666666")])

    # Create table
    table = ttk.Treeview(
        WINDOW, 
        columns=('Client', 'IP', 'Port', 'Password', 'Time of connection'), 
        show='headings', 
        style='TableStyle.Treeview'
    )
    
    # Set the table style to the configure we made above.
    style = ttk.Style()
    style.configure(
            "TableStyle", 
            background=table_color, 
            foreground=fg_color, 
            highlightthickness=0, 
            bd=0, 
            font=("Arial", 10), 
            rowheight=30, 
            headerbackground=table_heading_color, 
            headerforeground=fg_color, 
            headerfont=("Arial", 12)
        )

    # Headers of the table.
    headers = ('Client', 'IP', 'Port', 'Password', 'Time of connection')
    for head in headers:
        table.heading(head, text=head.upper())

    # setting the columns style.
    for column in range(1, 6):
        table.column(f"#{column}", anchor=tk.CENTER, stretch=tk.NO)

    table.grid(row=1, column=0, sticky="nsew")
    
    # add scrollbar
    scrollbar = ttk.Scrollbar(WINDOW, orient=tk.VERTICAL, command=table.yview)
    scrollbar.grid(row=1, column=1, sticky='ns')
    table.configure(yscrollcommand=scrollbar.set)

    # configure row and column weights
    WINDOW.rowconfigure(1, weight=1)
    WINDOW.columnconfigure(0, weight=1)
    table.grid_rowconfigure(0, weight=1)
    table.grid_columnconfigure(0, weight=1)

    return WINDOW, table

def generate_password() -> str:
    
    '''
    :Generates a random password using random + string modules.
    :RETURNS -> a string.
    '''
    # makes it more random.
    PASS_LEN = random.randint(5, 8)
    
    # characters.
    lower = string.ascii_lowercase
    upper = string.ascii_uppercase
    symbols = string.punctuation
    digits = string.digits
    
    # combine possibilities.
    all_matches = lower + upper + digits + symbols
    scramble = random.sample(all_matches, PASS_LEN)
    
    # create the password.
    password = "".join(scramble)
    return password

def create_db() -> None:
    
    '''
    :Creates a data base of all clients, a must addition to the admin page.
    :RETURNS -> the cursor for later means. 
    '''

    # connecting to the data base.
    data_base_file = 'admin.db'
    table = sl.connect(data_base_file)
    c = table.cursor()
    
    try:
        # when the server is closed, the table is deleted.
        c.execute("""CREATE TABLE users (
            client_name, text 
            ip text,
            port text,
            password text,
            connection text
            )""")
        
        # Finish the work by closing the cursor and the connection.
        c.commit()
        table.close()
    
    # handle exceptions.
    except Exception as e:
        raise e
    
    # returning the cursor.
    finally:
        return c

def insert_client(c, name, addr, password) -> None:
    
    '''
    :Gets: cursor, name, addrs = (IP, PORT), password
    :inserts the client to the data base.
    '''

    # insert online clients.
    date = datetime.today().strftime('%Y-%m-%d %H:%M:%S')
    table = sl.connect('admin.db')
    c = table.cursor()
    c.execute('''INSERT INTO users VALUES(?, ?, ?, ?, ?)''', (name, addr[0], addr[1], password, date)) # inserting
    
    # finishing the work.
    table.commit()
    table.close()
 
def visualize_client(table) -> None:
    
    '''
    :Get -> the table we want to update.
    '''
     
    entry = sl.connect('admin.db')
    c = entry.cursor()
    c.execute('''SELECT COUNT(*) FROM users''')
    num_users = c.fetchone()[0]
    client_data = c.execute(f'''SELECT * FROM users WHERE rowid = {num_users}''').fetchone()
    
    # Finishing the work.
    c.close()
    entry.close()
    table.insert('', 'end', values=tuple(client_data))
    
def delete_client():
    pass

def server_credentials() -> None:
    
    '''
    RETURNS: the credentials of the server -> (IP, PORT)
    1. uses subprocess to fetch the ip + string manipulation.
    2. uses the following 'port' code in order to find the first OPEN port on the device - (SERVER).
    '''
    
    data = subprocess.check_output('ipconfig').decode('utf-8')
    data = re.sub(FILTER_REG, '', data)

    k = data.index("IPv4Address") + 1 # the index of the ip address.
    ip = re.search(IP_REG, data[k: data.index('\n', k)])
    ip = ip.group(0) if ip != None else None
    
    # PORT
    scan_socket = socket(AF_INET, SOCK_STREAM)
    scan_socket.bind(("",0))
    scan_socket.listen(1)
    
    port = scan_socket.getsockname()[1]
    scan_socket.close()
    
    return (ip, port)

def get_addr(d):
    
    '''
    # d is the line of the LABEL.
    
    RETURNS: A tuple -> (IP, PORT) of the client, uses string manipulation with slices.
    # the label: I AM LOOKING FOR A SERVER is followed by an IP and a PORT.
    '''
    
    if not d:
        return None
    
    # SIGN is the line we need (line including the label)
    sign = d.replace(' ','')
    start, mid, end = sign.index('('), sign.index(','), sign.index(')')
    
    # getting the parameters.
    ip, port = sign[start+1: mid], int(sign[mid+1: end])
    
    return (ip, port)
 
def catch_looking_packet(server_ip, server_port) -> None:
     
    '''
    :We want to catch the 'LOOKING' packet, where the client tells the LAN that he is looking for a server.
    :When a client is opened he broadcasts the LAN that he is 'LOOKING FOR A SERVER' combined with his credentials.
    :The server then sniffs that UDP frame, checks the 'LOOKING' label then takes the ip & port of the client.
    :The server will send the clients its own credentials to the client.
    '''
    ip, port = server_ip, server_port
    server_udp = socket(family=AF_INET, type=SOCK_DGRAM)
    
    # catch the data.
    addr, looking = (), False
    while True:
        
        # using scapy to sniff the desired UDP packet.
        capture = sniff(count=1, filter="udp and dst 255.255.255.255")
        data_list = [data.split('\n') for packet in capture if 'I AM LOOKING FOR A SERVER' in (data:=packet.show(dump=True))]
        
        # d[-2] is the last line of the packet -> which includes the SIGN.
        # we want to take whats between the parentheses so that we will get the addr of the client.
        address_list = [addr for d in data_list if (addr:=get_addr(d[-2])) != None]
        for addr in address_list:
            
            # send the credentials.
            data = f'HELLO ITS A SERVER ({ip}, {port})'.encode('utf-8')
            server_udp.sendto(data, addr)
            
def notify_all(input_list, terminator, server):
     
    '''
    :Gets => list of clients, terminator & the server socket.
    :Imulates BROADCAST messages, when the terminator socket sends $TERMINATE, we notify the client about the case.
    '''
     
    # notify other clients.
    online_clients = [s for s in input_list if s not in {terminator, server}]
    print(online_clients)
    
    for sock in online_clients:
        sock.send(f'{sock.getpeername()} activated termination.'.encode('utf-8'))

def verify_termination(input_list, terminator, server, active_dict, PASSWORD):
    
    '''
    :Gets -> list of clients, server socket, active_dict, PASSWORD
    :Verifies the password corresponding to the client, can stop $TERMINATE process by sending Stop terminating.
    '''
    
    global SERVER_SHUT_DOWN
    
    while True: 
        try:
            data = terminator.recv(BUFSIZE).decode('utf-8')
            active_dict.update({terminator: time.time()})
            
            if data == PASSWORD:
                
                # closing signature.
                for sock in [s for s in input_list if s not in [server]]:
                    
                    # Tell the client that we very sorry for closing the connection. :)
                    data = 'CLOSE CONNECTION - CLIENT'
                    data = data.encode('utf-8')
                    sock.send(data) 
                    
                    # close the connection.
                    print(f'Connection with client: {sock.getpeername()} has been closed')
                    input_list.remove(sock)
                    sock.close()
                    
                SERVER_SHUT_DOWN = True

            elif data == 'Stop terminating':
                data = 'Stopped! you may continue.'
                terminator.send(data.encode('utf-8'))
                SENT = False 
                break
        
            else: terminator.send('server: Incorrect password!'.encode('utf-8'))

        except OSError:
            break    
            
        except Exception as e:
            break

def kick(input_list, active_dict) -> None:
    
    '''
    :Gets -> list of clients, active_dict which is a dictionary that matches to every KEY its Last ACTIVE time.
    
    $$$ IMPORTANT $$$
    :KICKS every client whos not been active for at least 2 minutes, updates the active_dict accordingly.
    '''

    while True:
        try:
            for client_sock, active_time in {sock: time for sock, time in active_dict.items() if sock not in KICKED}.items():
                
                information_time = 0
                if time.time() - active_time >= INACTIVE_GAP:
                    
                    # inform the user.
                    client_sock.setblocking(True)
                    data = f'You are a great human being! Sadly due to inactivity, you will be kicked in {INACTIVE_GAP+4-math.ceil((time.time() - active_time))} seconds.'
                    client_sock.send(data.encode('utf-8'))
                    information_time = time.time()
                
                if information_time - active_time >= INACTIVE_GAP + 3:
                    data = 'CLOSE CONNECTION - CLIENT'
                    print("SENT KICK!")
                    client_sock.send(data.encode('utf-8'))
                    
                    # KICK
                    input_list.remove(client_sock)
                    KICKED.append(client_sock)
                    client_sock.close()
            time.sleep(1)
                    
        # exceptions
        except ConnectionResetError:  
            print(f'Connection with {client_sock} has been closed')
            client_sock.close()
        except OSError:
            del active_dict[client_sock]
            continue
        except Exception as e:
            print(e)
            
def py_code(sock, active_dict):

    '''
    :The function behind the pycode mode, gets a sock & the active dict.
    :$pycode, has 6 sub-modes (/finish pycode, /finish coding!, /finish editing!, /create, /edit, /run).
    :the client can create .py files, edit them and finally run them.
    :TO create -> /create <file_name>.py E.g /create test.py
    :To edit -> /edit <file_name>.py as the above -> <line_number> <replacement> E.g 5 print("Hello")
    :To run -> /run <file_name>.py E.g /run test.py
    :To finish any process (/finish coding!, /finish editing!) you make write it and send it, the process will be finished.
    
    $$$ important comments $$$
    :DOES NOT SUPPORT INPUTS.
    :DOES SUPPORT LOOPS, VARIABLES, IF ELSE STATEMENTS, SPECIAL FUNCTIONS SUCH AS eval, print etc.
    :DOES SUPPORT IMPORT (has to be installed).
    
    :An error will be displayed once a client will /run a file, the client will then be able to /edit the file!
    :ALL OF THE CLIENTS CAN RUN & EDIT all of the files under the same SERVER session.
    :once a server is closed, all of the files are gone.
    '''

    global SENT

    while True:
        try:
            # recv file name in the format /create <file_name>.py & redefine important instances.
            sock.setblocking(True)
            file = sock.recv(BUFSIZE).decode('utf-8')
            active_dict.update({sock: time.time()})
            
            # SUB-MODES
            if not re.search(FILE_REG, file): # check valid commands with regex.
                sock.send('Enter a valid file name, or command.'.encode('utf-8'))
                continue
               
            if file == '/finish pycode':
                SENT = False 
                break
               
            if '/run' in file:
                file = re.sub('/run', '', file).strip()
                if file not in FILES:
                    sock.send('server: Enter an existing file!'.encode('utf-8'))
                    continue
                else: 
                    try:
                        # all of the files are stored in the same dir as the SERVER file.
                        os.chdir(PATH)
                        output = subprocess.check_output(f'python {file}', stderr=subprocess.STDOUT)
                        sock.send(output)
                         
                    # Get file error.     
                    except subprocess.CalledProcessError as e:
                        error_output = e.output.decode('utf-8').strip()
                        sock.send(f'{file} as an Error: {error_output}'.encode('utf-8'))
                    
                    finally: continue
            
            elif '/edit' in file:
                file = re.sub('/edit', '', file).strip()
               
                # validate file.
                if file not in FILES:
                    sock.send('server: Enter an existing file!'.encode('utf-8'))
                    continue
                
                # passed validation.
                with open(file, 'r+') as f:
                    
                    file_data = f.readlines()
                    code_len = len(file_data)
                    data = f'server: To edit, enter <line> <replacement>'.encode('utf-8')
                    sock.send(data)
                    
                    # editing loop.
                    while True:
                        command = sock.recv(BUFSIZE).decode('utf-8')
                        active_dict.update({sock: time.time()})
                        
                        # command handling.
                        if command == '/finish editing!': break
                        if not re.search(r'^\d+\s+.+$', command):
                            sock.send(f'server: enter a valid command in the specified format.'.encode('utf-8'))
                            continue
                         
                        # editing process
                        line_num = int(re.findall(r'^\d+', command)[0]) - 1
                        valid_line = 1 <= line_num + 1 <= code_len
                        if not valid_line: 
                            sock.send(f'server: enter a valid command in the specified format.'.encode('utf-8'))
                            continue
                              
                        # new line
                        replacement = re.sub(str(line_num+1), '', command).strip() +'\n'
                        if 'tab' in replacement: replacement = ' '*4 + replacement.replace('tab', '').strip()
                              
                        # EDIT PART
                        file_data[line_num] = replacement
                        f.seek(0, 0)
                        f.writelines(file_data)
                    
            # /create
            else: 
                file = re.sub('/create', '', file).strip()
                FILES.append(file)
                with open(file, 'w') as f:
                    data = f'server: {file} was created!, you may start coding.'.encode('utf-8')
                    sock.send(data)
                    
                    # The client is now coding.
                    while True:
                        code = sock.recv(BUFSIZE).decode('utf-8')
                        active_dict.update({sock: time.time()})
                         
                        # code handling.
                        if code == '/finish coding!': break
                        if 'tab' in code: code = ' '*4 + code.replace('tab', '').strip()
                        f.write(code + '\n')
        
        except ConnectionAbortedError as e:
            print('The client was closed / kicked')
            break
               
        except Exception as e:
            print('The client was closed / kicked')
            break
        
def service(WINDOW, table) -> None:
    
    '''
    :Gets -> WINDOW, table -> Window is the main window & table is the DATABASE table
    :The key to the server communication with other nodes -> can handle n > 2 nodes.
    RETURNS: Nothing.
    '''

    global SENT
    global SERVER_SHUT_DOWN

    NODES = 2
    BUFSIZE = 1024
    ADDR = server_credentials()

    server_socket = socket(AF_INET, SOCK_STREAM)
    server_socket.setblocking(False)
    server_socket.bind(ADDR)
    server_socket.listen(NODES)
    
    # creating the data base.
    cursor = create_db()
    active_dict = {}
    
    # lists for service.
    input_list = [server_socket]
    output_list = []
    
    # Catch connections.
    print(f"server <{ADDR}> is running.")
    Thread(target=catch_looking_packet, daemon=True, args=(ADDR[0], ADDR[1])).start()
    Thread(target=kick, daemon=True, args=(input_list, active_dict)).start()
    while input_list:
        
        # Helper to notify all clients.
        clients = len(input_list)
        
        if SERVER_SHUT_DOWN:
            print('Server was shut down.')
            WINDOW.destroy()
            server_socket.close()

            # pick a clearing command, based on the OS.
            clear_command = 'cls' if os.name == 'nt' else 'clear'
            os.system(clear_command)
                        
            # exit the service.
            return
        
        readables, writeables, exceptions = select.select(input_list, output_list, [], 1)
        for sock in readables: # SOCK is the socket we want to read from.
            
            if sock is server_socket:
                
                PASSWORD = generate_password()
                # accept current client.
                client_sock, address = sock.accept()
                ip, port = address
                
                # appending to the data base.
                insert_client(cursor, '', address, PASSWORD)
                visualize_client(table)
                
                # print the clients important data & managing the client, each session has its own password.
                print(f"Session with: {address}, PASSWORD: {PASSWORD}")
                input_list.append(client_sock)
                active_dict.update({client_sock: time.time()})
                SENT = False
              
            else:
                try:
                    connection_closed = False
                    peer_name = sock.getpeername()
                    data = sock.recv(BUFSIZE)
                    data = data.decode('utf-8')
                    data = data.strip()
                    
                    # COMMANDS
                    print(f"Server got: {data} from: {peer_name}")
                    active_dict.update({sock: time.time()})
                    if data[0] == '$':
                    
                        if data[1:] == 'TIME':
                            currentDateAndTime = datetime.now()
                            data = f'The current time is {currentDateAndTime.strftime("%H:%M:%S")}'
                        
                        elif data[1:] == 'CLOSE':
                            
                            # update the client side -> to close the windows & and the connection.
                            data = 'CLOSE CONNECTION - CLIENT'
                            sock.send(data.encode('utf-8')) 
                            
                            # close the connection.
                            print(f'Connection with client: {peer_name} has been closed')
                            input_list.remove(sock)
                            sock.close()
                            sent = True
                            
                        elif data[1:] == 'pycode':
                            
                            # send the information.
                            data = f'server: Enter /create <file_name> to create, /run <file_name> to run.\nCurrent files to run: {FILES}'.encode('utf-8')
                            sock.send(data)
                            SENT = True
                              
                            # Allows the client to write python code.
                            pycode_t = Thread(target=py_code, daemon=True, args=(sock, active_dict))
                            pycode_t.start()
                                                    
                        elif data[1:] == 'TERMINATE':
                            
                            # send all of the clients that SOCK wants to close the server in the same time.
                            if clients >= 2:
                                notify_thread = Thread(target=notify_all, args=(input_list, sock, server_socket))
                                notify_thread.start()
                            
                            data = f'We need your password :)'
                            data = f'server: {data}'.encode('utf-8')
                            sock.send(data)
                            SENT = True
                            # The server
                            sock.setblocking(True)
                            termination_thread = Thread(target=verify_termination, daemon=True, args=(input_list, sock, server_socket, active_dict, PASSWORD))
                            termination_thread.start()                                        
                                               
                    if not SENT:
                        data = f'server: {data}'.encode('utf-8')
                        sock.send(data) 
                    
                except ConnectionResetError:
                    print(f"Connection with client: {peer_name} has been closed.")
                    input_list.remove(sock)
                    sock.close()
                
                except OSError:
                    print(f'OSError, {sock} was closed.')
                    continue
                
                except Exception as e:
                    print(f'{e} {sock} was closed.')
                    continue
            
        for sock in exceptions:
            
            # clients credentials
            peer_name = sock.getpeername()
            print(f"Handling exceptions for: {peer_name}")
            
            # Removing 
            input_list.remove(sock)
            if sock in output_list: output_list.remove(sock)
            
            print(f'Connection with client: {peer_name} has been closed')
            sock.close()
             
if __name__ == '__main__':
    
    # objects / Widgets
    WINDOW, table = init_gui()
    
    # run server.    
    run_server_thread = Thread(target=service, daemon=True, args=(WINDOW, table))
    run_server_thread.start()
    
    # render window.
    WINDOW.mainloop()
