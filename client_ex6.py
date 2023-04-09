
'''
Client, Daniel Sapojnikov.
'''

# GUI MODULES
import time
from datetime import datetime
from tkinter import *
import tkinter as tk
import tkinter.ttk as ttk

# Networking MODULES
import os
from threading import Thread
from socket import *
import subprocess, re

# CONSTANTS.

BUFSIZE = 1024
FILTER_REG = r'[^\w\n|.]'
IP_REG = r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(?=\s|\Z)'
HEADER = f'''Chat with the server!, type $ before the additional commands\n1. TIME\n2. Guess the word!\n3. TERMINATE\n4. CLOSE\nDont forget to press Enter uppon sending!'''

def init_gui() -> None:
    
    '''
    :Creates the GUI of the client.
    :Gets -> nothing
    :Returns all the widgets on the screen.
    '''
    
    WINDOW = tk.Tk()
    WINDOW.title("Chat Client - Daniel Sapojnikov")
    WINDOW.configure(bg='#152033')
    
    # Responsive GUI
    Grid.columnconfigure(WINDOW, tuple(range(1)), weight=1)
    Grid.rowconfigure(WINDOW, tuple(range(4)), weight=1)
    
    # Colors
    colors = {
        "primary": "#005cff",
        "secondary": "#01021c",
        "background": "#152033",
        "text": "#dedffa",
        "placeholder": "#a0a0a0",
        "disabled": "#d0d0d0",
    }
    
    # Fonts
    fonts = {
        "title": ("Cascadia Code", 20, "bold"),
        "subtitle": ("Cascadia Code", 15, "bold"),
        "text": ("Open Sans", 12),
        "button": ("Open Sans", 12, "bold"),
    }
    
    # Window dimensions
    full_width = int(WINDOW.winfo_screenwidth()) 
    full_height = int(WINDOW.winfo_screenheight())
    width = int(full_width // 1.8)
    height = int(full_height // 1.8)
    WINDOW.geometry(f'{width}x{height}')
    
    # Top label
    top_label = tk.Label(
        WINDOW, 
        text="Chat Client", 
        font=('Open Sans ', 20, 'bold'), 
        fg=colors["primary"],
        bg=colors["secondary"],
        pady=10,
        padx=20
    )
    top_label.grid(column=0, row=0, columnspan=2, sticky="nsew")
    
    # Chat section
    chat_frame = tk.Frame(
        WINDOW,
        bg=colors["background"],
        pady=10,
        padx=20
    )
    chat_frame.grid(column=0, row=1, sticky="nsew")
    
    # Chat box
    chat_box = tk.Text(
        chat_frame,
        font=fonts["text"],
        fg=colors["text"],
        bg=colors["secondary"],
        padx=10,
        pady=10,
        state=tk.DISABLED,
        wrap="word",
        insertbackground=colors["text"]
    )
    chat_box.pack(fill="both", expand=True)
    
    # Chat entry
    entry_var = tk.StringVar()
    entry_var.set('Type a message')
    entry = tk.Entry(
        chat_frame,
        font=('Open Sans', '12'),
        fg=colors["text"],
        bg=colors["background"],
        textvariable=entry_var,
        relief='ridge',
        insertbackground=colors["text"],
        highlightcolor=colors["primary"],
        highlightbackground=colors["primary"],
        selectbackground=colors["primary"],
        selectforeground=colors["background"],
    )
    entry.pack(fill="x", pady=10)
    
    # Create the second frame
    utils_frame = tk.Frame(WINDOW, bg=colors["background"])
    utils_frame.grid(column=0, row=2, sticky='nsew')
    utils_frame.grid_columnconfigure((0,), weight=1)
    utils_frame.grid_rowconfigure((0,), weight=1)

    # --- UTILS ---     
    def clear():
        chat_box.configure(state=NORMAL)
        chat_box.delete(1.0, END)
        chat_box.configure(state=DISABLED)
        
    # Create a style object
    style = ttk.Style()

    # Configure the style to use a modern theme
    style.theme_use('clam')

    # Configure the style for the button
    style.configure('Modern.TButton', font=('Helvetica', 14), foreground='white', background='#4f63ab', borderwidth=0)
    style.map('Modern.TButton', background=[('active', '#38477a'), ('active', '#38477a')])
    
    clear_button = ttk.Button(
        utils_frame,
        text='clear screen',
        command=clear,
        style='Modern.TButton'
    )
    clear_button.grid(row=0, column=0, sticky='news', padx=500, pady=10)
    
    return WINDOW, top_label, chat_frame, chat_box, entry, entry_var

def update_chat(chat, data) -> None:
    
    '''
    updates the chat visuals.
    appends the messages the client sends into the chat using - INSERT.
    '''
    if type(data) is list: # multiline.
        for line in data:
            display = line.strip() + '\n'
    
            chat.config(state=NORMAL)
            chat.insert(END, display)
            chat.config(state=DISABLED)
        return
    else: 
        display = data.strip() + '\n'
    
        chat.config(state=NORMAL)
        chat.insert(END, display)
        chat.config(state=DISABLED)

def client_send(event, client_sock, entry, box) -> None:

    # sends a message from the client -> fetched from the entry widget.
    
    client_msg = entry.get() # Fetch the data from the ENTRY bar.
    print(f'SENT: {client_msg}')
    
    if client_msg == '' or not client_msg:
        entry.set('Enter valid text!')
        return
    
    try:
        # SEND to the server the msg.
        client_sock.send(client_msg.encode('utf-8'))
    
    except Exception as e:
        print("Error occured, try again.")
    
    # Modify chat visuals.
    entry.set('')
    currentDateAndTime = datetime.now()
    update_chat(box, f'client: {client_msg}') 
    
def await_server_answer(win, client_sock, box) -> None:
    
    # waits for a response from the server, function is threaded.
    # we want to run the gui at the same time as we recieve input from the server.

    while True:
        try:
            data = client_sock.recv(BUFSIZE).decode('utf-8')
            data = data.split('\n') if '\n' in data else data
            print("CLIENT GOT: ", data)
            if not data: 
                update_chat(box, 'Error Occured, please resend your message.')
                break
            
            # close connection from the clients side.
            if data == 'CLOSE CONNECTION - CLIENT' or data == 'You are a great human being! Sadly due to inactivity, you will be kicked in 0 seconds.':
                
                # close all the important stuff.
                win.destroy()
                client_sock.close()
                print("Connection with the server has been closed.")
                
                # pick a clearing command, based on the OS.
                clear_command = 'cls' if os.name == 'nt' else 'clear'
                os.system(clear_command)
                quit()
                
            else: update_chat(box, data)
           
        except ConnectionResetError:
            print("An error occured, server might have been shut down.")  
            
        except Exception as e:
            raise e

def client_credentials() -> None:
    
    '''
    RETURNS: the credentials of the server -> (IP, PORT)
    1. uses subprocess to fetch the ip + string manipulation.
    2. uses the following 'port' code in order to find the first OPEN port on the device - (SERVER).
    '''
    
    data = subprocess.check_output('ipconfig').decode('utf-8')
    data = re.sub(FILTER_REG, '', data)

    # IP
    k = data.index("IPv4Address") + 1 # the index of the ip address.
    ip = re.search(IP_REG, data[k: data.index('\n', k)])
    ip = ip.group(0) if ip != None else None
    
    # PORT
    scan_socket = socket(AF_INET, SOCK_STREAM)
    scan_socket.bind(("", 0))
    scan_socket.listen(1)
        
    port = scan_socket.getsockname()[1]
    scan_socket.close()
    
    return (ip, port)

def get_addr(d):
    
    if not d:
        return None
    
    # SIGN is the line we need (line including the label)
    sign = d.replace(' ','')
    start, mid, end = sign.index('('), sign.index(','), sign.index(')')
    
    # getting the parameters.
    ip, port = sign[start+1: mid], int(sign[mid+1: end])
    
    return (ip, port)

def define_end_points() -> None:
    
    # determine the payload.
    ip, client_port = client_credentials()
    data = f'I AM LOOKING FOR A SERVER ({ip}, {client_port})'.encode('utf-8')
    
    # open udp socket for the client.
    udp_sock = socket(family=AF_INET, type=SOCK_DGRAM)
    udp_sock.setsockopt(SOL_SOCKET, SO_BROADCAST, 1)
    
    udp_sock.sendto(data, ('255.255.255.255', client_port))
    udp_sock.close()
    
    # listening.
    udp_sock = socket(family=AF_INET, type=SOCK_DGRAM)
    udp_sock.bind(("", client_port))
    
    while True:
        data, addr = udp_sock.recvfrom(BUFSIZE)
        data = data.decode('utf-8')
        
        if "HELLO ITS A SERVER" in data: break
        
    udp_sock.close()
    addr = get_addr(data)
    
    print(f'CLIENT GOT: {data}')
    return addr
    
def main() -> None:

    SERVER = None
    while not SERVER:
        SERVER = define_end_points()
    
    client_socket = socket(AF_INET, SOCK_STREAM)
    client_socket.connect(SERVER)
    print(f'CLIENT: {client_socket.getsockname()}')
    
    # Get widgtes
        # Server answer.
    WINDOW, top_label, chat_frame, chat_box, entry, entry_var = init_gui()
    
    entry.bind("<Button-1>", lambda event: entry_var.set('') if entry_var.get() in {"Type a message", "Enter valid text!"} else None) # detect 'clicking'
    entry.bind("<Return>", lambda event: client_send(event, client_socket, entry_var, chat_box)) # detect 'sending'
    
    # Server answer.
    Thread(target=await_server_answer, daemon=True, args=(WINDOW, client_socket, chat_box)).start()
    WINDOW.mainloop()
    
 
if __name__ == '__main__':
    main()
