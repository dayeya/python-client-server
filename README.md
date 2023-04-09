# Client-Server Application

The Client Server Application is an application that allows clients to connect to a server and exchange data over a network. This comprehensive guide serves as your gateway to the world of My Client-Server Application. Here, you'll discover the features, installation process, usage instructions, and contribution guidelines.

# Table of Contents

    Features
    Modes
    Usage
    Connection process
    Installation
    Contributing
    License

# Features
My Client-Server Application is packed with numerous features that make it stand out among the crowd. Here are some of its amazing features:

    Clients can effortlessly connect to the server using TCP/IP protocol.
    Clients can send and receive data, enter special modes the spice up the experience!
    The server can handle multiple client connections concurrently, making it a highly scalable and efficient application.
    The server can quickly process client requests and respond with the appropriate data in real-time.
    The application provides a simple and intuitive command-line interface that enables the client to interact effortlessly.
    $ importtant $ A client will be kicked within 2 minutes of inactivity
    
# Modes
My Client-Server Application comes with a range of modes that enable clients to access different functionalities. Here are some of its available modes:

    $TIME: This mode provides clients with the current time of the server, making it easy to keep track of the server's time zone.
    $TERMINATE: This mode allows the client to shut down the server and all other clients connected to it. A password is needed to confirm termination.
    If the client enters "Stop terminating," the termination process will be canceled, and the client will revert to the regular mode.
    $CLOSE: This mode enables the client to disconnect from the server effortlessly.
    $PYCODE: This mode is the most exciting of all! It allows clients to code inside the chat. Clients can create, run, and edit Python files, including tabs, loops, 
    if statements, and variables.

# Usage
To run My Client-Server Application, follow these simple steps:

    Open a terminal window and navigate to the application directory.
    Start the server by running python server.py.
    Open another terminal window and navigate to the application directory.
    Start a client by running python client.py.
    Follow the on-screen instructions to connect to the server and send/receive data.

# $TIME:
To enter the $TIME mode, the client should send $TIME. The server will respond with the current time of the server.

# $TERMINATE:
To enter the $TERMINATE mode, the client should send $TERMINATE. The server will respond with a password that the client needs to provide to confirm the termination. If the client sends "Stop terminating," the termination process will be canceled. If the client provides the correct password, the server will shut down itself and all other clients.

# $CLOSE:
To enter the $CLOSE mode, the client should send $CLOSE. The server will disconnect the client from the server.

# $PYCODE:
To enter the $PYCODE mode, the client should send $PYCODE. The server will respond with instructions on how to create, run, and edit Python files. The available commands are:
    
    $ import note -> if the client want to use tabs to indent things inside IFs & Loops. The client has to write 'tab' before the line of code. E.g tab print("Hi")
    /create <file_name>.py: This command allows clients to start coding real Python code! However, inputs are not supported.
    /edit <file_name>.py: Allows the client to edit files and change them. The client will then be needed to provie the next format.
    <line_num> <replacement>: This command allows the client the change specific line with <replacement>.
    
### Connection process.
This app doesnt rely on hard-coded IP, PORT. There is a really cool algorithm behind the establishment of the connection.
The server is up & waits for clients to send an UDP packet in the next format ``` I AM LOOKING FOR A SERVER (IP, PORT) ``` in broadcast.
The server is calling a function wraped as a thread. The function scans the network with SCAPY & sniffs an UDP packet with the LOOKING label.
When the server finds the desired packet, it sends the following packet as well. ``` HELLO IS A SERVER (IP, PORT) ```
Both ends save the address they got & establish a connection together.

![image](https://user-images.githubusercontent.com/129618322/230676549-038c2480-10f6-4a77-9b9d-51306c957cd1.png)

### Conclusion
Thank you for choosing Client Server Application. We hope this guide has provided you with all the information you need to get started.
