from tkinter import Tk, Frame, Scrollbar, Label, END, Entry, Text, VERTICAL, Button, Listbox
import socket
import threading
import tkinter as tk
from tkinter import messagebox
import pyaudio
import sys
import time
import threading
import select
from Crypto.Cipher import AES
from Crypto import Random
import base64
import os
import hashlib
import wave


ENCODER = 'utf-8'
CHUNK = 1024
FORMAT = pyaudio.paInt16
CHANNELS = 2
RATE = 44100
RECORD_SECS = 5
OUTPUT_FILE = "output.wave"

size = 1024

p = pyaudio.PyAudio()

stream = p.open(format = FORMAT,channels = CHANNELS,rate = RATE,input = True, frames_per_buffer = CHUNK)


frames = []
#added for encrypted chat
#args = sys.argv

BS = 16
pad = lambda s: s + (BS - len(s) % BS) * chr(BS - len(s) % BS)
unpad = lambda s : s[0:-s[-1]]



class Client:
    client_socket = None
    login_list = None

    def __init__(self, master):
        self.root = master
        self.chat_transcript_area = None
        self.name_widget = None
        self.enter_text_widget = None
        self.join_button = None
        self.send_bttn = None
        self.exit_bttn = None
        self.call_bttn = None
        self.mute = True
        self.initialize_socket()
        self.initialize_gui()
        self.listen_for_incoming_messages_in_a_thread()
        self.addr = None
        #self.login_list = ''chunk
        key_text = "0123456789012345"
        self.key = hashlib.sha256(key_text.encode('utf-8')).digest()

    def initialize_socket(self):
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        host = '127.0.0.1'
        port = 10319
        self.addr = (host,port)
        try:
            self.client_socket.connect((host, port))
        except:
            print ("CLIENT_CANNOT_CONNECT.format(host,port)")

    def initialize_gui(self):
        self.root.title("Socket Chat")
        self.root.resizable(0, 0)
        self.login()
        self.display_login_list()
        self.chat_box()
        self.message_box()
        self.send_button()
        self.call_button()    


    def encrypt( self, raw ):
        raw = pad(raw)
        iv = Random.new().read( AES.block_size )
        cipher = AES.new( self.key, AES.MODE_CBC, iv )
        return base64.b64encode( iv + cipher.encrypt( raw.encode('utf8') ) )


    def decrypt( self, enc ):
        enc = base64.b64decode(enc)
        iv = enc[:16]
        cipher = AES.new(self.key, AES.MODE_CBC, iv )
        return unpad(cipher.decrypt( enc[16:] ))


        

    def listen_for_incoming_messages_in_a_thread(self):
        thread = threading.Thread(target=self.receive_message_from_server, args=(self.client_socket,))
        thread.start()

    def receive_message_from_server(self, so):
        while True:
            buffer = so.recv(256)
            if not buffer:
                break
            #the message below is the original
            #message = buffer.decode(ENCODER)
            print("Received Message: ",buffer)
            print("Length: "+str(len(buffer)))
            message = str(self.decrypt(buffer))
            

            #self.login_list.insert('end',self.name_widget.get())
            if "joined" in message:

                user = message.split(":")[1][:-1]
                message = user + " has joined"
                self.login_list.insert('end', user)
                self.chat_transcript_area.insert('end', message + '\n')
                self.chat_transcript_area.yview(END)

            else:
                self.chat_transcript_area.insert('end', message[2:-1] + '\n')
                self.chat_transcript_area.yview(END)


        so.close()




    def login(self):
        login_frame = Frame()
        Label(login_frame, text='Username:', font=("Times", 16)).pack(side='left', padx=10)
        self.name_widget = Entry(login_frame, width=40, borderwidth=2)
        self.name_widget.pack(side='left', anchor='e')
        self.join_button = Button(login_frame, text="login", width=10, command=self.join).pack(side='left')
        login_frame.pack(side='top', anchor='nw')

    def chat_box(self):
        chat_frame = Frame()
        Label(chat_frame, text='Chat Box:', font=("Serif", 12)).pack(side='top', anchor='w')
        self.chat_transcript_area = Text(chat_frame, width=60, height=10, font=("Serif", 12))
        scrollbar = Scrollbar(chat_frame, command=self.chat_transcript_area.yview, orient=VERTICAL)
        self.chat_transcript_area.config(yscrollcommand=scrollbar.set)
        self.chat_transcript_area.bind('<KeyPress>', lambda e: 'break')
        self.chat_transcript_area.pack(side='left', padx=10)
        scrollbar.pack(side='right', fill='y')
        chat_frame.pack(side='top')

    def message_box(self):
        msg_frame = Frame()
        Label(msg_frame, text='Enter message:', font="Times").pack(side='top', anchor='w')
        self.enter_text_widget = Text(msg_frame, width=60, height=3, font=("Serif", 12))
        self.enter_text_widget.pack(side='left', pady=15)
        self.enter_text_widget.bind('<Return>', self.enter_pressed)
        msg_frame.pack(side='top')

    def send_button(self):
        snd_btn = Frame()
        self.send_bttn = Button(snd_btn, text='send', width=10, command=self.send_pressed).pack(side='left')
        self.exit_bttn = Button(snd_btn, text='exit', width=10, command=self.exit_event).pack(side='left')
        snd_btn.pack(side='top')

    def call_button(self):
        call_frame = Frame()
        self.call_bttn = Button(call_frame, text='call', width=10, command=self.call_pressed).pack(side='left')
        call_frame.pack(side='top')    


    def display_login_list(self):
        list_frame = Frame()
        Label(list_frame, text='users', font="Times").pack(side='top', anchor='w')
        self.login_list = Listbox(list_frame, height=16, width=10)
        
        self.login_list.pack(side = 'right', expand='yes')
        #self.login_list.bind('<<ListBoxSelect>>')
        #print(self.name_widget.get())
        list_frame.pack(side='right')
        


    def join(self):
        if len(self.name_widget.get()) == 0:
            messagebox.showerror(
                "Enter your name", "Enter your name to send a message")
            return   
        #self.name_widget.config(state='disabled')
        message_str = "joined:" + self.name_widget.get()
        message_enc = (self.encrypt(message_str))
        #self.client_socket.send(("joined:" + self.name_widget.get()).encode(ENCODER))
        print("On Join: ", message_enc)
        print("On Join Type: ", type(message_enc))
        print("Decrypted: ", self.decrypt((message_enc)))
        self.client_socket.send((message_enc))
        
        self.login_list.insert(tk.END, self.name_widget.get())
        #self.login_list.insert(1, 'first')

    def enter_pressed(self,event):
        if len(self.name_widget.get()) == 0:
            messagebox.showerror(
                "Enter your name", "Enter your name to send a message")
            return
        self.send_chat()
        self.clear_text()


    def send_pressed(self):
        if len(self.name_widget.get()) == 0:
            messagebox.showerror(
                "Enter your name", "Enter your name to send a message")
            return
        self.send_chat()
        self.clear_text()
    
    def call_pressed(self):
        #messagebox.showinfo("call is connected")
        self.mute = False
        self.speakStart()


    def speakStart(self):
        t = threading.Thread(target=self.speak)
        t.start()

    def speak(self):
        print("You are now speaking")
        while self.mute is False:
            for i in range(0, int(RATE/ CHUNK*RECORD_SECS)):
                print("got here :",i)
                data = stream.read(CHUNK)
                print("You are now streaming")
                frames.append(data)
                print("You are now appending")
            self.client_socket.send(data)
            self.client_socket.recv(size)

            

    def exit_event(self):
        print("A")
        wf = wave.open(OUTPUT_FILE,'wb')
        print("B")
        wf.setnchannels(CHANNELS)
        print("C")
        wf.setsampwidth(p.get_sample_size(FORMAT))
        wf.setframerate(RATE)
        wf.writeframes(b''.join(frames))
        wf.close()
        self.root.destroy()
        self.client_socket.close()
        exit(0) 

    def clear_text(self):
        self.enter_text_widget.delete(1.0, 'end')

    def send_chat(self):
        senders_name = self.name_widget.get().strip() + ": "
        data = self.enter_text_widget.get(1.0, 'end').strip()
        message_str = senders_name + data
        
        
        #self.chat_transcript_area.insert('end', message.decode(ENCODER) + '\n')
        self.chat_transcript_area.insert('end', message_str + '\n')
        self.chat_transcript_area.yview(END)
        message_enc = (self.encrypt(message_str))
        print("Send Chat: ",message_enc)
        #message = (message_enc).encode(ENCODER)
       
        self.client_socket.send(message_enc)
        self.enter_text_widget.delete(1.0, 'end')
        return 'break'

    def close_window(self):
        self.root.destroy()
        self.client_socket.close()
        exit(0)


if __name__ == '__main__':
    root = Tk()
    client = Client(root)
    root.protocol("WM_DELETE_WINDOW", client.close_window)
    root.mainloop()
    stream.close()
    p.terminate()

    
