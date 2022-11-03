import basic_gui
import logging
import dearpygui.dearpygui as dpg
import hashlib
from chat_client import ChatClient
from generic_callback import GenericCallback
import base64
import os
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC 
import serpent


DEFAULT_VALUES = {
    "host" : "127.0.0.1",
    "port" : "6666",
    "name" : "foo",
    "password" : ""
}
class Ciphered_GUI(basic_gui.BasicGUI):
    def __init__(self)->None:
        # constructor
        self._client = None
        self._callback = None
        self._log = logging.getLogger(self.__class__.__name__)
        self._key = None
    
    def _create_connection_window(self) -> None:
        with dpg.window(label="Connection", pos=(200, 150), width=400, height=300, show=False, tag="connection_windows"):
            for field in ["host", "port", "name", "password"]:
                with dpg.group(horizontal=True):
                    if field == "password":
                        dpg.add_text(field)
                        dpg.add_input_text(default_value=DEFAULT_VALUES[field], tag=f"connection_{field}",password=True)
                        break
                    dpg.add_text(field)
                    dpg.add_input_text(default_value=DEFAULT_VALUES[field],tag=f"connection_{field}")
        
            dpg.add_button(label="Connect", callback=self.run_chat)


    def _create_chat_window(self)->None:
        # chat windows
        # known bug : the add_input_text do not display message in a user friendly way
        with dpg.window(label="Chat", pos=(0, 0), width=800, height=600, show=False, tag="chat_windows", on_close=self.on_close):
            dpg.add_input_text(default_value="Readonly\n\n\n\n\n\n\n\nfff", multiline=True, readonly=True, tag="screen", width=400, height=300)
            dpg.add_input_text(default_value="some text", tag="input", on_enter=True, callback=self.text_callback, width=400)


    def _create_menu(self)->None:
        # menu (file->connect)
        with dpg.viewport_menu_bar():
            with dpg.menu(label="File"):
                dpg.add_menu_item(label="Connect using Fernel encryption", callback=self.connect)
            
    def create(self):
        # create the context and all windows
        dpg.create_context()

        self._create_chat_window()
        self._create_connection_window()
        self._create_menu()        
            
        dpg.create_viewport(title='Secure Fernet encrypted chat', width=800, height=600)
        dpg.setup_dearpygui()
        dpg.show_viewport()

    def update_text_screen(self, new_text:str)->None:
        # from a nex_text, add a line to the dedicated screen text widget
        text_screen = dpg.get_value("screen")
        text_screen = text_screen + "\n" + new_text
        dpg.set_value("screen", text_screen)

    def text_callback(self, sender, app_data)->None:
        # every time a enter is pressed, the message is gattered from the input line
        text = dpg.get_value("input")
        self.update_text_screen(f"Me: {text}")
        self.send(text)
        dpg.set_value("input", "")

    def connect(self, sender, app_data)->None:
        # callback used by the menu to display connection windows
        dpg.show_item("connection_windows")

    def encrypt(self,message):
        message = bytes(message, "utf8")  
        f = Fernet(self._key)
        encrypted = f.encrypt(message)
        iv = os.urandom(16)
        return (iv, encrypted)
    
    def decrypt(self,iv,encrypted):
        f = Fernet(self._key) 
        decrypted = serpent.tobytes(encrypted)
        return f.decrypt(decrypted)

    def run_chat(self, sender, app_data)->None:
        # callback used by the connection windows to start a chat session
        host = dpg.get_value("connection_host")
        port = int(dpg.get_value("connection_port"))
        name = dpg.get_value("connection_name")
        password = dpg.get_value("connection_password")
        self._log.info(f"Connecting {name}@{host}:{port}@{password}")
        salt = bytes("16", "utf8")
        """kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        self._key = base64.b64encode(kdf.derive(bytes(password))) """
        # use sha256.digest + base64 to get a 32 bytes key
        
        self._key = base64.b64encode(hashlib.sha256(bytes(password, "utf8")).digest())
        

        
        
        self._callback = GenericCallback()

        self._client = ChatClient(host, port)
        self._client.start(self._callback)
        self._client.register(name)

        dpg.hide_item("connection_windows")
        dpg.show_item("chat_windows")
        dpg.set_value("screen", "Connecting")

    def on_close(self):
        # called when the chat windows is closed
        self._client.stop()
        self._client = None
        self._callback = None

    def recv(self)->None:
        # function called to get incoming messages and display them
        if self._callback is not None:
            for user, message in self._callback.get():
                message_decrypt = self.decrypt(message[0],message[1])
                self._log.info(f"Receiving {message}@{message_decrypt}")
                self.update_text_screen(f"{user} : {message_decrypt[2:-1]}")
            self._callback.clear()

    def send(self, text)->None:
        # function called to send a message to all (broadcasting)
        encrypted = self.encrypt(text)
        self._log.info(f"Sending {text}@{encrypted}")
        self._client.send_message(encrypted)

    def loop(self):
        # main loop
        while dpg.is_dearpygui_running():
            self.recv()
            dpg.render_dearpygui_frame()
        dpg.destroy_context()

if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)

    # instanciate the class, create context and related stuff, run the main loop
    client = Ciphered_GUI()
    client.create()
    client.loop()
    

    


