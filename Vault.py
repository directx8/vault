import os
import base64
import mmap
import re
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet


class User_Options:
    def __init__(self):
        try:
            file = open("enc_pass_vault.encrypted", "x")
            file.close()
        except FileExistsError:
            print("The vault is already initialized!")

        self.__master_pass = input("Please input the master password: ")
        self.enc = Encryption(self.__master_pass)

    def add_user(self):
        in_user = input("Input username: ")
        in_pass = input("Input password for username: ")

        # Decrypt the list and add user
        self.enc.FileDecrypt()
        with open("pass_vault.txt", "a") as myfile:
            myfile.write(
                "\n" + "Username: " + in_user + " || " + "Password: " + in_pass
            )

        # Encrypt the list and remove the unencrypted one
        self.enc.FileEncrypt()
        os.remove("pass_vault.txt")

    def edit_user(self):
        # Decrypt the list and find user (string)
        self.enc.FileDecrypt()
        found = False

        while found == False:
            account = input("Search for string: ")

            vault_txt = open("pass_vault.txt", "r")
            lineList = []
            i = 0
            for line in vault_txt:
                lineList.append(line.rstrip("\n"))
                if account in lineList[i]:
                    print(lineList[i])
                    found = True
                i += 1

        # Encrypt the list and remove the unencrypted one
        self.enc.FileEncrypt()
        os.remove("pass_vault.txt")

    def remove_user(self):
        return True


class Encryption:
    # Real way to generate a key with password
    def __init__(self, PassW):
        password = PassW.encode()

        salt = b"e\xe1\xab\x07I\x17\xb3\xeb\x03m2n05\xc0\x12"

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend(),
        )
        self.__key = base64.urlsafe_b64encode(kdf.derive(password))

    def FileEncrypt(self):
        # Open the file to encrypt
        with open("pass_vault.txt", "rb") as f:
            data = f.read()

        fernet = Fernet(self.__key)
        encrypted = fernet.encrypt(data)

        # Write the encrypted file
        with open("enc_pass_vault.encrypted", "wb") as f:
            f.write(encrypted)

    def FileDecrypt(self):
        # Open the file to decrypt
        with open("enc_pass_vault.encrypted", "rb") as f:
            data = f.read()

        fernet = Fernet(self.__key)
        decrypted = fernet.decrypt(data)

        # Write the encrypted file
        with open("pass_vault.txt", "wb") as f:
            f.write(decrypted)


def search_file():
    enc = Encryption(input())
    enc.FileDecrypt()
    found = False

    while found == False:
        inp = input("Search for string: ")

        txtFile = open("pass_vault.txt", "r")
        lineList = []
        i = 0
        for line in txtFile:
            lineList.append(line.rstrip("\n"))
            if inp in lineList[i]:
                print(lineList[i])
                found = True
            i += 1


def main():
    user_options = User_Options()
    # enc = Encryption(input())

    selection_dict = {
        # 0: enc.FileDecrypt,
        1: user_options.add_user,
        2: user_options.remove_user,
        3: user_options.edit_user,
    }

    selection_dict.get(
        int(
            input(
                "Please select an input: \n 1) Add user \n 2) Delete user \n 3) Edit user \n"
            )
        )
    )()


if __name__ == "__main__":
    main()

