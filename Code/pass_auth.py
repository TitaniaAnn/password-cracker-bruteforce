# This is a basic program on Python
#
# Writing this program has taught me that I really need
# Dinosaurs with lazer guns. pew pew
from ast import Bytes
from msilib import Binary
import os
from sys import maxsize
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


def get_username(su):
    # 10 char length a-z
    while True:
        try:
            username = input("Username: ")
            tst = len(username)
            tt = username.isalpha()
            if len(username) <= 10 and username.isalpha():
                if su == 0:
                    exists = exists_username(bytes(username, 'utf-8'))
                    if exists:
                        raise ValueError
                    else:
                        return bytes(username, 'utf-8')
                else:
                    return bytes(username, 'utf-8')
            else:
                raise ValueError
        except ValueError:
            print("Invalid username.")


def get_password():
    while True:
        try:
            password = input("Password: ")
            # lowercase a-z with configurable length
            if len(password) < maxsize and len(password) > 0 and password.isalpha() and password.islower():
                return bytes(password, 'utf-8')
            else:
                raise ValueError
        except ValueError:
            print("Invalid Password")
            

def hash_password(password: bytes):
    # Create a hash of the password
    hashPass = hashes.Hash(hashes.SHA256())
    hashPass.update(password)
    hPass = hashPass.finalize()
    return bytes(''.join(format(i, '08b') for i in bytearray(str(hPass), encoding ='utf-8')), 'utf-8')


def salt_password(password: bytes, salt: bytes):
    # Lastly hash your password using a salt
    if salt == b'':
        salt = os.urandom(1)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=480000,
    )
    # Add the password to the mix
    key = kdf.derive(password)
    return bytes(''.join(format(i, '08b') for i in bytearray(str(key), encoding ='utf-8')), 'utf-8'), salt


def write_plain(username: bytes, password: bytes):
    try:
        with open("./files/plaintext.txt", "ab") as fp:
            # Write user data to the file
            fp.write(username + b':' + password[0] + b';')
    except IOError:
        print("Failed to save text login")
        raise IOError


def write_hash(username: bytes, password: bytes):
    try:    
        with open("./files/hashPass.hsh", "ab") as fh:
            # write your data and remember to use your hashed password and not our plain text
            hshpass = hash_password(password[0])
            fh.write(username + b':' + hshpass + b';')
    except IOError:
        print("Failed to save hash login")
        raise IOError


def write_salt(username: bytes, password: bytes):
    try:    
        with open("./files/saltPass.slt", "ab") as fs:
            # Write your username and the salt hashed password
            passw, salt = salt_password(password[0], b'')
            fs.write(username + b':' + passw + b':' + salt + b';')
    except IOError:
        print("Failed to save salt login")
        raise IOError


def exists_username(un):
    if os.path.isfile("./files/plaintext.txt"):
        with open("./files/plaintext.txt", "rb") as fp:
            users = fp.read().split(b';')
            for line in users:
                user = line.split(b':')
                if user[0] == un:
                    return True
    return False


def login_txt(username: bytes, password: bytes):
    if os.path.isfile("./files/plaintext.txt"):
        with open("./files/plaintext.txt", "rb") as fp:
            users = fp.read().split(b';')
            for line in users:
                user = line.split(b':')
                if user[0] == username and user[1] == password:
                    return True
    return False


def login_hsh(username: bytes, password: bytes):
    if os.path.isfile("./files/hashPass.hsh"):
        with open("./files/hashPass.hsh", "rb") as hp:
            users = hp.read().split(b';')
            for line in users:
                values = line.split(b':')
                if values[0] == username:
                    hpass = hash_password(password)
                    if values[1] == hpass:
                        return True
                    else:
                        return False
    return False


def login_slt(username: bytes, password: bytes):
    if os.path.isfile("./files/saltPass.slt"):
        with open("./files/saltPass.slt", "rb") as sp:
            users = sp.read().split(b';')
            for line in users:
                if line.startswith(username):
                    values = line.split(b':')
                    print(values)
                    sltpass, salt = salt_password(password, values[2])
                    if values[1] == sltpass:
                        return True
                    else:
                        return False
    return False


def signup():
    print("Signup for an account\n")
    # Get user data
    username = get_username(0)
    password = get_password(),
    # Open plain text document and create if it doesn't exist
    write_plain(username, password)
    # Open/create the file that stores username and hashed passwords
    write_hash(username, password)
    # Open/create your file
    write_salt(username, password)
    # Close you file
    print("Signup Successful")
    signin()


def signin():
    print("signin")
    exists = False
    while exists == False:
        username = get_username(1)
        password = get_password()
        exists = exists_username(username)
        if exists:
            print("Trying to login")
            # find stored username and password
            txtlogin = login_txt(username, password)
            hshlogin = login_hsh(username, password)
            sltlogin = login_slt(username, password)
            if txtlogin:
                print("Text Login worked\n")
            else:
                print("Text login failed\n")
            if hshlogin:
                print("Hash login worked\n")
            else:
                print("Hash login failed\n")
            if sltlogin:
                print("Salt login worked\n")
            else:
                print("Salt login failed\n")
        else:
            print("Invalid Login\n")
            if input("Do you want to create an accout?(y/n) ").lower().strip() == 'y':
                signup()


def main():
    print("Welcome!\n")
    uInput = input("Do you have an account?(y/n)")
    if uInput.lower() == "y":
        signin()
    else:
        signup()
        

# main()