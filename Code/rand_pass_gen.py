import datetime
from fileinput import filename
import os
import random
import string
import pass_auth


def exists_username(file, username: bytes):
    ty = 'rb'
    if os.path.isfile('./files/' + file):
        with open('./files/' + file, ty) as fp:
            users = fp.read().split(';')
            for line in users:
                user = line.split(':')
                if user[0] == username:
                    return True
    return False


def write_file(file_name, data):
    ty = "ab"
    try:
        with open('./files/' + file_name, ty) as fp:
            # Write user data to the file
            fp.writelines(data)
    except IOError:
        print("Failed to save text login")
        raise IOError
    

def write_plain(username: bytes, password: bytes):
    return username + b':' + password + b';'


def write_hash(username: bytes, password: bytes):
    hshpass = pass_auth.hash_password(password)
    # hshpass = ''.join(format(i, '08b') for i in bytearray(str(pass_auth.hash_password(password)), encoding ='utf-8'))
    return username + b':' + hshpass + b';'


def write_salt(username: bytes, password: bytes):
    password, salt = pass_auth.salt_password(password, b'')
    # spass = ''.join(format(i, '08b') for i in bytearray(str(password), encoding ='utf-8'))
    return username + b':' + password + b':' + salt + b';'


def gen_user(users):
    while True:
        # ty = "rb"
        username = bytes(''.join(random.choices(string.ascii_lowercase, k=10)), 'utf-8')
        # exists = exists_username(file_name, username)
        if username not in users:
            return username


def gen_pass(pass_min, pass_max):
    pass_length = random.randint(pass_min, pass_max)
    return bytes(''.join(random.choices(string.ascii_lowercase, k=pass_length)), 'utf-8')


def get_userinput():
    file_name = input("Filename: ") or 'test'
    pass_min = int(input("Input password min length: ") or '3')
    pass_max = int(input("Input password max length: ") or '5')
    num_pass = int(input("Number of passwords: ") or '100')
    return file_name, pass_min, pass_max, num_pass


def create_txt():
    file_name, pass_min, pass_max, num_pass = get_userinput()
    pdata = []
    users = []
    while num_pass > 0:
        pdata.append(write_plain(users.append(gen_user(users)), gen_pass(pass_min, pass_max)))
        num_pass = num_pass - 1
    write_file(file_name + '.txt', pdata)
    print("Textfile Created")
    return
     
        
def create_unique_txt():
    file_name, pass_min, pass_max, num_pass = get_userinput()
    elapse = datetime.datetime.now()
    passwords = []
    write_pass = []
    while num_pass > 0:
        m = True
        while m:
            password = gen_pass(pass_min, pass_max)
            hpass = pass_auth.hash_password(password)
            password = password + b':' + hpass + b';'
            if password not in passwords:
                passwords.append(password)
                num_pass = num_pass - 1
                m = False
    write_file(file_name + '.txt', passwords)
    print("Unique File Created")
    elapse = datetime.datetime.now() - elapse
    print(f"Time Elapsed: {elapse.seconds} seconds")
    return


def create_hsh():
    file_name, pass_min, pass_max, num_pass = get_userinput()
    elapse = datetime.datetime.now()
    hdata = []
    users = []
    while num_pass > 0:
        users.append(gen_user(users))
        hdata.append(write_hash(users[-1], gen_pass(pass_min, pass_max)))
        num_pass = num_pass - 1
    write_file(file_name + '.hsh', hdata)
    print("Hashfile Created")
    elapse = datetime.datetime.now() - elapse
    print(f"Time Elapsed: {elapse.seconds} seconds")
    return
    
    
def create_slt():
    file_name, pass_min, pass_max, num_pass = get_userinput()
    elapse = datetime.datetime.now()
    sdata = []
    users = []
    while num_pass > 0:
        users.append(gen_user(users))
        sdata.append(write_salt(users[-1], gen_pass(pass_min, pass_max)))
        num_pass = num_pass - 1
    write_file(file_name + '.slt', sdata)
    print("Saltfile Created")
    elapse = datetime.datetime.now() - elapse
    print(f"Time Elapsed: {elapse.seconds} seconds")
    return


def create_all():
    file_name, pass_min, pass_max, num_pass = get_userinput()
    elapse = datetime.datetime.now()
    pdata = []
    hdata = []
    sdata = []
    users = []
    while num_pass > 0:
        users.append(gen_user(users))
        password = gen_pass(pass_min, pass_max)
        pdata.append(write_plain(users[-1], password))
        hdata.append(write_hash(users[-1], password))
        sdata.append(write_salt(users[-1], password))
        num_pass = num_pass - 1
    write_file(file_name + '.txt', pdata)
    write_file(file_name + '.hsh', hdata)
    write_file(file_name + '.slt', sdata)
    print("Files Created")
    elapse = datetime.datetime.now() - elapse
    print(f"Time Elapsed: {elapse.seconds} seconds")
    return


def main():
    print("random pass program")
    print("Written by: Cynthia Brown")
    while True:
        print("1) Create Text Password File")
        print("2) Create Hash Password File")
        print("3) Create Salt-Hash Password File")
        print("4) Create All Types Password Files")
        print("5) Create Unique Text Password File")
        print("0) Exit\n")
        try:
            choice = int(input("Selection Number: "))
            if choice >= 0 and choice < 6:
                match choice:
                    case 1:
                        create_txt()
                    case 2:
                        create_hsh()
                    case 3:
                        create_slt()
                    case 4:
                        create_all()
                    case 5:
                        create_unique_txt()
                    case 0:
                        return
            else:
                raise ValueError
        except ValueError:
            print("\nPick a number from 0-5\n")


# main()