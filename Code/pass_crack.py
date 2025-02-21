import datetime
from os import error
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from rand_pass_gen import write_file
files = ["hashPass.hsh", "saltPass.slt", "plainuniquetext.txt"]

def get_password_file(file):
    ty = 'rb'
    try:
        with open('./files/' + file, ty) as pf:
            txt = pf.read()
            return txt.split(b';')
    except IOError:
        print("failed to open file\n")
        return


def user_input():
    passfile = input("Password File: ") or ''
    crackfile = input("Rainbow Table File: ") or files[2]
    return passfile, crackfile


def hash_password(password: bytes):
    # Create a hash of the password
    hashPass = hashes.Hash(hashes.SHA256())
    hashPass.update(password)
    return hashPass.finalize()


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


def crack_hsh():
    print("Cracking Hash Passwords")
    passfile, crackfile = user_input()
    elapse = datetime.datetime.now()
    if not passfile:
        passfile = files[0]
    if not crackfile:
        crackfile = files[2]
    password_file = get_password_file(passfile)
    crack_file = get_password_file(crackfile)
    hash_crack = []
    hash_pass = []
    hacked_users = []
    hacked_users_file = []
    errors = []
    for line in crack_file:
        if line:
            tmp = line.split(b':')
            hash_pass.append(tmp[0])
            hash_crack.append(tmp[1])
    print(len(hash_crack))
    for line in password_file:
        user = line.split(b':')
        try:
            for hsh in hash_crack:
            # if user[1] in hash_crack:
                if user[1] == hsh:    
                    hacked_users.append([user[0],hash_pass[hash_crack.index(hsh)]])
                    hacked_users_file.append(user[0] + b':' + hash_pass[hash_crack.index(hsh)] + b';')
        except:
            errors.append(line)
    # Write hacked users to file and screen
    write_file("hacked_logins.txt", hacked_users_file)        
    elapse = datetime.datetime.now() - elapse
    print(f"Time Elapsed: {elapse.seconds} seconds, {elapse.microseconds} micro seconds")
    print(str(len(hacked_users)) + " Hacked Logins out of " + str(len(password_file)) + " with " + str(len(errors)) + " errors: ")
    for user in hacked_users:
        print("Username: " + user[0].decode('utf-8') + ", Password: " + user[1].decode('utf-8') + "")
    

def crack_slt():
    print("Cracking Salt Hash Passwords")
    passfile, crackfile = user_input()
    elapse = datetime.datetime.now()
    if not passfile:
        passfile = files[1]
    if not crackfile:
        crackfile = files[2]
    password_file = get_password_file(passfile)
    crack_file = get_password_file(crackfile)
    salt_crack = []
    hacked_users = []
    hacked_users_file = []
    errors = []
    users = []
    passwords = []
    salts = []
    for line in crack_file:
        if line:
            tmp = line.split(b':')
            salt_crack.append([tmp[0], tmp[1]])
    for login in password_file:
        if login:
            tst = login.split(b':')
            users.append(tst[0])
            passwords.append(tst[1])
            salts.append(tst[2])
    if salts:
        for salt in salts:
            if salt != b'':
                for line in salt_crack:
                    i = salts.index(salt)
                    if line:
                        spass, s = salt_password(line[0],salt)
                        salt_crack.append([spass, salt])
                        if spass == passwords[i]:
                            hacked_users.append([users[i], line, salt])
                            hacked_users_file.append(users[i]+ b':' + line[0] + b':' + salt)
                            del salts[i]
                            del users[i]
                            del passwords[i]
                            break
            #if hacked_users:
                #break

    # Write hacked users to file and screen
    write_file("hacked_salt_logins.txt", hacked_users_file)        
    elapse = datetime.datetime.now() - elapse
    print(f"Time Elapsed: {elapse.seconds} seconds, {elapse.microseconds} micro seconds")
    print(str(len(hacked_users)) + " Hacked Logins out of " + str(len(password_file)) + " with " + str(len(errors)) + " errors: ")
    for user in hacked_users:
        print("Username: " + user[0].decode('utf-8') + ", Password: " + str(user[1]) + ", Salt: " + user[2].decode('utf-8'))


def main():
    print("pass crack program")
    print("Written by: Cynthia Brown")
    while True:
        print("1) Crack Hash Password")
        print("2) Crack Salt Hash Password")
        print("0) Exit\n")
        try:
            choice = int(input("Selection Number: "))
            if choice >= 0 and choice < 3:
                match choice:
                    case 1:
                        crack_hsh()
                    case 2:
                        crack_slt()
                    case 0:
                        return
            else:
                raise ValueError
        except ValueError:
            print("\nPick a number from 1-3\n")
            

# main()    