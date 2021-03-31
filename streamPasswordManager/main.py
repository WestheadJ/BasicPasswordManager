import random, string, os
import bcrypt
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64

if os.path.isfile('salt.txt'):
    #Get the salt
    with open('salt.txt','rb') as saltfile:
        salt = saltfile.read()

else:
    with open('salt.txt','wb') as saltfile:
        salt = bcrypt.gensalt()
        saltfile.write(salt)

#Hashing Function
def hashingFunc(item):
    global passwordOut
    hashed = bcrypt.hashpw(item,salt)
    passwordOut = hashed

#Password Generator Function
def setPassword(length=30,char=string.ascii_letters+string.digits+string.punctuation):
    global generatedPassword
    generatedPassword = ''.join(random.choice(char) for x in range(length))

print("Hello and welcome to PMG!")
while True:
    #User Register/Login
    if os.path.isfile('user.txt'):
        with open('user.txt','rb') as user_file:
            file = user_file.read()

        getUser = input("Enter your username: ").encode('utf-8')
        getPass = input("Enter your password: ").encode('utf-8')

        #Using the hashing function:
        hashingFunc(item=getUser)
        usr = passwordOut
        hashingFunc(item=getPass)
        password = passwordOut

        key = password
        salt = b'SALT'
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        _key = base64.urlsafe_b64encode(kdf.derive(key))
        f = Fernet(_key)

        if usr in file and password in file:
            while True:
                print("""\nPick from the list of what you want to do:
                1. Generate a new password
                2. See passwords
                3. Delete All Passwords
                4. Delete User
                5. Quit """)

                usrinput = int(input('Choose an option from the menu: '))
                #Generate Password
                if usrinput == 1:
                    print('\nGenerating Password...')
                    setPassword()
                    usrinput = input("Enter what password is for: ")
                    if os.path.isfile('password.txt'):
                        with open('password.txt','ab') as password_file:
                            var = usrinput + ': ' + generatedPassword
                            encrypted = f.encrypt(bytes(var.encode('utf-8')))
                            password_file.write(encrypted)
                            password_file.write(b"--END OF PASSWORD--")

                            print('You new password for:',usrinput)
                            print('And the password is:',generatedPassword)

                    else:
                        with open('password.txt','wb') as password_file:
                            var = usrinput + ': ' + generatedPassword
                            encrypted = f.encrypt(bytes(var.encode('utf-8')))
                            password_file.write(encrypted)
                            password_file.write(b"--END OF PASSWORD--")

                            print('You new password for:', usrinput)
                            print('And the password is:', generatedPassword)

                #See Passwords
                elif usrinput == 2:
                    if os.path.isfile('password.txt'):
                        with open('password.txt','r') as password_file:
                            whole_file = password_file.read()
                            password_list = whole_file.split('--END OF PASSWORD--')
                            for password in password_list:
                                if password:
                                    decrypt = f.decrypt(bytes(password,encoding='utf-8'))
                                    password= str(decrypt)
                                    print('Your decrypted password is:',password[2:(len(password)-1)])
                    else:
                        print("\nNo passwords found!")
                #Deleting All Passwords
                elif usrinput == 3:
                    if os.path.isfile('password.txt'):
                        os.remove('password.txt')
                        print("\nPasswords Deleted")
                    else:
                        print('\nNo passwords to delete!')
                #Delete EVERYTHING
                elif usrinput == 4:
                    os.remove('user.txt')
                    print('Deleted User!')
                    os.remove('salt.txt')
                    print('Deleted Users Salt!')
                    if os.path.isfile('password.txt'):
                        os.remove('password.txt')
                        print("\nPasswords Deleted")
                    else:
                        print('\nNo passwords to delete!')

                    quit()
                elif usrinput == 5:
                    quit()
                else:
                    print("Not an option choose from the menu again")

        else:
            print('Incorrect username or password')
    else:
        print('Warning these cannot be changed!')
        getUser = input('Enter the username you want to use: ').encode('utf-8')
        getPass = input('Enter the password that you want to use: ').encode('utf-8')

        hashingFunc(item=getUser)
        usr = passwordOut
        hashingFunc(item=getPass)
        password = passwordOut

        with open('user.txt','wb') as user_file:
            user_file.write(usr)
            user_file.write(password)
        print('\nUser has been created!\n')