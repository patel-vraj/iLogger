import base64
import os
from os import path
import json
import random
import string
from getpass import getpass
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet


class Logger:

    def __init__(self):
        self.password = ''
        self.key = b''  # your key will be stored here while you are using the program
        self.itemData = {}  # dictionary to hold item data
        self.itemName = {}  # dictionary to hold items by key

    def keyGen(self):
        # This is the password as a type string
        password_created = ''.join (random.choice (string.ascii_letters) for i in range (32))  # Random String

        password = password_created.encode ()  # Convert to type bytes
        salt = os.urandom (16)
        kdf = PBKDF2HMAC (algorithm=hashes.SHA256 (),
                          length=32,
                          salt=salt,
                          iterations=100000,
                          backend=default_backend ())

        # this creates your encryption key
        self.key = base64.urlsafe_b64encode (kdf.derive (password))

        # The key generated can only be used once so we write it to a file
        file = open ('.key', 'wb')
        file.write (self.key)
        file.close ()

    def readKey(self):
        file = open ('.key', 'rb')
        self.key = file.read ()
        file.close ()

    def addItem(self):
        """takes user input and stores it in the dictionary itemData"""

        url = input ('Enter URL Address: ')
        username = input ('Enter username: ')
        self.password = input ('Enter password: ')

        # adds item data to the dictionary
        self.itemData = {'URL': url, 'Username': username}

    def encryptData(self):
        """encrypts the password field of the dictionary"""

        if path.exists ('.key'):
            self.readKey ()
        else:
            self.keyGen ()

        # the encrypt function  needs bytes so we encode it
        userPwd = self.password.encode ()

        # this encrypts the password
        f = Fernet (self.key)
        encryptedPwd = f.encrypt (userPwd)

        # json will not write bytes so it has decode it to utf-8, then add it to the dictionary
        self.itemData['Password'] = encryptedPwd.decode ('utf-8')

    def writeData(self):
        """writes new entry to json file"""

        # this is to store each entry with a specific label
        itemlabel = input ("Enter the name of the new item: ")

        # if file does not exist we create it
        # if file does exist we read in the data, append new data, write back to file
        if path.exists ("iLogger_UserFile.json"):
            print ("Logger exists! ")
            fin = open ('iLogger_UserFile.json', 'r')
            self.itemName = json.load (fin)
            fin.close ()

            # we are appending new data here
            self.itemName[itemlabel] = self.itemData

            print ("Updating Loggert... ")
            fout = open ("iLogger_UserFile.json", 'w')
            json.dump (self.itemName, fout, sort_keys=True)
            fout.close ()
            print ('Logger updated!!')
        else:
            print ('No Logger found! \n Creating a new Logger...')

            self.itemName[itemlabel] = self.itemData
            fout = open ("iLogger_UserFile.json", 'w+')
            json.dump (self.itemName, fout)
            fout.close ()
            print ('Logger created! \n Data written!!')

    def updateData(self):
        print ('Updating Logger... ')
        fout = open ("iLogger_UserFile.json", 'w')
        json.dump (self.itemName, fout, sort_keys=True)
        fout.close ()
        print ('Logger updated! ')

    def readData(self):
        print ('Reading in data...')
        # load the dictionary
        fin = open ('iLogger_UserFile.json', 'r')
        self.itemName = json.load (fin)
        fin.close ()

    def decryptData(self):
        """decrypts the data and displays it"""

        # read the key for use in decryption
        self.readKey ()

        # this is the name for the stored item
        userQuery = input ("Enter the name of the item to get: ")

        # calls readData method so the dictionary will contain data
        self.readData ()

        counter = 1  # Count the number ot tries user entered
        while userQuery not in self.itemName:  # Execute if user item data not found in json file
            if counter != 5:
                print ("Item entered is not found, please try again!")
                userQuery = input ("Enter the name of the item to get: ")
                counter += 1  # add one to total of count
            else:
                print ("Item entered is not found!\n")
                print ("If yes, press \'Y\'. Or if no, press any key to exit the iLogger program.")
                choice = input ("Do you want to see list of names in file: ").upper ()
                if choice == 'Y':
                    self.displayItems ()
                    self.decryptData ()
                    return None  # Exit the function and return back to Main
                else:  # Execute if user entered any key of word
                    print ("Exiting the iLogger....")
                    exit ()

        print ("Item data is Found!")
        # loads the query data into the itemData dictionary
        self.itemData = self.itemName.get (userQuery)

        # assigns each field of the data to a variable
        url = self.itemData.get ('URL')
        uname = self.itemData.get ('Username')
        pwd = self.itemData.get ('Password').encode ()

        f = Fernet (self.key)
        decryptedPassword = f.decrypt (pwd).decode ()

        # displays each field
        print ('URL: ', url)
        print ('Username: ', uname)
        print ('Password: ', decryptedPassword)

    def displayItems(self):
        """Displays all of the item names in the Logger"""

        fin = open ("iLogger_UserFile.json", 'r')
        self.itemName = json.load (fin)
        fin.close ()

        print ('The items you have stored are: ')
        for key in self.itemName:
            print (key)

    def removeItem(self):
        """Removes an item from the iLogger"""

        itemToRemove = input ("Enter the name of the item you want to remove: ")

        # Calls readData method so dictionarys contain data
        self.readData ()

        counter = 1  # Count the number ot tries user entered
        while itemToRemove not in self.itemName:  # Execute if user item data not found in json file
            if counter != 5:
                print ("Item entered is not found, please try again!")
                itemToRemove = input ("Enter the name of the item you want to remove: ")
                counter += 1  # add one to total of count
            else:
                print ("Item entered is not found!\n")
                print ("If yes, press \'Y\'. Or if no, press any key to exit the iLogger program.")
                choice = input ("Do you want to see list of names in file: ").upper ()
                if choice == 'Y':
                    self.displayItems ()
                    self.removeItem ()
                    return None  # Exit the function and return back to Main
                else:  # Execute if user entered any key of word
                    print ("Exiting the iLogger....")
                    exit ()

        # calls del method to remove item
        del self.itemName[itemToRemove]
        print (itemToRemove, 'has been removed from the Logger!')

        # Calls updateData method to update data in Logger
        self.updateData ()

    def displayOptions(self):
        """displays the options for user interaction"""

        print ("Enter the number of the task you would like to perform")

        task = input (" 1. Add new item: \n 2. Review specific item data: \n 3. Display list "
                      "of item names: \n 4. Remove item: \n 5. Will secure your data and exit!"
                      " ")

        return task

    def encrypt_masterPassword(self):
        """ Creating a Master Password, then encrypting it and save in file"""

        # Check if 'key' file is exists or not
        if path.exists ('.key'):
            self.readKey ()
        else:
            self.keyGen ()

        # # encrypts the master password
        f = Fernet (self.key)
        mastPwd = input ("Create your Master Password: ")
        confirm_mastPwd = input ("Confirm your Master Password: ")

        while mastPwd != confirm_mastPwd:
            print ("Your master password doesn't match, Try again!")
            mastPwd = input ("Create your Master Password: ")
            confirm_mastPwd = input ("Confirm your Master Password: ")

        # Convert 'confirm_mastPwd' string into bytes and then write in a file
        encryptMasterPwd = f.encrypt (confirm_mastPwd.encode ())

        # Saved encrypted password in a text file
        file = open ('.MasterPassword', 'wb')
        file.write (encryptMasterPwd)
        file.close ()

    def decrypt_masterPassword(self):
        """ Decrypting master password from a 'MasterPassword' file """

        # Read a 'key' and 'MasterPassword' file
        self.readKey ()
        file = open ('.MasterPassword', 'rb')
        encryptedMasterPwd = file.read ()

        # Decrypt the master password
        f = Fernet (self.key)
        pwd = f.decrypt (encryptedMasterPwd)
        decryptMasterPwd = pwd.decode ('utf-8')  # Convert to String from Bytes

        return decryptMasterPwd

    def master_pwd(self):

        if path.exists ('.MasterPassword'):  # Check the 'MasterPassword' file
            # getPass hide password when user input from keyboard
            master_password = getpass ("Enter your Master Password: ")

            count = 1

            # Comparing passwords and it will in loop until user entered it correct password
            while master_password != self.decrypt_masterPassword ():
                print ('The master password is not correct. Please try again!')
                master_password = getpass ("Enter your Master Password again: ")

                if count == 5:  # if count reached 5, the program will terminate
                    print ("Access Denied! \nSorry, please try again later! ")
                    print ("Exiting the iLogger...")
                    exit ()
                else:
                    count += 1

        else:
            self.encrypt_masterPassword ()

        print ("\nAccess Granted!!")
        print ('Logging into your Logger......')
        print ('Successfully logged in!!\n')


if __name__ == "__main__":

    # Welcoming message
    print ("Welcome to iLogger! \niLogger is a private data storage "
           "that secures and encrypts your personal data!")

    iL = Logger ()  # Calls class name 'Logger'
    flag = True  # Signal to keep going

    iL.master_pwd ()

    while flag:
        userOption = iL.displayOptions ()
        if userOption == '1':
            iL.addItem ()
            print ("Encrypting data...")
            iL.encryptData ()
            print ("Data encrypted!")
            iL.writeData ()
        elif userOption == '2':
            print ("Decrypting data...")
            iL.decryptData ()
            print ('Data decrypted!')
        elif userOption == '3':
            iL.displayItems ()
        elif userOption == '4':
            iL.removeItem ()
        elif userOption == '5':
            print ("Exiting iLogger and securing your data.")
            print ("Exited Successfully!")
            flag = False
        else:
            print ("Please enter a valid number!")