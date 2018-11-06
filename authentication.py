import os.path
import aes
import getpass
import random
import string

MY_PATH = os.path.abspath(os.path.dirname(__file__))
MY_PASSWORD = "justdoit"

PATH = os.path.join(MY_PATH, "config/password")


def change(old_password, password, password2, username="admin"):
    """Changing the password."""

    if authenticate(username, old_password) == True:
        if password == password2:
            save_credentials(username, password)
            return True

    return False


def save_credentials(username, password):
    authstring = "Username:'" + username + "'Password:'" + password + "'"

    with open(PATH, "w") as pwd_file:
        encrypted = aes.encrypt(MY_PASSWORD, authstring.encode())
        pwd_file.write(encrypted)


def authenticate(username, password):
    """Authenticating the password and username."""
    print("================= Authenticating =================")
    list_1 = []
    username2 = "Username:'" + username + "'Password:'" + password + "'"

    if not os.path.isfile(PATH):
        print("password file doesn't exist, creating default")
        save_credentials("admin", "admin")

    with open(PATH, "r") as pwd_file:
        for line in pwd_file:
            list_1.append(line)

    if len(list_1) == 0:
        return False

    decrypted = aes.decrypt(MY_PASSWORD, list_1[0])
    return bool(username2 in decrypted.decode())


def compare_new_passwords(password, password2):
    """Compares current password with the user inputed password"""
    return bool(password != password2)


def compare_current_password(oldpassword, username="admin"):
    return not bool(authenticate(username, oldpassword))


def authentication():
    username = raw_input("USERNAME: ")
    password = getpass.getpass("PASSWORD: ")

    if authenticate(username, password):
        print("Successfully authenticated!")
        change_password = raw_input("Do you want to change password?<Yes/No>")
        if "Yes" in change_password:
            old_password = getpass.getpass("Old password: ")
            new_password = getpass.getpass("New password: ")
            confirm_password = getpass.getpass("Confirm new password: ")
            if change(old_password, new_password, confirm_password, username):
                print("Your password has been changed successfully!")
            else:
                print("Could't change your password!")
    else:
        print("Wrong credentials!")

    print("Closing...")


def file_encryption():
    """"File encryption/decryption using aes"""
    print("File encryption/decryption using aes\n\n")

    command = raw_input("Choose an action<Encrypt/Decrypt>: ")

    path = raw_input("Please type the file path: ")
    if os.path.exists(path):
        with open(path, "r") as file_to_read:
            text = file_to_read.read()

        if not text:
            print("File doesn't have content!")
        else:
            key = raw_input("Please type the key: ")
            paths_directory = os.path.dirname(path)
            rand_string = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(5))
            file_extension = os.path.splitext(path)[1]

            if command.lower() == "encrypt":
                with open("%s\encryption_%s%s" % (paths_directory, rand_string, file_extension), "w+") as file_to_write:
                    encrypted_text = aes.encrypt(key, text.encode())
                    file_to_write.write(encrypted_text)

                print("Encryption completed successfully!")
            elif command.lower() == "decrypt":
                with open("%s\decryption_%s%s" % (paths_directory, rand_string, file_extension), "w+") as file_to_write:
                    decrypted_text = aes.decrypt(key, text)
                    if decrypted_text: 
                        file_to_write.write(decrypted_text.decode())
                        print("Decryption completed successfully!")
            else:
                print("Command wasn't recognised!")
    else:
        print("File doesn't exists!")

    print("Closing...")


file_encryption()
#authentication()

