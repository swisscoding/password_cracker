#!/usr/local/bin/python3
# Made by @swisscoding on Instagram

from colored import stylize, fg
import hashlib

# decoration
print(stylize("\n---- | Password Cracker | ----\n", fg("red")))

# user interaction
# hash must be md5 for this script -> customizable
hashed_pw = input("Enter hashed password: ")
# must be present in the current directory
pw_file = input("Enter passwords filename: ")

# password found
found = False

# comparing the hashes with the hashed_pw
with open(pw_file, "r") as f:
    for password in f:
        # encoding the password into utf-8
        enc_password = password.encode("utf-8")

        # hashing the password into md5 hash
        hashed_password = hashlib.md5(enc_password.strip())

        # digesting the hashed_password into a hexa decimal value
        digested_password = hashed_password.hexdigest()

        if digested_password == hashed_pw:
            print(f"\nPassword found! The password is: {password}\n")
            found = True
            break

if not found:
    print("\nPassword not found.\n")
