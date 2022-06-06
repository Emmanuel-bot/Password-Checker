
"""
Name: Bulk Password Checker
Purpose: This is a program that is used to checl for strong passwords and generate passwords
Code: username
Date: 7th April, 2022
"""

import sys
import os
import re
import string 
from random import choice, shuffle

# declare global variables to be used throughout the program
STUDENT_NAME = "Emmanuel"  # Student Name goes heres
PASSWORD_FILE = "users-pwds.txt"   # Default password file
CHECKED_PASSWORD_FILE = "users-pwds-chked.txt"  #default file to write into our checked_passwords
BASE_PASSWORD = string.ascii_letters + string.punctuation + string.digits


class Password:
	""" This is the password object and all its xtics"""
	def __init__(self, upper, lower, sym, digit, len):
		self.password_xtics = (upper, lower, sym, digit)
		self.password_len = len


	def classify_password(self):
		""" This is a function that is used to classify the password as POOR or STRONG"""
		if (self.password_xtics.count(True) == 4):
			if (self.password_len > 11):
				return "STRONG"
			elif (self.password_len < 8):
				return "POOR"
			else:
				return "MODERATE"
		elif (self.password_xtics.count(True) == 3):
			if (self.password_len >= 8):
				return "MODERATE"
			else:
				return "POOR"
		else:
			return "POOR"


class PasswordChecker:
	""" This is the password checker object and all its attributes, and x-tics"""
	def __init__(self):
		self.banner()
		self.init()


	def init(self):
		""" This is the base function used to intialize everything """
		option = self.menu()
		if option == 3:
			self.quit()
		elif option == 1:
			self.check_passwords()
		elif option == 2:
			self.get_details()


	def banner(self):
		""" This is used to print the banner for the running program """
		print("\nPassword Checker [V.10]")
		print("-----------------------")


	def menu(self):
		""" This is a function used to return a menu to select availabe options"""
		menu_options = "\n\t1. Check Password Strength.\n\t2. Generate Secure Passowrd(s).\n\t3. Exit Program.\n"
		print(menu_options)

		while(True):
			try:
				opt = int(input("[Option]: "))
				if (opt >= 1 and opt <= 3):
					return opt
				else:
					print("\tInvalid Choice! Try again")
			except ValueError as err:
				print("\tInvalid Choice! Try Again")

	def check_passwords(self):
		_file_exists = True

		while(True):
			ans = input("Use default password file ('%s')[y/n]: " % PASSWORD_FILE)
			if (ans == "Y" or ans == "y"):
				_filename = PASSWORD_FILE
				break
			elif (ans == "N" or ans == "n"):
				_filename = str(input("Please Enter filename [Full Path]: "))
				_file_exists = self.check_if_file_exists(_filename)
				break

		if (_file_exists):
			cake = []
			""" this is where we loop through each line read from the file and extract the password"""
			lines = [ii.strip() for ii in open(_filename, "r").readlines()]
		
			for line in lines:
				password = line.split(",")[1].strip()
				cake.append(self.check_each_password(password))
			print("\n[ No of Passwords Checked ]: %s" % len(lines))
			print("[ FeedBack Stored in ]: \"%s\"" % CHECKED_PASSWORD_FILE)
		
			with open(CHECKED_PASSWORD_FILE, "w") as file:
				for ii in range(0, len(lines)):
					file.write("%s, %s\n" % (lines[ii], cake[ii]))
			self.init()

		else:
			print("\n==[Sorry! The Password File '%s' does not exist]==" % _filename)
			self.init()

	def check_each_password(self, password):
		""" This is where each password is checked, read from the password file"""
		return Password(self.uppercase(password), self.lowercase(password), self.digits(password), self.symbols(password), len(password)).classify_password()


	def uppercase(self, _pass):
		""" Used to check if password contains uppercase chars"""
		pattern = "[A-Z]"
		if re.search(pattern, _pass):
			return True
		else:
			return False

	def lowercase(self, _pass):
		""" Used to check If password contains lowecase letters"""
		pattern = "[a-z]"
		if re.search(pattern ,_pass):
			return True
		else:
			return False

	def digits(self, _pass):
		""" Check if password contains lowercase letters """
		pattern = "[0-9]"
		if re.search(pattern, _pass):
			return True
		else:
			return False

	def symbols(self, _pass):
		""" Check if password contains symbols """
		pattern = "[^0-9A-Za-z]"
		if re.search(pattern, _pass):
			return True
		else:
			return False


	def get_details(self):
			""" Function called to get the details of out user username:password"""
			while True:
				username = input("Enter Username: ")
				if (len(username) < 20 and username != ""):
					break
				else:
					print("Please Enter a valid username!")
		
			while True:
				password = self.generate_password()
				print("\nUsername: %s \nPassword: %s" % (username, password))
				ans = input("\nSave this Data [y/n]: ")

				if (ans == "Y" or ans == "y"):
					self.save_data(username, password, self.check_each_password(password), CHECKED_PASSWORD_FILE)
					break
				elif(ans == "n" or ans == "N"):
					a = input("Generate another password: [y/n]")
					if (a == "Y" or a == "y"):
						pass
					elif (a == "n" or a == "N"):
						self.save_data(username, password, self.check_each_password(password), CHECKED_PASSWORD_FILE)
						break
				else:
					print("Invalid Answer!")
	

	def generate_password(self):
		""" This is used to generate random strong passwords to the user"""
		password = [choice(BASE_PASSWORD) for _ in range(20)]
		shuffle(password)
		return "".join(password)
		

	def save_data(self, username, password, mode, filename):
		""" This is used to save the data and password generate by the user"""
		with open(filename, "a") as file:
			data = "%s, %s, %s\n" %(username, password, mode)
			file.write(data)
		print("Password Username saved in [%s]" % filename)
		self.init()


	def check_if_file_exists(self, filename):
		""" This is used to check if the file provided by the user exists appending .txt and 
		without appending the .txt ext if and if not provided"""
		if (os.path.isfile(filename) == False):
			# append .txt to check if the file exists
			_filename = "%s.txt" % filename
			return os.path.isfile(_filename)
		else:
			return True


	def quit(self):
		""" This is the function used to exit the program after user chooses exit"""
		print("Copyright (c) THIS PROGRAM IS COURTESY OF ~ %s " % STUDENT_NAME.upper())
		sys.exit(1)


def main():
	try:
		PasswordChecker() # intialize the password checker class
	except KeyboardInterrupt as err:
		sys.exit(1)


if __name__ == "__main__":
	main()
