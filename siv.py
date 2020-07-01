#!/usr/bin/python
import argparse
import os
import sys
import time
from os.path import join, getsize
import pwd
from grp import getgrgid
import datetime
import hashlib
import json

# run help mode from command line:
# python3 siv.py -h

# run initialization mode from command line:
# python3 siv.py -i -D /home/samia/Desktop -V verification_file.txt -R report1.txt -H SHA1

# run varification mode from command line:
# python3 siv.py -v -D /home/samia/Desktop -V verification_file.txt -R report2.txt

class Siv:
    
    def initSiv(self):
        result_parser = self.addArgument()
        
        monitored_directory = result_parser.monitored_directory
        verification_file = result_parser.verification_file
        report_file = result_parser.report_file
        hash = result_parser.hash
        
        if result_parser.initialization:
            
            print("------------------------------------------------------------------\nStart Initialization Mode\n------------------------------------------------------------------\n")
            
            monitored_directory_exist = self.verifyDirectoryExist(result_parser.monitored_directory, "Monitored")
            
            verification_file_outside = self.verifyFileOutside(result_parser.monitored_directory, result_parser.verification_file, "Verification")
            report_file_outside = self.verifyFileOutside(result_parser.monitored_directory, result_parser.report_file, "Report")
            
            hash_verify = self.verifyHashSupport(result_parser.hash)
            
            verification_file_exist = self.verifyFileExist(result_parser.verification_file, "Verification")
            report_file_exist = self.verifyFileExist(result_parser.report_file, "Report")
            
            # ask to user if he wants to overwrite the existing verification file
            if monitored_directory_exist and verification_file_outside and report_file_outside and hash_verify and verification_file_exist and report_file_exist:
                
                overwrite_existing_file = input("Do you want to overwrite existing verification file? y/n: ")
                
                if overwrite_existing_file == "y":
                    
                    return_values = self.writeVerificationFile(monitored_directory, verification_file, hash)
                    print("---------------------------------\nDirectories and files information writing info verification file is complete!\n---------------------------------\n")
                    
                    start_time = return_values[0]
                    directory_count = return_values[1]
                    file_count = return_values[2]
                    
                    self.writeReport(monitored_directory, verification_file, report_file, start_time, directory_count, file_count, "Initialization")
                    print("---------------------------------\nReport writing for initialization mode is complete!\n---------------------------------\n")
                
                elif overwrite_existing_file == "n":
                    sys.exit()
                else:
                    sys.exit("You must input y/n. Please try again!")
            else:
                sys.exit()
            
            print("------------------------------------------------------------------\nEnd Initialization Mode\n------------------------------------------------------------------\n")
        
        elif result_parser.verification:
            
            print("------------------------------------------------------------------\nStart Verification Mode\n------------------------------------------------------------------\n")
            
            verification_file_exist = self.verifyFileExist(result_parser.verification_file, "Verification")
            verification_file_outside = self.verifyFileOutside(result_parser.monitored_directory, result_parser.verification_file, "Verification")
            report_file_outside = self.verifyFileOutside(result_parser.monitored_directory, result_parser.report_file, "Report")
            
            if verification_file_exist and verification_file_outside and report_file_outside:
                
                return_values = self.compareDirectoryContent(monitored_directory, verification_file)
                print("---------------------------------\nComparison for verification mode is complete!\n---------------------------------\n")
                
                start_time = return_values[0]
                directory_count = return_values[1]
                file_count = return_values[2]
                warning_count = return_values[3]
                warning_message = return_values[4]
                
                self.writeReport(monitored_directory, verification_file, report_file, start_time, directory_count, file_count, "Verification", warning_count, warning_message)
                print("---------------------------------\nReport writing for verification mode is complete!\n---------------------------------\n")
            
            print("------------------------------------------------------------------\nEnd Verification Mode\n------------------------------------------------------------------\n")
    
    # add argument for help
    def addArgument(self):
        parser = argparse.ArgumentParser()
        
        parser.add_argument("-i", "--initialization", action="store_true", help="Initialization Mode")
        parser.add_argument("-v", "--verification", action="store_true", help="Verification Mode")
        parser.add_argument("-D", "--monitored_directory", help="Monitored Directory")
        parser.add_argument("-V", "--verification_file", help="Verification File")
        parser.add_argument("-R", "--report_file", help="Report File")
        parser.add_argument("-H", "--hash", help="Supported hash functions are SHA1/SHA-1 and MD5/MD-5", default="SHA1")
        
        results = parser.parse_args()
        return results
    
    # check if specified monitored directory exists or not
    def verifyDirectoryExist(self, directory_path, directory_name):
        if os.path.isdir(directory_path):
            print("Verified! " + directory_name + " directory exists")
            return True
        else:
            sys.exit("" + directory_name + " directory doesn't exist!")
    
    # check if specified verification/report file exists or not
    def verifyFileExist(self, file_path, file_name):
        if os.path.exists(file_path):
            print("Verified! " + file_name + " file exists")
            return True
        else:
            sys.exit("" + file_name + " file doesn't exist!")
    
    # check if specified verification/ report file is outside the monitored directory
    def verifyFileOutside(self, monitored_directory, file_path, file_type=None):
        if os.path.commonprefix([monitored_directory, file_path]) != monitored_directory:
            print("Verified! " + file_type + " file is outside the monitored directory")
            return True
        else:
            sys.exit("" + file_type + " file is inside the monitored directory!")
    
    # check if specified hash functions, MD5/MD-5, SHA1/SHA-1 are supported by this SIV
    def verifyHashSupport(self, hash):
        if hash == "SHA1" or hash == "MD5" or hash == "SHA-1" or hash == "MD-5":
            print("Verified! " + hash + " is supported by SIV")
            return True
        else:
            sys.exit(hash + " is not supported by SIV!")
    
    # write into verification file - initialization mode
    def writeVerificationFile(self, monitored_directory, verification_file, hash):
        
        start_time = time.time() # for calculate time to complete the initialization mode
        directory_count = 0
        file_count = 0
        
        data = []           # dictionary for final data
        data_hash = {}      # dictionary for hash
        data_dir = {}       # dictionary for directory
        data_file = {}      # dictionary for file
        
        for root, dirs, files in os.walk(monitored_directory):
            
            for name in dirs:
                if os.path.exists(os.path.join(root, name)):
                    directory_count += 1
                    data_dir[os.path.join(root, name)] = self.getDirectories(root, name)
                    
            for name in files:
                if os.path.exists(os.path.join(root, name)):
                    file_count += 1
                    data_file[os.path.join(root, name)] = self.getFiles(root, name, hash)
        
        # write into verification file
        data.append(data_dir)
        data.append(data_file)
        
        data_hash = hash
        data.append(data_hash)
        
        with open(verification_file, "w") as vf:
            json.dump(data, vf, indent=4)
        
        return start_time, directory_count, file_count
    
    # get directory information
    def getDirectories(self, root, name):
        
        full_path = os.path.join(root, name)
        file_size = os.path.getsize(full_path)
        user_name = pwd.getpwuid(os.stat(full_path).st_uid).pw_name
        group_name = getgrgid(os.stat(full_path).st_gid).gr_name
        access_right = oct(os.stat(full_path).st_mode & 0o777)
        last_modification_date = datetime.datetime.fromtimestamp(os.path.getmtime(full_path)).isoformat()
        
        verification_dictionary = {
            "full_path": full_path,
            "file_size": file_size,
            "user_name": user_name,
            "group_name": group_name,
            "access_right": access_right,
            "last_modification_date": last_modification_date
        }
        
        return verification_dictionary
    
    # get file information
    def getFiles(self, root, name, hash):
        
        full_path = os.path.join(root, name)
        file_size = os.stat(full_path).st_size
        user_name = pwd.getpwuid(os.stat(full_path).st_uid).pw_name
        group_name = getgrgid(os.stat(full_path).st_gid).gr_name
        access_right = oct(os.stat(full_path).st_mode & 0o777)
        last_modification_date = datetime.datetime.fromtimestamp(os.path.getmtime(full_path)).isoformat()
        
        # message digest with specified hash function
        # https://stackoverflow.com/questions/22058048/hashing-a-file-in-python
        
        # BUF_SIZE is totally arbitrary, change for your app!
        BUF_SIZE = 65536  # lets read stuff in 64kb chunks!
            
        if(hash=="SHA1" or hash=="SHA-1"):
            sha1 = hashlib.sha1()
            
            with open(full_path, 'rb') as f:
                while True:
                    data = f.read(BUF_SIZE)
                    if not data:
                        break
                    sha1.update(data)
            
            file_content_hash = format(sha1.hexdigest())
            
        elif(hash=="MD5" or hash=="MD-5"):
            md5 = hashlib.md5()
            
            with open(full_path, 'rb') as f:
                while True:
                    data = f.read(BUF_SIZE)
                    if not data:
                        break
                    md5.update(data)
            
            file_content_hash = format(md5.hexdigest())
    
        verification_dictionary = {
            "full_path": full_path,
            "file_size": file_size,
            "user_name": user_name,
            "group_name": group_name,
            "access_right": access_right,
            "last_modification_date": last_modification_date,
            "file_content_hash": file_content_hash
        }
        
        return verification_dictionary
    
    # write into report file - initialization mode
    def writeReport(self, monitored_directory, verification_file, report_file, start_time, directory_count, file_count, mode_name, warning_count=0, warning_message=None):
        
        execution_time = time.time() - start_time
        
        data = ""
        data += "-----------------------------------------------\nStart " + mode_name + " Mode\n-----------------------------------------------\n"
        data += "Monitored Directory Path: " + monitored_directory + "\n"
        data += "Verification File Path: " + os.path.abspath(verification_file) + "\n"
        data += "Report File Path: " + os.path.abspath(report_file) + "\n"
        data += "Directory Count: " + str(directory_count) + "\n"
        data += "File Count: " + str(file_count) + "\n"
        data += "Execution Time: " + str(execution_time) + "\n"
        
        if mode_name=="Verification":
            data += "Warning Count: " + str(warning_count) + "\n"
            data += warning_message
        
        data += "\n-----------------------------------------------\nEnd " + mode_name + " Mode\n-----------------------------------------------\n\n"
        
        # write data to file
        with open(report_file, "w") as rf:
            rf.write(data)
    
    # read verification file and compare changes
    def compareDirectoryContent(self, monitored_directory, verification_file):
        
        start_time = time.time() # for calculate time to complete the initialization mode
        directory_count = 0
        file_count = 0
        warning_count = 0
        warning_message = ""
        
        data_dictionary = {}
        
        # read data from file
        if verification_file:
            with open(verification_file, "r") as vf:
                data_store = json.load(vf)
        
        warning_message += "\n-----------------------------------------------\nWarning Message for Directory\n-----------------------------------------------\n"
        
        for root, dirs, files in os.walk(monitored_directory):
            
            for name in dirs:
                
                directory_count += 1
                data_dictionary = self.getDirectories(root, name)
                
                return_values = self.detectChange(data_dictionary, data_store[0], "Directory")
                warning_count += return_values[0]
                warning_message += return_values[1]
                    
        for name in data_store[0]:
            
            if not os.path.exists(name):
                warning_count += 1
                warning_message += "Directory removed: " + name + "\n"
        
        warning_message += "\n-----------------------------------------------\nWarning Message for File\n-----------------------------------------------\n"
        hash = data_store[2]
        
        for root, dirs, files in os.walk(monitored_directory):
            
            for name in files:
                
                file_count += 1
                data_dictionary = self.getFiles(root, name, hash)
                
                return_values = self.detectChange(data_dictionary, data_store[1], "File")
                warning_count += return_values[0]
                warning_message += return_values[1]
                    
        for name in data_store[1]:
            
            if not os.path.exists(name):
                warning_count += 1
                warning_message += "File removed: " + name + "\n"
        
        return start_time, directory_count, file_count, warning_count, warning_message
    
    # detect changes between previous and new files/ directories
    def detectChange(self, data_dictionary, data_store, type = "File"):
        
        warning_count = 0
        warning_message = ""
        full_path = data_dictionary["full_path"]
                
        if full_path in data_store:
            path = data_store[full_path]
                    
            if path["file_size"] != data_dictionary["file_size"]:
                warning_count += 1
                warning_message += "Different size than recorded: " + full_path + "\n"
            if path["user_name"] != data_dictionary["user_name"]:
                warning_count += 1
                warning_message += "Different user name: " + full_path + "\n"
            if path["group_name"] != data_dictionary["group_name"]:
                warning_count += 1
                warning_message += "Different group name: " + full_path + "\n"
            if path["access_right"] != data_dictionary["access_right"]:
                warning_count += 1
                warning_message += "Modified access right: " + full_path + "\n"
            if path["last_modification_date"] != data_dictionary["last_modification_date"]:
                warning_count += 1
                warning_message += "Different modification date: " + full_path + "\n"
                
            if type == "File":
                if path["file_content_hash"] != data_dictionary["file_content_hash"]:
                    warning_count += 1
                    warning_message += "Different message digest than computed before: " + full_path + "\n"
        
        else:
            warning_count += 1
            warning_message += "New " + type.lower() + " created: " + full_path + "\n"
        
        return warning_count, warning_message
    
# create an object of Siv class
obj = Siv()
obj.initSiv()