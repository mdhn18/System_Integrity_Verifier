#!/usr/bin/python3

import sys
import argparse
import os
import pwd
import json
import hashlib
from datetime import datetime
from grp import getgrgid


print("\n SIV (System Integrity Verifier) implemented by Md Rabiul Ahamed Bin.\n")

# In help mode, the program will show usage and then terminates
if sys.argv[1] == "-h":
    print("Usage is as following:\n")
    print("python3 siv.py <-i|-v> -D <monitored_directory> -V <verification_file> -R <report_file> -H <hash_function>\n")
    sys.exit()


# add argument for help
parser = argparse.ArgumentParser()
arg_group = parser.add_mutually_exclusive_group()
arg_group.add_argument("-i", "--initialize", action="store_true", help="Initialization mode")
arg_group.add_argument("-v", "--verify", action="store_true", help="Verification mode")
parser.add_argument("-D", "--monitored_directory", type=str, help="Write the name of the directory that you want to monitor")
parser.add_argument("-V", "--verification_file", type=str,help="Write the Verification File path that can store information of directories & files in the monitored directory")
parser.add_argument("-R", "--report_file", type=str, help="Write the name of the Report File to store Initialization / Verification report")
parser.add_argument("-H", "--hash_function", type=str, help="Write name of the hash function, supported hashes are 'SHA-1' and 'MD-5'")

args = parser.parse_args()

startTime = 0   # For count time

# parameters define
mon_dir = args.monitored_directory     # For Monitored directory
verify_file_path = args.verification_file       # For Verification file path
report_file_path = args.report_file             # For Report file path
hash = args.hash_function                  # For Hash function



#Check if specified monitored directory exist or not
def check_mon_dir_exist():
    if os.path.isdir(mon_dir) == 1:
        return
    else:
        print ("Monitored directory does not exist.")
        print ("Program terminates here.")
        sys.exit()

#In the monitored directory verification are aviableable or not
def check_verif_in_mon_dir():
    if os.path.commonprefix([mon_dir, verify_file_path]) == mon_dir :
        print ("Verification file is inside monitored directory.")
        print ("Program terminates here.")
        sys.exit()
    else:
        return

#Check if report file is in the monitored directory or not
def check_report_in_mon_dir():
    if os.path.commonprefix([mon_dir, report_file_path]) == mon_dir :
        print ("Report file is inside monitored directory.")
        print ("Program terminates here.")
        sys.exit()
    else:
        return

#Check if the hash function is supported or not
def check_hash_supported():
    if hash == "md5" or hash == "sha1":
        return
    else:
        print("Hash is not supported. Please try again.")
        print ("Program terminates here.")
        sys.exit()

#Check if the verification file already exists or not
def verification_file_exist():
    if os.path.isfile(verify_file_path):
        return True
    else:
        return False

#Check if the report file already exists or not
def report_file_exist():
    if os.path.isfile(report_file_path):
        return True
    else:
        return False


# ************** Now mode start initialization mode******************


if args.initialize:

    print("*************************************************************************\nInitialization Mode\n*************************************************************************\n")
    check_mon_dir_exist()
    check_verif_in_mon_dir()
    check_report_in_mon_dir()

    if (hash == "sha1" or hash == "sha-1" or hash == "SHA1" or hash == "SHA-1"):
        hash = "sha1"
    if (hash == "md5" or hash == "md-5" or hash == "MD5" or hash == "MD-5"):
        hash = "md5"
    check_hash_supported()

    # ask to user if he wants to overwrite the existing verification file
    # If press yes = 'y' it will continue . If no = 'n' and invalid then exit.
    if verification_file_exist():
        print("Verification file already exists")
        input_str = input("You wanna Overwrite the verification file? (y/n):")
        if (input_str == "n"):
            print("\nIf you chose 'n' then program will exit here..\n")
            sys.exit()
        elif (input_str == "y"):
            print("Verification file will be overwritten.\n")
        else:
            print("Invalid input.\n")
            sys.exit()
    else:
        os.open(verify_file_path, os.O_CREAT, mode=0o777)
        print("Verification file was not available but created now.")


 # ask to user if he wants to overwrite the report file
    # If press yes = 'y' it will continue . If no = 'n' and invalid then exit.
    if report_file_exist():
        print("Report file already exists")
        input_str = input("Overwrite the report file? (y/n):")
        if (input_str == "n"):
            print("\nIf you chose 'n' overwrite the report file. Program will exit here.\n")
            sys.exit()
        elif (input_str == "y"):
            print("Report file will be overwritten.\n")
        else:
            print("Invalid input.\n")
            sys.exit()

    else:
        os.open(report_file_path, os.O_CREAT, mode=0o777)
        print("If report file missing then its create here now.")


    startTime = datetime.utcnow()
    print("*************************************************************************\nStart Initialization Mode\n*************************************************************************\n")
    print("*************************************************************************\nTime count starts.\n*************************************************************************\n")
    number_of_directory = 0
    number_of_file = 0
    data = [] # dictionary for final data all
    data_file = {} # here dictionary for file
    data_hash = {} # hash data for dictionary
    data_dir = {} # dictionary data for directory


    # This  loop use for goes inside in the monitored directory
    for sub_dir, dirs, files in os.walk(mon_dir):

        # to store any file and folders histiry in it.
        for i in dirs:

            number_of_directory += 1
            path = os.path.join(sub_dir, i)
            size = os.path.getsize(path) # Size of the file
            user = pwd.getpwuid(os.stat(path).st_uid).pw_name # location or directory of the file
            group = getgrgid(os.stat(path).st_gid).gr_name # Name of the group, which gorup its from
            access = oct(os.stat(path).st_mode & 0o777) # octal value of 0o777 = chmod 511
            mod_time = datetime.fromtimestamp(os.stat(path).st_mtime).strftime('%c') # Last update  time for file.

            # Store the Values in  'data_dir'
            data_dir[path] = {"Size": size, "User": user, "Group":group, "Accessibility": access, "Last Modification Time": mod_time}

        # For file in monitored directory to store the following values.
        for file in files:

            number_of_file += 1
            full_path = os.path.join(sub_dir, file)
            file_size = os.stat(full_path).st_size
            owner_user = pwd.getpwuid(os.stat(full_path).st_uid).pw_name
            owner_group = getgrgid(os.stat(full_path).st_gid).gr_name
            access_right = oct(os.stat(full_path).st_mode & 0o777) # octal value of 0o777 is equal to chmod 511
            total_time = datetime.fromtimestamp(os.stat(full_path).st_mtime).strftime('%c') # Record initialization time and date

	     # https://stackoverflow.com/questions/22058048/hashing-a-file-in-python
            # Message digest with MD-5 or MD5 hash
            if hash == "md5":
                hash_type = "md5"
                h = hashlib.md5()
                data_hash = {"hash_type": hash_type}
                with open(full_path, 'rb') as myfile:
                    buffer = myfile.read()
                    h.update(buffer)
                    message_digest = h.hexdigest()

            # Message digest with SHA-1 or SHA1 hash
            elif hash == "sha1":
                hash_type = "sha1"
                h = hashlib.sha1()
                data_hash = {"hash_type": hash_type}
                with open(full_path, 'rb') as myfile:
                    buffer = myfile.read()
                    h.update(buffer)
                    message_digest = h.hexdigest()

            # Save the Key or hash value :Values in a dictionary (data_file)
            data_file[full_path] = {"Size": file_size, "User": owner_user, "Group": owner_group, "Accessibility": access_right, "Last Modification Time": total_time , "hash_type": message_digest}

    data.append(data_dir)
    data.append(data_file)
    data.append(data_hash)
    json_string = json.dumps(data, indent=4, sort_keys=True)


    # Verification file writting here.
    with open(verify_file_path, "w") as writefile:
        writefile.write(json_string)

    print("\nVerification file writen successfully.")

    # Time calculating for initialization
    total_operation_time = datetime.utcnow() - startTime
    print (f"\nTotal time for initialization: {total_operation_time}")
    print(f"\nTotal directories: {number_of_directory} and total files: {number_of_file}")

    # Report file writting here.
    with open(report_file_path, "w") as writefile:
        writefile.write("\n\t  " + "*" * 38)
        writefile.write("\n\t  # # # Initialization mode report # # #\n")
        writefile.write("\t  " + "*" * 38)
        writefile.write(f"\n\n         Monitored directory :  {mon_dir}\n")
        writefile.write(f"\n  Verification file location :  {verify_file_path} \n")
        writefile.write(f"\n        Report file location :  {report_file_path} \n")
        writefile.write("\nNumber of directories parsed :  "+ str(number_of_directory) + "\n")
        writefile.write("\n      Number of files parsed :  "+ str(number_of_file) + "\n")
        writefile.write("\n                  Total Time :  "+ str(total_operation_time) + "\n")

    print("\nReport File writen successfully.\n")


#************Mode starts Verification Mode *************************


elif args.verify:

    print("*************************************************************************\nVerification Mode\n*************************************************************************\n")

    check_mon_dir_exist()

    if not verification_file_exist():
        print("If Verification does not exists. Program exit here.")
        sys.exit()

    check_verif_in_mon_dir()
    check_report_in_mon_dir()

    # ask to user if he wants to overwrite the report file
    # If press yes = 'y' it will continue . If no = 'n' and invalid then exit.

    if report_file_exist():
        print("Report file already exists")
        input_str = input("Overwrite the report file? (y/n):")
        if (input_str == "n"):
            print("\nYou choose not to overwrite the report file. Program will exit here.\n")
            sys.exit()
        elif (input_str == "y"):
            print("Report file will be overwritten.\n")
        else:
            print("Invalid input.\n")
            sys.exit()

    else:
        os.open(report_file_path, os.O_CREAT, mode=0o777)
        print("If report file missing then its create here now.")


    startTime = datetime.utcnow() # Start counting time for verification.
    print("*************************************************************************\nVerification starts\n*************************************************************************\n")
    print("*************************************************************************\nTime count starts.\n*************************************************************************\n")

    number_of_directory = 0  # Number of directories.
    number_of_file = 0  # Number of files.
    k = 0  # Number of warnings

    with open(verify_file_path) as input_file:
        json_decode = json.load(input_file)

    hash_type = json_decode[2]['hash_type']


    report_write = open(report_file_path, "a")

    for sub_dir, dirs, files in os.walk(mon_dir):
        for fds in dirs:
            number_of_directory += 1
            path = os.path.join(sub_dir, fds)
            size = os.stat(path).st_size
            user = pwd.getpwuid(os.stat(path).st_uid).pw_name
            group = getgrgid(os.stat(path).st_gid).gr_name
            access = oct(os.stat(path).st_mode & 0o777)
            mod_time = datetime.fromtimestamp(os.stat(path).st_mtime).strftime('%c')

            #For debugging
            #print(f"Directory >> {path}\n")

            if path in json_decode[0]: # [0] index means path, [1] means file, [2] means folder.

                # Checking file size compared to initial value which done in initial mode.
                if size != json_decode[0][path]['Size']:
                    report_write.write(f"WARNING... Directory {path} has a different size\n")
                    k = k+1

                # Checking user compared to initial value which done in initial mode.
                if user != json_decode[0][path]['User']:
                    report_write.write(f"\nWARNING... Directory {path} has a different user \n")
                    k = k+1

                # Checking group compared to initial value wwhich done in initial mode.
                if group != json_decode[0][path]['Group']:
                    report_write.write(f"\nWARNING... Directory {path} has a different group\n")
                    k = k+1

                # Checking access compared to initial value which done in initial mode.
                if access != json_decode[0][path]['Accessibility']:
                    report_write.write(f"\nWARNING... Directory {path} has changed the access permission\n")
                    k = k+1

                # Checking modification time compared to initial value which done in initial mode.
                if mod_time != json_decode[0][path]['Last Modification Time']:
                    report_write.write(f"\nWARNING... Directory {path} has a different modification date\n")
                    k = k+1

            else:
                report_write.write(f"\nWARNING... Directory {path} has been added\n")
                k = k+1

    # check if anything removed from the monitored path.
    for each_pre_dir in json_decode[0]:

        if os.path.isdir(each_pre_dir) == 0:
            report_write.write(f"\nWARNING... Directory {each_pre_dir} has been removed\n")
            k = k+1

    # Travercing the monitored directory by Depth First Search (DFS).
    for sub_dir, dirs, files in os.walk(mon_dir):
        for file in files:
            number_of_file += 1
            full_path = os.path.join(sub_dir, file)
            file_size = os.stat(full_path).st_size
            owner_user = pwd.getpwuid(os.stat(full_path).st_uid).pw_name
            owner_group = getgrgid(os.stat(full_path).st_gid).gr_name
            access_right = oct(os.stat(full_path).st_mode & 0o777)
            total_time = datetime.fromtimestamp(os.stat(full_path).st_mtime).strftime('%c')

            #For debugging
            #print(f" ----- File ----- {full_path}    is recorded successfully ...")

            # Message digest  MD-5 or MD5
            if hash_type == "md5":
                #print(hash_type)   # Writen for debugging purpose
                h = hashlib.md5()
                with open(full_path, 'rb') as mfile:
                    buffer = mfile.read()
                    h.update(buffer)
                    message_digest = h.hexdigest()


            # Message digest  SHA-1 or SHA1
            elif hash_type == "sha1":
                #print(hash_type)   # Writen for debugging purpose
                h = hashlib.sha1()
                with open(full_path, 'rb') as hfile:
                    buffer = hfile.read()
                    h.update(buffer)
                    message_digest = h.hexdigest()

            if full_path in json_decode[1]: # Index [1] means file.

                # Check if size is changed compared to initial value which done in initial mode.
                if file_size != json_decode[1][full_path]['Size']:
                    report_write.write(f"\nWARNING... File {full_path} is changed in size\n")
                    k += 1

                 # Check if user is changed compared to initial value which done in initial mode.
                if owner_user != json_decode[1][full_path]['User']:
                    report_write.write(f"\nWARNING... File {full_path} has a different user\n")
                    k += 1

                # Check if group is changed compared to initial value which done in initial mode.
                if owner_group != json_decode[1][full_path]['Group']:
                    report_write.write(f"\nWARNING... File {full_path} has a different group\n")
                    k += 1

                # Check if modification time is changed compared to initial value which done in initial mode.
                if total_time != json_decode[1][full_path]['Last Modification Time']:
                    report_write.write(f"\nWARNING... File {full_path} has a different modification date or time\n")
                    k += 1

                # Check if access is changed compared to initial value which done in initial mode.
                if access_right != json_decode[1][full_path]['Accessibility']:
                    report_write.write(f"\nWARNING... File {full_path} has modified accessibility permission\n")
                    k += 1

                # Check if encryption methode is changed compared to initial value which done in initial mode.
                if message_digest != json_decode[1][full_path]['hash_type']:
                    report_write.write(f"\nWARNING... File {full_path} has a change in its content\n")
                    k += 1
            else:
                report_write.write(f"\nWARNING... File {full_path} has been added\n")
                k += 1

    for each_prev_file in json_decode[1]:
        if os.path.isfile(each_prev_file) == 0:
            report_write.write("\nWARNING... File " + each_prev_file + " has been deleted\n")
            k += 1

    # Verification total time taken.
    total_operation_time = datetime.utcnow() - startTime

     # Writing report file
    report_write.write("\n\t  " + "*" * 36)
    report_write.write("\n\t  # # # Verification mode report # # #")
    report_write.write("\n\t  " + "*" * 36)
    report_write.write(f"\n\n         Monitored directory :  {mon_dir}\n")
    report_write.write(f"\n  Verification file location :  {verify_file_path}\n")
    report_write.write(f"\n        Report file location :  {report_file_path}\n")
    report_write.write("\nNumber of directories parsed :  " + str(number_of_directory) + "\n")
    report_write.write("\n      Number of files parsed :  " + str(number_of_file) + "\n")
    report_write.write("\n                 Total Time  :  " + str(total_operation_time) + "\n")
    report_write.write("\n          Number of Warnings :  " + str(k))
    report_write.close()

    print("\nVerification report writen successfully.\n")
    print("*************************************************************************\nVerification completed.\n*************************************************************************\n")
    print (f"\nTotal time taken for verification: {total_operation_time}")
    print(f"\nTotal {number_of_directory} directories and {number_of_file} files were handled.")
