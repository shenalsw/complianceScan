#!/usr/bin/python

import subprocess
import re
import os
import time

endpath = os.getcwd() + "/PAM Audit Report.txt"
report_file = open(endpath, "w")

def report_header(): 
    report_file.write("\n")
    report_file.write("===================================================================================")
    report_file.write("                                                         PAM *Pluggable Authentication Modules* Audit              \n")
    report_file.write("===================================================================================")
    
def report_line():
    report_file.write("===================================================================================")

def check_package(package_name):
    result = subprocess.run(['dpkg', '-s', package_name], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    return result.returncode == 0

def install_package():
    package_name = 'libpam-pwquality'

    if not check_package(package_name):
        response = input("libpam-pwquality package needs to be installed. Would you like to proceed (Y/N)? ")
        if response.lower() == 'y':
            print("Installing libpam-pwquality Package now...")
            subprocess.run(['sudo', 'apt', 'install', package_name], check=True)
            print("Installation of libpam-pwquality is complete.")
     
        else:
            print("libpam-pwquality Package was not installed.")
            report_file.write("\n1- libpam-pwquality Package was NOT installed on this machine.\n")  
            
    else:
        print(f"{package_name} is already installed.")
        report_file.flush()

def read_file(file_path):
    try:
        with open(file_path, 'r') as file:
            return file.readlines()
    except IOError as e:
        return []

def write_file(file_path, lines):
    try:
        with open(file_path, 'w') as file:
            file.writelines(lines)
    except IOError as e:
        print(f"Error writing to {file_path}: {e}")
        exit(1)

def check_pwquality():
    lines = read_file('/etc/security/pwquality.conf')
    minlen = None
    minclass = None
    for line in lines:
        if 'minlen' in line:
            minlen = line.strip()
        elif 'minclass' in line:
            minclass = line.strip()
    return minlen, minclass

#the changes are made in /etc/security/pwquality.conf
def check_pwquality():
    lines = read_file('/etc/security/pwquality.conf')
    minlen = None
    minclass = None
    for line in lines:
        if 'minlen' in line:
            minlen = line.strip()
        elif 'minclass' in line:
            minclass = line.strip()
    return minlen, minclass

def apply_pwquality(minlen, minclass):
    lines = read_file('/etc/security/pwquality.conf')
    with open('/etc/security/pwquality.conf', 'w') as file:
        for line in lines:
            if 'minlen' in line:
                file.write(f"minlen = {minlen}\n")
            elif 'minclass' in line:
                file.write(f"minclass = {minclass}\n")
            else:
                file.write(line)

def check_apply_pwquality():
    minlen, minclass = check_pwquality()

    minlen_value = int(minlen.split('=')[1].strip()) if minlen else 0
    minclass_value = int(minclass.split('=')[1].strip()) if minclass else 0

    if minlen_value == 14 and minclass_value == 4:
        print("The current password length and complexity meet requirements. No changes are needed.")
    elif minlen_value < 14 or minclass_value < 4:
        print("=== Warning: the current minimum length and password complexity do not meet requirements ===")
        response = input("Would you like to apply the recommended changes? Y/N: ")
        if response.lower() == 'y':
            apply_pwquality(14, 4)
            print("Updated pwquality.conf with minimum length=14 and complexity=4.")
            report_file.write("\n2- The minimum length and password complexity were updated in the password configuration file to meet standards. Minimum length: 14  / Password complexity: 4\n") 
        else:
            print("Password length and password complexity were not updated. No changes were applied.")
            report_file.write("\n2- The minimum length and password complexity were NOT changed for this machine.\n") 
            report_file.flush()
#the changes are made in the /etc/pam.d/common-password file
def update_common_password_file():
    common_password_path = '/etc/pam.d/common-password'
    lines = read_file(common_password_path)
    pam_pwquality_line = "password requisite pam_pwquality.so retry=3\n"

    if pam_pwquality_line.strip() in [line.strip() for line in lines]:
        print("Pam_pwquality is already enabled.")
    else:
        print("== Warning: the password checking module pam_pwquality.so is not enabled. Would you like to enable it? Y/N ==")
        response = input()
        if response.lower() == 'y':
            insert_position = 25
            if len(lines) >= insert_position:
                lines.insert(insert_position, pam_pwquality_line)
            else:
                lines.append(pam_pwquality_line)  
            write_file(common_password_path, lines)
            print("Password checking module has been enabled successfully.")
            report_file.write("\n3- The password checking module pam_pwquality.so was enabled.\n")
        else:
            print("Password checking module was not enabled. No changes were made.")
            report_file.write("\n3- The password checking module pam_pwquality.so was NOT enabled for this machine.\n")
            report_file.flush()

#changes made in /etc/pam.d/common-auth
def check_and_apply_faillock():
    common_auth_path = '/etc/pam.d/common-auth'
    lines = read_file(common_auth_path)

    if any('pam_faillock.so' in line for line in lines):
        print("Password lockouts are already configured.")
    else:
        print("== Warning: Password Lockouts are currently not configured.==")
        response = input("Would you like to configure password lockouts for your machine? Y/N: ")
        if response.lower() == 'y':
            configure_faillock(common_auth_path, lines)
            print("Password lockouts have been configured successfully.")
            report_file.write("\n4- Password lockouts were configured for this machine.\n")
        else:
            print("Password Lockouts were not configured. No changes were made.")
            report_file.write("\n4- Password lockouts were NOT configured for this machine.\n")
            report_file.flush()
         

def configure_faillock(file_path, lines):
    faillock_line = "auth required pam_faillock.so preauth silent audit deny=5 unlock_time=900\n"
    lines.append(faillock_line) 
    write_file(file_path, lines)

#changes made in /etc/pam.d/common-password
def check_and_apply_pwhistory():
    common_password_path = '/etc/pam.d/common-password'
    lines = read_file(common_password_path)
    pwhistory_line = "password required pam_pwhistory.so remember=5\n"

    if pwhistory_line.strip() in [line.strip() for line in lines]:
        print("Password Reuse Limit is already configured. No changes are needed.")
    else:
        print("== Warning: Password Reuse Limit is currently not configured ==")
        response = input("Would you like to configure a Password Reuse Limit ? Y/N: ")
        if response.lower() == 'y':
            configure_pwhistory(common_password_path, lines, pwhistory_line)
            print("Password Reuse limit is configured to refuse the past 5 passwords.")
            report_file.write("\n5- Password reuse limit has been configured on this machine to reject the last 5 passwords of a user.\n")
        else:
            print("Password Reuse limit was not configured. No changes were made.")
            report_file.write("\n5- Password reuse limit was NOT configured on this machine.\n")
            report_file.flush()
            

def configure_pwhistory(file_path, lines, pwhistory_line):
    insert_position = 25
    if len(lines) >= insert_position:
        lines.insert(insert_position, pwhistory_line + "\n")  
    write_file(file_path, lines)

#Changes are made in the /etc/pam.d/common-password file
def check_and_update_hashing():
    common_password_path = '/etc/pam.d/common-password'
    lines = read_file(common_password_path)
    sha512_line = "password        [success=1 default=ignore]      pam_unix.so obscure use_authtok try_first_pass sha512\n"
    
    sha512_present = False
    current_line_index = None

    for index, line in enumerate(lines):
        if "pam_unix.so" in line and "sha512" in line:
            sha512_present = True
            break
        elif "pam_unix.so" in line:
            current_line_index = index

    if sha512_present:
        print("The current password hashing algorithm meets requirements. No changes are needed.")
    else:
        print("== Warning: The current password hashing algorithm does not meet the requirements. Would you like to apply SHA512 hashing? Y/N? ==")
        response = input()
        if response.lower() == 'y':
            if current_line_index is not None:
                lines[current_line_index] = sha512_line
                write_file(common_password_path, lines)
                print("Password hashing algorithm has been changed successfully.")
                report_file.write("\n6- Password hashing algorithm was changed to SHA512 to meet standards.\n")
            else:
                print("Line not found in the file")
        else:
            print("Password hashing algorithim did not change. No changes were made.")
            report_file.write("\n4- Password hashing algorithm was NOT changed to SHA512 and currently does not meet standards.\n")
            report_file
              

def check_update_encrypt_method():
    login_defs_path = '/etc/login.defs'
    lines = read_file(login_defs_path)
    encrypt_method_line_prefix = "ENCRYPT_METHOD"
    sha512_line = f"{encrypt_method_line_prefix} SHA512"

    if any(sha512_line in line for line in lines):
        print("The default password encryption algorithm meets requirements.")
    else:
        print("== Warning: the default password encryption algorithm does not meet requirements. Would you like to change it to SHA512? Y/N? ==")
        response = input()
        if response.lower() == 'y':
            lines = [line.replace(line, sha512_line + "\n") if encrypt_method_line_prefix in line else line for line in lines]
            write_file(login_defs_path, lines)
            print("Default password encryption method has been updated successfully.")
            report_file.write("\n6- Password encryption method was updated on this machine to meet standards.\n")
            
        else:
            print("Password encryption method was not updated. No changes were made.")
            report_file.write("\n6- Password encryption method was NOT updated on this machine and currently does not meet standards.\n")
            report_file.flush()

#changes are made in the /etc/shadow file            

def list_without_sha512():
    shadow_path = '/etc/shadow'
    lines = read_file(shadow_path)

    users_without_sha512 = []
    for line in lines:
        if re.match(r'^[^:]+:\$6\$', line):
            continue  
        user = line.split(':')[0]
        if re.match(r'^[^:]+:[!*]', line):
            continue  
        users_without_sha512.append(user)

    if not users_without_sha512:
        print("All users have SHA512 password hashing algorithm. No changes are needed.")
    else:
        print("== Warning the Following Users are Using OUTDATED Password Hashing Algorithms ==")
        for user in users_without_sha512:
            print(user)

        response = input("Would you like to expire the passwords for the users listed above? (Recommended) Y/N? ")
        if response.lower() == 'y':
            for user in users_without_sha512:
                subprocess.run(['sudo', 'passwd', '-e', user])
            print("All Passwords for the listed users have been expired Sucessfully.")
            report_file.write("\n7- User passwords were expired since they used outdated hashing algorithms.\n")
        else:
            print("User Passwords were not expired. No changes were made.")
            report_file.write("\n7- User passwords were NOT expired and are currently using outdated hashing algorithms.\n")

            report_file.flush()
def pam_main():

    report_header()
      
    print("\n***// Checking if libpam-pwquality Package is Installed //***")
    install_package()
    time.sleep(5)
    
    print("\n***// Checking Password Requirements //***")
    check_apply_pwquality()
    time.sleep(5)

    print("\n***// Verifying if Password Checking Module is Enabled //***")
    update_common_password_file()
    time.sleep(5)

    print("\n***// Configuring Password Lockout Policy //***")
    check_and_apply_faillock()
    time.sleep(5)

    print("\n***// Configuring Password Reuse Limit //***")
    check_and_apply_pwhistory()
    time.sleep(5)

    print("\n***// Checking & Updating Password Hashing Algorithm //***")
    check_and_update_hashing()
    time.sleep(5)

    print("\n***// Checking & Updating Default Password Encryption Method //***")
    check_update_encrypt_method()
    time.sleep(5)

    print("\n***// Checking for Outdated Password Hashing Algorithms //***")
    list_without_sha512()
    time.sleep(5)

    print("\n***// Auditing For PAM has completed ! A copy of the audit results will be generated to a file called *PAM Audit Report.txt* //***")
    report_file.write("\n")
    report_file.close()
	


if __name__ == "__main__":
    pam_main()
