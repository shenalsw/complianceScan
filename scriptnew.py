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
    report_file.write("                   PAM *Pluggable Authentication Modules* Audit              \n")
    report_file.write("===================================================================================")
    
def report_line():
    report_file.write("===================================================================================")

def check_package_installed(package_name):
    result = subprocess.run(['dpkg', '-s', package_name], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    package_installed = result.returncode == 0

    if package_installed:
        print(f"{package_name} is already installed.")
        report_file.write(f"\n- {package_name} Package is already installed on this machine.\n")
    else:
        print(f"{package_name} is not installed.")
    
    return package_installed


def install_package():
    package_name = 'libpam-pwquality'

    if not check_package_installed(package_name):
        while True:
            response = input("libpam-pwquality package needs to be installed. Would you like to proceed (Y/N)? ")
            if response.lower() == 'y':
                print("Installing libpam-pwquality Package now...")
                subprocess.run(['sudo', 'apt', 'install', package_name], check=True)
                print("Installation of libpam-pwquality is complete.")
                report_file.write("\n1- libpam-pwquality Package was installed Successfully on this machine.\n")
                break
            elif response.lower() == 'n':
                print("libpam-pwquality Package was not installed.")
                report_file.write("\n1- libpam-pwquality Package was NOT installed on this machine.\n")
                break
            else:
                print("Invalid Choice, Please try again")
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
        
def check_pwquality_config():
    lines = read_file('/etc/security/pwquality.conf')
    minlen = None
    minclass = None
    for line in lines:
        if 'minlen' in line:
            minlen = line.strip()
        elif 'minclass' in line:
            minclass = line.strip()
    
    minlen_value = int(minlen.split('=')[1].strip()) if minlen else 0
    minclass_value = int(minclass.split('=')[1].strip()) if minclass else 0

    if minlen_value == 14 and minclass_value == 4:
        print("The current password length and complexity meet requirements. No changes are needed.")
    elif minlen_value < 14 or minclass_value < 4:
        print("=== Warning: the current minimum length and password complexity do NOT meet requirements ===")
        return False, minlen, minclass
    return True, minlen, minclass

def apply_pwquality_config(minlen, minclass):
    response = input("Would you like to apply the recommended changes? Y/N: ")
    if response.lower() == 'y':
        lines = read_file('/etc/security/pwquality.conf')
        with open('/etc/security/pwquality.conf', 'w') as file:
            for line in lines:
                if 'minlen' in line:
                    file.write(f"minlen = {minlen}\n")
                elif 'minclass' in line:
                    file.write(f"minclass = {minclass}\n")
                else:
                    file.write(line)
        print("Updated pwquality.conf with minimum length=14 and complexity=4.")
    elif response.lower() == 'n':
        print("Password length and password complexity were NOT updated. No changes were applied.")

def check_apply_pwquality():
    meets_requirements = check_pwquality()
    if not meets_requirements:
        apply_pwquality(14, 4)
            

def check_common_password():
    common_password_path = '/etc/pam.d/common-password'
    lines = read_file(common_password_path)
    pam_pwquality_line = "password requisite pam_pwquality.so retry=3"

    if pam_pwquality_line.strip() in [line.strip() for line in lines]:
        print("Password Checking module pam_pwquality.so is already enabled.")
        report_file.write("\n3- The Password checking module was already enabled on this machine.\n")
        return False
    else:
        print("Password Checking module pam_pwquality.so is NOT enabled.")
        report_file.write("\n3- The Password checking module pam_pwquality.so is NOT enabled for this machine.\n")
        return True

def apply_common_password():
    need_update = check_common_password()
    
    if need_update:
        response = input("Would you like to enable the password checking module pam_pwquality.so? Y/N: ")
        if response.lower() == 'y':
            common_password_path = '/etc/pam.d/common-password'
            lines = read_file(common_password_path)
            pam_pwquality_line = "password requisite pam_pwquality.so retry=3\n"
            
            insert_position = 25 
            if len(lines) >= insert_position:
                lines.insert(insert_position, pam_pwquality_line)
            else:
                lines.append(pam_pwquality_line)
            
            write_file(common_password_path, lines)
            print("Password checking module has been enabled successfully.")
            report_file.write("\n3- The password checking module pam_pwquality.so was enabled.\n")
        elif response.lower() == 'n':
            print("Password checking module was NOT enabled.")
            report_file.write("\n3- The password checking module pam_pwquality.so was NOT enabled after the prompt.\n")
        else:
            print("Invalid Choice, Please try again")

    report_file.flush()


def check_faillock_config():
    common_auth_path = '/etc/pam.d/common-auth'
    lines = read_file(common_auth_path)

    if any('pam_faillock.so' in line for line in lines):
        print("Password lockouts are already configured. No changes are needed.")
        report_file.write("\n4- Password Lockouts were already configured on this machine. No changes were made.\n")
        return True
    else:
        print("== Warning: Password Lockouts are currently NOT configured.==")
        report_file.write("\n4- Password lockouts are NOT configured for this machine.\n")
        return False


def apply_faillock_config():
    common_auth_path = '/etc/pam.d/common-auth'
    lines = read_file(common_auth_path)

    while True:
        response = input("Would you like to configure password lockouts for your machine? Y/N: ")
        if response.lower() == 'y':
            configure_faillock(common_auth_path, lines)
            print("Password lockouts have been configured successfully.")
            report_file.write("\n4- Password lockouts were configured for this machine.\n")
            break
        elif response.lower() == 'n':
            print("Password Lockouts were NOT configured. No changes were made.")
            report_file.write("\n4- Password lockouts were NOT configured for this machine.\n")
            break
        else:
            print("Invalid Choice, Please try again")
    report_file.flush()


def configure_faillock(file_path, lines):
    faillock_line = "auth required pam_faillock.so preauth silent audit deny=5 unlock_time=900\n"
    lines.append(faillock_line)
    write_file(file_path, lines)


def check_pwhistory_config():
    common_password_path = '/etc/pam.d/common-password'
    lines = read_file(common_password_path)
    pwhistory_line = "password required pam_pwhistory.so remember=5\n"

    if pwhistory_line.strip() in [line.strip() for line in lines]:
        print("Password Reuse Limit is already configured. No changes are needed.")
        report_file.write("\n5- The Required password reuse limit was already configured on this machine. No changes were made.\n")
        return False  
    else:
        print("== Warning: Password Reuse Limit is currently NOT configured ==")
        return True  
        
#changes made in /etc/pam.d/common-password        
def apply_pwhistory_config():
    common_password_path = '/etc/pam.d/common-password'
    lines = read_file(common_password_path)
    pwhistory_line = "password required pam_pwhistory.so remember=5\n"

    need_update = check_pwhistory_config()
    if need_update:
        while True:
            response = input("Would you like to configure a Password Reuse Limit ? Y/N: ")
            if response.lower() == 'y':
                insert_position = 25
                if len(lines) >= insert_position:
                    lines.insert(insert_position, pwhistory_line + "\n")
                else:
                    lines.append(pwhistory_line + "\n")
                write_file(common_password_path, lines)
                print("Password Reuse limit is configured to refuse the past 5 passwords.")
                report_file.write("\n5- Password reuse limit has been configured on this machine to reject the last 5 passwords of a user.\n")
                break
            elif response.lower() == 'n':
                print("Password Reuse limit was NOT configured. No changes were made.")
                report_file.write("\n5- Password reuse limit was NOT configured on this machine.\n")
                break
            else:
                print("Invalid Choice, Please try again")
        report_file.flush()
       

#Changes are made in the /etc/pam.d/common-password file
def check_hashing_config():
    common_password_path = '/etc/pam.d/common-password'
    lines = read_file(common_password_path)
    sha512_line = "password        [success=1 default=ignore]      pam_unix.so obscure use_authtok try_first_pass sha512\n"

    sha512_present = any("pam_unix.so" in line and "sha512" in line for line in lines)

    if sha512_present:
        print("The current password hashing algorithm meets requirements. No changes are needed.")
        report_file.write("\n6- The current password hashing algorithm meets standards. No changes were made.\n")
        return False  
    else:
        print("== Warning: The current password hashing algorithm does NOT meet the requirements. ==")
        return True 
        
def apply_hashing_config():
    common_password_path = '/etc/pam.d/common-password'
    lines = read_file(common_password_path)
    sha512_line = "password        [success=1 default=ignore]      pam_unix.so obscure use_authtok try_first_pass sha512\n"

    need_update = check_hashing_config()
    current_line_index = next((index for index, line in enumerate(lines) if "pam_unix.so" in line), None)

    if need_update:
        while True:
            response = input("Would you like to apply SHA512 hashing? Y/N: ")
            if response.lower() == 'y':
                if current_line_index is not None:
                    lines[current_line_index] = sha512_line
                    write_file(common_password_path, lines)
                    print("Password hashing algorithm has been changed successfully.")
                    report_file.write("\n6- Password hashing algorithm was changed to SHA512 to meet standards.\n")
                    break
                else:
                    print("Line not found in the file")
                    break
            elif response.lower() == 'n':
                print("Password hashing algorithm did NOT change. No changes were made.")
                report_file.write("\n6- Password hashing algorithm was NOT changed to SHA512 and currently does not meet standards.\n")
                break
            else:
                print("Invalid Choice, Please try again")
        report_file.flush()        

              

def check_encrypt_method():
    login_defs_path = '/etc/login.defs'
    lines = read_file(login_defs_path)
    encrypt_method_line_prefix = "ENCRYPT_METHOD"
    sha512_line = f"{encrypt_method_line_prefix} SHA512"

    if any(sha512_line in line for line in lines):
        print("The default password encryption algorithm meets requirements.")
        report_file.write("\n7- The Default password encryption algorithm meets standards. No changes were made.\n")
        return False  
    else:
        print("== Warning: the default password encryption algorithm does NOT meet requirements. ==")
        return True 
        
#changes are made in the /etc/login.defs file
def apply_encrypt_method():
    login_defs_path = '/etc/login.defs'
    lines = read_file(login_defs_path)
    encrypt_method_line_prefix = "ENCRYPT_METHOD"
    sha512_line = f"{encrypt_method_line_prefix} SHA512"

    need_update = check_encrypt_method()

    if need_update:
        while True:
            response = input("Would you like to change it to SHA512? Y/N: ")
            if response.lower() == 'y':
                lines = [line.replace(line, sha512_line + "\n") if encrypt_method_line_prefix in line else line for line in lines]
                write_file(login_defs_path, lines)
                print("Default password encryption method has been updated successfully.")
                report_file.write("\n7- Password encryption method was updated on this machine to meet standards.\n")
                break
            elif response.lower() == 'n':
                print("Password encryption method was NOT updated. No changes were made.")
                report_file.write("\n7- Password encryption method was NOT updated on this machine and currently does not meet standards.\n")
                break
            else:
                print("Invalid Choice, Please try again")
        report_file.flush()           

def check_users_hashing():
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
        print("== Warning: the following Users are Using OUTDATED Password Hashing Algorithms ==")
        for user in users_without_sha512:
            print(user)
    
    return users_without_sha512

def apply_hashing_changes(users_without_sha512):
    if users_without_sha512:
        response = input("Would you like to expire the passwords for the users listed above? (Recommended) Y/N? ")
        while response.lower() not in ['y', 'n']:
            print("Invalid Choice, Please try again")
            response = input("Would you like to expire the passwords for the users listed above? (Recommended) Y/N? ")

        if response.lower() == 'y':
            for user in users_without_sha512:
                subprocess.run(['sudo', 'passwd', '-e', user])
            print("All Passwords for the listed users have been expired Successfully.")
        elif response.lower() == 'n':
            print("User Passwords were NOT expired. No changes were made.")
    else:
        print("No users with outdated password hashing algorithms. No action required.")



def pam_main():

    while True:
        mode = input("Select Mode of Operation:\n 1 - Scan Only\n 2 - Scan + Apply Changes\nPlease enter your choice (1/2): ")
        if mode == '1':
            scan_only = True
            print("\n***// Running in Scan Only Mode //***")
            break
        elif mode == '2':
            scan_only = False
            print("\n***// Running in Apply Changes Mode //***")
            break
        else:
            print("Invalid Choice, Please try again")

    report_header()
      
    print("\n***// Verifying if libpam-pwquality Package is Installed //***")
    package_name = 'libpam-pwquality'
    if scan_only:
        check_package_installed(package_name)
    else:
        install_package()
    time.sleep(5)
    
    print("\n***// Checking Current Password Requirements //***")
    if scan_only:
        requirements_met, minlen, minclass = check_pwquality_config()
    else:
        requirements_met, minlen, minclass = check_pwquality_config()
        if not requirements_met:
            apply_pwquality_config(minlen, minclass)
    time.sleep(5)

    print("\n***// Verifying if Password Checking Module is Enabled //***")
    if scan_only:
        check_common_password()
    else:
        apply_common_password()
    time.sleep(5)

    print("\n***// Checking if Password Lockout Policy is Enforced //***")
    if scan_only:
        check_faillock_config()
    else:
        if not check_faillock_config():  
            apply_faillock_config()
    time.sleep(5)

    print("\n***// Configuring a Password Reuse Limit //***")
    if scan_only:
        check_pwhistory_config()
    else:
        apply_pwhistory_config()
    time.sleep(5)

    print("\n***// Verifying & Updating Password Hashing Algorithm //***")
    if scan_only:
        check_hashing_config()
    else:
        apply_hashing_config()
    time.sleep(5)

    print("\n***// Verifying & Updating Default Password Encryption Method //***")
    if scan_only:
        check_encrypt_method()
    else:
        apply_encrypt_method()
    time.sleep(5)

    print("\n***// Auditing for Outdated Password Hashing Algorithms //***")
    if scan_only:
        check_users_hashing()
    else:
        users_with_outdated_hashing = check_users_hashing()
        apply_hashing_changes(users_with_outdated_hashing)
    time.sleep(5)

    print("\n***// PAM Audit has been Completed Successfully! A copy of the audit results will be generated to a .txt file //***")
    report_file.write("\n")
    report_file.close()
    
    
   
pam_main()
	



