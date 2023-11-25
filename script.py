#!/usr/bin/python

import subprocess

def is_package_installed(package_name):
    result = subprocess.run(['dpkg', '-s', package_name], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    return result.returncode == 0

def install_libpam_pwquality():
    package_name = 'libpam-pwquality'

    if not is_package_installed(package_name):
        response = input("libpam-pwquality package needs to be installed. Would you like to proceed (Y/N)? ")
        if response.lower() == 'y':
            print("Installing libpam-pwquality Package now...")
            subprocess.run(['sudo', 'apt', 'install', package_name], check=True)
            print("Installation is complete.")
        else:
            print("Exiting script.")
            exit()
    else:
        print(f"{package_name} is already installed.")

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

def check_pwquality_conf():
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
def apply_pwquality_changes(minlen, minclass):
    lines = read_file('/etc/security/pwquality.conf')
    with open('/etc/security/pwquality.conf', 'w') as file:
        for line in lines:
            if 'minlen' in line:
                file.write(f"minlen = {minlen}\n")
            elif 'minclass' in line:
                file.write(f"minclass = {minclass}\n")
            else:
                file.write(line)

def check_and_prompt_pwquality():
    minlen, minclass = check_pwquality_conf()

    minlen_value = int(minlen.split('=')[1].strip()) if minlen else 0
    minclass_value = int(minclass.split('=')[1].strip()) if minclass else 0

    if minlen_value == 14 and minclass_value == 4:
        print("The current password length and complexity meet requirements. No changes are needed.")
    elif minlen_value < 14 or minclass_value < 4:
        print("===Warning: the current minimum length and password complexity do not meet requirements.===")
        response = input("Press Y to apply changes: ")
        if response.lower() == 'y':
            apply_pwquality_changes(14, 4)
            print("Updated pwquality.conf with minlen=14 and minclass=4.")
        else:
            print("No changes applied.")

#the changes are made in the /etc/pam.d/common-password file
def update_common_password_file():
    common_password_path = '/etc/pam.d/common-password'
    lines = read_file(common_password_path)
    pam_pwquality_line = "password requisite pam_pwquality.so retry=3\n"

    if any('pam_pwquality.so' in line for line in lines):
        print("Policies are up to date. No changes were made.")
    else:
        lines.append(pam_pwquality_line)
        write_file(common_password_path, lines)
        print("Policies were updated Sucessfully.")

def check_and_configure_faillock():
    common_auth_path = '/etc/pam.d/common-auth'
    lines = read_file(common_auth_path)

    if any('pam_faillock.so' in line for line in lines):
        print("Password lockouts are already configured.")
    else:
        print("Password Lockouts are currently not configured.")
        response = input("Would you like to configure password lockouts for your machine? Y/N: ")
        if response.lower() == 'y':
            configure_faillock(common_auth_path, lines)
            print("Password lockouts have been configured successfully.")
        else:
            print("Exiting the script..")
            exit()
#changes made in /etc/pam.d/common-auth
def configure_faillock(file_path, lines):
    faillock_line = "auth required pam_faillock.so preauth silent audit deny=5 unlock_time=900\n"
    lines.append(faillock_line) 
    write_file(file_path, lines)

def check_and_configure_pwhistory():
    common_password_path = '/etc/pam.d/common-password'
    lines = read_file(common_password_path)
    pwhistory_line = "password required pam_pwhistory.so remember=5\n"

    if pwhistory_line.strip() in [line.strip() for line in lines]:
        print("Password Reuse Limit is already configured.")
    else:
        print("Password Reuse Limit is not configured.")
        response = input("Would you like to configure it? Y/N: ")
        if response.lower() == 'y':
            configure_pwhistory(common_password_path, lines, pwhistory_line)
            print("Password Reuse limit is configured to refuse the past 5 passwords.")
        else:
            print("Exiting Script..")
            exit()

def configure_pwhistory(file_path, lines, pwhistory_line):
    insert_position = 25
    if len(lines) >= insert_position:
        lines.insert(insert_position, pwhistory_line + "\n")  
    write_file(file_path, lines)

def main():
    print("\n***// Checking Password Requirements //***")
    check_and_prompt_pwquality()

    print("\n***// Checking & Updating Configuration File //***")
    update_common_password_file()

    print("\n*** // Configuring Password Lockout Policy //***")
    check_and_configure_faillock()

    print("\n***// Configuring Password Reuse Limit //***")
    check_and_configure_pwhistory()

    print("\n***// Auditing For PAM has completed //*** ")

if __name__ == "__main__":
    main()
