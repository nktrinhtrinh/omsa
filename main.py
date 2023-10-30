import os
import sys
import subprocess
import platform
import time
import hashlib
import datetime
import logging
import pathlib
import re
import argparse
import glob
# from masvs1 import sqlite_data, firebase_data

color_reset = '\033[0m'
color_red = "\033[31m"
color_red_bold = "\033[1;31m"
color_brown = "\033[33m"
color_blue = "\033[34m"
color_blue_bold = "\033[1;34m"
color_cyan = "\033[36m"
color_cyan_bold = "\033[1;36m"
color_purple = "\033[1;35m"


def apk_search_intro_func():
    print(color_red_bold)
    print(
        '''
         _    ____  _  ______                      _      
        / \  |  _ \| |/ / ___|  ___  __ _ _ __ ___| |__   
       / _ \ | |_) | ' /\___ \ / _ \/ _` | '__/ __| '_ \  
      / ___ \|  __/| . \ ___) |  __| (_| | | | (__| | | | 
     /_/   \_|_|   |_|\_|____/ \___|\__,_|_|  \___|_| |_| 
                                                                                           
    -----------------------------------------------------
    OWASP MASVS v.2 Static Analyzer for Android Application                               
    '''
    )
    print(color_reset)
    # print("[+] APKSearch - a comprehensive static code analysis tool for Android apps")
    print("[+] Based on: OWASP MASVS v2.0.0 - https://mas.owasp.org/MASVS/")
    print("[+] Author: trinhnk17 && vutq13")
    # print("[*] Connect: Please do write to us for any suggestions/feedback.")


def apk_search_basic_req_checks():
    # OS type check
    if platform.system() != "Linux":
        apk_search_intro_func()
        print("\n[+] Checking if APKSearch is being executed on Linux OS or not...")
        print("[!] Linux OS has not been identified! \n[!] Exiting...")
        print("\n[+] It is recommended to execute APKsearch on Kali Linux OS.")
        sys.exit(0)

    # Grep/jadx/dex2jar filepath check
    required_utilities = ["grep", "jadx", "d2j-dex2jar"]
    for utility in required_utilities:
        try:
            subprocess.check_output(["which", utility])
        except subprocess.CalledProcessError:
            apk_search_intro_func()
            if utility == "grep":
                print("\n[!] grep utility has not been observed. \n[!] Kindly install it first! \n[!] Exiting...")
            elif utility == "jadx":
                print("\n[!] JADX decompiler has not been observed. \n[!] Kindly install it first! \n[!] Exiting...")
            elif utility == "d2j-dex2jar":
                print("\n[!] dex2jar has not been observed. \n[!] Kindly install it first! \n[!] Exiting...")
            sys.exit(0)


def apk_search_help():
    print(color_brown)
    print("\n    APKSearch Usage:")
    print(color_reset)
    print("\t  python APKSearch.py [options] {.apk file}")
    print(color_brown)
    print("\n    Options:")
    print(color_reset)
    print("\t -h     For help")
    print("\t -p     Provide a single APK file path")
    # print("\t -m     Provide the folder path for multiple APK scanning")
    print("\t -l     For logging (.txt file)")
    print(color_brown)
    print("\n    Examples:")
    print(color_reset)
    print("\t APKsearch.py -p /Downloads/android_app.apk")
    print("\t APKsearch.py -p /Downloads/android_app.apk -l")
    # print("\t APKsearch.py -m /Downloads/android_apps/")
    # print("\t APKsearch.py -m /Downloads/android_apps/ -l")
    print(color_brown)
    print("\n    Note:")
    print(color_reset)
    print("\t - Tested on Linux only!")
    print("\t - Keep tools such as JADX, dex2jar, Python, grep, etc. installed")


def main():
    # APKsearch basic requirement checks
    apk_search_basic_req_checks()

    # Function processing command
    if len(sys.argv[1:]) == 0 or sys.argv[1] == "-h":
        apk_search_intro_func()
        apk_search_help()
        sys.exit(0)

    parser = argparse.ArgumentParser()
    parser.add_argument("-p", "--path", action="store_true")
    # parser.add_argument("-f", "--folder", action="store_true")
    parser.add_argument("-l", "--log", action="store_true")
    parser.add_argument("source", help="Source file path") 

    args = parser.parse_args()
    apk_path = args.source
    if args.path:
        if not os.path.exists(apk_path):
            print("\n[!] Given file-path '{}' does not exist. \n[!] Kindly verify the path/filename! \n[!] Exiting...".format(apk_path))
            sys.exit(0)
        if args.log:
            print("\nStart to logging the process...")
            apk_search_core_log(apk_path)
        else:
            logging.basicConfig(level=logging.DEBUG, format='%(message)s')
        print("APK path: ", apk_path)
        apk_search_core(apk_path)
    # elif args.folder:
    #     if not os.path.exists(apk_path):
    #         print("\n[!] Given file-path '{}' does not exist. \n[!] Kindly verify the path/filename! \n[!] Exiting...".format(apk_path))
    #         sys.exit(0)

    #     apk_files = []
    #     count_apk = 0

    #     for root, dirs, files in os.walk(apk_path):
    #         for file in files:
    #             if file.endswith(".apk"):
    #                 apk_files.append(os.path.join(root, file))
    #                 count_apk += 1

    #     print(color_brown)
    #     print("\n==>> Total number of APK files: {} \n\n".format(count_apk))
    #     print(color_reset)
    #     if count_apk == 0:
    #         print("[!] No APK files found in the given directory. \n[!] Kindly verify the path/directory! \n[!] Exiting...")
    #         sys.exit(0)

    #     print(color_brown)
    #     print("==>> List of the APK files:")
    #     print(color_reset)
    #     count_apk_files = 0
    #     for apk_file in apk_files:
    #         count_apk_files += 1
    #         print("    ", count_apk_files, os.path.basename(apk_file))


# Logging function
def apk_search_core_log(apk_path):
    the_time = datetime.datetime.now()
    time_year = str(the_time.year)
    time_month = the_time.month
    time_day = the_time.day
    time_hour = the_time.hour
    time_minute = the_time.minute
    time_second = the_time.second
    ctime = f"{time_year}-{time_month:02d}-{time_day:02d}_{time_hour:02d}-{time_minute:02d}-{time_second:02d}"
    apk_file_name = pathlib.Path(apk_path).stem
    log_file_path = os.path.join(os.path.dirname(apk_path), f"APKsearch_{apk_file_name}_{ctime}.txt")

    logging.basicConfig(filename=log_file_path, level=logging.DEBUG, format='%(message)s')
    logging.getLogger().addHandler(logging.StreamHandler())

    logging.info("\n[+] Log-file path: %s", log_file_path)


def run_command(command, description):
    print(color_blue)
    logging.info(f"{description}")
    try:
        result = subprocess.run(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
        print(color_reset)
        logging.info(f"{result.stdout}")
        if result.returncode != 0:
            print(color_red)
            logging.info(f"{result.stderr}")
    except subprocess.CalledProcessError as e:
        print(color_red)
        logging.info(f"Error: {e}")


def manifest_command(command, keyword, description):
    print(color_blue)
    logging.info(f"{description}")
    try:
        grep_factor = ["grep", command, keyword, and_manifest_path]
        grep_command = ' '.join(grep_factor)
        print(grep_command)
        result = subprocess.run(grep_command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
        print(color_reset)
        logging.info(f"{result.stdout}")
        if result.returncode != 0:
            print(color_red)
            logging.info(f"{result.stderr}")
    except subprocess.CalledProcessError as e:
        print(color_red)
        logging.info(f"Error: {e}")

def apk_search_core(apk_path):

    start_time = time.strftime("%Y-%m-%d %H:%M:%S")
    logging.info(f"\n[+] Scan has been started at: {start_time}")

    # APK filepath analysis
    apk_pathbase = os.path.basename(apk_path)
    logging.info(f"[+] APK Base: {apk_pathbase}")

    file_size = os.path.getsize(apk_path)
    megabytes = file_size / (1024 * 1024)
    logging.info(f"[+] APK Size: {megabytes:.2f} MB")

    apk_pathdir = os.path.dirname(apk_path) + "/"
    logging.info(f"[+] APK Directory: {apk_pathdir}")
    ext = os.path.splitext(apk_pathbase)[1]
    apkname = os.path.splitext(apk_pathbase)[0]

    is_alphanumeric = bool(re.match("^[a-zA-Z0-9_-]*$", apkname))
    if not is_alphanumeric:
        logging.error("[!] Only Alphanumeric string with/without underscore/dash is accepted as APK file-name. Request you to rename the APK file.")
        return

    apkoutpath = apk_pathdir + apkname
    dex2jarpath = apkoutpath + ".jar"
    jadxpath = apkoutpath + "_SAST/"
    logging.info(f"[+] APK Static Analysis Path: {jadxpath}")

    with open(apk_path, 'rb') as file:
        file_hash = hashlib.md5(file.read()).hexdigest()
        logging.info(f"[+] APK Hash: MD5: {file_hash}")
        file.seek(0)
        file_hash_sha256 = hashlib.sha256(file.read()).hexdigest()
        logging.info(f"[+] APK Hash: SHA256: {file_hash_sha256}")

    cmd_dex2jar = f"d2j-dex2jar {apk_path} -f -o {dex2jarpath}"
    run_command(cmd_dex2jar, "[+] d2j-dex2jar has started converting APK to Java JAR file")

    # Decompile the application using JADX
    cmd_jadx = f"jadx --deobf {apk_path} -d {jadxpath}"
    run_command(cmd_jadx, "[+] Jadx has started decompiling the application")

    global and_manifest_path
    and_manifest_path = f"{jadxpath}resources/AndroidManifest.xml"
    print(color_blue)
    logging.info("[+] Capturing the data from the AndroidManifest file")

    # AndroidManifest file - Package name
    # cmd_and_pkg_nm = f'grep -i "package" "{and_manifest_path}"'
    # run_command2(cmd_and_pkg_nm, "Package Name")
    manifest_command("-i", "package", "Package Name")

    # AndroidManifest file - Package version number
    # cmd_and_pkg_ver = f'grep -i "versionName" "{and_manifest_path}"'
    # run_command2(cmd_and_pkg_ver, "Version Name")
    manifest_command("-i", "versionName", "Version Name")

    # # AndroidManifest file - minSdkVersion
    # cmd_and_pkg_minSdkVersion = f'grep -i "minSdkVersion" "{and_manifest_path}"'
    # run_command2(cmd_and_pkg_minSdkVersion, "minSdkVersion")
    manifest_command("-i", "minSdkVersion", "minSdkVersion")

    # # AndroidManifest file - targetSdkVersion
    # cmd_targetSdkVersion = f'grep -i "targetSdkVersion" "{and_manifest_path}"'
    # run_command2(cmd_targetSdkVersion, "android:targetSdkVersion")
    manifest_command("-i", "targetSdkVersion", "android:targetSdkVersion")

    # # AndroidManifest file - android:networkSecurityConfig
    # cmd_nwSecConf = f'grep -i "android:networkSecurityConfig=" "{and_manifest_path}"'
    # run_command2(cmd_nwSecConf, "android:networkSecurityConfig attribute")
    manifest_command("-i", "android:networkSecurityConfig=", "android:networkSecurityConfig attribute")

    # # AndroidManifest file - Activities
    print(color_blue)
    logging.info("The Activities...")
    # cmd_actv = f'grep -ne "<activity" "{and_manifest_path}"'
    # run_command2(cmd_actv, "Activities")
    manifest_command("-ne", "'<activity'", "Activities")

    # # AndroidManifest file - Exported Activities
    exp_actv = f'grep -ne "<activity" "{and_manifest_path}" | grep -e "android:exported="true""'
    run_command(exp_actv, "Exported Activities")


    # # AndroidManifest file - Content Providers
    print(color_blue)
    logging.info("[+] The Content Providers...")
    # cmd_cont = f'grep -ne "<provider" "{and_manifest_path}"'
    # run_command2(cmd_cont, "Content Providers")
    manifest_command("-ne", "'<provider'", "Content Providers")

    # # AndroidManifest file - Exported Content Providers
    exp_cont = f'grep -ne "<provider" "{and_manifest_path}" | grep -e "android:exported="true""'
    run_command(exp_cont, "Exported Content Providers")

    # # AndroidManifest file - Broadcast Receivers
    print(color_blue)
    logging.info("[+] The Broadcast Receivers...")
    # cmd_brod = f'grep -ne "<receiver" "{and_manifest_path}"'
    # run_command2(cmd_brod, "Broadcast Receivers")
    manifest_command("-ne", "'<receiver'", "Broadcast Receivers")

    # # AndroidManifest file - Exported Broadcast Receivers
    exp_brod = f'grep -ne "<receiver" "{and_manifest_path}" | grep -e "android:exported="true""'
    run_command(exp_brod, "Exported Broadcast Receivers")

    # # AndroidManifest file - Services
    print(color_blue)
    logging.info("[+] The Services...")
    # cmd_serv = f'grep -ne "<service" "{and_manifest_path}"'
    # run_command2(cmd_serv, "Services")
    manifest_command("-ne", "package", "Services")

    # # AndroidManifest file - Exported Services
    exp_serv = f'grep -ne "<service" "{and_manifest_path}" | grep -e "android:exported="true""'
    run_command(exp_serv, "Exported Services")

    # # AndroidManifest file - Intent Filters
    print(color_blue)
    logging.info("[+] The Intent Filters...")
    # cmd_intentFilters = f'grep -ne "android.intent." "{and_manifest_path}"'
    # run_command2(cmd_intentFilters, "Intent Filters")
    manifest_command("-ne", "android.intent.", "Intent Filters")
    print(color_reset)
    logging.info("[+] QuickNote: It is recommended to use Intent Filters securely, if observed.")

    # APK Component Summary

    #SAST - Recursive file reading
    # global java_files
    # java_files = glob.glob(os.path.join(jadxpath, "sources", "**", "*.java"), recursive=True)
    # xml_files = glob.glob(os.path.join(jadxpath, "resources", "**", "*.xml"), recursive=True)
    # print(color_blue)
    # logging.info("[+] Let's start the static assessment based on 'OWASP MASVS v2'")

    # search_and_log("openOrCreateDatabase|getWritableDatabase|getReadableDatabase", ".java", "The SQLite Database Storage related instances...", """
    #     - It is recommended that sensitive data should not be stored in unencrypted SQLite databases, if observed. Please note that, SQLite databases should be password-encrypted.
    #     - OWASP MASVS: MSTG-STORAGE-2 | CWE-922: Insecure Storage of Sensitive Information
    #     - https://mobile-security.gitbook.io/masvs/security-requirements/0x07-v2-data_storage_and_privacy_requirements
    # """)
    # search_and_log(**firebase_data)
    
    # MASVS V2 - MSTG-STORAGE-2 - SQLite Database
    # print(color_blue)
    # logging.info("[+] The SQLite Database Storage related instances...\n")
    # countSqliteDb = 0
    # for sources_file in java_files:
    #     if sources_file.endswith(".java"):
    #         cmd = f'grep -nr -e "openOrCreateDatabase" -e "getWritableDatabase" -e "getReadableDatabase" "{sources_file}"'
    #         result = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
    #         if any(keyword in result.stdout for keyword in ["openOrCreateDatabase", "getWritableDatabase", "getReadableDatabase"]):
    #             print(color_reset)
    #             logging.info(f"{sources_file}")
    #             logging.info(result.stdout)
    #             countSqliteDb += 1
    # if countSqliteDb > 0:
    #     print(color_brown)
    #     logging.info("[!] QuickNote:\n")
    #     logging.info("    - It is recommended that sensitive data should not be stored in unencrypted SQLite databases, if observed. Please note that, SQLite databases should be password-encrypted.")
    #     logging.info("[*] Reference:\n")
    #     logging.info("    - OWASP MASVS: MSTG-STORAGE-2 | CWE-922: Insecure Storage of Sensitive Information")
    #     logging.info("    - https://mobile-security.gitbook.io/masvs/security-requirements/0x07-v2-data_storage_and_privacy_requirements")

    # MASVS V2 - MSTG-STORAGE-2 - Firebase Database
    # print(color_blue)
    # print("[+] The Firebase Database instances...\n")
    # countFireDB = 0
    # for sources_file in xml_files:
    #     if sources_file.endswith(".xml"):
    #         cmd = f'grep -nr -F ".firebaseio.com" "{sources_file}"'
    #         result = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
    #         if "firebaseio" in result.stdout:
    #             print(f"\033[0;33m{sources_file}\033[0m")
    #             print(result.stdout)
    #             countFireDB += 1
    # if countFireDB > 0:
    #     print("\033[0;36m[!] QuickNote:")
    #     print("\033[0m")
    #     print("    - It is recommended that Firebase Realtime database instances should not be misconfigured, if observed. Please note that, An attacker can read the content of the database without any authentication, if rules are set to allow open access or access is not restricted to specific users for specific data sets.")
    #     print("\033[0;36m[*] Reference:")
    #     print("\033[0m")
    #     print("    - OWASP MASVS: MSTG-STORAGE-2 | CWE-200: Exposure of Sensitive Information to an Unauthorized Actor")
    #     print("    - https://mobile-security.gitbook.io/masvs/security-requirements/0x07-v2-data_storage_and_privacy_requirements")





if __name__ == "__main__":
    main()

