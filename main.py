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


def run_command2(command, description):
    logging.info(f"\033[34m{description}\033[0m")
    try:
        result = subprocess.run(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
        logging.info(f"\033[34m{result.stdout}\033[0m")
        if result.returncode != 0:
            logging.info(f"\033[31m{result.stderr}\033[0m")
    except subprocess.CalledProcessError as e:
        logging.info(f"\033[31mError: {e}\033[0m")

#Buged ;v if doesnt use -l => no output
def apk_search_core(apk_path):
    def run_command(command):
        result = subprocess.run(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
        return result.stdout

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
    run_command2(cmd_dex2jar, "[+] d2j-dex2jar has started converting APK to Java JAR file")

    # Decompile the application using JADX
    cmd_jadx = f"jadx --deobf {apk_path} -d {jadxpath}"
    run_command2(cmd_jadx, "[+] Jadx has started decompiling the application")

    and_manifest_path = f"{jadxpath}resources/AndroidManifest.xml"
    logging.info("\033[34m[+] Capturing the data from the AndroidManifest file\033[0m")

    # AndroidManifest file - Package name
    cmd_and_pkg_nm = f'grep -i "package" "{and_manifest_path}"'
    run_command2(cmd_and_pkg_nm, "Package Name")

    # AndroidManifest file - Package version number
    cmd_and_pkg_ver = f'grep -i "versionName" "{and_manifest_path}"'
    run_command2(cmd_and_pkg_ver, "Version Name")

    # AndroidManifest file - minSdkVersion
    cmd_and_pkg_minSdkVersion = f'grep -i "minSdkVersion" "{and_manifest_path}"'
    run_command2(cmd_and_pkg_minSdkVersion, "minSdkVersion")

    # AndroidManifest file - targetSdkVersion
    cmd_targetSdkVersion = f'grep -i "targetSdkVersion" "{and_manifest_path}"'
    run_command2(cmd_targetSdkVersion, "android:targetSdkVersion")

    # AndroidManifest file - android:networkSecurityConfig
    cmd_nwSecConf = f'grep -i "android:networkSecurityConfig=" "{and_manifest_path}"'
    run_command2(cmd_nwSecConf, "android:networkSecurityConfig attribute")

    # AndroidManifest file - Activities
    logging.info("\033[34m[+] The Activities...\033[0m")
    cmd_actv = f'grep -ne "<activity" "{and_manifest_path}"'
    run_command2(cmd_actv, "Activities")

    # AndroidManifest file - Exported Activities
    exp_actv = f'grep -ne "<activity" "{and_manifest_path}" | grep -e "android:exported="true""'
    run_command2(exp_actv, "Exported Activities")

    # AndroidManifest file - Content Providers
    logging.info("\033[34m[+] The Content Providers...\033[0m")
    cmd_cont = f'grep -ne "<provider" "{and_manifest_path}"'
    run_command2(cmd_cont, "Content Providers")

    # AndroidManifest file - Exported Content Providers
    exp_cont = f'grep -ne "<provider" "{and_manifest_path}" | grep -e "android:exported="true""'
    run_command2(exp_cont, "Exported Content Providers")

    # AndroidManifest file - Broadcast Receivers
    logging.info("\033[34m[+] The Broadcast Receivers...\033[0m")
    cmd_brod = f'grep -ne "<receiver" "{and_manifest_path}"'
    run_command2(cmd_brod, "Broadcast Receivers")

    # AndroidManifest file - Exported Broadcast Receivers
    exp_brod = f'grep -ne "<receiver" "{and_manifest_path}" | grep -e "android:exported="true""'
    run_command2(exp_brod, "Exported Broadcast Receivers")

    # AndroidManifest file - Services
    logging.info("\033[34m[+] The Services...\033[0m")
    cmd_serv = f'grep -ne "<service" "{and_manifest_path}"'
    run_command2(cmd_serv, "Services")

    # AndroidManifest file - Exported Services
    exp_serv = f'grep -ne "<service" "{and_manifest_path}" | grep -e "android:exported="true""'
    run_command2(exp_serv, "Exported Services")

    # AndroidManifest file - Intent Filters
    logging.info("\033[34m[+] The Intent Filters...\033[0m")
    cmd_intentFilters = f'grep -ne "android.intent." "{and_manifest_path}"'
    run_command2(cmd_intentFilters, "Intent Filters")
    logging.info("[+] QuickNote: It is recommended to use Intent Filters securely, if observed.")



if __name__ == "__main__":
    main()

