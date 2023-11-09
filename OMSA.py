import os
import sys
import subprocess
import platform
import logging
import argparse
from utils import *
from core import OMSA


# TODO:
#   - Add more modules
#   - When running a modules, the core will process *.ext target_file
#   - Specify file name/path when output grep command
#   - Add -m option which can specify which module(s) can be run
#   - Add -f option which will run on multiple apk files in a folder
#   - Make change to the log file to improve UX


def omsa_intro():
    print(color_red_bold)
    print(
        '''
     _______    __   __    _______    _\___/_ 
    |       |  |  |_|  |  |       | _|_____  |
    |   _   |  |       |  |  _____| |_____|  |__
    |  | |  |  |       |  | |_____   |       |  |
    |  |_|  |  |       |  |_____  |  |       |  |
    |       |  | ||_|| |   _____| |  |   _   |__|
    |_______|  |_|   |_|  |_______|  |__| |__|
    --------------------------------------------------------
    OWASP MASVS v.2 Static Analyzer for Android Applications
    '''
    )
    print(color_reset)
    print("[+] Based on: OWASP MASVS v2.0.0 && MASTG v1.6.0 - https://mas.owasp.org/MASVS/")
    print("[+] Author: trinhnk17")
    #print("[+] Author: trinhnk17 && vutq13")
    print()


def omsa_basic_req_checks():
    # OS type check
    if platform.system() != "Linux":
        omsa_intro()
        print("\n[+] Checking if OMSA is being executed on Linux OS or not...")
        print("[!] Linux OS has not been identified! \n[!] Exiting...")
        print("\n[+] It is recommended to execute OMSA on Kali Linux OS.")
        sys.exit(0)

    # Grep/jadx/dex2jar filepath check
    required_utilities = ["grep", "jadx", "d2j-dex2jar"]
    for utility in required_utilities:
        try:
            subprocess.check_output(["which", utility])
        except subprocess.CalledProcessError:
            omsa_intro()
            if utility == "grep":
                print("\n[!] grep utility has not been observed. \n[!] Kindly install it first! \n[!] Exiting...")
            elif utility == "jadx":
                print("\n[!] JADX decompiler has not been observed. \n[!] Kindly install it first! \n[!] Exiting...")
            elif utility == "d2j-dex2jar":
                print("\n[!] dex2jar has not been observed. \n[!] Kindly install it first! \n[!] Exiting...")
            sys.exit(0)

def main():
    omsa_basic_req_checks()
    omsa_intro()

    parser = argparse.ArgumentParser(description="A static analyzer for Android applications using MASVS v2.", epilog="Note: Make sure you are running on Linux. Also, tools such as JADX, dex2jar and grep need to be installed")
    parser.add_argument("-p", "--path", type=str, help="Provide a single APK file path.")
    parser.add_argument("-f", "--folder", type=str, help="Provide a folder path for multiple APK scanning.")
    parser.add_argument("-l", "--log", action="store_true", help="Enable logging. Log file will be saved to ./log folder.")
    
    # Function processing command
    if len(sys.argv[1:]) == 0:
        omsa_intro()
        parser.print_help(sys.stderr)
        sys.exit(1)

    args = parser.parse_args()

    if args.path and args.folder:
        print("\n[!] Kindly provide either a single APK file path or a folder path. \n[!] Exiting...")
        sys.exit(0)

    if args.path:
        apk_path = args.path
        if not os.path.exists(apk_path):
            print("\n[!] Given file-path '{}' does not exist. \n[!] Kindly verify the path/filename! \n[!] Exiting...".format(apk_path))
            sys.exit(0)
        # Enable logging
        if args.log:
            print("\n[+] Start the logging process...")
            enable_logging(apk_path)
        else:
            logging.basicConfig(level=logging.DEBUG, format='%(message)s')
        
        logging.info(f"\n[+] Start OMSA on APK path: {apk_path}")

        omsa = OMSA(apk_path)
        omsa.omsa_core()
    elif args.folder:
        folder_path = args.folder
        if not os.path.exists(folder_path):
            print("\n[!] Given file-path '{}' does not exist. \n[!] Kindly verify the path/filename! \n[!] Exiting...".format(apk_path))
            sys.exit(0)
        # Enable logging
        # TODO: all apks will be logged into one file or into a folder with each log separately?
        if args.log:
            print("\n[+] Start the logging process...")
            enable_logging(folder_path)
        else:
            logging.basicConfig(level=logging.DEBUG, format='%(message)s')

        # Get apk paths from folder
        apk_paths = get_file_paths(folder_path, "*.apk")
        # print discovered path in format item1, item2
        print(color_cyan)
        logging.info(f"[+] Discovered {len(apk_paths)} APK paths:")
        for path in apk_paths:
            logging.info(f"   [-] {path}")
        print(color_reset)

        for path in apk_paths:
            print(color_reset + color_purple)
            logging.info(f"[+] Start OMSA on APK path: {path}\n-------------------------------------------------------------------------------------")
            omsa = OMSA(path)
            omsa.omsa_core()

if __name__ == "__main__":
    main()