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
#   - Modules Template: 
#       + If possible, use Type in which has a hardcoded argument in module templates.
#       + Decide if reference should be whithin the note for separated
#   - Idea: Run manifest info before running any module only so we won't need to check if the module is manifest_info

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
        print("\n[+] It is recommended to execute OMSA on Kali Linux.")
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
    parser.add_argument("-m", "--module", type=str, help="Specify module(s) to run. Syntax: module_1,module_2,...")
    parser.add_argument("--no-color", action="store_true", help="Disable color output.")
    parser.add_argument("-l", "--log", action="store_true", help="Enable logging to ./log folder. Default to --no-color.")
    
    # Function processing command
    if len(sys.argv[1:]) == 0:
        omsa_intro()
        parser.print_help(sys.stderr)
        sys.exit(1)

    args = parser.parse_args()

    if args.path and args.folder:
        print("\n[!] Kindly provide either a single APK file path or a folder path. \n[!] Exiting...")
        sys.exit(0)

    enable_color = True
    if args.no_color:
        enable_color = no_color()

    # Default modules
    modules = [
        "manifest_info",
        "manifest_exported",
        "storage1",
        "storage2",
        "crypto1",
        "crypto2",
        "auth2",
        "network1",
        "network2",
        "platform1",
        "platform2",
        "platform3",
        "code2",
        "code4",
        "resilience1",
        "resilience2",
        "resilience3",
        "resilience4"

    ]

    if args.module:
        modules = [module.strip() for module in args.module.split(',')]
    
    if args.path:
        apk_path = args.path
        if not os.path.exists(apk_path):
            print(f"\n[!] Given file-path '{apk_path}' does not exist. \n[!] Kindly verify the path/filename! \n[!] Exiting...")
            sys.exit(0)
        # Enable logging
        if args.log:
            print("\n[+] Start the logging process...")
            enable_logging(apk_path)
        else:
            logging.basicConfig(level=logging.DEBUG, format='%(message)s')
        
        omsa = OMSA(apk_path, modules=modules, color=enable_color)
        omsa.omsa_core()

    elif args.folder:
        folder_path = args.folder
        if not os.path.exists(folder_path):
            print(f"\n[!] Given path '{folder_path}' does not exist. \n[!] Kindly verify the path! \n[!] Exiting...")
            sys.exit(0)

        # Get apk paths from folder
        apk_paths = get_apk_paths(folder_path)

        # print discovered path in format item1, item2
        print(color_cyan)
        print(f"[+] Discovered {len(apk_paths)} APK paths:")
        for path in apk_paths:
            print(f"   [-] {path}")
        print(color_reset)

        for path in apk_paths:
            print(color_reset + color_purple)
            print(f"[+] Start OMSA on APK path: {path}\n-------------------------------------------------------------------------------------")
            # Enable logging
            if args.log:
                print("\n[+] Start the logging process...")
                enable_logging(path)
            else:
                logging.basicConfig(level=logging.DEBUG, format='%(message)s')

            omsa = OMSA(path, modules=modules, color=enable_color)
            omsa.omsa_core()

if __name__ == "__main__":
    main()