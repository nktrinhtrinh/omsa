import os
import sys
import subprocess
import platform
import time
import hashlib
import datetime
import logging
import re
import argparse
import glob
import json
from utils import *
from OMSA import OMSA


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

def omsa_help():
    print(color_brown)
    print("\n    OMSA Usage:")
    print(color_reset)
    print("\t  python OMSA.py [options] {.apk file}")
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
    print("\t OMSA.py -p ./Downloads/android_app.apk")
    print("\t OMSA.py -p ./Downloads/android_app.apk -l")
    # print("\t OMSA.py -m /Downloads/android_apps/")
    # print("\t OMSA.py -m /Downloads/android_apps/ -l")
    print(color_brown)
    print("\n    Note:")
    print(color_reset)
    print("\t - Tested on Linux only!")
    print("\t - Keep tools such as JADX, dex2jar, grep, etc. installed")

def main():
    omsa_basic_req_checks()
    omsa_intro()

    # Function processing command
    if len(sys.argv[1:]) == 0 or sys.argv[1] == "-h":
        omsa_intro()
        omsa_help()
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
            print("\nStart the logging process...")
            enable_logging(apk_path)
        else:
            logging.basicConfig(level=logging.DEBUG, format='%(message)s')
        print("\n[+] APK path: ", apk_path)

        omsa = OMSA(apk_path)
        omsa.omsa_core()
    else:
        omsa_help()

if __name__ == "__main__":
    main()
