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
import json

color_reset = '\033[0m'
color_red = "\033[31m"
color_red_bold = "\033[1;31m"
color_brown = "\033[33m"
color_blue = "\033[34m"
color_blue_bold = "\033[1;34m"
color_cyan = "\033[36m"
color_cyan_bold = "\033[1;36m"
color_purple = "\033[1;35m"

# global res_manifest

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
    print("[+] Based on: OWASP MASVS v2.0.0 - https://mas.owasp.org/MASVS/")
    print("[+] Author: trinhnk17 && vutq13")


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
    print("\t OMSA.py -p /Downloads/android_app.apk")
    print("\t OMSA.py -p /Downloads/android_app.apk -l")
    # print("\t OMSA.py -m /Downloads/android_apps/")
    # print("\t OMSA.py -m /Downloads/android_apps/ -l")
    print(color_brown)
    print("\n    Note:")
    print(color_reset)
    print("\t - Tested on Linux only!")
    print("\t - Keep tools such as JADX, dex2jar, Python, grep, etc. installed")

def main():
    # OMSA basic requirement checks
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
            print("\nStart to logging the process...")
            omsa_core_log(apk_path)
        else:
            logging.basicConfig(level=logging.DEBUG, format='%(message)s')
        print("\n[+] APK path: ", apk_path)
        omsa_core(apk_path)
    elif args.folder:
        if not os.path.exists(apk_path):
            print("\n[!] Given file-path '{}' does not exist. \n[!] Kindly verify the path/filename! \n[!] Exiting...".format(apk_path))
            sys.exit(0)

        apk_files = []
        count_apk = 0

        for root, dirs, files in os.walk(apk_path):
            for file in files:
                if file.endswith(".apk"):
                    apk_files.append(os.path.join(root, file))
                    count_apk += 1

        print(color_brown)
        print("\n==>> Total number of APK files: {} \n\n".format(count_apk))
        print(color_reset)
        if count_apk == 0:
            print("[!] No APK files found in the given directory. \n[!] Kindly verify the path/directory! \n[!] Exiting...")
            sys.exit(0)

        print(color_brown)
        print("==>> List of the APK files:")
        print(color_reset)
        count_apk_files = 0
        for apk_file in apk_files:
            count_apk_files += 1
            print("    ", count_apk_files, os.path.basename(apk_file))

def omsa_core_log(apk_path):
    the_time = datetime.datetime.now()
    time_year = str(the_time.year)
    time_month = the_time.month
    time_day = the_time.day
    time_hour = the_time.hour
    time_minute = the_time.minute
    time_second = the_time.second
    ctime = f"{time_year}-{time_month:02d}-{time_day:02d}_{time_hour:02d}-{time_minute:02d}-{time_second:02d}"
    apk_file_name = pathlib.Path(apk_path).stem
    log_file_path = os.path.join(os.path.dirname(apk_path), f"OMSA_{apk_file_name}_{ctime}.txt")

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

def manifest_command(command, keyword, description, note):
    print(color_blue)
    logging.info(f"[+] {description}")
    try:
        grep_factor = ["grep", command, keyword, and_manifest_path]
        grep_command = ' '.join(grep_factor)
        result = subprocess.run(grep_command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
        print(color_reset)
        logging.info(f"{result.stdout}")
        if result.returncode != 0:
            print(color_red)
            logging.info(f"{result.stderr}")
    except subprocess.CalledProcessError as e:
        print(color_red)
        logging.info(f"Error: {e}")
    if note != "":
        print(color_brown)
        logging.info(f"----> QuickNote: {note}\n")

def manifest_exported_command(command1, keyword1, command2, keyword2, description, note):
    print(color_blue)
    logging.info(f"[+] {description}")
    try:
        grep_factor = ["grep", command1, keyword1, and_manifest_path, "|", "grep", command2, keyword2]
        grep_command = ' '.join(grep_factor)
        result = subprocess.run(grep_command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
        print(color_reset)
        logging.info(f"{result.stdout}")
        stdout_lines = result.stdout.split('\n')
        line_count = len([line for line in stdout_lines if line.strip()])
        if result.returncode != 0:
            print(color_red)
            logging.info(f"{result.stderr}")
    except subprocess.CalledProcessError as e:
        print(color_red)
        logging.info(f"Error: {e}")
    if line_count > 0:
        print(color_brown)
        # res_manifest[{description}] = {line_count}
        logging.info(f"----> Total {description} are: {line_count}\n")
        logging.info(f"----> QuickNote: {note}\n")


def masvs_java_command(description, patterns, filters, command, note, reference):
    print(color_blue)
    logging.info(f"==> {description}")
    count = 0
    for sources_file in java_files:
        if sources_file.endswith(".java"):
            if isinstance(patterns, list) and "-e" in command:
                combined_pattern = " -e ".join(patterns)
            else: combined_pattern = patterns

            if filters != '' and isinstance(filters, list):
                    keywords = [s.strip("'") for s in filters]
            elif filters == '':
                if isinstance(patterns, list):
                    keywords = [s.strip("'") for s in patterns]
                else: keywords = patterns.replace("'", '')

            
            grep_factor = ["grep", command, combined_pattern, sources_file]
            grep_command = ' '.join(grep_factor)
            # print(grep_command)
            result = subprocess.run(grep_command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
            
            if isinstance(keywords, list) and any(keyword in result.stdout for keyword in keywords):
                print(color_brown)
                logging.info(f"{sources_file}")
                print(color_reset)
                logging.info(result.stdout)
                count += 1
            elif isinstance(keywords, str) and keywords in result.stdout:
                print(color_brown)
                logging.info(f"{sources_file}")
                print(color_reset)
                logging.info(result.stdout)
                count += 1
        
    if count > 0:
        print(color_brown)
        logging.info(f"[!] QuickNote: {note}")
        logging.info(f"\n[*] Reference: {reference}")

def masvs_xml_command(description, patterns, command, note, reference):
    print(color_blue)
    logging.info(f"\n==> {description}\n")
    count = 0
    for sources_file in xml_files:
        if sources_file.endswith(".xml"):
            if isinstance(patterns, list) and "-e" in command:
                combined_pattern = " -e ".join(patterns)
                keywords = [s.strip("'") for s in patterns]
            else:
                combined_pattern = patterns
                keywords = patterns.replace("'", '')

            grep_factor = ["grep", command, combined_pattern, sources_file]
            grep_command = ' '.join(grep_factor)
            # print(grep_command)
            result = subprocess.run(grep_command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
            
            if isinstance(keywords, list) and any(keyword in result.stdout for keyword in keywords):
                print(color_brown)
                logging.info(f"{sources_file}")
                print(color_reset)
                logging.info(result.stdout)
                count += 1
            elif isinstance(keywords, str) and keywords in result.stdout:
                print(color_brown)
                logging.info(f"{sources_file}")
                print(color_reset)
                logging.info(result.stdout)
                count += 1
        
    if count > 0:
        print(color_brown)
        logging.info(f"[!] QuickNote: {note}")
        logging.info(f"\n[*] Reference: {reference}")

def omsa_core(apk_path):

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

    with open('manifest.json', 'r') as json_file:
        data = json.load(json_file)
    for item in data:
        manifest_command(item['command'], item['keyword'], item['description'], item['note'])


    with open('manifest_exported.json', 'r') as json_file:
        data = json.load(json_file)
    for item in data:
        manifest_exported_command(item['command1'], item['keyword1'], item['command2'], item['keyword2'], item['description'], item['note'])

    # APK Component Summary
    # print(res_manifest)

    # SAST - Recursive file reading
    global java_files, xml_files
    java_files = glob.glob(os.path.join(jadxpath, "sources", "**", "*.java"), recursive=True)
    xml_files = glob.glob(os.path.join(jadxpath, "resources", "**", "*.xml"), recursive=True)
    print(color_blue)
    logging.info("[+] Let's start the static assessment based on 'OWASP MASVS v2'")
    
    # MASVS V2 - MSTG-STORAGE
    print(color_blue_bold)
    logging.info("[+] MASVS V2.0.0 - MSTG-STORAGE")
    print(color_cyan_bold)
    logging.info("[+] MSTG-STORAGE-1: The app securely stores sensitive data.")
    print(color_reset)
    with open('storage1_java.json', 'r') as json_file:
        data = json.load(json_file)
    for item in data:
        masvs_java_command(item['description'], item['patterns'], item['filters'], item['command'], item['note'], item['reference'])
    with open('storage1_xml.json', 'r') as json_file:
        data = json.load(json_file)
    masvs_xml_command(data['description'], data['patterns'], data['command'], data['note'], data['reference'])
    
    print(color_cyan_bold)
    logging.info("\n[+] MSTG-STORAGE-2: The app prevents leakage of sensitive data.")
    print(color_reset)
    with open('storage2_java.json', 'r') as json_file:
        data = json.load(json_file)
    for item in data:
        masvs_java_command(item['description'], item['patterns'], item['filters'], item['command'], item['note'], item['reference'])
    with open('storage2_xml.json', 'r') as json_file:
        data = json.load(json_file)
    masvs_xml_command(data['description'], data['patterns'], data['command'], data['note'], data['reference'])

    #MASVS V2 - MSTG-CRYPTO
    print(color_blue_bold)
    logging.info("[+] MASVS V2.0.0 - MSTG-CRYPTO")
    print(color_cyan_bold)
    logging.info("[+] MSTG-CRYPTO-1: The app employs current strong cryptography and uses it according to industry best practices.")
    print(color_reset)
    with open('crypto1_java.json', 'r') as json_file:
        data = json.load(json_file)
    for item in data:
        masvs_java_command(item['description'], item['patterns'], item['filters'], item['command'], item['note'], item['reference'])






if __name__ == "__main__":
    main()
