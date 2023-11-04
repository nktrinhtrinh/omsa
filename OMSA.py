import hashlib
import json
import logging
import os
import re
import sys
import time

from utils import *

list_modules = [

]

class OMSA:
    def __init__(self, apk_path):
        self.apk_path = apk_path
        self.apk_pathbase = os.path.basename(apk_path)
        self.file_size = os.path.getsize(apk_path) / (1024 * 1024)
        self.apk_pathdir = os.path.dirname(apk_path) + "/"
        self.ext = os.path.splitext(self.apk_pathbase)[1]
        self.apk_name = os.path.splitext(self.apk_pathbase)[0]
        self.jadxpath = self.apk_pathdir + self.apk_name + "_SAST"

    def validate_apk_path(self):
        if not self.ext == ".apk":
            logging.error("\n[!] Given file-path '{}' is not an APK file. \n[!] Kindly verify the path/filename! \n[!] Exiting...".format(self.apk_path))
            return False

        if not bool(re.match("^[a-zA-Z0-9_-]*$", self.apk_name)):
            print(self.apk_name)
            logging.error("[!] Only Alphanumeric string with/without underscore/dash is accepted as APK file-name. Request you to rename the APK file.")
            return False

        if not os.path.exists(self.apk_path):
            logging.error("\n[!] Given file-path '{}' does not exist. \n[!] Kindly verify the path/filename! \n[!] Exiting...".format(self.apk_path))
            return False

        return True

    def omsa_core(self):

        if not self.validate_apk_path():
            sys.exit(0)

        start_time = time.strftime("%Y-%m-%d %H:%M:%S")
        logging.info(f"\n[+] Scan has been started at: {start_time}")

        # APK filepath analysis
        logging.info(f"[+] APK Base: {self.apk_pathbase}")
        logging.info(f"[+] APK Size: {self.file_size:.2f} MB")
        logging.info(f"[+] APK Directory: {self.apk_pathdir}")

        logging.info(f"[+] APK Static Analysis Path: {self.jadxpath}")

        with open(self.apk_path, 'rb') as file:
            file_hash_md5 = hashlib.md5(file.read()).hexdigest()
            logging.info(f"[+] APK Hash (MD5): {file_hash_md5}")
            file.seek(0)
            file_hash_sha256 = hashlib.sha256(file.read()).hexdigest()
            logging.info(f"[+] APK Hash (SHA256): {file_hash_sha256}")

        dex2jarpath = self.apk_pathdir + self.apk_name + ".jar"

        # Convert APK to Java JAR
        # cmd_dex2jar = f"d2j-dex2jar {self.apk_path} -f -o {dex2jarpath}"
        # out = run_command(cmd_dex2jar, "[+] d2j-dex2jar has started converting APK to Java JAR file")
        # logging.info(out)

        # # Decompile the application using JADX
        # cmd_jadx = f"jadx --deobf {self.apk_path} -d {self.jadxpath}"
        # out = run_command(cmd_jadx, "[+] Jadx has started decompiling the application")
        # logging.info(out)

        self.omsa_run_module("manifest_info")

    
    def get_info_from_manifest(self, jadxpath):
        manifest_path = f"{jadxpath}/resources/AndroidManifest.xml"
        print(color_blue)
        logging.info("[+] Capturing the data from the AndroidManifest file")
        with open('manifest.json', 'r') as json_file:
            data = json.load(json_file)
        for item in data:
            args = item['args']
            keyword = item['keyword']
            description = item['description']
            note = item['note']
            logging.info(f"[+] {description}")
            try:
                result = subprocess.run(f"grep {args} {keyword} {manifest_path}", shell=True, universal_newlines=True, capture_output=True)
                if result.returncode != 0 or result.stderr:
                    print(color_red)
                    logging.info(f"{result.stderr}")
                    sys.exit(0)
            except subprocess.CalledProcessError as e:
                print(color_red)
                logging.info(f"Error: {e}")

    def omsa_run_module(self, module_name):
        module_path = f"modules/{module_name}.json"
        with open(module_path, 'r') as module_file:
            module = json.load(module_file)
        print(color_blue)
        logging.info(f"[+] {module['name']}: {module['description']}")
        print(color_reset)

        module_target_file = self.jadxpath + '/' + module['target_file']
        module_data = module['data']

        for item in module_data:
            args = item['args']
            keyword = item['keyword']
            keywords = ' '.join(f" -e '{key}'" for key in keyword)
            description = "[+] " + item['description']
            note = item['note']
            command = f"grep {args} {keywords} {module_target_file}"
            run_command(command, description)
            if note != "":
                print(color_brown)
                logging.info(f"----> QuickNote: {note}\n")
        
        