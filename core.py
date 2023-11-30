import hashlib
import json
import logging
import os
import re
import sys
import time

from utils import *

def no_color():
    global color_reset, color_red, color_red_bold, color_brown, color_blue, color_blue_bold, color_cyan, color_cyan_bold, color_purple
    color_reset = ''
    color_red = ''
    color_red_bold = ''
    color_brown = ''
    color_blue = ''
    color_blue_bold = ''
    color_cyan = ''
    color_cyan_bold = ''
    color_purple = ''

class OMSA:
    def __init__(self, apk_path, modules=[], color=True):
        apk_path = os.path.realpath(apk_path)
        self.apk_path = apk_path
        self.apk_pathbase = os.path.basename(apk_path)
        self.file_size = os.path.getsize(apk_path) / (1024 * 1024)
        self.apk_pathdir = os.path.dirname(apk_path) + "/"
        self.ext = os.path.splitext(self.apk_pathbase)[1]
        self.apk_name = os.path.splitext(self.apk_pathbase)[0]
        self.jadxpath = self.apk_pathdir + self.apk_name + "_SAST"

        self.modules = modules

        if not color:
            no_color()

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

        logging.info(f"\n[+] Start OMSA on APK path: {self.apk_path}")

        start_time = time.strftime("%Y-%m-%d %H:%M:%S")
        logging.info(color_purple)
        logging.info(f"[+] Scan has been started at: {start_time}")

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

        # Convert APK to Java JAR
        logging.info(color_reset + color_blue_bold)
        logging.info("\n[+] Start converting into jar file...")
        self.convert_apk_to_jar()

        # Decompile the application using JADX
        logging.info(color_blue_bold)
        logging.info("\n[+] Start decompiling the application...")
        self.decompile_jar()
        
        # Run OMSA modules
        for module in self.modules:
            self.omsa_run_module(module)

    
    def convert_apk_to_jar(self):
        dex2jarpath = self.apk_pathdir + self.apk_name + ".jar"
        # check of jar file exist
        if os.path.exists(dex2jarpath):
            # print jar file existed
            logging.info(color_cyan)
            logging.info(f"[+] Java JAR file existed at {dex2jarpath}! Skipping...{color_reset}")
            return
        # Convert APK to Java JAR
        cmd_dex2jar = f"d2j-dex2jar {self.apk_path} -f -o {dex2jarpath}"
        ouput = run_command(cmd_dex2jar, "[+] d2j-dex2jar has started converting APK to Java JAR file")
        logging.info(ouput)

    def decompile_jar(self):
        # check if self.jadxpath folder exist
        if os.path.exists(self.jadxpath):
            logging.info(color_cyan)
            logging.info(f"[+] The decompile folder existed at {self.jadxpath}! Skipping...{color_reset}")
            return
        cmd_jadx = f"jadx --deobf {self.apk_path} -d {self.jadxpath}"
        output = run_command(cmd_jadx, "[+] Jadx has started decompiling the application! This may takes a while...")
        logging.info(output)

    def omsa_run_module(self, module_name):
        module_path = f"modules/{module_name}.json"
        # exit if module not found
        if not os.path.exists(module_path):
            logging.error(f"{color_red_bold}\n[!] ERROR: Module '{module_name}' not found! Exiting...{color_reset}")
            sys.exit(0)
        with open(module_path, 'r') as module_file:
            module = json.load(module_file)
        logging.info(color_blue_bold)
        logging.info(f"\n[+] Start running module {module['name']}: {module['description']}")

        for item in module['data']:
            target_file = item['target_file']
            for rule in item['rules']:
                args = rule['args']
                # Parse keyword
                keyword = rule['keyword']
                if isinstance(keyword, str):
                    keyword_string = f" -e '{keyword}'"
                else:
                    keyword_string = ' '.join(f" -e '{key}'" for key in keyword)
                description = "[+] " + rule['description']
                command = f"grep -r --include={target_file} {args} {keyword_string} {self.jadxpath}"
                cmd_out = run_command(command, description)
                # Print the ouput
                out_dict = grep_output_to_dict(cmd_out)
                for path, lines in out_dict.items():
                    if not module_name == "manifest_info":
                        logging.info(color_cyan_bold)
                        logging.info(path)
                        logging.info(color_reset)
                    for line in lines :
                        
                        logging.info(line)
                # Print quicknote
                if len(cmd_out) > 0 :
                    try: 
                        note = rule['note']
                        if note != "":
                            logging.info(color_brown)
                            logging.info(f"=> QuickNote: {note}")
                        
                        reference = rule['reference']
                        if reference != "":
                            logging.info(color_purple)
                            logging.info(f"Reference: {reference}\n")
                    except:
                        pass
                else:
                    logging.info(f"{color_red}No match instances!")