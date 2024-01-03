import datetime
import os
import pathlib
import subprocess
import logging
import sys

color_reset = '\033[0m'
color_red = "\033[31m"
color_red_bold = "\033[1;31m"
color_brown = "\033[33m"
color_blue = "\033[34m"
color_blue_bold = "\033[1;34m"
color_cyan = "\033[36m"
color_cyan_bold = "\033[1;36m"
color_purple = "\033[1;35m"
color_green = "\033[32m"
color_green_bold = "\033[1;32m" 

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
    return False

def run_command(command, description):
    logging.info(color_reset + color_blue)
    logging.info(description)
    logging.info(color_reset)
    try:
        result = subprocess.run(command, shell=True, universal_newlines=True, capture_output=True)
        if result.stderr and "Exception" in result.stderr:
            print(color_red)
            logging.info(result.stderr)
            sys.exit(0)
        if len(result.stdout) > 0:
            return result.stdout
        return ''
    except subprocess.CalledProcessError as e:
        print(color_red)
        logging.info(f"Error: {e}")


# Run command function that return output in realtime
# def run_command_realtime(command, description):
#     logging.info(f"{color_blue + description + color_reset}")
#     try:
#         process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
#         while True:
#             stdout_output = process.stdout.readline()
#             stderr_output = process.stderr.readline()
            
#             if stdout_output == '' and stderr_output == '' and process.poll() is not None:
#                 break
            
#             if stderr_output:
#                 print(color_red)
#                 logging.info(stderr_output.strip())
#                 sys.exit(0)

#             logging.info(stdout_output.strip())
            
#         process.communicate()
#         if process.returncode != 0:
#             print(color_red)
#             logging.info(f"Command exited with non-zero status ({process.returncode})")
#     except subprocess.CalledProcessError as e:
#         print(color_red)
#         logging.info(f"Error: {e}")


def enable_logging(apk_path):
    the_time = datetime.datetime.now()
    time_year = str(the_time.year)
    time_month = the_time.month
    time_day = the_time.day
    time_hour = the_time.hour
    time_minute = the_time.minute
    time_second = the_time.second
    ctime = f"{time_year}-{time_month:02d}-{time_day:02d}_{time_hour:02d}-{time_minute:02d}-{time_second:02d}"
    apk_file_name = pathlib.Path(apk_path).stem
    log_file_path = os.path.join(f"./log/OMSA_{apk_file_name}_{ctime}.txt")

    logging.basicConfig(filename=log_file_path, level=logging.DEBUG, format='%(message)s')
    logging.getLogger().addHandler(logging.StreamHandler())

    logging.info("\n[+] Log-file path: %s", log_file_path)

# get apk paths from folder, no recursive
def get_apk_paths(folder_path):
    apk_paths = []
    for item in os.scandir(folder_path):
        if item.is_file() and item.name.endswith(".apk"):
            apk_paths.append(item.path)
    return apk_paths
    

import glob

def get_file_paths(folder, pattern, recursive=False):
    paths = []
    for root, dirs, files in os.walk(folder):
        if not recursive:
            dirs.clear()
        for name in files:
            if glob.fnmatch.fnmatch(name, pattern):
                paths.append(os.path.join(root, name))
    return paths

def grep_output_to_dict(output):
    lines = output.split('\n')
    result = {}
    for line in lines:
        if line:
            key, value = line.split(':', 1)
            result.setdefault(key.strip(), []).append(value.strip())
    return result
