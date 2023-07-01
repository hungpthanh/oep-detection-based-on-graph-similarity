import os.path
import re


def insert_string(string, added_string, index):
    return string[:index] + added_string + string[index:]


def get_file_name_from_log(log_file):
    log_file = os.path.basename(log_file)[4:]
    return "_".join(log_file.split("_")[1:])[:-4]
