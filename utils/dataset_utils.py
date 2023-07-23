import glob
import os.path


def get_test_list():
    test_folder = "data/test"
    test_files = glob.glob(test_folder + "/*")
    test_list = []
    for test_file in test_files:
        with open(test_file, "r") as f:
            for line in f:
                test_list.append(line.strip())
    return test_list


def get_train_list():
    train_folder = "data/train"
    train_files = glob.glob(train_folder + "/*")
    train_list = []
    for test_file in train_files:
        with open(test_file, "r") as f:
            for line in f:
                train_list.append(line.strip())
    return train_list


def get_inference_list():
    log_files = glob.glob("data/log_bepum_malware/*.log")
    inference_list = []
    print("log files = {}".format(log_files))
    for log_file in log_files:
        file_name = os.path.basename(log_file)
        print("zzz {}".format(file_name))
        if ("Backdoor" in file_name) or ("Trojan" in file_name):
            name = file_name[4:-4]
            inference_list.append(name)
    return inference_list
