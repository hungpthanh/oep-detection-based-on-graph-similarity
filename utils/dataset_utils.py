import glob


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