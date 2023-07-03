from collections import Counter

from sklearn.ensemble import RandomForestRegressor

from utils.preprocess_be_pum import update_information_UPX, update_information_FSG, update_information_ASPACK, \
    update_information_MPRESS, update_information_petitepacked
import matplotlib.pyplot as plt
from sklearn.svm import SVR
import numpy as np
from sklearn import preprocessing

packed_list_path = ""


def get_X_y():
    print("UPX")
    information = update_information_UPX(packed_list_path)
    print(information)
    print(len(information))

    with open(packed_list_path, "r") as f:
        packed_file = [line.strip() for line in f]
    x = []
    y = []
    for name in packed_file:
        if not (name in information):
            continue
        print(name)
        print(information[name])
        if not ("end_unpacking" in information[name]):
            continue
        if not ("previous_OEP" in information[name]):
            continue
        x.append(int(information[name]["end_unpacking"], base=16))
        y.append(int(information[name]["previous_OEP"], base=16))

    return x, y


def get_X_y_FSG():
    print("FSG")
    information = update_information_FSG(packed_list_path)
    # print(information)
    # print(len(information))

    with open(packed_list_path, "r") as f:
        packed_file = [line.strip() for line in f]
    x = []
    y = []
    z = []
    for name in packed_file:
        if not (name in information):
            continue
        # print(name)
        # print(information[name])
        if not ("end_unpacking" in information[name]):
            continue
        if not ("previous_OEP" in information[name]):
            continue
        x.append(int(information[name]["end_unpacking"], base=16))
        y.append(int(information[name]["previous_OEP"], base=16))
        z.append(int(information[name]["OEP"], base=16))
    return x, y, z


def get_X_y_ASPACK():
    print("ASPACK")
    information = update_information_ASPACK(packed_list_path)
    print(information)
    print(len(information))

    with open(packed_list_path, "r") as f:
        packed_file = [line.strip() for line in f]
    x = []
    y = []
    z = []
    names = []
    for name in packed_file:
        if not (name in information):
            continue
        # print(name)
        # print(information[name])
        if not ("end_unpacking" in information[name]):
            continue
        if not ("previous_OEP" in information[name]):
            continue
        x.append(int(information[name]["end_unpacking"], base=16))
        y.append(int(information[name]["previous_OEP"], base=16))
        z.append(int(information[name]["OEP"], base=16))
        names.append(name)
    return x, y, z, names


def get_X_y_MPRESS():
    print("MPRESS")
    information = update_information_MPRESS(packed_list_path)
    print(information)
    print(len(information))

    with open(packed_list_path, "r") as f:
        packed_file = [line.strip() for line in f]
    x = []
    y = []
    z = []
    names = []
    for name in packed_file:
        if not (name in information):
            continue
        # print(name)
        # print(information[name])
        if not ("end_unpacking" in information[name]):
            continue
        if not ("previous_OEP" in information[name]):
            continue
        x.append(int(information[name]["end_unpacking"], base=16))
        y.append(int(information[name]["previous_OEP"], base=16))
        z.append(int(information[name]["OEP"], base=16))
        names.append(name)
    return x, y, z, names


def get_X_y_PETITEPACKED():
    print("PETITEPACKED")
    information = update_information_petitepacked(packed_list_path)
    print(information)
    print(len(information))

    with open(packed_list_path, "r") as f:
        packed_file = [line.strip() for line in f]
    x = []
    y = []
    z = []
    names = []
    for name in packed_file:
        if not (name in information):
            continue
        # print(name)
        # print(information[name])
        if not ("end_unpacking" in information[name]):
            continue
        if not ("previous_OEP" in information[name]):
            continue
        x.append(int(information[name]["end_unpacking"], base=16))
        y.append(int(information[name]["previous_OEP"], base=16))
        z.append(int(information[name]["OEP"], base=16))
        names.append(name)
    return x, y, z, names


def main(packer_name):
    global packed_list_path
    print("Go to main")
    if packer_name == "upx":
        packed_list_path = "../data/packed_files.txt"
        X, y = get_X_y()
    elif packer_name == "fsg":
        packed_list_path = "../data/packed_files_FSG.txt"
        X, y, z = get_X_y_FSG()
    elif packer_name == "aspack":
        packed_list_path = "../data/packed_files_ASPACK.txt"
        X, y, z, names = get_X_y_ASPACK()
    elif packer_name == "mpress":
        packed_list_path = "../data/packed_files_MPRESS.txt"
        X, y, z, names = get_X_y_MPRESS()
    else:
        packed_list_path = "../data/packed_files_PETITE.txt"
        X, y, z, names = get_X_y_PETITEPACKED()
    fig, ax = plt.subplots(figsize=(12, 8))
    colors = []
    for index in range(len(X)):
        v = y[index] - X[index] if y[index] - X[index] <= 150 else -1
        if v == -1:
            colors.append("red")
        else:
            colors.append("blue")
        # ax.text(X[index], y[index], v, size=8)
    plt.scatter(X, y, color=colors)
    # plt.show()
    plt.xlabel("Matched Signature")
    plt.ylabel("Preceding OEP")
    plt.title("Preceding OEP and Matched Signature")
    plt.show()

    # plt.scatter(x, y)
    # plt.show()


def bar_chart(packer_name):
    global packed_list_path
    # data = {'C': 20, 'C++': 15, 'Java': 30,
    #         'Python': 35}
    # courses = list(data.keys())
    # values = list(data.values())
    names = None
    if packer_name == "upx":
        packed_list_path = "../data/packed_files.txt"
        x, y = get_X_y()
    elif packer_name == "fsg":
        packed_list_path = "../data/packed_files_FSG.txt"
        x, y, z = get_X_y_FSG()
    elif packer_name == "aspack":
        packed_list_path = "../data/packed_files_ASPACK.txt"
        x, y, z, names = get_X_y_ASPACK()
    elif packer_name == "mpress":
        packed_list_path = "../data/packed_files_MPRESS.txt"
        x, y, z, names = get_X_y_MPRESS()
    else:
        packed_list_path = "../data/packed_files_PETITE.txt"
        x, y, z, names = get_X_y_PETITEPACKED()
    courses = list(range(1, len(x) + 1))
    values = list(1 * (np.asarray(y) - np.asarray(x)))

    # for idx in range(0, len(names)):
    #     print("name: {}, distance: {}".format(names[idx], values[idx]))
    plt.figure(figsize=(10, 5))

    # creating the bar plot
    plt.bar(courses, values, color='maroon',
            width=0.4)

    plt.xlabel("End of Unpacking")
    plt.ylabel("Previous OEP")
    plt.title("")
    plt.show()
    print(x)
    print(y)
    print(len(values))
    data = Counter(values)
    print(data)


if __name__ == '__main__':
    # main("petite")
    bar_chart("fsg")
