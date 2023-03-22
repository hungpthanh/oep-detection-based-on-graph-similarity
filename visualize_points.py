from utils.preprocess_be_pum import update_information_UPX
import matplotlib.pyplot as plt

packed_list_path = "data/packed_files.txt"


def main():
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
    # x = [1, 2, 3, 4, 5, 6, 7, 8]
    # y = [2, 3, 1, 3, 1, 4, 2, 3]

    plt.scatter(x, y)
    plt.show()


if __name__ == '__main__':
    main()
