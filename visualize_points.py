from utils.preprocess_be_pum import update_information_UPX

packed_list_path = "data/packed_files.txt"


def main():
    information = update_information_UPX(packed_list_path)


if __name__ == '__main__':
    main()