def get_test_list():
    test_list = []
    with open("data/test.txt", "r") as f:
        for line in f:
            test_list.append(line.strip())
    return test_list