from collections import Counter

from sklearn.ensemble import RandomForestRegressor

from utils.preprocess_be_pum import update_information_UPX, update_information_FSG
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

    return x, y


def main(packer_name):
    global packed_list_path
    print("Go to main")
    if packer_name == "upx":
        packed_list_path = "data/packed_files.txt"
        X, y = get_X_y()
    else:
        packed_list_path = "data/packed_files_FSG.txt"
        X, y = get_X_y_FSG()
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
    plt.xlabel("The address determined")
    plt.ylabel("Previous OEP")
    plt.title("Previous OEP and the address determined")
    plt.show()

    plt.scatter(x, y)
    plt.show()


def linear_regression():
    # Code source: Jaques Grobler
    # License: BSD 3 clause

    import matplotlib.pyplot as plt
    import numpy as np
    from sklearn import datasets, linear_model
    from sklearn.metrics import mean_squared_error, r2_score

    # Load the diabetes dataset
    diabetes_X, diabetes_y = datasets.load_diabetes(return_X_y=True)
    diabetes_X, diabetes_y = get_X_y()
    diabetes_X = np.asarray(diabetes_X).reshape((-1, 1))
    diabetes_y = np.asarray(diabetes_y).reshape((-1, 1)).ravel()
    print(diabetes_X.shape)
    # Use only one feature
    # diabetes_X = diabetes_X[:, np.newaxis, 2]

    print(diabetes_X.shape)
    # Split the data into training/testing sets
    diabetes_X_train = diabetes_X[:]
    diabetes_X_test = diabetes_X[-20:]

    # Split the targets into training/testing sets
    diabetes_y_train = diabetes_y[:]
    diabetes_y_test = diabetes_y[-20:]

    # Create linear regression object
    regr = linear_model.LinearRegression()

    # Train the model using the training sets
    regr.fit(diabetes_X_train, diabetes_y_train)

    # Make predictions using the testing set
    diabetes_y_pred = regr.predict(diabetes_X_test)

    # The coefficients
    print("Coefficients: \n", regr.coef_)
    # The mean squared error
    print("Mean squared error: %.2f" % mean_squared_error(diabetes_y_test, diabetes_y_pred))
    # The coefficient of determination: 1 is perfect prediction
    print("Coefficient of determination: %.2f" % r2_score(diabetes_y_test, diabetes_y_pred))

    # Plot outputs
    plt.scatter(diabetes_X_train, diabetes_y_train, color="green")
    plt.plot(diabetes_X_train, diabetes_y_train, color="blue", linewidth=1)

    plt.xticks(())
    plt.yticks(())

    plt.show()


def bar_chart():
    # data = {'C': 20, 'C++': 15, 'Java': 30,
    #         'Python': 35}
    # courses = list(data.keys())
    # values = list(data.values())

    x, y = get_X_y()
    courses = list(range(1, len(x) + 1))
    values = list(1 * (np.asarray(y) - np.asarray(x)))
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
    main("fsg")
    # linear_regression()
    # bar_chart()
