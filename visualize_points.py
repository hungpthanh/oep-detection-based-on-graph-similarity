from collections import Counter

from sklearn.ensemble import RandomForestRegressor

from utils.preprocess_be_pum import update_information_UPX
import matplotlib.pyplot as plt
from sklearn.svm import SVR
import numpy as np
from sklearn import preprocessing

packed_list_path = "data/packed_files.txt"


def get_X_y():
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


def main():
    # x = [1, 2, 3, 4, 5, 6, 7, 8]
    # y = [2, 3, 1, 3, 1, 4, 2, 3]
    X, y = get_X_y()
    # X = np.asarray(X).reshape((-1, 1))
    # y = np.asarray(y).reshape((-1, 1)).ravel()
    # svr_rbf = SVR(kernel="rbf", C=100, gamma=0.01, epsilon=0.005)
    # svr_lin = SVR(kernel="linear", C=100, gamma="auto")
    # svr_poly = SVR(kernel="poly", C=100, gamma="auto", degree=3, epsilon=0.1, coef0=1)
    # rf = RandomForestRegressor(max_depth=2, random_state=0)
    # lw = 2
    #
    # # svrs = [svr_rbf, svr_lin, svr_poly]
    # svrs = [svr_rbf, svr_lin]
    # kernel_label = ["RBF", "Linear", "Polynomial"]
    # model_color = ["m", "c", "g"]
    #
    # fig, axes = plt.subplots(nrows=1, ncols=3, figsize=(15, 10), sharey=True)
    # for ix, svr in enumerate(svrs):
    #     print("model: {}".format(ix))
    #     axes[ix].plot(
    #         X,
    #         svr.fit(X, y).predict(X),
    #         color=model_color[ix],
    #         lw=lw,
    #         label="{} model".format(kernel_label[ix]),
    #     )
    #     axes[ix].scatter(
    #         X[svr.support_],
    #         y[svr.support_],
    #         facecolor="none",
    #         edgecolor=model_color[ix],
    #         s=50,
    #         label="{} support vectors".format(kernel_label[ix]),
    #     )
    #     axes[ix].scatter(
    #         X[np.setdiff1d(np.arange(len(X)), svr.support_)],
    #         y[np.setdiff1d(np.arange(len(X)), svr.support_)],
    #         facecolor="none",
    #         edgecolor="k",
    #         s=50,
    #         label="other training data",
    #     )
    #     axes[ix].legend(
    #         loc="upper center",
    #         bbox_to_anchor=(0.5, 1.1),
    #         ncol=1,
    #         fancybox=True,
    #         shadow=True,
    #     )
    #
    # fig.text(0.5, 0.04, "data", ha="center", va="center")
    # fig.text(0.06, 0.5, "target", ha="center", va="center", rotation="vertical")
    # fig.suptitle("Support Vector Regression", fontsize=14)
    fig, ax = plt.subplots(figsize=(12, 8))
    colors = []
    for index in range(len(X)):
        v = y[index] - X[index] if y[index] - X[index]  <= 150 else -1
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

    # plt.scatter(x, y)
    # plt.show()


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
    main()
    # linear_regression()
    # bar_chart()