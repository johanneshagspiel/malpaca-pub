import csv
import glob
import math
import os
import sys
from random import random, seed
from timeit import default_timer as timer
import time
from statistics import mean
from pathlib import Path
import networkx as nx
import numpy as np
from scapy.layers.inet import IP, UDP
from scapy.utils import PcapWriter, PcapReader
import tkinter as tk
from tkinter import filedialog
import zat
from zat.log_to_dataframe import LogToDataFrame
import pandas as pd
import matplotlib.pyplot as plt
from matplotlib.font_manager import FontProperties
from matplotlib.pyplot import cm
import matplotlib.transforms as mtrans
from sklearn.linear_model import LinearRegression
from sklearn import tree
import graphviz

class Regression_Analysis():

    @staticmethod
    def create_summary_csv_for_multiple_regression(path_to_experiment):

        shortened_summary = glob.glob(path_to_experiment + "/*shortened_summary.csv")[0]
        overall_summary = glob.glob(path_to_experiment + "/*overall_summary.csv")[0]

        shortened_summary_csv = pd.read_csv(shortened_summary)
        overall_summary_csv = pd.read_csv(overall_summary)

        regression_summary_csv = shortened_summary_csv

        interesting_columns = overall_summary_csv[["experiment", "total_number_connections", "total_number_packets"]]

        regression_summary_csv = regression_summary_csv.merge(right=interesting_columns, on="experiment", how="left")
        regression_summary_csv = regression_summary_csv.dropna()

        Y = regression_summary_csv["avg_clustering_error"]
        X = regression_summary_csv.drop(columns=["avg_clustering_error", "experiment"])

        model = LinearRegression().fit(X, Y)
        print(model.score(X, Y))

    @staticmethod
    def regression_analysis(path_to_regression):

        regression_summary_path = glob.glob(path_to_regression + "/*.csv")[0]
        regression_decision_tree = path_to_regression + "/decision_tree.dot"

        regression_summary_csv = pd.read_csv(regression_summary_path)

        Y = regression_summary_csv["avg_clustering_error"]
        X = regression_summary_csv.drop(columns=["avg_clustering_error", "name", "experiment", "balanced", "dataset"])

        feature_names = X.columns

        linear_regression = LinearRegression().fit(X, Y)
        print(linear_regression.score(X, Y))

        decision_tree_regressor = tree.DecisionTreeRegressor().fit(X, Y)
        print(decision_tree_regressor.score(X, Y))

        dot_data = tree.export_graphviz(decision_tree_regressor, regression_decision_tree,
                                        feature_names=feature_names,
                                        filled=True, rounded=True,
                                        special_characters=True)
        graphviz.render('dot', 'png', regression_decision_tree)
        plt.show()
