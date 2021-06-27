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

from scripts.graph_creation.graph_multiple_experiments import Graph_Multiple_Experiments


class Multiple_Experiment_Results_Combination():

    @staticmethod
    def combine_results_from_experiment_1_3_4(path_to_experiment_1, experiment_number = None):
        path_to_experiment_1 = path_to_experiment_1

        if experiment_number:
            storage_file_path = path_to_experiment_1 + "/experiment_" + str(experiment_number) + "_overall_summary.csv"
            table_image_path = path_to_experiment_1 + "/experiment_" + str(experiment_number) + "_overall_summary.png"

            shortened_summary_path = path_to_experiment_1 + "/experiment_" + str(experiment_number) + "_shortened_summary.csv"
            shortened_table_image_path = path_to_experiment_1 + "/experiment_" + str(experiment_number) + "_shortened_summary.png"

        else:
            storage_file_path = path_to_experiment_1 + "/experiment_1_overall_summary.csv"
            table_image_path = path_to_experiment_1 + "/experiment_1_overall_summary.png"

            shortened_summary_path = path_to_experiment_1 + "/experiment_1_shortened_summary.csv"
            shortened_table_image_path = path_to_experiment_1 + "/experiment_1_shortened_summary.png"

        folders = sorted([f.path for f in os.scandir(path_to_experiment_1) if f.is_dir()])


        #
        # overall summary
        #

        df_list = []
        for folder_path in folders:
            path_to_summary_csv = folder_path + "/summaries/overall_summary*"
            path_to_csv_file = glob.glob(path_to_summary_csv)[0]

            csv_df = pd.read_csv(path_to_csv_file)

            experiment_name = os.path.basename(folder_path)
            csv_df["experiment"] = experiment_name

            df_list.append(csv_df)

        summary_df = df_list.pop()
        loop_length = len(df_list)
        for to_add_df in range(loop_length):
            summary_df = summary_df.append(df_list.pop())

        summary_df["avg_label_purity"] = summary_df["avg_label_purity"].apply(lambda x: round(x, 3))
        summary_df["avg_detailed_label_purity"] = summary_df["avg_detailed_label_purity"].apply(lambda x: round(x, 3))
        summary_df["avg_application_name_purity"] = summary_df["avg_application_name_purity"].apply(lambda x: round(x, 3))
        summary_df["avg_application_category_name_purity"] = summary_df["avg_application_category_name_purity"].apply(lambda x: round(x, 3))
        summary_df["avg_name_purity"] = summary_df["avg_name_purity"].apply(lambda x: round(x, 3))
        summary_df["avg_cluster_probability"] = summary_df["avg_label_purity"].apply(lambda x: round(x, 3))


        summary_df["sort_column"] = summary_df["experiment"].apply(lambda x: int(x.split("_")[0]))
        summary_df = summary_df.sort_values(by="sort_column", ascending=True)
        summary_df = summary_df.drop(columns=["sort_column"])

        column_list = summary_df.columns.to_list()
        column_list.pop()
        column_list.insert(0, "experiment")
        summary_df = summary_df.reindex(columns=column_list)

        summary_df = summary_df.fillna("nan")

        summary_df.to_csv(index=False, path_or_buf=storage_file_path)

        fig, ax = plt.subplots()
        fig.patch.set_visible(False)
        ax.axis('off')
        ax.axis('tight')
        table = ax.table(cellText=summary_df.values, colLabels=summary_df.columns, loc='center',
                         cellLoc='center')
        table.auto_set_column_width(col=list(range(len(summary_df.columns))))
        for (row, col), cell in table.get_celld().items():
            if (row == 0):
                cell.set_text_props(fontproperties=FontProperties(weight='bold'))
                cell.set
        fig.tight_layout()
        plt.savefig(table_image_path, dpi=fig.dpi, bbox_inches='tight')
        plt.close()
        plt.clf()

        #
        # shortened summary
        #

        folders = sorted([f.path for f in os.scandir(path_to_experiment_1) if f.is_dir()])

        df_shortened_list = []
        for folder_path in folders:
            path_to_shortened_summary_csv = folder_path + "/summaries/shortened_summary*"
            path_to_csv_file = glob.glob(path_to_shortened_summary_csv)[0]

            csv_df = pd.read_csv(path_to_csv_file)

            experiment_name = os.path.basename(folder_path)
            csv_df["experiment"] = experiment_name



            df_shortened_list.append(csv_df)

        shortened_summary_df = df_shortened_list.pop()
        loop_length = len(df_shortened_list)
        for to_add_df in range(loop_length):
            shortened_summary_df = shortened_summary_df.append(df_shortened_list.pop())


        shortened_summary_df["cohesion_score"] = shortened_summary_df["cohesion_score"].apply(lambda x: round(x, 3))
        shortened_summary_df["purity_score"] = shortened_summary_df["purity_score"].apply(lambda x: round(x, 3))
        shortened_summary_df["avg_cluster_probability"] = shortened_summary_df["avg_cluster_probability"].apply(lambda x: round(x, 3))

        shortened_summary_df["sort_column"] = shortened_summary_df["experiment"].apply(lambda x: int(x.split("_")[0]))
        shortened_summary_df = shortened_summary_df.sort_values(by="sort_column", ascending=True)
        shortened_summary_df = shortened_summary_df.drop(columns=["sort_column"])


        shortened_column_list = shortened_summary_df.columns.to_list()
        shortened_column_list.pop()
        shortened_column_list.insert(0, "experiment")
        shortened_summary_df = shortened_summary_df.reindex(columns=shortened_column_list)

        shortened_summary_df = shortened_summary_df.fillna("nan")

        shortened_summary_df.to_csv(index=False, path_or_buf=shortened_summary_path)

        fig, ax = plt.subplots()
        fig.patch.set_visible(False)
        ax.axis('off')
        ax.axis('tight')
        table = ax.table(cellText=shortened_summary_df.values, colLabels=shortened_summary_df.columns, loc='center',
                         cellLoc='center')
        table.auto_set_column_width(col=list(range(len(shortened_summary_df.columns))))
        for (row, col), cell in table.get_celld().items():
            if (row == 0):
                cell.set_text_props(fontproperties=FontProperties(weight='bold'))
                cell.set
        fig.tight_layout()
        plt.savefig(shortened_table_image_path, dpi=fig.dpi, bbox_inches='tight')
        plt.close()
        plt.clf()

    @staticmethod
    def combine_results_from_experiment_2(path_to_experiment_2):

        scenarios = sorted([f.path for f in os.scandir(path_to_experiment_2) if f.is_dir()])

        for scenario_path in scenarios:

            experiment_name = os.path.basename(scenario_path)

            Graph_Multiple_Experiments.create_cluster_transition_graph(experiment_name, scenario_path, path_to_experiment_2)
            Graph_Multiple_Experiments.create_experiment_overview_graphs(experiment_name, scenario_path, path_to_experiment_2)

    @staticmethod
    def combine_results_from_experiment_3(path_to_experiment_3):
        Multiple_Experiment_Results_Combination.combine_results_from_experiment_1(path_to_experiment_3, 3)

    @staticmethod
    def combine_results_from_experiment_4(path_to_experiment_4):
        Multiple_Experiment_Results_Combination.combine_results_from_experiment_1(path_to_experiment_4, 4)