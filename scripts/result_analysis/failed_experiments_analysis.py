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

from scripts.dataset_analysis.filtered_dataset_analysis import Filtered_Dataset_Analysis


class Failed_Experiment_Analysis():

    @staticmethod
    def create_results_for_failed_experiments(path_to_results, path_to_for_malpaca_files, data_set_name):

        for_malpaca_folders = [f.path for f in os.scandir(path_to_for_malpaca_files) if f.is_dir()]
        for_malpaca_folders = [(x, os.path.basename(x)) for x in for_malpaca_folders]

        results_folders = [f.path for f in os.scandir(path_to_results) if f.is_dir()]
        results_folders  = [os.path.basename(x) for x in results_folders]

        failed_experiments = []

        for path, for_malpaca_name in for_malpaca_folders:
            if for_malpaca_name not in results_folders:
                failed_experiments.append((path, for_malpaca_name))

        for path, for_malpaca_name in failed_experiments:

            csv_files = glob.glob(path + "/*.csv")

            for csv_index, csv_file in enumerate(csv_files):
                csv_df = pd.read_csv(csv_file)
                if csv_index == 0:
                    combined_summary_df = csv_df
                else:
                    combined_summary_df = combined_summary_df.append(csv_df)

            new_results_path = path_to_results + "/" + for_malpaca_name + "_failed"
            new_csv_path = new_results_path + "/combined_summary.csv"
            path_detailed_label_csv = new_results_path + "/detailed_length_summary.csv"
            path_detailed_label_table = new_results_path + "/detailed_length_summary.png"
            shortened_summary_path = new_results_path + "/shortened_summary.csv"
            overall_summary_path = new_results_path + "/overall_summary.csv"

            os.mkdir(new_results_path)

            combined_summary_df.to_csv(new_csv_path, index=False)

            total_amount_connections = len(combined_summary_df.index)

            dl_average_length_df = combined_summary_df.groupby("detailed_label")[
                "connection_length"].mean().to_frame().reset_index()
            dl_average_length_df = dl_average_length_df.rename(
                columns={"connection_length": "avg_connection_length"})
            dl_average_length_df["avg_connection_length"] = dl_average_length_df["avg_connection_length"].apply(
                lambda x: round(x, 2))
            dl_con_count_df = combined_summary_df.groupby("detailed_label")[
                "connection_length"].count().to_frame().reset_index()
            dl_con_count_df = dl_con_count_df.rename(columns={"connection_length": "connection_count"})
            detailed_label_info_df = dl_average_length_df.merge(right=dl_con_count_df, on="detailed_label")
            detailed_label_info_df["ratio"] = round(
                (detailed_label_info_df["connection_count"] / total_amount_connections) * 100, 4)
            detailed_label_info_df = detailed_label_info_df.sort_values(by="connection_count", ascending=False)
            detailed_label_info_df.to_csv(path_detailed_label_csv, index=False)

            fig, ax = plt.subplots()
            fig.patch.set_visible(False)
            ax.axis('off')
            ax.axis('tight')
            table = ax.table(cellText=detailed_label_info_df.values, colLabels=detailed_label_info_df.columns,
                             loc='center',
                             cellLoc='center')
            table.auto_set_column_width(col=list(range(len(detailed_label_info_df.columns))))
            for (row, col), cell in table.get_celld().items():
                if (row == 0):
                    cell.set_text_props(fontproperties=FontProperties(weight='bold'))
            fig.tight_layout(pad=3.0)
            plt.savefig(path_detailed_label_table, dpi=1200, bbox_inches='tight')
            plt.close()
            plt.clf()


            data_shortened = {
                "validity_index": "nan",
                "shilouette_score": "nan",

                "noise_percentage": "nan",
                "number_clusters": "nan",

                "cohesion_score": "nan",
                "purity_score": "nan",

                "avg_cluster_probability": "nan",
                "avg_clustering_error": "nan"}

            shortened_summary = pd.DataFrame(data_shortened, index=[0])
            shortened_summary.to_csv(shortened_summary_path, index=False)


            data_overall = {
            "total_time_processing" : "nan",
            "validity_index" : "nan",
            "shilouette_score" : "nan",
            "total_number_connections" : "nan",
            "total_number_packets" : "nan",
            "total_number_clusters" : "nan",
            "avg_cluster_size" : "nan",
            "std_cluster_size" : "nan",
            "noise_percentage" : "nan",
            "avg_label_cohesion" : "nan",
            "avg_detailed_label_cohesion" : "nan",
            "avg_application_name_cohesion" : "nan",
            "avg_application_category_name_cohesion" : "nan",
            "avg_name_cohesion" : "nan",
            "avg_label_purity" : "nan",
            "avg_detailed_label_purity" : "nan",
            "avg_application_name_purity" : "nan",
            "avg_application_category_name_purity" : "nan",
            "avg_name_purity" : "nan",
            "avg_cluster_probability" : "nan",
            "avg_clustering_error" : "nan"
            }

            overall_summary = pd.DataFrame(data_overall, index=[0])
            overall_summary.to_csv(overall_summary_path, index=False)