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

class Multiple_Results_Analysis():

    @staticmethod
    def combine_results_of_multiple_clusterings(folder_to_results):

        folder_to_results = folder_to_results

        folders = sorted([f.path for f in os.scandir(folder_to_results) if f.is_dir()])

        summary_csv_path = folder_to_results + "/combined_summary.csv"

        lines_list = []
        result_list = []

        for index, folder in enumerate(folders):
            txt_file = glob.glob(folder + "/*.txt")[0]

            file_name = "_".join(os.path.basename(txt_file).split("_")[1:-1])

            lines = []

            with open(txt_file, 'r') as txt_file_reader:
                lines = txt_file_reader.readlines()
            txt_file_reader.close()

            lines = [x.strip() for x in lines]
            lines = list(map(lambda x: x.split(":")[1].strip(), lines))
            lines.insert(0, file_name)

            lines_list.append(lines)

        for list_1 in lines_list:
            for index, value in enumerate(list_1):

                if index < len(result_list):
                    result_list[index].append(value)
                else:
                    result_list.append([value])

        result_list[0].insert(0, "file_name")
        result_list[1].insert(0, "total_processing_time")
        result_list[2].insert(0, "validity_index")
        result_list[3].insert(0, "silhouette_score")
        result_list[4].insert(0, "number_connection")
        result_list[5].insert(0, "number_packets")
        result_list[6].insert(0, "number_clusters")
        result_list[7].insert(0, "average_cluster_size")
        result_list[8].insert(0, "standard_deviation_cluster_size")
        result_list[9].insert(0, "noise_percentage")
        result_list[10].insert(0, "%_total_unknown_connections_in_noise_cluster")
        result_list[11].insert(0, "%_connections_in_noise_cluster_unknown")
        result_list[12].insert(0, "%_detailed_labels_in_noise_cluster")
        result_list[13].insert(0, "avg_cluster_purity")
        result_list[14].insert(0, "avg_detailed_label_cohesion")
        result_list[15].insert(0, "avg_cluster_probability")

        results = []
        for list_2 in result_list:
            list_as_string = ",".join(list_2)
            results.append(list_as_string)

        with open(summary_csv_path, 'w', newline='') as csvfile:
            csv_writer = csv.writer(csvfile, delimiter=',', quotechar='|', quoting=csv.QUOTE_MINIMAL)
            for result in result_list:
                csv_writer.writerow(result)

        csvfile.close()