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

class Graph_Filtered_Data_Set():

    @staticmethod
    def create_summary_graph_filtered_dataset_summary_file(path_to_summary_csv_files):

        summary_df = pd.read_csv(path_to_summary_csv_files)

        labels_df = summary_df.groupby("label")["src_ip"].count().to_frame()
        labels = ["Benign", "Malicious", "Unknown"]
        colors = {"Benign" : "g", "Malicious" : "r", "Unknown" : "grey"}
        plt.pie(labels_df.src_ip, labels=labels, colors=colors.values())
        #plt.show()
        plt.close()
        plt.clf()

        file_name_df = summary_df.groupby("file")["src_ip"].count().to_frame().reset_index()
        plt.barh(y=file_name_df.file, width=file_name_df.src_ip, log=True)
        plt.tick_params(axis='y', which='major')
        #plt.show()
        plt.close()
        plt.clf()

        name_df = summary_df.groupby("name")["src_ip"].count().to_frame().reset_index()
        plt.bar(x=name_df.name, height=name_df.src_ip, log=False)
        plt.xticks(rotation=45, ha='right')
        plt.show()
        plt.close()
        plt.clf()

        detailed_label_df = summary_df.groupby("detailed_label")["src_ip"].count().to_frame().reset_index()
        plt.bar(x=detailed_label_df.detailed_label, height=detailed_label_df.src_ip, log=True)
        plt.xticks(rotation=45, ha='right')
        plt.show()
        plt.close()
        plt.clf()


    @staticmethod
    def create_summary_graph_filtered_dataset_non_combining(path_to_filtered_files):

        folder_to_filtered_files = path_to_filtered_files

        scan_file_order_path = folder_to_filtered_files + "/" + "scan_order.txt"
        scanned_files = []
        with open(scan_file_order_path, 'r') as inputfile:
            scanned_files = inputfile.readlines()

        scanned_files_list = [x.strip() for x in scanned_files]
        scanned_files_list = list(map(lambda x: (x.split(",")[0], x.split(",")[1]), scanned_files_list))
        scanned_files_list = sorted(scanned_files_list)

        file_name_list = []
        scenario_name_list = []

        benign_count_list_packets = []
        benign_count_list_connections = []
        malicious_count_list_packets = []
        malicious_count_list_connections = []
        unknown_count_list_packets = []
        unknown_count_list_connections = []

        detailed_label_set = set()
        application_name_set = set()
        application_category_name_set = set()

        detailed_label_name_list_list = []
        detailed_label_count_list_list = []
        most_frequent_detailed_label = []

        total_packet_count_list = []
        total_connection_count_list = []

        for index, (scenario_name, file_name) in enumerate(scanned_files_list):

            path_to_csv_file = folder_to_filtered_files + "/" + scenario_name + "/" + file_name + "/" + file_name + "_summary.csv"
            csv_df = pd.read_csv(path_to_csv_file)

            detailed_labels = csv_df["detailed_label"].unique().tolist()
            application_names = csv_df["application_name"].unique().tolist()
            application_category_names = csv_df["application_category_name"].unique().tolist()

            for detailed_label in detailed_labels:
                detailed_label_set.add(detailed_label)

            for application_name in application_names:
                application_name_set.add(application_name)

            for application_category_name in application_category_names:
                application_category_name_set.add(application_category_name)

        total_detailed_label_list = list(detailed_label_set)
        total_application_name_list = list(application_name_set)
        total_application_category_name_list = list(application_category_name_set)

        print(total_detailed_label_list)

        for index, (scenario_name, file_name) in enumerate(scanned_files_list):
            # print("Scenario name: " + scenario_name)
            # print("File name : " + file_name)
            # print("Number: " + str(index + 1) + "/" + str(len(scanned_files_list)))
            # print("Create pcap file")

            path_to_csv_file = folder_to_filtered_files + "/" + scenario_name + "/" + file_name + "/" + file_name + "_summary.csv"
            csv_df = pd.read_csv(path_to_csv_file)

            scenario_name_list.append(scenario_name)
            file_name_list.append(file_name)

            benign_count = csv_df[csv_df["label"] == "Benign"]["connection_length"]
            benign_count_list_packets.append(benign_count.sum())
            benign_count_list_connections.append(benign_count.count())

            malicious_count = csv_df[csv_df["label"] == "Malicious"]["connection_length"]
            malicious_count_list_packets.append(malicious_count.sum())
            malicious_count_list_connections.append(malicious_count.count())

            unknown_count = csv_df[csv_df["label"] == "Unknown"]["connection_length"]
            unknown_count_list_packets.append(unknown_count.sum())
            unknown_count_list_connections.append(unknown_count.count())

            detailed_label = csv_df["detailed_label"].value_counts().to_frame().reset_index()
            detailed_label = detailed_label.rename(columns={"detailed_label" : "count", "index" : "detailed_label"})

            max_detailed_label_count = detailed_label["count"].max()
            max_detail_label_index = detailed_label["count"].idxmax()
            max_detail_label_name = detailed_label["detailed_label"][max_detail_label_index]
            count_name_combination = str(max_detail_label_name) + ":" + str(max_detailed_label_count)
            most_frequent_detailed_label.append(count_name_combination)

            detailed_label_name_list_list.append(detailed_label["detailed_label"].tolist())
            detailed_label_count_list_list.append(detailed_label["count"].tolist())

            packet_count = csv_df["connection_length"].sum()
            connection_count = csv_df["connection_length"].count()
            total_packet_count_list.append(packet_count)
            total_connection_count_list.append(connection_count)


        max_detailed_label_list_length = 0
        detailed_label_count_overall_list = []
        detailed_label_name_overall_list = []

        for detailed_label_list in detailed_label_name_list_list:
            if len(detailed_label_list) > max_detailed_label_list_length:
                max_detailed_label_list_length = len(detailed_label_list)

        for detailed_label_number in range(max_detailed_label_list_length):
            detailed_label_count_overall_list.append([])
            detailed_label_name_overall_list.append([])

        for detailed_label_count_list in detailed_label_count_list_list:
            for index, detailed_label_count in enumerate(detailed_label_count_list):
                detailed_label_count_overall_list[index].append(detailed_label_count)

            if len(detailed_label_count_list) < max_detailed_label_list_length:
                for index in range(len(detailed_label_count_list), max_detailed_label_list_length):
                    detailed_label_count_overall_list[index].append(0)

        for detailed_label_name_list in detailed_label_name_list_list:
            for index, detailed_label_name in enumerate(detailed_label_name_list):
                detailed_label_name_overall_list[index].append(detailed_label_name)

            if len(detailed_label_name_list) < max_detailed_label_list_length:
                for index in range(len(detailed_label_name_list), max_detailed_label_list_length):
                    detailed_label_name_overall_list[index].append("none")

        colors = {}
        colors["none"] = (1, 1, 0, 0.5)
        cmap = cm.get_cmap('viridis', len(total_detailed_label_list))

        for index, color in enumerate(cmap.colors):
            detailed_label_name = total_detailed_label_list.pop()
            colors[detailed_label_name] = color

        plt.barh(y=file_name_list, width=detailed_label_count_overall_list[0], color=[colors[key] for key in detailed_label_name_overall_list[0]])

        for index in range(1, max_detailed_label_list_length):
            plt.barh(y=file_name_list, width=detailed_label_count_overall_list[index], left=detailed_label_count_overall_list[index - 1], color=[colors[key] for key in detailed_label_name_overall_list[index]])
        plt.show()
        plt.close()

        total_benign_packets = sum(benign_count_list_packets)
        total_benign_connections = sum(benign_count_list_connections)
        total_malicious_packets = sum(malicious_count_list_packets)
        total_malicious_connections = sum(malicious_count_list_connections)
        total_unknown_packets = sum(unknown_count_list_packets)
        total_unknown_connections = sum(unknown_count_list_connections)

        sizes_pie_chart_list_packets = [total_benign_packets, total_malicious_packets, total_unknown_packets]
        sizes_pie_chart_list_connections = [total_benign_connections, total_malicious_connections, total_unknown_connections]
        labels = ["Benign", "Malicious", "Unknown"]
        colors = {"Benign" : "g", "Malicious" : "r", "Unknown" : "grey"}

        plt.pie(sizes_pie_chart_list_connections, labels=labels, colors=colors.values())
        plt.show()
        plt.close()

        plt.barh(file_name_list, benign_count_list_packets, color="g")
        plt.barh(file_name_list, malicious_count_list_packets, left=benign_count_list_packets, color = "r")
        plt.barh(file_name_list, unknown_count_list_packets, left=malicious_count_list_packets, color = "grey")
        plt.title("Label per  Per File ")
        plt.show()
        plt.close()

        plt.barh(file_name_list, benign_count_list_connections, color="g")
        plt.barh(file_name_list, malicious_count_list_connections, left=benign_count_list_connections, color = "r")
        plt.barh(file_name_list, unknown_count_list_connections, left=malicious_count_list_connections, color = "grey")
        plt.show()
        plt.close()


        total_dic = {"file_name" : file_name_list, "scenario_name" : scenario_name_list, "packet_count" : total_packet_count_list, "connection_count" : total_connection_count_list, "benign_connections" : benign_count_list_connections, "malicious_connections" : malicious_count_list_connections, "unknown_connections" : unknown_count_list_connections, "most_frequent_detailed_label" : most_frequent_detailed_label}
        total_df = pd.DataFrame(total_dic)
        total_df = total_df.sort_values(by="packet_count", ascending=False)

        fig, ax = plt.subplots()
        fig.patch.set_visible(False)
        ax.axis('off')
        ax.axis('tight')
        table = ax.table(cellText=total_df.values, colLabels=total_df.columns, loc='center',
                         cellLoc='center')
        table.auto_set_column_width(col=list(range(len(total_df.columns))))
        table.scale(1, 2)
        #plt.show()
        #plt.savefig("test.png", dpi=1200, bbox_inches='tight')
        plt.close()