import csv
import glob
import math
import os
import sys
from operator import itemgetter
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

class Util():

    @staticmethod
    def get_protocol_name_from_protocol_number(protocol_number):
        protocol_dic = {
        51 : "AH",
        7 : "CBT",
        60 : "DSTOPTS",
        8 : "EGP",
        50 : "ESP",
        44 : "FRAGMENT",
        3 : "GGP",
        78 : "ICLFXBM",
        1 : "ICMP",
        58 : "ICMPV6",
        22 : "IDP",
        2 : "IGMP",
        9 : "IGP",
        0 : "IP",
        4 : "IPV4",
        41 : "IPV6",
        115 : "L2TP",
        256 : "MAX",
        77 : "ND",
        59 : "NONE",
        113 : "PGM",
        103 : "PIM",
        12 : "PUP",
        255 : "RAW",
        27 : "RDP",
        43 : "ROUTING",
        132 : "SCTP",
        5 : "ST",
        6 : "TCP",
        17 : "UDP"
        }

        protocol_number_as_int = int(protocol_number)
        return protocol_dic[protocol_number_as_int]

    @staticmethod
    def create_scan_order_file(path_to_original_folder):

        scan_file_order_path = path_to_original_folder + "/scan_order.txt"

        scenarios = sorted([f.path for f in os.scandir(path_to_original_folder) if f.is_dir()])

        for scenario_index, scenario_path in enumerate(scenarios):
            scenario_name = os.path.basename(scenario_path)

            files = sorted([f.path for f in os.scandir(scenario_path) if f.is_dir()])

            for file in files:
                file_name = os.path.basename(file)

                with open(scan_file_order_path, 'a') as scan_file:
                    scan_file.write(scenario_name + "," + file_name + "\n")
                    scan_file.close()

    @staticmethod
    def rename_detailed_conn_info(path_to_original_file):

        path_to_original_file = path_to_original_file

        scenarios = sorted([f.path for f in os.scandir(path_to_original_file) if f.is_dir()])

        for scenario_index, scenario_path in enumerate(scenarios):
            scenario_name = os.path.basename(scenario_path)

            print(scenario_name)
            print("Scenario " + str(scenario_index + 1) + "/" + str(len(scenarios)))

            subfolders = [f.path for f in os.scandir(scenario_path) if f.is_dir()]

            for subfolder in subfolders:
                if os.path.basename(subfolder) == "bro":
                    old_name = subfolder + "/detailed_label_check.csv"
                    new_name = subfolder + "/detailed_label_conn_level.csv"

                    os.rename(old_name, new_name)

    @staticmethod
    def compare_scenario_names(folder_to_filtered_files):

        scan_file_order_path = folder_to_filtered_files + "/" + "scan_order.txt"
        scanned_files = []
        with open(scan_file_order_path, 'r') as inputfile:
            scanned_files = inputfile.readlines()

        scanned_files_list = [x.strip() for x in scanned_files]
        scanned_files_list = list(map(lambda x: (x.split(",")[0], x.split(",")[1]), scanned_files_list))
        scanned_files_list = sorted(list(set(scanned_files_list)))

        for index, (scenario_name, file_name) in enumerate(scanned_files_list):

            path_to_csv_file = folder_to_filtered_files + "/" + scenario_name + "/" + file_name + "/" + file_name + "_summary.csv"
            csv_df = pd.read_csv(path_to_csv_file)
            scenario_names = csv_df["scenario"].unique().tolist()

            if (scenario_names[0] == scenario_name) == False:
                print(scenario_names[0])
                print(scenario_name)
                print("  ")

    @staticmethod
    def summary_csv_keep_get_duplicates(path_to_keep_summary_csv, path_to_storage):

        path_to_keep_summary_csv = path_to_keep_summary_csv
        path_to_storage = path_to_storage

        keep_summary_df = pd.read_csv(path_to_keep_summary_csv)
        keep_summary_df = keep_summary_df[keep_summary_df.duplicated(['src_ip', 'dst_ip', 'scenario'], keep=False)]
        keep_summary_df.to_csv(path_to_storage, index=False)



    @staticmethod
    def add_file_and_scenario_info_back(folder_to_filtered_files):

        folder_to_filtered_files = folder_to_filtered_files

        scan_file_order_path = folder_to_filtered_files + "/" + "scan_order.txt"
        scanned_files = []
        with open(scan_file_order_path, 'r') as inputfile:
            scanned_files = inputfile.readlines()
        inputfile.close()

        scanned_files_list = [x.strip() for x in scanned_files]
        scanned_files_list = list(map(lambda x: (x.split(",")[0], x.split(",")[1]), scanned_files_list))
        scanned_files_list = sorted(scanned_files_list)

        for index, (scenario_name, file_name) in enumerate(scanned_files_list):

            csv_summary_file_path = folder_to_filtered_files + "/" + scenario_name + "/" + file_name + "/" + file_name + "_summary.csv"

            csv_df = pd.read_csv(csv_summary_file_path)
            csv_df["scenario"] = scenario_name
            csv_df["file"] = file_name

            columns_list = ["src_ip", "dst_ip", "scenario", "file", "connection_length", "label", "detailed_label", "detailed_label_count", "name", 'application_name', 'application_category_name', "status"]
            csv_df = csv_df.reindex(columns=columns_list)

            csv_df.to_csv(csv_summary_file_path, index=False)



    @staticmethod
    def windows_path_to_malpaca_path(windows_path):
        return windows_path.replace("\\", "/" )

    @staticmethod
    def rename_unknown_to_benign_detailed_label(folder_to_filtered_files):

        folder_to_filtered_files = folder_to_filtered_files

        scan_file_order_path = folder_to_filtered_files + "/" + "scan_order.txt"
        scanned_files = []
        with open(scan_file_order_path, 'r') as inputfile:
            scanned_files = inputfile.readlines()

        scanned_files_list = [x.strip() for x in scanned_files]
        scanned_files_list = list(map(lambda x: (x.split(",")[0], x.split(",")[1]), scanned_files_list))
        scanned_files_list = sorted(scanned_files_list)

        for index, (scenario_name, file_name) in enumerate(scanned_files_list):

            csv_summary_file_path = folder_to_filtered_files + "/" + scenario_name + "/" + file_name + "/" + file_name + "_summary.csv"

            csv_df = pd.read_csv(csv_summary_file_path)

            csv_df['detailed_label'] = csv_df['detailed_label'].replace(["Unknown", "-"], 'Benign')
            csv_df['label'] = np.where(csv_df['detailed_label'] == "Benign", 'Benign', csv_df['label'])

            csv_df.to_csv(csv_summary_file_path, index=False)

    @staticmethod
    def add_name_info(folder_to_filtered_files, path_to_name_info):

        folder_to_filtered_files = folder_to_filtered_files

        scan_file_order_path = folder_to_filtered_files + "/" + "scan_order.txt"
        scanned_files = []
        with open(scan_file_order_path, 'r') as inputfile:
            scanned_files = inputfile.readlines()

        scanned_files_list = [x.strip() for x in scanned_files]
        scanned_files_list = list(map(lambda x: (x.split(",")[0], x.split(",")[1]), scanned_files_list))
        scanned_files_list = sorted(scanned_files_list)

        name_info_df = pd.read_csv(path_to_name_info)

        for index, (scenario_name, file_name) in enumerate(scanned_files_list):
            csv_summary_file_path = folder_to_filtered_files + "/" + scenario_name + "/" + file_name + "/" + file_name + "_summary.csv"

            csv_df = pd.read_csv(csv_summary_file_path)

            current_name = name_info_df[name_info_df["scenario_name"] == scenario_name]["name"].values[0]
            csv_df["name"] = current_name

            csv_df.to_csv(csv_summary_file_path, index=False)

    @staticmethod
    def change_column_order_of_original_dataset(path_file_wrong_column_order, path_to_detailed_label_folder, path_to_storage):

        path_file_wrong_column_order = path_file_wrong_column_order
        path_to_detailed_label_folder = path_to_detailed_label_folder
        path_to_storage = path_to_storage

        summary_df = pd.read_csv(path_file_wrong_column_order)

        total_detailed_label_list = pd.read_csv(path_to_detailed_label_folder)["detailed_label"].tolist()
        total_detailed_label_list.sort()
        total_detailed_label_list.insert(0, "scenario")

        summary_df = summary_df.reindex(columns=total_detailed_label_list)
        summary_df = summary_df.sort_values(by="scenario")

        summary_df.to_csv(path_to_storage, index=False)

    @staticmethod
    def test_logg_file(path_to_logg_file, path_to_storage):

        zat = LogToDataFrame()
        print("Step 1: Reading File")
        startf = time.time()
        bro_original_df = zat.create_dataframe(path_to_logg_file)
        endf = time.time()
        print("Time: " + str(endf - startf))

        print("Step 2: Creating Detailed/Label Column")
        startf = time.time()
        bro_original_df["label"] = bro_original_df["tunnel_parents   label   detailed-label"].apply(
            lambda x: x.split("  ")[1].strip())
        bro_original_df["detailed_label"] = bro_original_df["tunnel_parents   label   detailed-label"].apply(
            lambda x: x.split("  ")[2].strip())
        endf = time.time()
        print("Time: " + str(endf - startf))

        print("Step 3: Renaming Columns")
        startf = time.time()
        bro_original_df = bro_original_df.rename(columns={"id.orig_h" : "src_ip", "id.resp_h" : "dst_ip"})
        endf = time.time()
        print("Time: " + str(endf - startf))

        print("Step 4: Dropping Columns")
        startf = time.time()
        bro_original_df = bro_original_df.drop(
            columns=['uid', 'id.orig_p', 'id.resp_p', 'proto', 'service', 'duration', 'orig_bytes', 'resp_bytes', 'conn_state', 'local_orig', 'local_resp', 'missed_bytes', 'history', 'orig_pkts','orig_ip_bytes', 'resp_pkts', 'resp_ip_bytes','tunnel_parents   label   detailed-label'])
        endf = time.time()
        print("Time: " + str(endf - startf))

        print("Step 5: Sorting")
        startf = time.time()
        bro_original_df.sort_values(["src_ip","dst_ip"], inplace=True)
        endf = time.time()
        print("Time: " + str(endf - startf))

        print("Step 6: Grouping")
        startf = time.time()
        bro_original_df = bro_original_df.groupby(['src_ip', 'dst_ip'])[['detailed_label', 'label']].agg({'detailed_label': 'value_counts', 'label': 'value_counts'})
        bro_original_df = bro_original_df.rename(columns={"detailed_label" : "detailed_label_count", 'label' : 'label_count'})
        endf = time.time()
        print("Time: " + str(endf - startf))

        print("Step 7: Reseting Index")
        startf = time.time()
        bro_original_df = bro_original_df.reset_index()
        endf = time.time()
        print("Time: " + str(endf - startf))

        print("Step 8: Write to File")
        startf = time.time()
        bro_original_df.to_csv(path_to_storage, index=False)
        endf = time.time()
        print("Time: " + str(endf - startf))

    @staticmethod
    def test_new_detailed_label_method(path_to_new_csv, path_to_old_csv, path_to_storage):

        path_to_new_csv = path_to_new_csv
        path_to_old_csv = path_to_old_csv
        path_to_storage = path_to_storage

        print("Step 1: Reading File")
        startf = time.time()
        new_csv_df = pd.read_csv(path_to_new_csv)
        old_csv_df = pd.read_csv(path_to_old_csv)
        endf = time.time()
        print("Time: " + str(endf - startf))

        print("Step 2: Enhancing New DF")
        startf = time.time()
        new_csv_df = new_csv_df.sort_values(by=['src_ip','dst_ip'])
        new_csv_df = new_csv_df.set_index(['src_ip', 'dst_ip'])
        endf = time.time()
        print("Time: " + str(endf - startf))

        print("Step 3: Creating new column")
        startf = time.time()

        #old_csv_df["new_status"] = [Util.new_row_helper(src_ip, dst_ip, new_csv_df) for src_ip, dst_ip in zip(old_csv_df.src_ip, old_csv_df.dst_ip)]

        old_csv_df["new_status"] = [Util.new_row_helper(new_csv_df.loc[(src_ip, dst_ip)]) for src_ip, dst_ip in zip(old_csv_df.src_ip, old_csv_df.dst_ip)]

        endf = time.time()
        print("Time: " + str(endf - startf))

        print("Step 4: Writing to File")
        startf = time.time()

        old_csv_df.to_csv(path_to_storage, index=False)
        endf = time.time()
        print("Time: " + str(endf - startf))

    @staticmethod
    def test_new_detailed_label_method_2(path_to_new_csv, path_to_old_csv, path_to_storage):

        path_to_new_csv = path_to_new_csv
        path_to_old_csv = path_to_old_csv
        path_to_storage = path_to_storage

        path_to_first_file = path_to_storage + "\detailed_label.csv"
        path_to_second_file = path_to_storage + "\deleted.csv"

        path_to_third_file = path_to_storage + "\combined_2_merged_3.csv"
        path_to_four_file = path_to_storage + "\combined_2_merged_4.csv"

        print("Step 1: Reading File")
        startf = time.time()
        new_csv_df = pd.read_csv(path_to_new_csv)
        old_csv_df = pd.read_csv(path_to_old_csv)
        endf = time.time()
        print("Time: " + str(endf - startf))

        print("Step 2: Preparing DFs for merging")
        startf = time.time()
        new_csv_df = new_csv_df.sort_values(by=['src_ip','dst_ip'])
        new_csv_df = new_csv_df.set_index(['src_ip', 'dst_ip'])
        old_csv_df = old_csv_df.sort_values(['src_ip', 'dst_ip'])
        old_csv_df = old_csv_df.set_index(['src_ip', 'dst_ip'])
        endf = time.time()
        print("Time: " + str(endf - startf))

        print("Step 3: Merging DFs")
        startf = time.time()
        merged_df = old_csv_df.merge(on=['src_ip','dst_ip'], right=new_csv_df, how="inner")
        endf = time.time()
        print("Time: " + str(endf - startf))

        merged_df = merged_df.reset_index()
        old_csv_df = old_csv_df.reset_index()

        print(" ")
        print("Rows before: " + str(len(old_csv_df.drop_duplicates(subset=['src_ip','dst_ip'], keep='last').index)))
        print("Rows after: " + str(len(merged_df.drop_duplicates(subset=['src_ip','dst_ip'], keep='last').index)))
        print(" ")

        detailed_label_df = merged_df.drop_duplicates(subset=['src_ip','dst_ip'], keep=False)
        deleted_df = merged_df[merged_df.duplicated(['src_ip','dst_ip'], keep=False)]

        to_check_df = pd.concat([old_csv_df, merged_df.drop_duplicates(subset=['src_ip','dst_ip'], keep='last')]).drop_duplicates(subset=['src_ip','dst_ip'], keep=False)
        to_check_df = to_check_df.rename(columns={"src_ip" : "dst_ip", "dst_ip" : "src_ip"})[["src_ip", "dst_ip"]]

        merged_df_2 = to_check_df.merge(on=['src_ip', 'dst_ip'], right=old_csv_df, how="left")
        merged_df_2.reset_index()
        merged_df_2 = merged_df_2.rename(columns={"src_ip" : "dst_ip", "dst_ip" : "src_ip"})

        detailed_label_2_df = merged_df_2.dropna()
        deleted_2_df = merged_df_2[merged_df_2.duplicated(['src_ip','dst_ip'], keep=False)]

        unknown_df = merged_df_2[merged_df_2.isnull().any(axis=1)]

        print("Detailed Label: " + str(len(detailed_label_df.index)))
        print("Deleted Labels: " + str(len(deleted_df.drop_duplicates(subset=['src_ip','dst_ip'], keep='last').index)))
        print("Detailed Labels 2: " + str(len(detailed_label_2_df.index)))
        print("Deleted Labels 2: " + str(len(deleted_2_df.index)))
        print("Unknown: " + str(len(unknown_df.index)))

        print("     ")

        print("Detailed Label: " + str(detailed_label_df.columns))
        print("Deleted Labels: " + str(deleted_df.columns))
        print("Detailed Labels 2: " + str(detailed_label_2_df.columns))
        print("Deleted Labels 2: " + str(deleted_2_df.columns))
        print("Unknown: " + str(unknown_df.columns))

    @staticmethod
    def new_row_helper(corresponding_series):

        #print(corresponding_series)

        # old_src_ip = old_src_ip
        # old_dst_ip = old_dst_ip

        #corresponding_series = new_csv_df[(new_csv_df["src_ip"] == old_src_ip) & (new_csv_df["dst_ip"] == old_dst_ip)]

        if len(corresponding_series) == 0:
            print("hi")
            return "delete"
        elif len(corresponding_series) == 1:
            detailed_label = corresponding_series["detailed_label"]
            return detailed_label
        else:
            return "delete"

    @staticmethod
    def application_name_analysis(folder_to_filtered_files):

        application_name_dic = {}

        folder_to_filtered_files = folder_to_filtered_files

        scan_file_order_path = folder_to_filtered_files + "/" + "scan_order.txt"
        scanned_files = []
        with open(scan_file_order_path, 'r') as inputfile:
            scanned_files = inputfile.readlines()

        scanned_files_list = [x.strip() for x in scanned_files]
        scanned_files_list = list(map(lambda x: (x.split(",")[0], x.split(",")[1]), scanned_files_list))
        scanned_files_list = sorted(scanned_files_list)

        for index, (scenario_name, file_name) in enumerate(scanned_files_list):
            csv_summary_file_path = folder_to_filtered_files + "/" + scenario_name + "/" + file_name + "/" + file_name + "_summary.csv"

            csv_df = pd.read_csv(csv_summary_file_path)

            application_names_per_port_scan = csv_df[csv_df["detailed_label"] == "Partofahorizontalportscan"]["application_name"].value_counts().to_frame().reset_index()

            #print(application_names_per_port_scan.columns)

            for row in application_names_per_port_scan.iterrows():
                count = int(row[1]["application_name"])
                application_name = row[1]["index"]

                if application_name in application_name_dic:
                    old_entry = application_name_dic[application_name]
                    new_entry = old_entry + count
                    application_name_dic[application_name] = new_entry
                else:
                    application_name_dic[application_name] = count

        application_name_list = list(application_name_dic.items())
        application_name_list.sort(key=itemgetter(1), reverse=True)
        count = [x[1] for x in application_name_list]
        total_application_name_count = sum(count)

        print(total_application_name_count)

        # application_name_list = list(map(lambda x: (x[0], x[1], round((x[1] / total_application_name_count), 3)), application_name_list))
        #
        # with open("horizontal_port_scan.txt", 'w') as file:
        #     file.write("application_name, total_count, percentage\n")
        #     for entry in application_name_list:
        #         application_name = entry[0]
        #         count = entry[1]
        #         percentage = entry[2]
        #
        #         file.write(str(application_name) + ": " + str(count) + " " + str(percentage) + "%\n")

            #csv_df.to_csv(csv_summary_file_path, index=False)
