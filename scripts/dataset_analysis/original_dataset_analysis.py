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

class Original_Dataset_Analysis():

    @staticmethod
    def calculate_avg_connection_length_per_detailed_label(path_to_avg_connection_length, path_to_storage):

        csv_files = glob.glob(path_to_avg_connection_length + "/*.csv")
        df_list = []

        for csv_file in csv_files:
            csv_df = pd.read_csv(csv_file)
            df_list.append(csv_df)

        summary_df = df_list.pop()
        loop_length = len(df_list)
        for to_add_df in range(loop_length):
            summary_df = summary_df.append(df_list.pop())

        summary_df["length"] = summary_df.length.astype(int)

        avg_length_connection = summary_df.groupby("detailed_label")["length"].mean()
        avg_length_connection.to_csv(path_to_storage)

    @staticmethod
    def restart_determine_connection_length(path_to_iot_scenarios_folder, folder_to_store):

        path_to_iot_scenarios_folder = path_to_iot_scenarios_folder
        folder_to_store = folder_to_store

        scanned_files = sorted([f.path for f in os.scandir(folder_to_store)])
        scanned_files = sorted(list(set([os.path.basename(x).split("_", maxsplit=1)[0] for x in scanned_files])))

        folders = sorted([f.path for f in os.scandir(path_to_iot_scenarios_folder) if f.is_dir()])
        folders = [(x, os.path.basename(x)) for x in folders]

        to_scan_files = []

        for path, scenario in folders:
            if scenario not in scanned_files:
                to_scan_files.append(path)

        folders = to_scan_files

        for index, folder in enumerate(folders):

            scenario_name = str(os.path.basename(folder)).strip()

            print("Scenario: " + str(index + 1) + "/" + str(len(folders)))
            print("Scenario name: " + scenario_name)

            pcap_files = glob.glob(folder + "/*.pcap")

            for index_file, pcap_file in enumerate(pcap_files):
                file_name = str(os.path.basename(pcap_file)).strip()
                path_to_pcap_file = pcap_file

                print("File: " + str(index_file + 1) + "/" + str(len(pcap_files)))
                print("File name : " + file_name)

                summary_csv_path = folder_to_store + "/" + scenario_name + "_" + file_name + "_con_length.csv"

                with open(summary_csv_path, 'a', newline='') as csvfile:
                    csv_writer = csv.writer(csvfile, delimiter=',', quotechar='|', quoting=csv.QUOTE_MINIMAL)
                    new_row = ["src_ip","dst_ip","length"]
                    csv_writer.writerow(new_row)
                csvfile.close()

                appended_packet_counter = 0
                connections = {}
                write_counter = 1

                with PcapReader(path_to_pcap_file) as packets:
                    for packet_count, packet in enumerate(packets):
                        if IP in packet:

                            src_ip = packet[IP].src
                            dst_ip = packet[IP].dst

                            if (src_ip, dst_ip) not in connections:
                                connections[(src_ip, dst_ip)] = 0
                                appended_packet_counter = appended_packet_counter + 1

                            old_entry = connections[(src_ip, dst_ip)]
                            new_entry = old_entry + 1
                            connections[(src_ip, dst_ip)] = new_entry

                            if appended_packet_counter == 1500000:
                                with open(summary_csv_path, 'a', newline='') as csvfile:
                                    csv_writer = csv.writer(csvfile, delimiter=',', quotechar='|', quoting=csv.QUOTE_MINIMAL)
                                    for (src_ip, dst_ip), amount in connections.items():
                                        new_line = [src_ip, dst_ip, amount]
                                        csv_writer.writerow(new_line)
                                csvfile.close()
                                appended_packet_counter = 0
                                connections.clear()
                                appended_packet_counter = 0
                                print("Write " + str(write_counter) + " Finish")
                                write_counter = write_counter + 1

                packets.close()

                if (len(connections) > 0):
                    print("Write " + str(write_counter))
                    with open(summary_csv_path, 'a', newline='') as csvfile:
                        csv_writer = csv.writer(csvfile, delimiter=',', quotechar='|', quoting=csv.QUOTE_MINIMAL)
                        for (src_ip, dst_ip), amount in connections.items():
                            new_line = [src_ip, dst_ip , amount]
                            csv_writer.writerow(new_line)
                    csvfile.close()
                    connections.clear()
        sys.exit()

    @staticmethod
    def adding_detailed_label_info_to_connection_list(path_to_avg_length_files, path_to_detailed_labels, path_to_storage):

        checked_files = sorted([f.path for f in os.scandir(path_to_storage)])
        checked_files = list(map(lambda x: os.path.basename(x), checked_files))

        avg_length_files = sorted([f.path for f in os.scandir(path_to_avg_length_files)])
        avg_length_files = list(map(lambda x: (os.path.basename(x), x), avg_length_files))

        to_check_files = []

        for file_name, path in avg_length_files:
            if file_name not in checked_files:
                to_check_files.append(path)


        for file_index, file_path in enumerate(to_check_files):

            combined_file_name = os.path.basename(file_path)

            scenario = combined_file_name.split("_", maxsplit=1)[0]
            file = str(combined_file_name.split("_", maxsplit=1)[1].split(".pcap")[0])

            print("File " + str(file_index + 1) + "/" + str(len(to_check_files)))
            print("Scenario name " + str(scenario))
            print("File name " + str(file))

            csv_df = pd.read_csv(file_path)

            csv_df = csv_df.groupby(["src_ip", "dst_ip"])["length"].sum().to_frame().reset_index()

            csv_df["scenario"] = scenario
            csv_df["file"] = file
            csv_df = csv_df.sort_values(['src_ip', 'dst_ip'])
            csv_df = csv_df.set_index(['src_ip', 'dst_ip'])

            path_to_logg_file = path_to_detailed_labels + "/" + scenario + "/bro/conn.log.labeled"

            zat = LogToDataFrame()
            bro_original_df = zat.create_dataframe(path_to_logg_file)

            bro_original_df["label"] = bro_original_df["tunnel_parents   label   detailed-label"].apply(
                lambda x: x.split("  ")[1].strip())
            bro_original_df["detailed_label"] = bro_original_df["tunnel_parents   label   detailed-label"].apply(
                lambda x: x.split("  ")[2].strip())
            bro_original_df = bro_original_df.rename(columns={"id.orig_h": "src_ip", "id.resp_h": "dst_ip"})
            bro_original_df = bro_original_df.drop(
                columns=['uid', 'id.orig_p', 'id.resp_p', 'proto', 'service', 'duration', 'orig_bytes',
                         'resp_bytes',
                         'conn_state', 'local_orig', 'local_resp', 'missed_bytes', 'history', 'orig_pkts',
                         'orig_ip_bytes',
                         'resp_pkts', 'resp_ip_bytes', 'tunnel_parents   label   detailed-label'])
            bro_original_df.sort_values(["src_ip", "dst_ip"], inplace=True)

            bro_original_df = bro_original_df.groupby(['src_ip', 'dst_ip'])[
                'detailed_label'].value_counts().to_frame()
            bro_original_df = bro_original_df.rename(columns={"detailed_label": "detailed_label_count"})
            bro_original_df = bro_original_df.drop(columns="detailed_label_count")
            bro_original_df = bro_original_df.reset_index()

            bro_original_df = bro_original_df.sort_values(by=['src_ip', 'dst_ip'])
            bro_original_df = bro_original_df.set_index(['src_ip', 'dst_ip'])

            merged_df = csv_df.merge(on=['src_ip', 'dst_ip'], right=bro_original_df, how="inner")
            merged_df = merged_df.reset_index()

            addition_csv_path = path_to_storage + "/" + combined_file_name
            merged_df.to_csv(addition_csv_path, index=False)

    @staticmethod
    def determine_connection_length(path_to_iot_scenarios_folder, folder_to_store):

        path_to_iot_scenarios_folder = path_to_iot_scenarios_folder
        folder_to_store = folder_to_store

        folders = sorted([f.path for f in os.scandir(path_to_iot_scenarios_folder) if f.is_dir()])

        for index, folder in enumerate(folders):

            scenario_name = str(os.path.basename(folder)).strip()

            print("Scenario: " + str(index + 1) + "/" + str(len(folders)))
            print("Scenario name: " + scenario_name)

            pcap_files = glob.glob(folder + "/*.pcap")

            for index_file, pcap_file in enumerate(pcap_files):
                file_name = str(os.path.basename(pcap_file)).strip()
                path_to_pcap_file = pcap_file

                print("File: " + str(index_file + 1) + "/" + str(len(pcap_files)))
                print("File name : " + file_name)

                summary_csv_path = folder_to_store + "/" + scenario_name + "_" + file_name + "_con_length.csv"

                with open(summary_csv_path, 'a', newline='') as csvfile:
                    csv_writer = csv.writer(csvfile, delimiter=',', quotechar='|', quoting=csv.QUOTE_MINIMAL)
                    new_row = ["src_ip","dst_ip","length"]
                    csv_writer.writerow(new_row)
                csvfile.close()

                appended_packet_counter = 0
                connections = {}
                write_counter = 1

                with PcapReader(path_to_pcap_file) as packets:
                    for packet_count, packet in enumerate(packets):
                        if IP in packet:

                            src_ip = packet[IP].src
                            dst_ip = packet[IP].dst

                            if (src_ip, dst_ip) not in connections:
                                connections[(src_ip, dst_ip)] = 0
                                appended_packet_counter = appended_packet_counter + 1

                            old_entry = connections[(src_ip, dst_ip)]
                            new_entry = old_entry + 1
                            connections[(src_ip, dst_ip)] = new_entry

                            if appended_packet_counter == 1500000:
                                with open(summary_csv_path, 'a', newline='') as csvfile:
                                    csv_writer = csv.writer(csvfile, delimiter=',', quotechar='|', quoting=csv.QUOTE_MINIMAL)
                                    for (src_ip, dst_ip), amount in connections.items():
                                        new_line = [src_ip, dst_ip, amount]
                                        csv_writer.writerow(new_line)
                                csvfile.close()
                                appended_packet_counter = 0
                                connections.clear()
                                appended_packet_counter = 0
                                print("Write " + str(write_counter) + " Finish")
                                write_counter = write_counter + 1

                packets.close()

                if (len(connections) > 0):
                    print("Write " + str(write_counter))
                    with open(summary_csv_path, 'a', newline='') as csvfile:
                        csv_writer = csv.writer(csvfile, delimiter=',', quotechar='|', quoting=csv.QUOTE_MINIMAL)
                        for (src_ip, dst_ip), amount in connections.items():
                            new_line = [src_ip, dst_ip , amount]
                            csv_writer.writerow(new_line)
                    csvfile.close()
                    connections.clear()
        sys.exit()

    @staticmethod
    def determining_avg_connection_length_per_detailed_label_connection_level(path_to_original_file, path_to_storage):

        path_to_original_file = path_to_original_file
        path_to_storage = path_to_storage

        scenarios = sorted([f.path for f in os.scandir(path_to_original_file) if f.is_dir()])

        for scenario_index, scenario_path in enumerate(scenarios):
            scenario_name = os.path.basename(scenario_path)

            print(scenario_name)
            print("Scenario " + str(scenario_index + 1) + "/" + str(len(scenarios)))
            print("Loading Logg File")

            subfolders = [f.path for f in os.scandir(scenario_path) if f.is_dir()]

            for subfolder in subfolders:
                if os.path.basename(subfolder) == "bro":
                    log_file = subfolder + "/conn.log.labeled"
                    detailed_label_count_file = subfolder + "/detailed_label_conn_level.csv"

                    detailed_label_df = pd.read_csv(detailed_label_count_file)

                    zat = LogToDataFrame()
                    bro_original_df = zat.create_dataframe(log_file)
                    break

            bro_original_df["detailed_label"] = bro_original_df["tunnel_parents   label   detailed-label"].apply(lambda x: x.split("  ")[2].strip())

            bro_original_df = bro_original_df.drop(columns=['uid', 'id.orig_p', 'id.resp_p', 'proto', 'service', 'duration', 'orig_bytes','resp_bytes', 'conn_state', 'local_orig', 'local_resp', 'missed_bytes', 'history','orig_pkts', 'orig_ip_bytes', 'resp_pkts', 'resp_ip_bytes', 'tunnel_parents   label   detailed-label'])
            bro_original_df = bro_original_df.rename(columns={"id.orig_h": "src_ip", "id.resp_h": "dst_ip"})
            bro_original_df.sort_values(["src_ip", "dst_ip"], inplace=True)
            bro_original_df.set_index(['src_ip', 'dst_ip'])

            bro_original_df = bro_original_df.groupby(['src_ip', 'dst_ip'])["detailed_label"].value_counts().to_frame()
            bro_original_df = bro_original_df.rename(columns={"detailed_label": "count"}).reset_index().drop(columns="count")
            bro_original_df = bro_original_df.sort_values(by=['src_ip', 'dst_ip'])

            detailed_label_df["connection_count"] = np.where(detailed_label_df["connection_count"] > 1000, 1000, detailed_label_df["connection_count"])

            detailed_label_dic = detailed_label_df.drop(columns="scenario").set_index("detailed_label").to_dict()

            print("Reading PCAP File")
            pcap_files = glob.glob(scenario_path + "/*.pcap")

            for file_index, pcap_file_path in enumerate(pcap_files):
                file_name = os.path.basename(pcap_file_path)

                print(file_name)
                print("File " + str(file_index + 1) + "/" + str(len(pcap_files)))

                connection_dic = {}
                with PcapReader(pcap_file_path) as packets:
                    for packet_count, packet in enumerate(packets):
                        if IP in packet:
                            src_ip = packet[IP].src
                            dst_ip = packet[IP].dst

                            detailed_label = bro_original_df[(bro_original_df["src_ip"] == src_ip) & (bro_original_df["dst_ip"] == dst_ip)]["detailed_label"].values

                            if len(detailed_label) > 0:
                                detailed_label = detailed_label[0]

                                if (src_ip, dst_ip, detailed_label) in connection_dic:
                                    old_value = connection_dic[(src_ip, dst_ip, detailed_label)]
                                    new_value = old_value + 1
                                    connection_dic[(src_ip, dst_ip, detailed_label)] = new_value
                                else:
                                    still_needed = int(detailed_label_dic["connection_count"][detailed_label])

                                    if still_needed > 0:
                                        new_needed = still_needed - 1
                                        detailed_label_dic["connection_count"][detailed_label] = new_needed
                                        connection_dic[(src_ip, dst_ip, detailed_label)] = 1
                packets.close()

                if len(connection_dic) > 0:
                    src_ip_list = []
                    dst_ip_list = []
                    detailed_label_list = []
                    connection_length_list = []

                    for key, value in connection_dic.items():
                        src_ip_list.append(key[0])
                        dst_ip_list.append(key[1])
                        detailed_label_list.append(key[2])
                        connection_length_list.append(value)

                    data = {"src_ip": src_ip_list, "dst_ip": dst_ip_list, "detailed_label" : detailed_label_list, "connection_length": connection_length_list}
                    final_df = pd.DataFrame(data)
                    final_df["scenario"] = scenario_name
                    final_df["file_name"] = file_name

                    storage_path = path_to_storage + "/" + scenario_name + "_" + file_name + "_con_analysis.csv"
                    final_df.to_csv(storage_path, index=False)

    @staticmethod
    def original_dataset_detailed_label_netflow_level(path_to_original_files):

        folders = [f.path for f in os.scandir(path_to_original_files) if f.is_dir()]

        for index, folder in enumerate(folders):
            scenario_name = os.path.basename(folder)

            print(scenario_name)
            print("Scenario " + str(index + 1) + "/" + str(len(folders)))

            subfolders = [f.path for f in os.scandir(folder) if f.is_dir()]

            for folder in subfolders:
                if os.path.basename(folder) == "bro":
                    path_to_logg_file = folder + "/conn.log.labeled"
                    path_to_storage = folder + "/detailed_label_netflow_level.csv"

                    zat = LogToDataFrame()
                    bro_original_df = zat.create_dataframe(path_to_logg_file)
                    bro_original_df["detailed_label"] = bro_original_df[
                        "tunnel_parents   label   detailed-label"].apply(lambda x: x.split("  ")[2].strip())

                    bro_original_df = bro_original_df.rename(
                        columns={"id.orig_h": "src_ip", "id.resp_h": "dst_ip", "id.orig_p": "src_port",
                                 "id.resp_p": "dst_port", "proto": "ip_protocol"})
                    bro_original_df = bro_original_df.drop(
                        columns=['uid', 'service', 'duration', 'orig_bytes', 'resp_bytes', 'conn_state', 'local_orig',
                                 'local_resp', 'missed_bytes', 'history', 'orig_pkts', 'orig_ip_bytes',
                                 'resp_pkts', 'resp_ip_bytes', 'tunnel_parents   label   detailed-label'])
                    bro_original_df["ip_protocol"] = bro_original_df["ip_protocol"].str.upper()
                    bro_original_df.sort_values(["src_ip", "dst_ip", "src_port", "dst_port", "ip_protocol"],
                                                inplace=True)
                    bro_original_df.set_index(["src_ip", "dst_ip", "src_port", "dst_port", "ip_protocol"])

                    detailed_label_df = bro_original_df.groupby(["src_ip", "dst_ip", "src_port", "dst_port", "ip_protocol"])[
                        "detailed_label"].value_counts().to_frame()

                    detailed_label_df = detailed_label_df.rename(columns={"detailed_label": "count"})
                    detailed_label_df = detailed_label_df.drop(columns="count").reset_index()

                    detailed_label_count_df = detailed_label_df[
                        "detailed_label"].value_counts().to_frame().reset_index()
                    detailed_label_count_df = detailed_label_count_df.rename(
                        columns={"detailed_label": "connection_count", "index": "detailed_label"})
                    detailed_label_count_df["scenario"] = scenario_name

                    detailed_label_count_df.to_csv(path_to_storage, index=False)

    @staticmethod
    def original_dataset_detailed_label_connection_level(path_to_original_files):

        folders = [f.path for f in os.scandir(path_to_original_files) if f.is_dir()]

        for index, folder in enumerate(folders):
            scenario_name = os.path.basename(folder)

            print(scenario_name)
            print("Scenario " + str(index + 1) + "/" + str(len(folders)))

            subfolders = [f.path for f in os.scandir(folder) if f.is_dir()]

            for folder in subfolders:
                if os.path.basename(folder) == "bro":
                    path_to_logg_file = folder + "/conn.log.labeled"
                    path_to_storage = folder + "/detailed_label_check.csv"

                    zat = LogToDataFrame()
                    bro_original_df = zat.create_dataframe(path_to_logg_file)
                    bro_original_df["detailed_label"] = bro_original_df[
                        "tunnel_parents   label   detailed-label"].apply(lambda x: x.split("  ")[2].strip())

                    bro_original_df = bro_original_df.drop(
                        columns=['uid', 'id.orig_p', 'id.resp_p', 'proto', 'service', 'duration', 'orig_bytes',
                                 'resp_bytes', 'conn_state', 'local_orig', 'local_resp', 'missed_bytes', 'history',
                                 'orig_pkts', 'orig_ip_bytes', 'resp_pkts', 'resp_ip_bytes',
                                 'tunnel_parents   label   detailed-label'])
                    bro_original_df = bro_original_df.rename(columns={"id.orig_h": "src_ip", "id.resp_h": "dst_ip"})
                    bro_original_df.sort_values(["src_ip", "dst_ip"], inplace=True)
                    bro_original_df.set_index(['src_ip', 'dst_ip'])

                    detailed_label_df = bro_original_df.groupby(['src_ip', 'dst_ip'])[
                        "detailed_label"].value_counts().to_frame()

                    detailed_label_df = detailed_label_df.rename(columns={"detailed_label": "count"})
                    detailed_label_df = detailed_label_df.drop(columns="count").reset_index()

                    detailed_label_count_df = detailed_label_df[
                        "detailed_label"].value_counts().to_frame().reset_index()
                    detailed_label_count_df = detailed_label_count_df.rename(
                        columns={"detailed_label": "connection_count", "index": "detailed_label"})
                    detailed_label_count_df["scenario"] = scenario_name

                    detailed_label_count_df.to_csv(path_to_storage, index=False)


    @staticmethod
    def original_dataset_detailed_label_analysis_flow_level(path_to_original_files):


        folders = [f.path for f in os.scandir(path_to_original_files) if f.is_dir()]

        for index, folder in enumerate(folders):
            scenario_name = os.path.basename(folder)

            print(scenario_name)
            print("Scenario " + str(index + 1) + "/" + str(len(folders)))

            subfolders = [f.path for f in os.scandir(folder) if f.is_dir()]

            for folder in subfolders:
                if os.path.basename(folder) == "bro":
                    path_to_logg_file = folder + "/conn.log.labeled"
                    path_to_storage = folder + "/detailed_label_flow_level.csv"

                    zat = LogToDataFrame()
                    bro_original_df = zat.create_dataframe(path_to_logg_file)
                    bro_original_df["detailed_label"] = bro_original_df[
                        "tunnel_parents   label   detailed-label"].apply(lambda x: x.split("  ")[2].strip())

                    bro_original_df = bro_original_df.drop(
                        columns=['uid', 'id.orig_p', 'id.resp_p', 'proto', 'service', 'duration', 'orig_bytes',
                                 'resp_bytes', 'conn_state', 'local_orig', 'local_resp', 'missed_bytes', 'history',
                                 'orig_pkts', 'orig_ip_bytes', 'resp_pkts', 'resp_ip_bytes',
                                 'tunnel_parents   label   detailed-label'])
                    bro_original_df = bro_original_df.rename(columns={"id.orig_h": "src_ip", "id.resp_h": "dst_ip"})

                    detailed_label_count_df = bro_original_df["detailed_label"].value_counts().to_frame().reset_index()
                    detailed_label_count_df = detailed_label_count_df.rename(columns={"detailed_label": "flow_count", "index": "detailed_label"})
                    detailed_label_count_df["scenario"] = scenario_name

                    detailed_label_count_df.to_csv(path_to_storage, index=False)


    @staticmethod
    def filtered_dataset_information(path_to_original_dataset, path_to_filtered_dataset):

        path_to_original_dataset = path_to_original_dataset
        path_to_filtered_dataset = path_to_filtered_dataset

        original_folders = sorted([f.path for f in os.scandir(path_to_original_dataset) if f.is_dir()])
        original_folders = list(map(lambda x: x.strip(), original_folders))

        total_packets_original = 0
        packets_per_file_dic = {}
        for original_folder in original_folders:
            txt_files = glob.glob(original_folder + "/*.txt")

            if len(txt_files) > 0:
                for txt_file in txt_files:
                    file_name = os.path.basename(txt_file).split("_count.txt")[0]
                    with open(txt_file, "r") as txt_file_in:  # or just open
                        total_number_packets = int(txt_file_in.readline())
                    txt_file_in.close()
                    total_packets_original = total_packets_original + total_number_packets
                    packets_per_file_dic[file_name] = total_number_packets


        filtered_folders = sorted([f.path for f in os.scandir(path_to_filtered_dataset) if f.is_dir()])
        filtered_folders = list(map(lambda x: x.strip(), filtered_folders))

        total_packets_filtered = 0
        first_time = True
        for filtered_folder in filtered_folders:

            sub_folders = [f.path for f in os.scandir(filtered_folder) if f.is_dir()]
            for sub_folder in sub_folders:

                summary_csv_files = glob.glob(sub_folder + "/*.csv")
                if len(summary_csv_files) > 0:
                    summary_csv_df = pd.read_csv(summary_csv_files[0])

                    if first_time:
                        combined_filtered_df = summary_csv_df
                        first_time = False
                    else:
                        combined_filtered_df = combined_filtered_df.append(summary_csv_df, ignore_index=True)

        total_packets_filtered = combined_filtered_df["connection_length"].sum()

        detailed_label_connections_count = combined_filtered_df.groupby("detailed_label")[
            "connection_length"].count().to_frame().reset_index()
        detailed_label_connections_count = detailed_label_connections_count[
            detailed_label_connections_count["detailed_label"] != "-"]
        detailed_label_connections_count = detailed_label_connections_count.rename(
            columns={"connection_length": "Connections", "detailed_label": "Detailed Label"})
        detailed_label_connections_count.plot(kind="bar", x="Detailed Label", y="Connections", legend=None)
        # plt.show()
        plt.close()

        detailed_label_packets_count = combined_filtered_df.groupby("detailed_label")[
            "connection_length"].sum().to_frame().reset_index()
        detailed_label_packets_count = detailed_label_packets_count[
            detailed_label_packets_count["detailed_label"] != "-"]
        detailed_label_packets_count = detailed_label_packets_count.rename(
            columns={"connection_length": "Packets", "detailed_label": "Detailed Label"})
        detailed_label_packets_count.plot(kind="bar", x="Detailed Label", y="Packets", legend=None)
        # plt.show()
        plt.close()

        label_count = combined_filtered_df["label"].value_counts().to_frame().reset_index()
        label_count = label_count.rename(columns={"index": "Label", "label": "Connections"})
        label_count_relative = combined_filtered_df["label"].value_counts(normalize=True).to_frame().reset_index()
        label_count_relative = label_count_relative.rename(columns={"index": "Label", "label": "relative_count"})
        label_count_relative["relative_count"] = label_count_relative["relative_count"].apply(
            lambda x: str(round(x * 100, 2)) + "%")
        merged_df = label_count.merge(right=label_count_relative, on="Label")
        merged_df.plot(kind="pie", x="Label", y="Connections", labels=merged_df["relative_count"])
        plt.legend(merged_df["Label"])
        plt.ylabel("")
        # plt.show()
        plt.close()

        packets_per_file_filtered_df = combined_filtered_df.groupby("file")[
            "connection_length"].sum().to_frame().reset_index()
        packets_per_file_filtered_df["original_connection_length"] = packets_per_file_filtered_df["file"].apply(
            lambda x: packets_per_file_dic[x])
        packets_per_file_filtered_df["%_packets_used"] = round((packets_per_file_filtered_df["connection_length"] /
                                                                packets_per_file_filtered_df[
                                                                    "original_connection_length"]) * 100, 2)

        avg_per_packets_per_file_used = round(packets_per_file_filtered_df["%_packets_used"].mean(), 2)

        avg_packets_per_connection = round(sucmmary_csv_df["connection_length"].mean(), 2)

        print(packets_per_file_filtered_df)