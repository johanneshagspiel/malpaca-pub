import csv
import glob
import math
import os
import sys
from random import random, seed
import socket
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

class Adding_More_Information_Netflow():

    @staticmethod
    def adding_name_info_and_rename_labels_of_benign_devices_for_netflow(path_to_filtered_files, path_to_name_info):

        path_to_filtered_files = path_to_filtered_files
        path_to_name_info = path_to_name_info

        name_info_df = pd.read_csv(path_to_name_info)

        scan_file_order_path = path_to_filtered_files + "/scan_order.txt"
        with open(scan_file_order_path, 'r') as inputfile:
            scanned_files = inputfile.readlines()

        scanned_files_list = [x.strip() for x in scanned_files]
        scanned_files_list = [(x.split(",")[0], x.split(",")[1]) for x in scanned_files_list]

        for index, (scenario, file_name) in enumerate(scanned_files_list):
            print("Scenario " + str(index + 1) + "/" + str(len(scanned_files_list)))

            name = name_info_df[name_info_df["scenario_name"] == scenario]["name"].values[0]

            path_to_csv_file = path_to_filtered_files + "/" + scenario + "/" + file_name + "/" + file_name + "_summary.csv"
            summary_csv_df = pd.read_csv(path_to_csv_file)

            summary_csv_df["name"] = name

            columns_list = ["src_ip", "dst_ip", "src_port", "dst_port", "ip_protocol", "scenario", "file",
                            "connection_length", "label", "detailed_label",
                            "detailed_label_count", "name", "status"]
            summary_csv_df = summary_csv_df.reindex(columns=columns_list)

            summary_csv_df.to_csv(path_to_csv_file, index=False)

    @staticmethod
    def create_summary_from_separate_files_for_netflow(path_to_iot_scenarios_folder, folder_to_filtered_files, filename_addition):

        path_to_iot_scenarios_folder = path_to_iot_scenarios_folder
        folder_to_filtered_files = folder_to_filtered_files
        filename_addition = filename_addition

        scan_file_order_path = folder_to_filtered_files + "/" + "scan_order.txt"
        scanned_files = []
        with open(scan_file_order_path, 'r') as inputfile:
            scanned_files = inputfile.readlines()

        scanned_files_list = [x.strip() for x in scanned_files]
        scanned_files_list = list(map(lambda x: (x.split(",")[0], x.split(",")[1]), scanned_files_list))
        scanned_files_list = sorted(list(set(scanned_files_list)))

        for index, (scenario_name, file_name) in enumerate(scanned_files_list):
            print("Scenario name: " + scenario_name)
            print("File name : " + file_name)
            print("Number: " + str(index + 1) + "/" + str(len(scanned_files_list)))

            log_order_path = folder_to_filtered_files + "/" + "log_order.txt"
            with open(log_order_path, 'a') as log_order_file:
                log_order_file.write(scenario_name + "," + file_name + "\n")
                log_order_file.close()

            print("Reading PCAP File")

            path_to_csv_file = folder_to_filtered_files + "/" + scenario_name + "/" + file_name + "/" + file_name + "_summary.csv"
            path_to_pcap_file = folder_to_filtered_files + "/" + scenario_name + "/" + file_name + "/" + file_name + "_" + filename_addition + ".pcap"
            path_to_original_folder = path_to_iot_scenarios_folder + "/" + scenario_name

            path_to_old_file = folder_to_filtered_files + "/" + scenario_name + "/" + file_name + "/" + file_name + "_old.csv"
            path_to_bro_file = folder_to_filtered_files + "/" + scenario_name + "/" + file_name + "/" + file_name + "_bro.csv"
            path_to_merge_file = folder_to_filtered_files + "/" + scenario_name + "/" + file_name + "/" + file_name + "_merge.csv"

            file_packet_dic = {}
            with PcapReader(path_to_pcap_file) as packets:
                for packet_count, packet in enumerate(packets):

                    packet_string = packet.show(dump=True)
                    packet_for_print = packet_string
                    packet_string = packet_string.split("\n")
                    packet_string = [x.replace(" ", "") for x in packet_string]

                    current_layer = "none"
                    packet_dic = {}
                    for line in packet_string:
                        if len(line) > 0:
                            if line[0] == '#':
                                new_layer = line.split('[')[1].split(']')[0]
                                current_layer = new_layer
                                packet_dic[current_layer] = {}
                            elif (line[0] != '\\') & (line[0] != '|'):
                                key = line.split("=")[0]
                                value = line.split("=")[1]

                                packet_dic[current_layer][key] = value

                    src_ip = packet_dic["IP"]["src"]
                    dst_ip = packet_dic["IP"]["dst"]
                    ip_protocol = packet_dic["IP"]["proto"].upper()

                    if ip_protocol == "UDP" and "UDP" in packet_dic:
                        src_port = packet_dic["UDP"]["sport"]
                        dst_port = packet_dic["UDP"]["dport"]
                    elif ip_protocol == "TCP" and "TCP" in packet_dic:
                        src_port = packet_dic["TCP"]["sport"]
                        dst_port = packet_dic["TCP"]["dport"]
                    elif ip_protocol == "ICMP" and "ICMP" in packet_dic:
                        src_port = 0
                        dst_port = str(packet_dic["ICMP"]["type"]) + "/" + str(packet_dic["ICMP"]["code"])
                    else:
                        src_port = 0
                        dst_port = 0

                    if not isinstance(src_port, int):
                        if not all(char.isdigit() for char in src_port):
                            try:
                                src_port = socket.getservbyname(src_port, ip_protocol)
                            except:
                                src_port = src_port

                    if not isinstance(dst_port, int) or ():
                        if not all(char.isdigit() for char in dst_port):
                            try:
                                dst_port = socket.getservbyname(dst_port, ip_protocol)
                            except:
                                dst_port = dst_port


                    ip_tos = packet_dic["IP"]["tos"]

                    if (src_ip, dst_ip, ip_protocol, src_port, dst_port, ip_tos) in file_packet_dic:
                        old_value = file_packet_dic[(src_ip, dst_ip, ip_protocol, src_port, dst_port, ip_tos)]
                        new_value = old_value + 1
                        file_packet_dic[(src_ip, dst_ip, ip_protocol, src_port, dst_port, ip_tos)] = new_value
                    else:
                        file_packet_dic[(src_ip, dst_ip, ip_protocol, src_port, dst_port, ip_tos)] = 1

            packets.close()

            src_ip_list = []
            dst_ip_list = []
            ip_protocol_list = []
            src_port_list = []
            dst_port_list = []
            ip_tos_list = []
            connection_length_list = []

            for (src_ip, dst_ip, ip_protocol, src_port, dst_port, ip_tos), connection_length in file_packet_dic.items():
                src_ip_list.append(src_ip)
                dst_ip_list.append(dst_ip)
                ip_protocol_list.append(ip_protocol)
                src_port_list.append(src_port)
                dst_port_list.append(dst_port)
                ip_tos_list.append(ip_tos)

                connection_length_list.append(connection_length)

            data = {"src_ip": src_ip_list, "dst_ip": dst_ip_list, "ip_protocol" : ip_protocol_list, "src_port" : src_port_list,
                    "dst_port" : dst_port_list, "ip_tos" : ip_tos_list, "connection_length": connection_length_list}
            old_info_df = pd.DataFrame(data)
            old_info_df["scenario"] = scenario_name
            old_info_df["file"] = file_name

            print("Adding Logg Data")
            sub_folders = [f.path for f in os.scandir(path_to_original_folder) if f.is_dir()]
            bro_folder_found = False

            for sub_folder in sub_folders:
                base_name = str(os.path.basename(sub_folder))

                if base_name == "bro":
                    labeled_files = glob.glob(sub_folder + "/*.labeled")
                    bro_folder_found = True
                    break

            if bro_folder_found and len(labeled_files) > 0:

                logg_file = labeled_files[0]

                zat = LogToDataFrame()
                bro_original_df = zat.create_dataframe(logg_file)
                bro_original_df["label"] = bro_original_df["tunnel_parents   label   detailed-label"].apply(
                    lambda x: x.split("  ")[1].strip())
                bro_original_df["detailed_label"] = bro_original_df["tunnel_parents   label   detailed-label"].apply(
                    lambda x: x.split("  ")[2].strip())
                bro_original_df = bro_original_df.rename(columns={"id.orig_h": "src_ip", "id.resp_h": "dst_ip", "id.orig_p" : "src_port", "id.resp_p" : "dst_port", "proto" : "ip_protocol"})
                bro_original_df = bro_original_df.drop(
                    columns=['uid', 'service', 'duration', 'orig_bytes', 'resp_bytes', 'conn_state', 'local_orig',
                             'local_resp', 'missed_bytes', 'history', 'orig_pkts', 'orig_ip_bytes',
                             'resp_pkts', 'resp_ip_bytes', 'tunnel_parents   label   detailed-label'])
                bro_original_df["ip_protocol"] = bro_original_df["ip_protocol"].str.upper()
                bro_original_df.sort_values(["src_ip", "dst_ip", "src_port", "dst_port", "ip_protocol"], inplace=True)

                bro_original_df = bro_original_df.groupby(["src_ip", "dst_ip", "src_port", "dst_port", "ip_protocol"])[
                    'detailed_label'].value_counts().to_frame()
                bro_original_df = bro_original_df.rename(columns={"detailed_label": "detailed_label_count"})
                bro_original_df = bro_original_df.reset_index()



                bro_original_df["src_ip"] = bro_original_df["src_ip"].apply(lambda x: str(x).strip())
                bro_original_df["dst_ip"] = bro_original_df["dst_ip"].apply(lambda x: str(x).strip())
                bro_original_df["src_port"] = bro_original_df["src_port"].apply(lambda x: str(x).strip())
                bro_original_df["dst_port"] = bro_original_df["dst_port"].apply(lambda x: str(x).strip())
                bro_original_df["ip_protocol"] = bro_original_df["ip_protocol"].apply(lambda x: str(x).strip())

                bro_original_df["src_ip"] = bro_original_df["src_ip"].astype(str)
                bro_original_df["dst_ip"] = bro_original_df["dst_ip"].astype(str)
                bro_original_df["src_port"] = bro_original_df["src_port"].astype(str)
                bro_original_df["dst_port"] = bro_original_df["dst_port"].astype(str)
                bro_original_df["ip_protocol"] = bro_original_df["ip_protocol"].astype(str)

                bro_original_df = bro_original_df.sort_values(by=["src_ip", "dst_ip", "src_port", "dst_port", "ip_protocol"])
                bro_original_df = bro_original_df.set_index(["src_ip", "dst_ip", "src_port", "dst_port", "ip_protocol"])
                old_info_df = old_info_df.sort_values(["src_ip", "dst_ip", "src_port", "dst_port", "ip_protocol"])
                old_info_df = old_info_df.set_index(["src_ip", "dst_ip", "src_port", "dst_port", "ip_protocol"])
                merged_df = old_info_df.merge(on=["src_ip", "dst_ip", "src_port", "dst_port", "ip_protocol"], right=bro_original_df, how="inner")
                merged_df = merged_df.reset_index()
                old_info_df = old_info_df.reset_index()

                detailed_label_df = merged_df.drop_duplicates(subset=["src_ip", "dst_ip", "src_port", "dst_port", "ip_protocol"], keep=False)
                detailed_label_df["status"] = "Found"
                deleted_df = merged_df[merged_df.duplicated(["src_ip", "dst_ip", "src_port", "dst_port", "ip_protocol"], keep=False)]
                deleted_df["status"] = "Mixed"

                to_check_df = pd.concat(
                    [old_info_df, merged_df.drop_duplicates(subset=["src_ip", "dst_ip", "src_port", "dst_port", "ip_protocol"], keep='last')]).drop_duplicates(
                    subset=["src_ip", "dst_ip", "src_port", "dst_port", "ip_protocol"], keep=False)
                to_check_df = to_check_df.reset_index()
                to_check_df = to_check_df.rename(columns={"src_ip": "dst_ip", "dst_ip": "src_ip", "src_port" : "dst_port", "dst_port" : "src_port"}).drop(
                    columns=["detailed_label", "detailed_label_count"])

                to_check_df["src_ip"] = to_check_df["src_ip"].apply(lambda x: str(x).strip())
                to_check_df["dst_ip"] = to_check_df["dst_ip"].apply(lambda x: str(x).strip())
                to_check_df["src_port"] = to_check_df["src_port"].apply(lambda x: str(x).strip())
                to_check_df["dst_port"] = to_check_df["dst_port"].apply(lambda x: str(x).strip())
                to_check_df["ip_protocol"] = to_check_df["ip_protocol"].apply(lambda x: str(x).strip())

                to_check_df["src_ip"] = to_check_df["src_ip"].astype(str)
                to_check_df["dst_ip"] = to_check_df["dst_ip"].astype(str)
                to_check_df["src_port"] = to_check_df["src_port"].astype(str)
                to_check_df["dst_port"] = to_check_df["dst_port"].astype(str)
                to_check_df["ip_protocol"] = to_check_df["ip_protocol"].astype(str)

                to_check_df = to_check_df.set_index(["src_ip", "dst_ip", "src_port", "dst_port", "ip_protocol"])

                merged_df_2 = to_check_df.merge(on=["src_ip", "dst_ip", "src_port", "dst_port", "ip_protocol"], right=bro_original_df, how="left")

                merged_df_2 = merged_df_2.reset_index()
                merged_df_2 = merged_df_2.rename(columns={"src_ip": "dst_ip", "dst_ip": "src_ip", "src_port" : "dst_port", "dst_port" : "src_port"})

                detailed_label_2_df = merged_df_2.dropna()
                detailed_label_2_df["status"] = "Response"

                deleted_2_df = merged_df_2[merged_df_2.duplicated(["src_ip", "dst_ip", "src_port", "dst_port", "ip_protocol"], keep=False)]
                deleted_2_df["status"] = "Mixed"

                unknown_df = merged_df_2[merged_df_2.isnull().any(axis=1)]
                unknown_df["status"] = "Unknown"

                combined_detailed_label_df = detailed_label_df.append(detailed_label_2_df)
                combined_detailed_label_2_df = combined_detailed_label_df.drop_duplicates(subset=["src_ip", "dst_ip", "src_port", "dst_port", "ip_protocol"],
                                                                                          keep=False)
                # combined_detailed_label_2_df["status"] = "Keep"
                deleted_3_df = combined_detailed_label_df[
                    combined_detailed_label_df.duplicated(["src_ip", "dst_ip", "src_port", "dst_port", "ip_protocol"], keep=False)]

                combined_deleted_df = deleted_df.append(deleted_2_df).append(deleted_3_df)
                combined_deleted_df = combined_deleted_df.drop_duplicates(subset=["src_ip", "dst_ip", "src_port", "dst_port", "ip_protocol", 'detailed_label'],
                                                                          keep='last')
                combined_deleted_df["status"] = "Mixed"

                combined_df = combined_detailed_label_2_df.append(combined_deleted_df).append(unknown_df)

                combined_df["detailed_label"] = combined_df.detailed_label.astype(str)

                combined_df["detailed_label"] = combined_df["detailed_label"].fillna(value="Unknown")
                combined_df["detailed_label_count"] = combined_df["detailed_label_count"].fillna(value="0")

                combined_df["detailed_label"] = combined_df["detailed_label"].replace(to_replace="nan", value="Unknown")
                combined_df["detailed_label"] = combined_df["detailed_label"].replace(to_replace="-", value="Benign")

                combined_df["label"] = np.where(combined_df["detailed_label"] == "Benign", "Benign", "Malicious")
                combined_df["label"] = np.where(combined_df["detailed_label"] == "Unknown", "Unknown",
                                                combined_df["label"])

                columns_list = ["src_ip", "dst_ip", "src_port", "dst_port", "ip_protocol", "ip_tos", "scenario", "file",
                                "connection_length", "label", "detailed_label", "detailed_label_count", "status"]

                combined_df = combined_df.reindex(columns=columns_list)

                combined_df.to_csv(path_to_csv_file, index=False)

            else:
                old_info_df["label"] = "Unknown"
                old_info_df["detailed_label"] = "Unknown"
                old_info_df["detailed_label_count"] = 0
                old_info_df["status"] = "Unknown"

                columns_list = ["src_ip", "dst_ip", "src_port", "dst_port", "ip_protocol", "ip_tos", "scenario", "file",
                                "connection_length", "label", "detailed_label", "detailed_label_count", "status"]

                old_info_df = combined_df.reindex(columns=columns_list)
                old_info_df.to_csv(path_to_csv_file, index=False)

    @staticmethod
    def restart_creating_summary_from_separate_files_for_netflow(path_to_iot_scenarios_folder, folder_to_filtered_files,
                                                       filename_addition):

        path_to_iot_scenarios_folder = path_to_iot_scenarios_folder
        folder_to_filtered_files = folder_to_filtered_files
        filename_addition = filename_addition

        scan_file_order_path = folder_to_filtered_files + "/scan_order.txt"
        log_order_path = folder_to_filtered_files + "/log_order.txt"

        with open(scan_file_order_path, 'r') as inputfile:
            scanned_files = inputfile.readlines()

        with open(log_order_path, 'r') as inputfile:
            logged_files = inputfile.readlines()

        scanned_files_list = [x.strip() for x in scanned_files]
        logged_files_list = [x.strip() for x in logged_files]

        folders_still_to_scan = []

        for scanned_file in scanned_files_list:
            if scanned_file not in logged_files_list:
                folders_still_to_scan.append(scanned_file)

        folders = folders_still_to_scan

        folders = list(map(lambda x: (x.split(",")[0], x.split(",")[1]), folders))

        for index, (scenario_name, file_name) in enumerate(folders):
            print("Scenario name: " + scenario_name)
            print("File name : " + file_name)
            print("Number: " + str(index + 1) + "/" + str(len(folders)))

            log_order_path = folder_to_filtered_files + "/" + "log_order.txt"
            with open(log_order_path, 'a') as log_order_file:
                log_order_file.write(scenario_name + "," + file_name + "\n")
                log_order_file.close()

            print("Reading PCAP File")

            path_to_csv_file = folder_to_filtered_files + "/" + scenario_name + "/" + file_name + "/" + file_name + "_summary.csv"
            path_to_pcap_file = folder_to_filtered_files + "/" + scenario_name + "/" + file_name + "/" + file_name + "_" + filename_addition + ".pcap"
            path_to_original_folder = path_to_iot_scenarios_folder + "/" + scenario_name

            path_to_old_file = folder_to_filtered_files + "/" + scenario_name + "/" + file_name + "/" + file_name + "_old.csv"
            path_to_bro_file = folder_to_filtered_files + "/" + scenario_name + "/" + file_name + "/" + file_name + "_bro.csv"
            path_to_merge_file = folder_to_filtered_files + "/" + scenario_name + "/" + file_name + "/" + file_name + "_merge.csv"

            file_packet_dic = {}
            with PcapReader(path_to_pcap_file) as packets:
                for packet_count, packet in enumerate(packets):

                    packet_string = packet.show(dump=True)
                    packet_for_print = packet_string
                    packet_string = packet_string.split("\n")
                    packet_string = [x.replace(" ", "") for x in packet_string]

                    current_layer = "none"
                    packet_dic = {}
                    for line in packet_string:
                        if len(line) > 0:
                            if line[0] == '#':
                                new_layer = line.split('[')[1].split(']')[0]
                                current_layer = new_layer
                                packet_dic[current_layer] = {}
                            elif (line[0] != '\\') & (line[0] != '|'):
                                key = line.split("=")[0]
                                value = line.split("=")[1]

                                packet_dic[current_layer][key] = value

                    src_ip = packet_dic["IP"]["src"]
                    dst_ip = packet_dic["IP"]["dst"]
                    ip_protocol = packet_dic["IP"]["proto"].upper()

                    if ip_protocol == "UDP" and "UDP" in packet_dic:
                        src_port = packet_dic["UDP"]["sport"]
                        dst_port = packet_dic["UDP"]["dport"]
                    elif ip_protocol == "TCP" and "TCP" in packet_dic:
                        src_port = packet_dic["TCP"]["sport"]
                        dst_port = packet_dic["TCP"]["dport"]
                    elif ip_protocol == "ICMP" and "ICMP" in packet_dic:
                        src_port = 0
                        dst_port = str(packet_dic["ICMP"]["type"]) + "/" + str(packet_dic["ICMP"]["code"])
                    else:
                        src_port = 0
                        dst_port = 0

                    if not isinstance(src_port, int):
                        if not all(char.isdigit() for char in src_port):
                            try:
                                src_port = socket.getservbyname(src_port, ip_protocol)
                            except:
                                src_port = src_port

                    if not isinstance(dst_port, int) or ():
                        if not all(char.isdigit() for char in dst_port):
                            try:
                                dst_port = socket.getservbyname(dst_port, ip_protocol)
                            except:
                                dst_port = dst_port

                    ip_tos = packet_dic["IP"]["tos"]

                    if (src_ip, dst_ip, ip_protocol, src_port, dst_port, ip_tos) in file_packet_dic:
                        old_value = file_packet_dic[(src_ip, dst_ip, ip_protocol, src_port, dst_port, ip_tos)]
                        new_value = old_value + 1
                        file_packet_dic[(src_ip, dst_ip, ip_protocol, src_port, dst_port, ip_tos)] = new_value
                    else:
                        file_packet_dic[(src_ip, dst_ip, ip_protocol, src_port, dst_port, ip_tos)] = 1

            packets.close()

            src_ip_list = []
            dst_ip_list = []
            ip_protocol_list = []
            src_port_list = []
            dst_port_list = []
            ip_tos_list = []
            connection_length_list = []

            for (src_ip, dst_ip, ip_protocol, src_port, dst_port, ip_tos), connection_length in file_packet_dic.items():
                src_ip_list.append(src_ip)
                dst_ip_list.append(dst_ip)
                ip_protocol_list.append(ip_protocol)
                src_port_list.append(src_port)
                dst_port_list.append(dst_port)
                ip_tos_list.append(ip_tos)

                connection_length_list.append(connection_length)

            data = {"src_ip": src_ip_list, "dst_ip": dst_ip_list, "ip_protocol": ip_protocol_list,
                    "src_port": src_port_list,
                    "dst_port": dst_port_list, "ip_tos": ip_tos_list, "connection_length": connection_length_list}
            old_info_df = pd.DataFrame(data)
            old_info_df["scenario"] = scenario_name
            old_info_df["file"] = file_name

            print("Adding Logg Data")
            sub_folders = [f.path for f in os.scandir(path_to_original_folder) if f.is_dir()]
            bro_folder_found = False

            for sub_folder in sub_folders:
                base_name = str(os.path.basename(sub_folder))

                if base_name == "bro":
                    labeled_files = glob.glob(sub_folder + "/*.labeled")
                    bro_folder_found = True
                    break

            if bro_folder_found and len(labeled_files) > 0:

                logg_file = labeled_files[0]

                zat = LogToDataFrame()
                bro_original_df = zat.create_dataframe(logg_file)
                bro_original_df["label"] = bro_original_df["tunnel_parents   label   detailed-label"].apply(
                    lambda x: x.split("  ")[1].strip())
                bro_original_df["detailed_label"] = bro_original_df["tunnel_parents   label   detailed-label"].apply(
                    lambda x: x.split("  ")[2].strip())
                bro_original_df = bro_original_df.rename(
                    columns={"id.orig_h": "src_ip", "id.resp_h": "dst_ip", "id.orig_p": "src_port",
                             "id.resp_p": "dst_port", "proto": "ip_protocol"})
                bro_original_df = bro_original_df.drop(
                    columns=['uid', 'service', 'duration', 'orig_bytes', 'resp_bytes', 'conn_state', 'local_orig',
                             'local_resp', 'missed_bytes', 'history', 'orig_pkts', 'orig_ip_bytes',
                             'resp_pkts', 'resp_ip_bytes', 'tunnel_parents   label   detailed-label'])
                bro_original_df["ip_protocol"] = bro_original_df["ip_protocol"].str.upper()
                bro_original_df.sort_values(["src_ip", "dst_ip", "src_port", "dst_port", "ip_protocol"], inplace=True)

                bro_original_df = bro_original_df.groupby(["src_ip", "dst_ip", "src_port", "dst_port", "ip_protocol"])[
                    'detailed_label'].value_counts().to_frame()
                bro_original_df = bro_original_df.rename(columns={"detailed_label": "detailed_label_count"})
                bro_original_df = bro_original_df.reset_index()

                bro_original_df["src_ip"] = bro_original_df["src_ip"].apply(lambda x: str(x).strip())
                bro_original_df["dst_ip"] = bro_original_df["dst_ip"].apply(lambda x: str(x).strip())
                bro_original_df["src_port"] = bro_original_df["src_port"].apply(lambda x: str(x).strip())
                bro_original_df["dst_port"] = bro_original_df["dst_port"].apply(lambda x: str(x).strip())
                bro_original_df["ip_protocol"] = bro_original_df["ip_protocol"].apply(lambda x: str(x).strip())

                # bro_original_df["src_ip"] = bro_original_df["src_ip"].astype(str)
                # bro_original_df["dst_ip"] = bro_original_df["dst_ip"].astype(str)
                # bro_original_df["src_port"] = bro_original_df["src_port"].astype(str)
                # bro_original_df["dst_port"] = bro_original_df["dst_port"].astype(str)
                # bro_original_df["ip_protocol"] = bro_original_df["ip_protocol"].astype(str)

                bro_original_df = bro_original_df.sort_values(
                    by=["src_ip", "dst_ip", "src_port", "dst_port", "ip_protocol"])
#                bro_original_df = bro_original_df.set_index(["src_ip", "dst_ip", "src_port", "dst_port", "ip_protocol"])
                old_info_df = old_info_df.sort_values(["src_ip", "dst_ip", "src_port", "dst_port", "ip_protocol"])
              #  old_info_df = old_info_df.set_index(["src_ip", "dst_ip", "src_port", "dst_port", "ip_protocol"])
                merged_df = old_info_df.merge(on=["src_ip", "dst_ip", "src_port", "dst_port", "ip_protocol"],
                                              right=bro_original_df, how="inner")
                merged_df = merged_df.reset_index()
                old_info_df = old_info_df.reset_index()

                detailed_label_df = merged_df.drop_duplicates(
                    subset=["src_ip", "dst_ip", "src_port", "dst_port", "ip_protocol"], keep=False)
                detailed_label_df["status"] = "Found"
                deleted_df = merged_df[
                    merged_df.duplicated(["src_ip", "dst_ip", "src_port", "dst_port", "ip_protocol"], keep=False)]
                deleted_df["status"] = "Mixed"

                to_check_df = pd.concat(
                    [old_info_df,
                     merged_df.drop_duplicates(subset=["src_ip", "dst_ip", "src_port", "dst_port", "ip_protocol"],
                                               keep='last')]).drop_duplicates(
                    subset=["src_ip", "dst_ip", "src_port", "dst_port", "ip_protocol"], keep=False)
                to_check_df = to_check_df.reset_index()
                to_check_df = to_check_df.rename(
                    columns={"src_ip": "dst_ip", "dst_ip": "src_ip", "src_port": "dst_port",
                             "dst_port": "src_port"}).drop(
                    columns=["detailed_label", "detailed_label_count"])

                to_check_df["src_ip"] = to_check_df["src_ip"].apply(lambda x: str(x).strip())
                to_check_df["dst_ip"] = to_check_df["dst_ip"].apply(lambda x: str(x).strip())
                to_check_df["src_port"] = to_check_df["src_port"].apply(lambda x: str(x).strip())
                to_check_df["dst_port"] = to_check_df["dst_port"].apply(lambda x: str(x).strip())
                to_check_df["ip_protocol"] = to_check_df["ip_protocol"].apply(lambda x: str(x).strip())

                to_check_df["src_ip"] = to_check_df["src_ip"].astype(str)
                to_check_df["dst_ip"] = to_check_df["dst_ip"].astype(str)
                to_check_df["src_port"] = to_check_df["src_port"].astype(str)
                to_check_df["dst_port"] = to_check_df["dst_port"].astype(str)
                to_check_df["ip_protocol"] = to_check_df["ip_protocol"].astype(str)

                to_check_df = to_check_df.set_index(["src_ip", "dst_ip", "src_port", "dst_port", "ip_protocol"])

                merged_df_2 = to_check_df.merge(on=["src_ip", "dst_ip", "src_port", "dst_port", "ip_protocol"],
                                                right=bro_original_df, how="left")

                #merged_df_2 = merged_df_2.reset_index()
                merged_df_2 = merged_df_2.rename(
                    columns={"src_ip": "dst_ip", "dst_ip": "src_ip", "src_port": "dst_port", "dst_port": "src_port"})

                detailed_label_2_df = merged_df_2.dropna()
                detailed_label_2_df["status"] = "Response"

                deleted_2_df = merged_df_2[
                    merged_df_2.duplicated(["src_ip", "dst_ip", "src_port", "dst_port", "ip_protocol"], keep=False)]
                deleted_2_df["status"] = "Mixed"

                unknown_df = merged_df_2[merged_df_2.isnull().any(axis=1)]
                unknown_df["status"] = "Unknown"

                combined_detailed_label_df = detailed_label_df.append(detailed_label_2_df)
                combined_detailed_label_2_df = combined_detailed_label_df.drop_duplicates(
                    subset=["src_ip", "dst_ip", "src_port", "dst_port", "ip_protocol"],
                    keep=False)
                # combined_detailed_label_2_df["status"] = "Keep"
                deleted_3_df = combined_detailed_label_df[
                    combined_detailed_label_df.duplicated(["src_ip", "dst_ip", "src_port", "dst_port", "ip_protocol"],
                                                          keep=False)]

                combined_deleted_df = deleted_df.append(deleted_2_df).append(deleted_3_df)
                combined_deleted_df = combined_deleted_df.drop_duplicates(
                    subset=["src_ip", "dst_ip", "src_port", "dst_port", "ip_protocol", 'detailed_label'],
                    keep='last')
                combined_deleted_df["status"] = "Mixed"

                combined_df = combined_detailed_label_2_df.append(combined_deleted_df).append(unknown_df)

                combined_df["detailed_label"] = combined_df.detailed_label.astype(str)

                combined_df["detailed_label"] = combined_df["detailed_label"].fillna(value="Unknown")
                combined_df["detailed_label_count"] = combined_df["detailed_label_count"].fillna(value="0")

                combined_df["detailed_label"] = combined_df["detailed_label"].replace(to_replace="nan", value="Unknown")
                combined_df["detailed_label"] = combined_df["detailed_label"].replace(to_replace="-", value="Benign")

                combined_df["label"] = np.where(combined_df["detailed_label"] == "Benign", "Benign", "Malicious")
                combined_df["label"] = np.where(combined_df["detailed_label"] == "Unknown", "Unknown",
                                                combined_df["label"])

                columns_list = ["src_ip", "dst_ip", "src_port", "dst_port", "ip_protocol", "ip_tos", "scenario", "file",
                                "connection_length", "label", "detailed_label", "detailed_label_count", "status"]

                combined_df = combined_df.reindex(columns=columns_list)

                combined_df.to_csv(path_to_csv_file, index=False)

            else:
                old_info_df["label"] = "Unknown"
                old_info_df["detailed_label"] = "Unknown"
                old_info_df["detailed_label_count"] = 0
                old_info_df["status"] = "Unknown"

                columns_list = ["src_ip", "dst_ip", "src_port", "dst_port", "ip_protocol", "ip_tos", "scenario", "file",
                                "connection_length", "label", "detailed_label", "detailed_label_count", "status"]

                old_info_df = combined_df.reindex(columns=columns_list)
                old_info_df.to_csv(path_to_csv_file, index=False)
