import csv
import glob
import math
import os
import socket
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

class Dataset_Balancing():

    @staticmethod
    def creating_balanced_dataset_netflow(path_to_balancing_file, path_to_original_data_set, path_to_storage, old_exp_name,
                                  new_exp_name):

        path_to_balancing_file = path_to_balancing_file
        path_to_original_data_set = path_to_original_data_set
        path_to_storage = path_to_storage
        old_exp_name = old_exp_name
        new_exp_name = new_exp_name

        new_folder_path = path_to_storage + "/" + new_exp_name
        os.mkdir(new_folder_path)

        balancing_df = pd.read_csv(path_to_balancing_file)

        for scenario_index, scenario in enumerate(balancing_df.iterrows()):

            scenario_name = scenario[1]["scenario"]
            row = scenario[1].drop("scenario")

            print("Balancing Scenario: " + str(scenario_index + 1) + "/" + str(len(balancing_df.index)))
            print("Scenario: " + scenario_name)

            detailed_labels_to_get = pd.Series(row).where(lambda x: x != 0).dropna()

            if len(detailed_labels_to_get) > 0:

                scenario_path = path_to_original_data_set + "/" + scenario_name

                files = sorted([f.path for f in os.scandir(scenario_path) if f.is_dir()])

                for file_index, file in enumerate(files):
                    csv_summary = glob.glob(file + "/*.csv")[0]
                    csv_summary_df = pd.read_csv(csv_summary)

                    if file_index == 0:
                        combined_df = csv_summary_df
                    else:
                        combined_df = combined_df.append(csv_summary_df)

                combined_df["detailed_label"] = combined_df["detailed_label"].str.lower()
                found_df = combined_df[(combined_df["status"] == "Found")]
                response_df = combined_df[(combined_df["status"] == "Response")]
                combined_df = found_df.append(response_df)

                for index, detailed_label_to_get in enumerate(detailed_labels_to_get.iteritems()):
                    detailed_label = detailed_label_to_get[0]
                    amount = detailed_label_to_get[1]

                    filtered_df = combined_df[combined_df["detailed_label"] == detailed_label]
                    selected_df = filtered_df.sample(n=amount)

                    if index == 0:
                        combined_selected_df = selected_df
                    else:
                        combined_selected_df = combined_selected_df.append(selected_df)

                files = combined_selected_df["file"].unique().tolist()

                for selected_file_index, file in enumerate(files):

                    print("Balancing File: " + str(selected_file_index + 1) + "/" + str(len(files)))
                    print("File: " + file)

                    file_df = combined_selected_df[combined_selected_df["file"] == file]
                    scenario_name = file_df["scenario"].unique().tolist()[0]

                    scenario_folder_path = new_folder_path + "/" + scenario_name

                    if os.path.exists(scenario_folder_path) == False:
                        os.mkdir(scenario_folder_path)

                    file_path = scenario_folder_path + "/" + file
                    os.mkdir(file_path)

                    path_to_original_pcap = path_to_original_data_set + "/" + scenario_name + "/" + file + "/" + file + "_" + old_exp_name + ".pcap"

                    connections_needed = [x for x in zip(file_df["src_ip"], file_df["dst_ip"], file_df["ip_protocol"], file_df["src_port"], file_df["dst_port"])]
                    connections_needed = [(str(x[0]).strip(), str(x[1]).strip(), str(x[2]).strip(), str(x[3]).strip(), str(x[4]).strip(),) for x in connections_needed]

                    new_pcap_path = file_path + "/" + file + "_" + new_exp_name + ".pcap"


                    appended_packets = 0
                    file_dic = {}
                    with PcapReader(path_to_original_pcap) as packets:
                        for packet in packets:

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

                            src_ip = str(src_ip.strip())
                            dst_ip = str(dst_ip.strip())
                            ip_protocol = str(ip_protocol.strip())
                            src_port = str(src_port).strip()
                            dst_port = str(dst_port).strip()

                            if (src_ip, dst_ip, ip_protocol, src_port, dst_port) in connections_needed:
                                if (src_ip, dst_ip, ip_protocol, src_port, dst_port) in file_dic:
                                    file_dic[(src_ip, dst_ip, ip_protocol, src_port, dst_port)].append(packet)
                                else:
                                    file_dic[(src_ip, dst_ip, ip_protocol, src_port, dst_port)] = [packet]
                                appended_packets = appended_packets + 1

                                if appended_packets % 500000 == 0:
                                    if appended_packets != 0:
                                        pktdump = PcapWriter(new_pcap_path, append=True, sync=True)
                                        for to_write_packets in file_dic.values():
                                            for to_write_packet in to_write_packets:
                                                pktdump.write(to_write_packet)
                                        pktdump.close()
                                        file_dic.clear()
                    packets.close()

                    if len(file_dic) > 0:
                        pktdump = PcapWriter(new_pcap_path, append=True, sync=True)
                        for to_write_packets in file_dic.values():
                            for to_write_packet in to_write_packets:
                                pktdump.write(to_write_packet)
                        pktdump.close()
                        file_dic.clear()

                    csv_summary_path = file_path + "/" + file + "_summary.csv"
                    file_df.to_csv(csv_summary_path, index=False)

    @staticmethod
    def creating_balanced_dataset(path_to_balancing_file, path_to_original_data_set, path_to_storage, old_exp_name, new_exp_name):

        path_to_balancing_file = path_to_balancing_file
        path_to_original_data_set = path_to_original_data_set
        path_to_storage = path_to_storage
        old_exp_name = old_exp_name
        new_exp_name = new_exp_name

        new_folder_path = path_to_storage + "/" + new_exp_name
        os.mkdir(new_folder_path)

        balancing_df = pd.read_csv(path_to_balancing_file)

        for scenario_index, scenario in enumerate(balancing_df.iterrows()):

            scenario_name = scenario[1]["scenario"]
            row = scenario[1].drop("scenario")

            print("Balancing Scenario: " + str(scenario_index + 1) + "/" + str(len(balancing_df.index)))
            print("Scenario: " + scenario_name)

            detailed_labels_to_get = pd.Series(row).where(lambda x : x!=0).dropna()

            if len(detailed_labels_to_get) > 0:

                scenario_path = path_to_original_data_set + "/" + scenario_name

                files = sorted([f.path for f in os.scandir(scenario_path) if f.is_dir()])

                for file_index, file in enumerate(files):
                    csv_summary = glob.glob(file + "/*.csv")[0]
                    csv_summary_df = pd.read_csv(csv_summary)

                    if file_index == 0:
                        combined_df = csv_summary_df
                    else:
                        combined_df = combined_df.append(csv_summary_df)

                combined_df["detailed_label"] = combined_df["detailed_label"].str.lower()
                found_df = combined_df[(combined_df["status"] == "Found")]
                response_df = combined_df[(combined_df["status"] == "Response")]
                combined_df = found_df.append(response_df)

                for index, detailed_label_to_get in enumerate(detailed_labels_to_get.iteritems()):
                    detailed_label = detailed_label_to_get[0]
                    amount = detailed_label_to_get[1]

                    filtered_df = combined_df[combined_df["detailed_label"] == detailed_label]
                    selected_df = filtered_df.sample(n=amount)

                    if index == 0:
                        combined_selected_df = selected_df
                    else:
                        combined_selected_df = combined_selected_df.append(selected_df)

                files = combined_selected_df["file"].unique().tolist()

                for selected_file_index, file in enumerate(files):

                    print("Balancing File: " + str(selected_file_index + 1) + "/" + str(len(files)))
                    print("File: " + file)

                    file_df = combined_selected_df[combined_selected_df["file"] == file]
                    scenario_name = file_df["scenario"].unique().tolist()[0]

                    scenario_folder_path = new_folder_path + "/" + scenario_name

                    if os.path.exists(scenario_folder_path) == False:
                        os.mkdir(scenario_folder_path)

                    file_path = scenario_folder_path + "/" + file
                    os.mkdir(file_path)

                    path_to_original_pcap = path_to_original_data_set + "/" + scenario_name + "/" + file + "/" + file + "_" + old_exp_name + ".pcap"
                    connections_needed = [x for x in zip(file_df["src_ip"], file_df["dst_ip"])]

                    new_pcap_path = file_path + "/" + file + "_" + new_exp_name + ".pcap"

                    # with PcapReader(path_to_original_pcap) as packets, PcapWriter(new_pcap_path, append=True, sync=True) as pktdump:
                    #     for packet in packets:
                    #
                    #         src_ip = packet[IP].src
                    #         dst_ip = packet[IP].dst
                    #
                    #         if (src_ip, dst_ip) in connections_needed:
                    #             pktdump.write(packet)
                    # packets.close()
                    # pktdump.close()

                    appended_packets = 0
                    file_dic = {}
                    with PcapReader(path_to_original_pcap) as packets:
                        for packet in packets:

                            src_ip = packet[IP].src
                            dst_ip = packet[IP].dst

                            if (src_ip, dst_ip) in connections_needed:
                                if (src_ip, dst_ip) in file_dic:
                                    file_dic[(src_ip, dst_ip)].append(packet)
                                else:
                                    file_dic[(src_ip, dst_ip)] = [packet]
                                appended_packets = appended_packets + 1

                                if appended_packets % 500000 == 0:
                                    if appended_packets != 0:
                                        pktdump = PcapWriter(new_pcap_path, append=True, sync=True)
                                        for to_write_packets in file_dic.values():
                                            for to_write_packet in to_write_packets:
                                                pktdump.write(to_write_packet)
                                        pktdump.close()
                                        file_dic.clear()
                    packets.close()

                    if len(file_dic) > 0:
                        pktdump = PcapWriter(new_pcap_path, append=True, sync=True)
                        for to_write_packets in file_dic.values():
                            for to_write_packet in to_write_packets:
                                pktdump.write(to_write_packet)
                        pktdump.close()
                        file_dic.clear()

                    csv_summary_path = file_path + "/" + file + "_summary.csv"
                    file_df.to_csv(csv_summary_path, index=False)

    @staticmethod
    def creating_balanced_dataset_with_min_size(path_to_balancing_file, path_to_original_data_set, path_to_storage, old_exp_name,
                                  new_exp_name, min_size):

        path_to_balancing_file = path_to_balancing_file
        path_to_original_data_set = path_to_original_data_set
        path_to_storage = path_to_storage
        old_exp_name = old_exp_name
        new_exp_name = new_exp_name
        min_size = int(min_size)

        new_folder_path = path_to_storage + "/" + new_exp_name
        os.mkdir(new_folder_path)

        balancing_df = pd.read_csv(path_to_balancing_file)

        for scenario_index, scenario in enumerate(balancing_df.iterrows()):

            scenario_name = scenario[1]["scenario"]
            row = scenario[1].drop("scenario")

            print("Balancing Scenario: " + str(scenario_index + 1) + "/" + str(len(balancing_df.index)))
            print("Scenario: " + scenario_name)

            detailed_labels_to_get = pd.Series(row).where(lambda x: x != 0).dropna()

            if len(detailed_labels_to_get) > 0:

                scenario_path = path_to_original_data_set + "/" + scenario_name

                files = sorted([f.path for f in os.scandir(scenario_path) if f.is_dir()])

                for file_index, file in enumerate(files):
                    csv_summary = glob.glob(file + "/*.csv")[0]
                    csv_summary_df = pd.read_csv(csv_summary)

                    if file_index == 0:
                        combined_df = csv_summary_df
                    else:
                        combined_df = combined_df.append(csv_summary_df)

                combined_df["detailed_label"] = combined_df["detailed_label"].str.lower()
                combined_df = combined_df[combined_df["status"] == "Found"]
                combined_df = combined_df[combined_df["connection_length"] >= min_size]

                for index, detailed_label_to_get in enumerate(detailed_labels_to_get.iteritems()):
                    detailed_label = detailed_label_to_get[0]
                    amount = detailed_label_to_get[1]

                    filtered_df = combined_df[combined_df["detailed_label"] == detailed_label]

                    selected_df = filtered_df.sample(n=amount)

                    if index == 0:
                        combined_selected_df = selected_df
                    else:
                        combined_selected_df = combined_selected_df.append(selected_df)

                files = combined_selected_df["file"].unique().tolist()

                for selected_file_index, file in enumerate(files):

                    print("Balancing File: " + str(selected_file_index + 1) + "/" + str(len(files)))
                    print("File: " + file)

                    file_df = combined_selected_df[combined_selected_df["file"] == file]
                    scenario_name = file_df["scenario"].unique().tolist()[0]

                    scenario_folder_path = new_folder_path + "/" + scenario_name

                    if os.path.exists(scenario_folder_path) == False:
                        os.mkdir(scenario_folder_path)

                    file_path = scenario_folder_path + "/" + file
                    os.mkdir(file_path)

                    path_to_original_pcap = path_to_original_data_set + "/" + scenario_name + "/" + file + "/" + file + "_" + old_exp_name + ".pcap"
                    connections_needed = [x for x in zip(file_df["src_ip"], file_df["dst_ip"])]

                    new_pcap_path = file_path + "/" + file + "_" + new_exp_name + ".pcap"

                    # with PcapReader(path_to_original_pcap) as packets, PcapWriter(new_pcap_path, append=True, sync=True) as pktdump:
                    #     for packet in packets:
                    #
                    #         src_ip = packet[IP].src
                    #         dst_ip = packet[IP].dst
                    #
                    #         if (src_ip, dst_ip) in connections_needed:
                    #             pktdump.write(packet)
                    # packets.close()
                    # pktdump.close()

                    appended_packets = 0
                    file_dic = {}
                    with PcapReader(path_to_original_pcap) as packets:
                        for packet in packets:

                            src_ip = packet[IP].src
                            dst_ip = packet[IP].dst

                            if (src_ip, dst_ip) in connections_needed:
                                if (src_ip, dst_ip) in file_dic:
                                    file_dic[(src_ip, dst_ip)].append(packet)
                                else:
                                    file_dic[(src_ip, dst_ip)] = [packet]
                                appended_packets = appended_packets + 1

                                if appended_packets % 500000 == 0:
                                    if appended_packets != 0:
                                        pktdump = PcapWriter(new_pcap_path, append=True, sync=True)
                                        for to_write_packets in file_dic.values():
                                            for to_write_packet in to_write_packets:
                                                pktdump.write(to_write_packet)
                                        pktdump.close()
                                        file_dic.clear()
                    packets.close()

                    if len(file_dic) > 0:
                        pktdump = PcapWriter(new_pcap_path, append=True, sync=True)
                        for to_write_packets in file_dic.values():
                            for to_write_packet in to_write_packets:
                                pktdump.write(to_write_packet)
                        pktdump.close()
                        file_dic.clear()

                    csv_summary_path = file_path + "/" + file + "_summary.csv"
                    file_df.to_csv(csv_summary_path, index=False)