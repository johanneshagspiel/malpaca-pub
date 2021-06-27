import csv
import glob
import math
import os
import shutil
import sys
from random import random, seed
from timeit import default_timer as timer
import time
from statistics import mean
from pathlib import Path
import networkx as nx
import numpy as np
from scapy.layers.inet import IP, UDP, TCP, ICMP
from scapy.layers.ntp import NTPInfoIfStatsIPv4, NTPInfoIfStatsIPv6
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

class Scaling_Down_Dataset():

    @staticmethod
    def changing_max_length_one_scenario(path_to_scenario_to_change, path_to_storage, new_max_length, new_exp_name):

        path_to_scenario_to_change = path_to_scenario_to_change
        path_to_storage = path_to_storage
        new_max_length = int(new_max_length)
        new_exp_name = new_exp_name

        scenario_name = os.path.basename(path_to_scenario_to_change)
        scan_file_order_path = path_to_storage + "/scan_order.txt"

        print("Scenario name: " + scenario_name)

        scenario_folder_storage = path_to_storage + "/" + scenario_name
        os.mkdir(scenario_folder_storage)

        files = sorted([f.path for f in os.scandir(path_to_scenario_to_change) if f.is_dir()])
        files = list(map(lambda x: (x, str(os.path.basename(x)).strip()), files))

        for file_index, (file_path, file_name) in enumerate(files):

            print("File: " + str(file_index + 1) + "/" + str(len(files)))
            print("File name: " + file_name)

            with open(scan_file_order_path, 'a') as scan_file:
                scan_file.write(scenario_name + "," + file_name + "\n")
                scan_file.close()

            file_folder_storage = scenario_folder_storage + "/" + file_name
            os.mkdir(file_folder_storage)

            pcap_file_path = glob.glob(file_path + "/*.pcap")[0]
            csv_file_path = glob.glob(file_path + "/*.csv")[0]

            csv_df = pd.read_csv(csv_file_path)

            connections_below_max_connection_df = csv_df[csv_df["connection_length"] <= new_max_length]
            unchanged_connections = [x for x in zip(connections_below_max_connection_df["src_ip"],
                                                    connections_below_max_connection_df["dst_ip"])]

            connections_above_max_connection_df = csv_df[csv_df["connection_length"] > new_max_length]
            connections_above_max_connection_df["connection_length"] = new_max_length

            new_pcap_path = file_folder_storage + "/" + file_name + "_" + new_exp_name + ".pcap"

            if len(connections_above_max_connection_df) > 0:

                to_change_condition = [x for x in zip(connections_above_max_connection_df["src_ip"],
                                                      connections_above_max_connection_df["dst_ip"])]
                to_change_connections_dic = dict.fromkeys(to_change_condition, 0)

                with PcapReader(pcap_file_path) as packets, PcapWriter(new_pcap_path, append=True,
                                                                       sync=True) as pktdump:
                    for packet in packets:

                        src_ip = packet[IP].src
                        dst_ip = packet[IP].dst

                        if (src_ip, dst_ip) in unchanged_connections:
                            pktdump.write(packet)

                        elif (src_ip, dst_ip) in to_change_connections_dic:
                            current_conn_length = to_change_connections_dic[(src_ip, dst_ip)]

                            if current_conn_length < new_max_length:
                                new_conn_length = current_conn_length + 1
                                to_change_connections_dic[(src_ip, dst_ip)] = new_conn_length
                                pktdump.write(packet)

                packets.close()
                pktdump.close()

            else:
                shutil.copy(pcap_file_path, new_pcap_path)

            csv_summary_path = file_folder_storage + "/" + file_name + "_" + new_exp_name + "_summary.csv"

            combined_df = connections_below_max_connection_df.append(connections_above_max_connection_df)
            combined_df = combined_df.sort_values(by="status")

            combined_df.to_csv(csv_summary_path, index=False)

    @staticmethod
    def changing_max_length_dataset(path_to_dataset_to_change, path_to_storage, new_max_length, new_exp_name):

        path_to_dataset_to_change = path_to_dataset_to_change
        path_to_storage = path_to_storage
        new_max_length = int(new_max_length)
        new_exp_name = new_exp_name

        new_folder_path = path_to_storage + "/" + new_exp_name
        scan_file_order_path = new_folder_path + "/" + "scan_order.txt"
        os.mkdir(new_folder_path)

        scenarios = sorted([f.path for f in os.scandir(path_to_dataset_to_change) if f.is_dir()])
        scenarios = list(map(lambda x: (x, str(os.path.basename(x)).strip()), scenarios))

        for scenario_index, (scenario_path, scenario_name) in enumerate(scenarios):

            print("Scenario: " + str(scenario_index + 1) + "/" + str(len(scenarios)))
            print("Scenario name: " + scenario_name)

            scenario_folder_storage = new_folder_path + "/" + scenario_name
            os.mkdir(scenario_folder_storage)

            files = sorted([f.path for f in os.scandir(scenario_path) if f.is_dir()])
            files = list(map(lambda x: (x, str(os.path.basename(x)).strip()), files))

            for file_index, (file_path, file_name) in enumerate(files):

                print("File: " + str(file_index + 1) + "/" + str(len(files)))
                print("File name: " + file_name)

                with open(scan_file_order_path, 'a') as scan_file:
                    scan_file.write(scenario_name + "," + file_name + "\n")
                    scan_file.close()

                file_folder_storage = scenario_folder_storage + "/" + file_name
                os.mkdir(file_folder_storage)

                pcap_file_path = glob.glob(file_path + "/*.pcap")[0]
                csv_file_path = glob.glob(file_path + "/*.csv")[0]

                csv_df = pd.read_csv(csv_file_path)

                connections_below_max_connection_df = csv_df[csv_df["connection_length"] <= new_max_length]
                unchanged_connections = [x for x in zip(connections_below_max_connection_df["src_ip"], connections_below_max_connection_df["dst_ip"])]

                connections_above_max_connection_df = csv_df[csv_df["connection_length"] > new_max_length]
                connections_above_max_connection_df["connection_length"] = new_max_length

                new_pcap_path = file_folder_storage + "/" + file_name + "_" + new_exp_name + ".pcap"

                if len(connections_above_max_connection_df) > 0:

                    to_change_condition = [x for x in zip(connections_above_max_connection_df["src_ip"], connections_above_max_connection_df["dst_ip"])]
                    to_change_connections_dic = dict.fromkeys(to_change_condition, 0)

                    with PcapReader(pcap_file_path) as packets, PcapWriter(new_pcap_path, append=True, sync=True) as pktdump:
                        for packet in packets:

                            src_ip = packet[IP].src
                            dst_ip = packet[IP].dst

                            if (src_ip, dst_ip) in unchanged_connections:
                                pktdump.write(packet)

                            elif (src_ip, dst_ip) in to_change_connections_dic:
                                current_conn_length = to_change_connections_dic[(src_ip, dst_ip)]

                                if current_conn_length < new_max_length:
                                    new_conn_length = current_conn_length + 1
                                    to_change_connections_dic[(src_ip, dst_ip)] = new_conn_length
                                    pktdump.write(packet)

                    packets.close()
                    pktdump.close()

                else:
                    shutil.copy(pcap_file_path, new_pcap_path)

                csv_summary_path = file_folder_storage + "/" + file_name + "_" + new_exp_name + "_summary.csv"

                combined_df = connections_below_max_connection_df.append(connections_above_max_connection_df)
                combined_df = combined_df.sort_values(by="status")

                combined_df.to_csv(csv_summary_path, index=False)

    @staticmethod
    def changing_min_length(path_to_dataset_to_change, path_to_storage, new_min_length, new_exp_name):

        path_to_dataset_to_change = path_to_dataset_to_change
        path_to_storage = path_to_storage
        new_min_length = int(new_min_length)
        new_exp_name = new_exp_name

        new_folder_path = path_to_storage + "/" + new_exp_name
        scan_file_order_path = new_folder_path + "/" + "scan_order.txt"
        os.mkdir(new_folder_path)

        scenarios = sorted([f.path for f in os.scandir(path_to_dataset_to_change) if f.is_dir()])
        scenarios = list(map(lambda x: (x, str(os.path.basename(x)).strip()), scenarios))

        for scenario_index, (scenario_path, scenario_name) in enumerate(scenarios):

            print("Scenario: " + str(scenario_index + 1) + "/" + str(len(scenarios)))
            print("Scenario name: " + scenario_name)

            scenario_folder_storage = new_folder_path + "/" + scenario_name
            os.mkdir(scenario_folder_storage)

            files = sorted([f.path for f in os.scandir(scenario_path) if f.is_dir()])
            files = list(map(lambda x: (x, str(os.path.basename(x)).strip()), files))

            for file_index, (file_path, file_name) in enumerate(files):

                print("File: " + str(file_index + 1) + "/" + str(len(files)))
                print("File name: " + file_name)

                with open(scan_file_order_path, 'a') as scan_file:
                    scan_file.write(scenario_name + "," + file_name + "\n")
                    scan_file.close()

                file_folder_storage = scenario_folder_storage + "/" + file_name
                os.mkdir(file_folder_storage)

                pcap_file = glob.glob(file_path + "/*.pcap")[0]
                csv_file = glob.glob(file_path + "/*.csv")[0]

                csv_df = pd.read_csv(csv_file)

                down_balanced_df = csv_df[csv_df["connection_length"] >= new_min_length]
                connections_needed = [x for x in zip(down_balanced_df["src_ip"], down_balanced_df["dst_ip"])]

                new_pcap_path = file_folder_storage + "/" + file_name + "_" + new_exp_name + ".pcap"
                with PcapReader(pcap_file) as packets, PcapWriter(new_pcap_path, append=True, sync=True) as pktdump:
                    for packet in packets:

                        src_ip = packet[IP].src
                        dst_ip = packet[IP].dst

                        if (src_ip, dst_ip) in connections_needed:
                            pktdump.write(packet)
                packets.close()
                pktdump.close()

                csv_summary_path = file_folder_storage + "/" + file_name + "_" + new_exp_name + "_summary.csv"
                down_balanced_df.to_csv(csv_summary_path, index=False)
