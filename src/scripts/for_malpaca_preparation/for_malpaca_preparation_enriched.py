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

class For_Malpaca_Preparation_Enriched():

    @staticmethod
    def split_connection_into_X_equal_parts_for_malpaca(threshold, parts, folder_to_filtered_files, folder_to_move_data_to, old_file_addition):

        folder_to_filtered_files = folder_to_filtered_files
        folder_to_move_data_to = folder_to_move_data_to

        threshold = int(threshold)
        parts = int(parts)

        new_folder_name = folder_to_move_data_to + "/" + str(threshold) + "_threshold_" + str(parts) + "_parts"
        os.mkdir(new_folder_name)

        for piece in range(1, (parts + 1)):
            new_folder = new_folder_name + "/" + str(threshold) + "_threshold_" + str(piece) + "_part"
            os.mkdir(new_folder)

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
            print("Create pcap file")

            path_to_csv_file = folder_to_filtered_files + "/" + scenario_name + "/" + file_name + "/" + file_name + "_summary.csv"
            path_to_pcap_file = folder_to_filtered_files + "/" + scenario_name + "/" + file_name + "/" + file_name + "_" + old_file_addition + ".pcap"

            parts_list = []
            for part in range(parts):
                parts_list.append([])

            file_packet_dic = {}
            connections_used = []

            with PcapReader(path_to_pcap_file) as packets:
                for packet_count, packet in enumerate(packets):

                    src_ip = packet[IP].src
                    dst_ip = packet[IP].dst

                    if (src_ip, dst_ip) not in file_packet_dic:
                        file_packet_dic[(src_ip, dst_ip)] = [packet]
                    else:
                        file_packet_dic[(src_ip, dst_ip)].append(packet)

            for address, packets_value in file_packet_dic.items():
                len_connection = len(packets_value)
                if len_connection >= (threshold * parts):
                    connections_used.append(address)

                    remainder = len_connection - (threshold * parts)

                    to_skip_packets = math.floor((remainder / (parts - 1)))
                    one_move = threshold + to_skip_packets

                    one_to_last_packet = one_move * (parts - 1)

                    index = 0
                    for start_value in range(0, one_to_last_packet, one_move):
                        packet_slice = packets_value[start_value:(start_value + threshold)]

                        parts_list[index].append(packet_slice)
                        index = index + 1

                    parts_list[index].append(packets_value[-threshold:])

            summary_df = pd.read_csv(path_to_csv_file)

            if len(connections_used) > 0:
                for connection_index, (src_ip, dst_ip) in enumerate(connections_used):
                    one_file_df = summary_df[(summary_df["src_ip"] == src_ip) & (summary_df["dst_ip"] == dst_ip)]
                    one_file_df["connection_length"] = threshold

                    if connection_index == 0:
                        combined_df = one_file_df
                    else:
                        combined_df = combined_df.append(one_file_df)
                for part_index, part in enumerate(parts_list):
                    new_file_path = folder_to_move_data_to + "/" + str(threshold) + "_threshold_" + str(parts) + "_parts/"+ str(threshold) + "_threshold_" + str(part_index + 1) + "_part/" + scenario_name + "_" + file_name
                    csv_summary_path = folder_to_move_data_to + "/" + str(threshold) + "_threshold_" + str(parts) + "_parts/" +  str(threshold) + "_threshold_" + str(part_index + 1) + "_part/" + scenario_name + "_" + file_name + "_summary.csv"
                    pktdump = PcapWriter(new_file_path, append=True, sync=True)
                    for packet in part:
                        pktdump.write(packet)
                    pktdump.close()
                    combined_df.to_csv(csv_summary_path, index=False)



    @staticmethod
    def get_data_equal_to_fixed_window_size_for_malpaca(folder_to_filtered_files, folder_to_move_data_to, window_size, old_file_addition):

        window_size = window_size

        folder_to_filtered_files = folder_to_filtered_files
        folder_to_move_data_to = folder_to_move_data_to

        new_folder_path = folder_to_move_data_to + "/" + (str(window_size)) + "_window_size"
        os.mkdir(new_folder_path)

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
            print("Create pcap file")

            path_to_csv_file = folder_to_filtered_files + "/" + scenario_name + "/" + file_name + "/" + file_name + "_summary.csv"
            path_to_pcap_file = folder_to_filtered_files + "/" + scenario_name + "/" + file_name + "/" + file_name + "_" + old_file_addition + ".pcap"

            file_packet_dic = {}
            window_dic = {}

            with PcapReader(path_to_pcap_file) as packets:
                for packet_count, packet in enumerate(packets):

                    src_ip = packet[IP].src
                    dst_ip = packet[IP].dst

                    if (src_ip, dst_ip) not in file_packet_dic:
                        file_packet_dic[(src_ip, dst_ip)] = [packet]
                    else:
                        file_packet_dic[(src_ip, dst_ip)].append(packet)

            new_file_path = new_folder_path + "/" + scenario_name + "_" + file_name


            for address, packets_value in file_packet_dic.items():
                amount_packets = len(packets_value)
                if amount_packets >= window_size:
                    amount_windows = (math.floor(amount_packets / window_size))
                    amount_packets = amount_windows * window_size
                    window_dic[address] = amount_windows

                    pktdump = PcapWriter(new_file_path, append=True, sync=True)
                    for index, packet in enumerate(packets_value):
                        if index < amount_packets:
                            pktdump.write(packet)
                        else:
                            break
                    pktdump.close()



            print("Create csv file")

            csv_df = pd.read_csv(path_to_csv_file)
            csv_df["src_ip"] = csv_df["src_ip"].apply(lambda x: str(x))
            csv_df["dst_ip"] = csv_df["dst_ip"].apply(lambda x: str(x))


            if len(window_dic) > 0:
                row_list = []
                for index, (address, amount_windows) in enumerate(window_dic.items()):
                    src_ip = str(address[0])
                    dst_ip = str(address[1])

                    row = csv_df[(csv_df["src_ip"] == src_ip) & (csv_df["dst_ip"] == dst_ip)]

                    for window_index in range(0, amount_windows):
                        new_row = row.copy()
                        new_row["connection_length"] = window_size
                        new_row["window"] = window_index

                        row_list.append(new_row)

                combined_df = pd.concat(row_list)

                file_packet_dic.clear()
                window_dic.clear()

                new_csv_file_path = new_folder_path + "/" + scenario_name + "_" + file_name + "_summary.csv"
                combined_df = combined_df.sort_values(by=['src_ip', 'dst_ip', 'window'], ascending=True)
                combined_df.to_csv(new_csv_file_path, index=False)



    @staticmethod
    def determine_optimal_threshold(folder_to_filtered_files):

        # folder_to_filtered_files = "C:/Users/Johannes/iCloudDrive/Uni/CSE/Year 3/Q4/Code/Dataset/Filtered/20_none"
        folder_to_filtered_files = folder_to_filtered_files

        scan_file_order_path = folder_to_filtered_files + "/" + "scan_order.txt"
        scanned_files = []
        with open(scan_file_order_path, 'r') as inputfile:
            scanned_files = inputfile.readlines()

        scanned_files_list = [x.strip() for x in scanned_files]
        scanned_files_list = list(map(lambda x: (x.split(",")[0], x.split(",")[1]), scanned_files_list))
        scanned_files_list = sorted(list(set(scanned_files_list)))

        connection_length_dic = {}

        for index, (scenario_name, file_name) in enumerate(scanned_files_list):

            path_to_csv_file = folder_to_filtered_files + "/" + scenario_name + "/" + file_name + "/" + file_name + "_summary.csv"

            csv_df = pd.read_csv(path_to_csv_file)

            for row in csv_df.iterrows():
                connection_length = row[1]["connection_length"]

                while (connection_length > 0):
                    if connection_length in connection_length_dic:
                        old_entry = connection_length_dic[connection_length]
                        new_entry = old_entry + connection_length
                        connection_length_dic[connection_length] = new_entry
                    else:
                        connection_length_dic[connection_length] = connection_length

                    connection_length = connection_length - 1

        max_packets = 0
        threshold = 0

        for key, value in connection_length_dic.items():
            if value > max_packets:
                threshold = key
                max_packets = value

        print("Max threshold: " + str(threshold))
        print("Max packets: " + str(max_packets))

        return threshold






    @staticmethod
    def get_data_equal_to_fixed_threshold_for_malpaca_enriched(threshold, folder_to_filtered_files, folder_to_move_data_to, old_file_addition):

        threshold = int(threshold)

        folder_to_filtered_files = folder_to_filtered_files
        folder_to_move_data_to = folder_to_move_data_to

        new_folder_path = folder_to_move_data_to + "/" + (str(threshold)) + "_fixed_threshold"
        os.mkdir(new_folder_path)

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
            print("Create pcap file")

            path_to_csv_file = folder_to_filtered_files + "/" + scenario_name + "/" + file_name + "/" + file_name + "_summary.csv"
            path_to_pcap_file = folder_to_filtered_files + "/" + scenario_name + "/" + file_name + "/" + file_name + "_" + old_file_addition + ".pcap"

            file_packet_dic = {}
            connections_used = []

            new_file_path = new_folder_path + "/" + scenario_name + "_" + file_name
            write_count = 1

            with PcapReader(path_to_pcap_file) as packets:
                for packet_count, packet in enumerate(packets):

                    src_ip = packet[IP].src
                    dst_ip = packet[IP].dst

                    if (src_ip, dst_ip) not in file_packet_dic:
                        file_packet_dic[(src_ip, dst_ip)] = [packet]
                    else:
                        file_packet_dic[(src_ip, dst_ip)].append(packet)

                    if (packet_count % 500000) == 0:
                        if packet_count != 0:
                            print("Write " + str(write_count) + " Start")
                            for address, packets_value in file_packet_dic.items():
                                amount = len(packets_value)
                                if amount >= threshold:
                                    connections_used.append(address)
                                    pktdump = PcapWriter(new_file_path, append=True, sync=True)
                                    for index, packet in enumerate(packets_value):
                                        if index < threshold:
                                            pktdump.write(packet)
                                        else:
                                            break
                                    pktdump.close()

                            file_packet_dic.clear()
                            print("Write " + str(write_count) + " End")
                            write_count = write_count + 1

            packets.close()

            if len(file_packet_dic) > 0:
                print("Write Last Packets Start")
                for address, packets_value in file_packet_dic.items():
                    amount = len(packets_value)
                    if amount >= threshold:
                        connections_used.append(address)
                        pktdump = PcapWriter(new_file_path, append=True, sync=True)
                        for index, packet in enumerate(packets_value):
                            if index < threshold:
                                pktdump.write(packet)
                            else:
                                break
                        pktdump.close()

                file_packet_dic.clear()
                print("Write Last Packets End")

            print("Create csv file")

            csv_df = pd.read_csv(path_to_csv_file)
            csv_df["src_ip"] = csv_df["src_ip"].apply(lambda x: str(x))
            csv_df["dst_ip"] = csv_df["dst_ip"].apply(lambda x: str(x))

            if len(connections_used) > 0:
                for index, (src_ip, dst_ip) in enumerate(connections_used):
                    src_ip = str(src_ip)
                    dst_ip = str(dst_ip)

                    row = csv_df[(csv_df["src_ip"] == src_ip) & (csv_df["dst_ip"] == dst_ip)]

                    if index == 0:
                        combined_df = row
                    else:
                        combined_df = combined_df.append(row)

                file_packet_dic.clear()
                connections_used.clear()

                new_csv_file_path = new_folder_path + "/" + scenario_name + "_" + file_name + "_summary.csv"
                combined_df["connection_length"] = threshold
                combined_df.to_csv(new_csv_file_path, index=False)



    @staticmethod
    def get_data_skip_x_then_take_fixed_threshold_for_malpaca_enriched(skip, threshold, folder_to_filtered_files, folder_to_move_data_to, old_file_addition):

        skip = int(skip)
        threshold = int(threshold)

        folder_to_filtered_files = folder_to_filtered_files
        folder_to_move_data_to = folder_to_move_data_to

        new_folder_path = folder_to_move_data_to + "/" + str(threshold) + "_fixed_threshold_" + str(skip) + "_skip"
        os.mkdir(new_folder_path)

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
            print("Create pcap file")

            path_to_csv_file = folder_to_filtered_files + "/" + scenario_name + "/" + file_name + "/" + file_name + "_summary.csv"
            path_to_pcap_file = folder_to_filtered_files + "/" + scenario_name + "/" + file_name + "/" + file_name + "_" + old_file_addition + ".pcap"

            file_packet_dic = {}
            connections_used = []

            new_file_path = new_folder_path + "/" + scenario_name + "_" + file_name
            write_count = 1

            with PcapReader(path_to_pcap_file) as packets:
                for packet_count, packet in enumerate(packets):

                    src_ip = packet[IP].src
                    dst_ip = packet[IP].dst

                    if (src_ip, dst_ip) not in file_packet_dic:
                        file_packet_dic[(src_ip, dst_ip)] = [packet]
                    else:
                        file_packet_dic[(src_ip, dst_ip)].append(packet)

                        if (packet_count % 500000) == 0:
                            if packet_count != 0:
                                print("Write " + str(write_count) + " Start")
                                for address, packets_value in file_packet_dic.items():
                                    amount = len(packets_value)
                                    if amount >= (threshold + skip):
                                        connections_used.append(address)
                                        pktdump = PcapWriter(new_file_path, append=True, sync=True)
                                        for index, packet in enumerate(packets_value):
                                            if (index > skip):
                                                if (index <= (skip + threshold)):
                                                    pktdump.write(packet)
                                        pktdump.close()

                                file_packet_dic.clear()
                                print("Write " + str(write_count) + " End")
                                write_count = write_count + 1

                packets.close()

            if len(file_packet_dic) > 0:
                print("Write Last Packets Start")
                for address, packets_value in file_packet_dic.items():
                    amount = len(packets_value)
                    if amount >= (threshold + skip):
                        connections_used.append(address)
                        pktdump = PcapWriter(new_file_path, append=True, sync=True)
                        for index, packet in enumerate(packets_value):
                            if (index > skip):
                                if (index <= (skip + threshold)):
                                    pktdump.write(packet)
                        pktdump.close()

                file_packet_dic.clear()
                print("Write Last Packets End")

            print("Create csv file")

            csv_df = pd.read_csv(path_to_csv_file)
            csv_df["src_ip"] = csv_df["src_ip"].apply(lambda x: str(x))
            csv_df["dst_ip"] = csv_df["dst_ip"].apply(lambda x: str(x))

            if len(connections_used) > 0:
                for index, (src_ip, dst_ip) in enumerate(connections_used):
                    src_ip = str(src_ip)
                    dst_ip = str(dst_ip)

                    row = csv_df[(csv_df["src_ip"] == src_ip) & (csv_df["dst_ip"] == dst_ip)]

                    if index == 0:
                        combined_df = row
                    else:
                        combined_df = combined_df.append(row)

                file_packet_dic.clear()
                connections_used.clear()

                new_csv_file_path = new_folder_path + "/" + scenario_name + "_" + file_name + "_summary.csv"
                combined_df["connection_length"] = threshold
                combined_df.to_csv(new_csv_file_path, index=False)

    @staticmethod
    def get_data_skip_x_then_take_fixed_threshold_from_end_for_malpaca_enriched(skip, threshold, folder_to_filtered_files, folder_to_move_data_to, old_file_addition):

        skip = int(skip)
        threshold = int(threshold)

        folder_to_filtered_files = folder_to_filtered_files
        folder_to_move_data_to = folder_to_move_data_to

        new_folder_path = folder_to_move_data_to + "/" + (str(threshold)) + "_fixed_threshold_" + str(
            skip) + "_skip_from_end"
        os.mkdir(new_folder_path)

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
            print("Create pcap file")

            path_to_csv_file = folder_to_filtered_files + "/" + scenario_name + "/" + file_name + "/" + file_name + "_summary.csv"
            path_to_pcap_file = folder_to_filtered_files + "/" + scenario_name + "/" + file_name + "/" + file_name + "_" + old_file_addition + ".pcap"

            file_packet_dic = {}
            connections_used = []

            new_file_path = new_folder_path + "/" + scenario_name + "_" + file_name
            write_count = 1

            with PcapReader(path_to_pcap_file) as packets:
                for packet_count, packet in enumerate(packets):

                    src_ip = packet[IP].src
                    dst_ip = packet[IP].dst

                    if (src_ip, dst_ip) not in file_packet_dic:
                        file_packet_dic[(src_ip, dst_ip)] = [packet]
                    else:
                        file_packet_dic[(src_ip, dst_ip)].append(packet)

                    if (packet_count % 500000) == 0:
                        if packet_count != 0:
                            print("Write " + str(write_count) + " Start")
                            for address, packets_value in file_packet_dic.items():
                                amount = len(packets_value)
                                if amount >= (threshold + skip):
                                    connections_used.append(address)
                                    pktdump = PcapWriter(new_file_path, append=True, sync=True)

                                    threshold_int = (threshold + skip) * (-1)
                                    packets_value = packets_value[threshold_int:]

                                    for index, packet in enumerate(packets_value):
                                        if index < threshold:
                                            pktdump.write(packet)
                                        else:
                                            break
                                    pktdump.close()

                            file_packet_dic.clear()
                            print("Write " + str(write_count) + " End")
                            write_count = write_count + 1

            packets.close()

            if len(file_packet_dic) > 0:
                print("Write Last Packets Start")
                for address, packets_value in file_packet_dic.items():
                    amount = len(packets_value)
                    if amount >= (threshold + skip):
                        connections_used.append(address)
                        pktdump = PcapWriter(new_file_path, append=True, sync=True)

                        threshold_int = (threshold + skip) * (-1)
                        packets_value = packets_value[threshold_int:]

                        for index, packet in enumerate(packets_value):
                            if index < threshold:
                                pktdump.write(packet)
                            else:
                                break
                        pktdump.close()

                file_packet_dic.clear()
                print("Write Last Packets End")

            print("Create csv file")

            csv_df = pd.read_csv(path_to_csv_file)
            csv_df["src_ip"] = csv_df["src_ip"].apply(lambda x: str(x))
            csv_df["dst_ip"] = csv_df["dst_ip"].apply(lambda x: str(x))

            if len(connections_used) > 0:
                for index, (src_ip, dst_ip) in enumerate(connections_used):
                    src_ip = str(src_ip)
                    dst_ip = str(dst_ip)

                    row = csv_df[(csv_df["src_ip"] == src_ip) & (csv_df["dst_ip"] == dst_ip)]

                    if index == 0:
                        combined_df = row
                    else:
                        combined_df = combined_df.append(row)

                file_packet_dic.clear()
                connections_used.clear()

                new_csv_file_path = new_folder_path + "/" + scenario_name + "_" + file_name + "_summary.csv"
                combined_df["connection_length"] = threshold
                combined_df.to_csv(new_csv_file_path, index=False)

    @staticmethod
    def get_data_equal_to_fixed_threshold_from_end_for_malpaca_enriched(threshold, folder_to_filtered_files, folder_to_move_data_to, old_file_addition):

        threshold = threshold

        folder_to_filtered_files = folder_to_filtered_files
        folder_to_move_data_to = folder_to_move_data_to

        new_folder_path = folder_to_move_data_to + "/" + (str(threshold)) + "_fixed_threshold_from_end"
        os.mkdir(new_folder_path)

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
            print("Create pcap file")

            path_to_csv_file = folder_to_filtered_files + "/" + scenario_name + "/" + file_name + "/" + file_name + "_summary.csv"
            path_to_pcap_file = folder_to_filtered_files + "/" + scenario_name + "/" + file_name + "/" + file_name + "_" + old_file_addition + ".pcap"

            file_packet_dic = {}
            connections_used = []

            new_file_path = new_folder_path + "/" + scenario_name + "_" + file_name
            write_count = 1

            with PcapReader(path_to_pcap_file) as packets:
                for packet_count, packet in enumerate(packets):

                    src_ip = packet[IP].src
                    dst_ip = packet[IP].dst

                    if (src_ip, dst_ip) not in file_packet_dic:
                        file_packet_dic[(src_ip, dst_ip)] = [packet]
                    else:
                        file_packet_dic[(src_ip, dst_ip)].append(packet)

                    if (packet_count % 500000) == 0:
                        if packet_count != 0:
                            print("Write " + str(write_count) + " Start")
                            for address, packets_value in file_packet_dic.items():
                                amount = len(packets_value)
                                if amount >= threshold:
                                    connections_used.append(address)
                                    pktdump = PcapWriter(new_file_path, append=True, sync=True)

                                    threshold_int = int(threshold) * (-1)
                                    packets_value = packets_value[threshold_int:]

                                    for index, packet in enumerate(packets_value):
                                        if index < threshold:
                                            pktdump.write(packet)
                                        else:
                                            break
                                    pktdump.close()

                            file_packet_dic.clear()
                            print("Write " + str(write_count) + " End")
                            write_count = write_count + 1

            packets.close()

            if len(file_packet_dic) > 0:
                print("Write Last Packets Start")
                for address, packets_value in file_packet_dic.items():
                    amount = len(packets_value)
                    if amount >= threshold:
                        connections_used.append(address)
                        pktdump = PcapWriter(new_file_path, append=True, sync=True)

                        threshold_int = int(threshold) * (-1)
                        packets_value = packets_value[threshold_int:]

                        for index, packet in enumerate(packets_value):
                            if index < threshold:
                                pktdump.write(packet)
                            else:
                                break
                        pktdump.close()

                file_packet_dic.clear()
                print("Write Last Packets End")

            print("Create csv file")

            csv_df = pd.read_csv(path_to_csv_file)
            csv_df["src_ip"] = csv_df["src_ip"].apply(lambda x: str(x))
            csv_df["dst_ip"] = csv_df["dst_ip"].apply(lambda x: str(x))

            if len(connections_used) > 0:
                for index, (src_ip, dst_ip) in enumerate(connections_used):
                    src_ip = str(src_ip)
                    dst_ip = str(dst_ip)

                    row = csv_df[(csv_df["src_ip"] == src_ip) & (csv_df["dst_ip"] == dst_ip)]

                    if index == 0:
                        combined_df = row
                    else:
                        combined_df = combined_df.append(row)

                file_packet_dic.clear()
                connections_used.clear()

                new_csv_file_path = new_folder_path + "/" + scenario_name + "_" + file_name + "_summary.csv"
                combined_df["connection_length"] = threshold
                combined_df.to_csv(new_csv_file_path, index=False)
