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

class For_Malpaca_Preparation():


    @staticmethod
    def determine_optimal_threshold(folder_to_filtered_files):

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
    def split_connection_into_X_equal_parts_for_malpaca(threshold, parts, folder_to_filtered_files, folder_to_move_data_to):

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
            path_to_pcap_file = folder_to_filtered_files + "/" + scenario_name + "/" + file_name + "/" + file_name + "_filtered_20.pcap"

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
                amount = len(packets_value)
                if amount >= (threshold * parts):
                    connections_used.append(address)

                    remainder = amount - (threshold * parts)

                    to_skip_packets = math.floor((remainder / (amount - 1)))
                    one_move = threshold + to_skip_packets

                    one_to_last_packet = one_move * (parts - 1)
                    to_write_list = []

                    for start_value in range(0, one_to_last_packet, one_move):
                        packet_slice = packets_value[start_value:(start_value + amount)]
                        to_write_list.append(packets_value)

                    to_write_list.append(packets_value[-amount:])



    @staticmethod
    def get_data_equal_to_fixed_window_size_for_malpaca(threshold, folder_to_filtered_files, folder_to_move_data_to):

        threshold = threshold

        folder_to_filtered_files = folder_to_filtered_files
        folder_to_move_data_to = folder_to_move_data_to

        new_folder_path = folder_to_move_data_to + "/" + (str(threshold)) + "_window_size"
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
            path_to_pcap_file = folder_to_filtered_files + "/" + scenario_name + "/" + file_name + "/" + file_name + "_filtered_20.pcap"

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

            new_file_path = new_folder_path + "/" + scenario_name + "_" + file_name

            for address, packets_value in file_packet_dic.items():
                amount = len(packets_value)
                if amount >= threshold:
                    amount_window_size = (math.floor(amount / threshold)) * threshold

                    connections_used.append(address)
                    pktdump = PcapWriter(new_file_path, append=True, sync=True)
                    for index, packet in enumerate(packets_value):
                        if index < amount_window_size:
                            pktdump.write(packet)
                        else:
                            break
                    pktdump.close()

            print("Create csv file")

            csv_df = pd.read_csv(path_to_csv_file)
            csv_df["src_ip"] = csv_df["src_ip"].apply(lambda x: str(x))
            csv_df["dst_ip"] = csv_df["dst_ip"].apply(lambda x: str(x))

            new_csv_file_path = new_folder_path + "/" + scenario_name + "_" + file_name + "_summary.csv"

            with open(new_csv_file_path, 'w', newline='') as csvfile:

                csv_writer = csv.writer(csvfile, delimiter=',', quotechar='|', quoting=csv.QUOTE_MINIMAL)

                new_line = ["src_ip", "dst_ip", "connection_length", "scenario", "file", "label", "detailed_label"]
                csv_writer.writerow(new_line)

                for (src_ip, dst_ip) in connections_used:
                    src_ip = str(src_ip)
                    dst_ip = str(dst_ip)

                    label = csv_df[(csv_df["src_ip"] == src_ip) & (csv_df["dst_ip"] == dst_ip)]["label"].values[0]
                    detailed_label = \
                        csv_df[(csv_df["src_ip"] == src_ip) & (csv_df["dst_ip"] == dst_ip)]["detailed_label"].values[0]

                    new_line = [str(src_ip), str(dst_ip), str(threshold), scenario_name, file_name, label,
                                detailed_label]
                    csv_writer.writerow(new_line)

            csvfile.close()

            file_packet_dic.clear()
            connections_used.clear()




    @staticmethod
    def get_data_equal_to_fixed_threshold_for_malpaca(threshold, folder_to_filtered_files, folder_to_move_data_to):

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
            path_to_pcap_file = folder_to_filtered_files + "/" + scenario_name + "/" + file_name + "/" + file_name + "_filtered_20.pcap"

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

            new_csv_file_path = new_folder_path + "/" + scenario_name + "_" + file_name + "_summary.csv"

            with open(new_csv_file_path, 'w', newline='') as csvfile:

                csv_writer = csv.writer(csvfile, delimiter=',', quotechar='|', quoting=csv.QUOTE_MINIMAL)

                new_line = ["src_ip", "dst_ip", "connection_length", "scenario", "file", "label", "detailed_label"]
                csv_writer.writerow(new_line)

                for (src_ip, dst_ip) in connections_used:
                    src_ip = str(src_ip)
                    dst_ip = str(dst_ip)

                    label = csv_df[(csv_df["src_ip"] == src_ip) & (csv_df["dst_ip"] == dst_ip)]["label"].values[0]
                    detailed_label = \
                    csv_df[(csv_df["src_ip"] == src_ip) & (csv_df["dst_ip"] == dst_ip)]["detailed_label"].values[0]

                    new_line = [str(src_ip), str(dst_ip), str(threshold), scenario_name, file_name, label,
                                detailed_label]
                    csv_writer.writerow(new_line)

            csvfile.close()

            file_packet_dic.clear()
            connections_used.clear()


    @staticmethod
    def get_data_skip_x_then_take_fixed_threshold_for_malpaca(skip, threshold, folder_to_filtered_files, folder_to_move_data_to):

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
            path_to_pcap_file = folder_to_filtered_files + "/" + scenario_name + "/" + file_name + "/" + file_name + "_filtered_20.pcap"

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

            new_csv_file_path = new_folder_path + "/" + file_name + "_summary.csv"

            with open(new_csv_file_path, 'w', newline='') as csvfile:

                csv_writer = csv.writer(csvfile, delimiter=',', quotechar='|', quoting=csv.QUOTE_MINIMAL)

                new_line = ["src_ip", "dst_ip", "connection_length", "scenario", "file", "label", "detailed_label"]
                csv_writer.writerow(new_line)

                for (src_ip, dst_ip) in connections_used:
                    src_ip = str(src_ip)
                    dst_ip = str(dst_ip)

                    label = csv_df[(csv_df["src_ip"] == src_ip) & (csv_df["dst_ip"] == dst_ip)]["label"].values[0]
                    detailed_label = \
                    csv_df[(csv_df["src_ip"] == src_ip) & (csv_df["dst_ip"] == dst_ip)]["detailed_label"].values[0]

                    new_line = [str(src_ip), str(dst_ip), str(threshold), scenario_name, file_name, label,
                                detailed_label]
                    csv_writer.writerow(new_line)

            csvfile.close()

            file_packet_dic.clear()
            connections_used.clear()


    @staticmethod
    def get_data_skip_x_then_take_fixed_threshold_from_end_for_malpaca(skip, threshold, folder_to_filtered_files, folder_to_move_data_to):

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
            path_to_pcap_file = folder_to_filtered_files + "/" + scenario_name + "/" + file_name + "/" + file_name + "_filtered_20.pcap"

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

            new_csv_file_path = new_folder_path + "/" + file_name + "_summary.csv"

            with open(new_csv_file_path, 'w', newline='') as csvfile:

                csv_writer = csv.writer(csvfile, delimiter=',', quotechar='|', quoting=csv.QUOTE_MINIMAL)

                new_line = ["src_ip", "dst_ip", "connection_length", "scenario", "file", "label", "detailed_label"]
                csv_writer.writerow(new_line)

                for (src_ip, dst_ip) in connections_used:
                    src_ip = str(src_ip)
                    dst_ip = str(dst_ip)

                    label = csv_df[(csv_df["src_ip"] == src_ip) & (csv_df["dst_ip"] == dst_ip)]["label"].values[0]
                    detailed_label = \
                        csv_df[(csv_df["src_ip"] == src_ip) & (csv_df["dst_ip"] == dst_ip)]["detailed_label"].values[0]

                    new_line = [str(src_ip), str(dst_ip), str(threshold), scenario_name, file_name, label,
                                detailed_label]
                    csv_writer.writerow(new_line)

            csvfile.close()

            file_packet_dic.clear()
            connections_used.clear()

    @staticmethod
    def get_data_equal_to_fixed_threshold_from_end_for_malpaca(threshold, folder_to_filtered_files, folder_to_move_data_to):

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
            path_to_pcap_file = folder_to_filtered_files + "/" + scenario_name + "/" + file_name + "/" + file_name + "_filtered_20.pcap"

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

            new_csv_file_path = new_folder_path + "/" + file_name + "_summary.csv"

            with open(new_csv_file_path, 'w', newline='') as csvfile:

                csv_writer = csv.writer(csvfile, delimiter=',', quotechar='|', quoting=csv.QUOTE_MINIMAL)

                new_line = ["src_ip", "dst_ip", "connection_length", "scenario", "file", "label", "detailed_label"]
                csv_writer.writerow(new_line)

                for (src_ip, dst_ip) in connections_used:
                    src_ip = str(src_ip)
                    dst_ip = str(dst_ip)

                    label = csv_df[(csv_df["src_ip"] == src_ip) & (csv_df["dst_ip"] == dst_ip)]["label"].values[0]
                    detailed_label = \
                        csv_df[(csv_df["src_ip"] == src_ip) & (csv_df["dst_ip"] == dst_ip)]["detailed_label"].values[0]

                    new_line = [str(src_ip), str(dst_ip), str(threshold), scenario_name, file_name, label,
                                detailed_label]
                    csv_writer.writerow(new_line)

            csvfile.close()

            file_packet_dic.clear()
            connections_used.clear()
