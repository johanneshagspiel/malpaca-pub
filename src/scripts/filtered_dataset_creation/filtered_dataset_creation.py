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

class Filtered_Dataset_Creation():

    @staticmethod
    def restart_filter_connections_based_on_netflow_into_separate_files_max_length(threshold, max_length,
                                                                           path_to_iot_scenarios_folder,
                                                                           folder_to_restart, experiment_name):

        threshold = threshold
        path_to_iot_scenarios_folder = path_to_iot_scenarios_folder
        folder_to_restart = folder_to_restart
        experiment_name = experiment_name

        new_folder_path = folder_to_restart

        to_skip_scenario = "CTU-IoT-Malware-Capture-60-1"

        folders = sorted([f.path for f in os.scandir(path_to_iot_scenarios_folder) if f.is_dir()])
        folders = list(map(lambda x: (x, str(os.path.basename(x)).strip()), folders))


        scan_file_order_path = folder_to_restart + "/" + "scan_order.txt"

        with open(scan_file_order_path, 'r') as inputfile:
            scanned_files = inputfile.readlines()

        scanned_files_list = [x.strip() for x in scanned_files]
        scanned_files_set = set()

        for file in scanned_files_list:
            scanned_files_set.add(file.split(",")[0])

        filtered_folders = []
        folders_still_to_scan = []

        for path, folder in folders:
            if folder not in scanned_files_set and folder != to_skip_scenario:
                folders_still_to_scan.append(path)

        folders = folders_still_to_scan

        scan_file_order_path = new_folder_path + "/" + "scan_order.txt"

        for index, folder in enumerate(folders):

            scenario_name = str(os.path.basename(folder)).strip()
            scenario_folder_storage = new_folder_path + "/" + scenario_name
            os.mkdir(scenario_folder_storage)

            print("Scenario: " + str(index + 1) + "/" + str(len(folders)))
            print("Scenario name: " + scenario_name)

            connections = {}
            pcap_files = glob.glob(folder + "/*.pcap")

            for index_file, pcap_file in enumerate(pcap_files):
                file_name = str(os.path.basename(pcap_file)).strip()
                file_folder = scenario_folder_storage + "/" + file_name
                os.mkdir(file_folder)

                path_to_pcap_file = pcap_file

                print("File: " + str(index_file + 1) + "/" + str(len(pcap_files)))
                print("File name : " + file_name)

                with open(scan_file_order_path, 'a') as scan_file:
                    scan_file.write(scenario_name + "," + file_name + "\n")
                    scan_file.close()

                count_file_name = file_name + "_count.txt"
                count_file_path = path_to_iot_scenarios_folder + "/" + scenario_name + "/" + count_file_name
                count_file_exist = os.path.exists(count_file_path)

                write_counter = 1
                appended_packet_counter = 0

                if count_file_exist:
                    with open(count_file_path, 'r') as count_file:
                        total_number_packets = int(count_file.readline())
                        count_file.close()
                    start_time = time.time()

                last_packet = None
                last_packet_src = None
                last_packet_dst = None
                counted_packets = 0
                log_file_path = file_folder + "/" + file_name + "_log.txt"
                new_file_path = file_folder + "/" + file_name + "_" + experiment_name + ".pcap"

                with PcapReader(path_to_pcap_file) as packets:
                    for packet_count, packet in enumerate(packets):
                        counted_packets = packet_count + 1

                        if IP in packet:

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

                            ip_tos = packet_dic["IP"]["tos"]

                            last_packet_src = src_ip
                            last_packet_dst = dst_ip
                            last_packet = packet

                            if (
                            src_ip, dst_ip, ip_protocol, src_port, dst_port, ip_protocol, ip_tos) not in connections:
                                connections[(src_ip, dst_ip, ip_protocol, src_port, dst_port, ip_protocol, ip_tos)] = [
                                    packet]
                                appended_packet_counter = appended_packet_counter + 1
                            else:
                                connections[
                                    (src_ip, dst_ip, ip_protocol, src_port, dst_port, ip_protocol, ip_tos)].append(
                                    packet)
                                appended_packet_counter = appended_packet_counter + 1

                            if appended_packet_counter == 500000:

                                print("Write " + str(write_counter))
                                for address, packets_value in connections.items():
                                    amount = len(packets_value)
                                    if amount >= threshold:
                                        pktdump = PcapWriter(new_file_path, append=True, sync=True)
                                        for index, packet in enumerate(packets_value):
                                            if index < max_length:
                                                pktdump.write(packet)
                                            else:
                                                break
                                        pktdump.close()

                                with open(log_file_path, 'w') as log_file:
                                    log_file.write("last_packet_count:" + str(packet_count) + "\n")
                                    log_file.write("last_packet_src:" + last_packet_src + "\n")
                                    log_file.write("last_packet_dst:" + last_packet_dst + "\n")
                                    log_file.write("last_packet:" + str(last_packet) + "\n")
                                log_file.close()

                                connections.clear()
                                appended_packet_counter = 0
                                print("Write " + str(write_counter) + " Finish")
                                write_counter = write_counter + 1

                                if count_file_exist:
                                    end_time = time.time()
                                    passed_time = end_time - start_time
                                    progress_percent = int((counted_packets / total_number_packets) * 100)
                                    packets_remaining = total_number_packets - counted_packets
                                    average_time_packet = counted_packets / passed_time
                                    time_remaining = packets_remaining * average_time_packet
                                    time_remaining_minutes = round((time_remaining / 60), 2)

                                    print("Progress: " + str(progress_percent) + " %")
                                    print("Time remaining: " + str(time_remaining_minutes) + " minutes")

                packets.close()

                if (len(connections) > 0):
                    print("Write " + str(write_counter))

                    for address, packets_value in connections.items():
                        amount = len(packets_value)
                        if amount >= threshold:
                            pktdump = PcapWriter(new_file_path, append=True, sync=True)
                            for index, packet in enumerate(packets_value):
                                if index < max_length:
                                    pktdump.write(packet)
                                else:
                                    break
                    connections.clear()

                    with open(log_file_path, 'w') as log_file:
                        log_file.write("last_packet_count:end\n")
                        log_file.write("last_packet_src:" + last_packet_src + "\n")
                        log_file.write("last_packet_dst:" + last_packet_dst + "\n")
                        log_file.write("last_packet:" + str(last_packet) + "\n")
                    log_file.close()

                    print("Write " + str(write_counter) + " Finish")

                if (count_file_exist == False):
                    with open(count_file_path, 'w') as output_file:
                        output_file.write(str(counted_packets))
                    output_file.close()

        sys.exit()

    @staticmethod
    def filter_connections_based_on_netflow_into_separate_files_max_length(threshold, max_length, path_to_iot_scenarios_folder, folder_to_store, experiment_name):

        threshold = threshold
        path_to_iot_scenarios_folder = path_to_iot_scenarios_folder
        folder_to_store = folder_to_store
        experiment_name = experiment_name

        to_skip_scenario = "CTU-IoT-Malware-Capture-60-1"

        new_folder_path = folder_to_store + "/" + experiment_name
        os.mkdir(new_folder_path)

        folders = sorted([f.path for f in os.scandir(path_to_iot_scenarios_folder) if f.is_dir()])
        folders = list(map(lambda x: (x, str(os.path.basename(x)).strip()), folders))

        filtered_folders = []

        for path, folder in folders:
            if folder != to_skip_scenario:
                filtered_folders.append(path)

        folders = filtered_folders

        scan_file_order_path = new_folder_path + "/" + "scan_order.txt"

        for index, folder in enumerate(folders):

            scenario_name = str(os.path.basename(folder)).strip()
            scenario_folder_storage = new_folder_path + "/" + scenario_name
            os.mkdir(scenario_folder_storage)

            print("Scenario: " + str(index + 1) + "/" + str(len(folders)))
            print("Scenario name: " + scenario_name)

            connections = {}
            pcap_files = glob.glob(folder + "/*.pcap")

            for index_file, pcap_file in enumerate(pcap_files):
                file_name = str(os.path.basename(pcap_file)).strip()
                file_folder = scenario_folder_storage + "/" + file_name
                os.mkdir(file_folder)

                path_to_pcap_file = pcap_file

                print("File: " + str(index_file + 1) + "/" + str(len(pcap_files)))
                print("File name : " + file_name)

                with open(scan_file_order_path, 'a') as scan_file:
                    scan_file.write(scenario_name + "," + file_name + "\n")
                    scan_file.close()

                count_file_name = file_name + "_count.txt"
                count_file_path = path_to_iot_scenarios_folder + "/" + scenario_name + "/" + count_file_name
                count_file_exist = os.path.exists(count_file_path)

                write_counter = 1
                appended_packet_counter = 0

                if count_file_exist:
                    with open(count_file_path, 'r') as count_file:
                        total_number_packets = int(count_file.readline())
                        count_file.close()
                    start_time = time.time()

                last_packet = None
                last_packet_src = None
                last_packet_dst = None
                counted_packets = 0
                log_file_path = file_folder + "/" + file_name + "_log.txt"
                new_file_path = file_folder + "/" + file_name + "_" + experiment_name + ".pcap"

                with PcapReader(path_to_pcap_file) as packets:
                    for packet_count, packet in enumerate(packets):
                        counted_packets = packet_count + 1

                        if IP in packet:

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

                            ip_tos = packet_dic["IP"]["tos"]

                            last_packet_src = src_ip
                            last_packet_dst = dst_ip
                            last_packet = packet

                            if (src_ip, dst_ip, ip_protocol, src_port, dst_port, ip_protocol, ip_tos) not in connections:
                                connections[(src_ip, dst_ip, ip_protocol, src_port, dst_port, ip_protocol, ip_tos)] = [packet]
                                appended_packet_counter = appended_packet_counter + 1
                            else:
                                connections[(src_ip, dst_ip, ip_protocol, src_port, dst_port, ip_protocol, ip_tos)].append(packet)
                                appended_packet_counter = appended_packet_counter + 1

                            if appended_packet_counter == 500000:

                                print("Write " + str(write_counter))
                                for address, packets_value in connections.items():
                                    amount = len(packets_value)
                                    if amount >= threshold:
                                        pktdump = PcapWriter(new_file_path, append=True, sync=True)
                                        for index, packet in enumerate(packets_value):
                                            if index < max_length:
                                                pktdump.write(packet)
                                            else:
                                                break
                                        pktdump.close()

                                with open(log_file_path, 'w') as log_file:
                                    log_file.write("last_packet_count:" + str(packet_count) + "\n")
                                    log_file.write("last_packet_src:" + last_packet_src + "\n")
                                    log_file.write("last_packet_dst:" + last_packet_dst + "\n")
                                    log_file.write("last_packet:" + str(last_packet) + "\n")
                                log_file.close()

                                connections.clear()
                                appended_packet_counter = 0
                                print("Write " + str(write_counter) + " Finish")
                                write_counter = write_counter + 1

                                if count_file_exist:
                                    end_time = time.time()
                                    passed_time = end_time - start_time
                                    progress_percent = int((counted_packets / total_number_packets) * 100)
                                    packets_remaining = total_number_packets - counted_packets
                                    average_time_packet = counted_packets / passed_time
                                    time_remaining = packets_remaining * average_time_packet
                                    time_remaining_minutes = round((time_remaining / 60), 2)

                                    print("Progress: " + str(progress_percent) + " %")
                                    print("Time remaining: " + str(time_remaining_minutes) + " minutes")

                packets.close()

                if (len(connections) > 0):
                    print("Write " + str(write_counter))

                    for address, packets_value in connections.items():
                        amount = len(packets_value)
                        if amount >= threshold:
                            pktdump = PcapWriter(new_file_path, append=True, sync=True)
                            for index, packet in enumerate(packets_value):
                                if index < max_length:
                                    pktdump.write(packet)
                                else:
                                    break
                    connections.clear()

                    with open(log_file_path, 'w') as log_file:
                        log_file.write("last_packet_count:end\n")
                        log_file.write("last_packet_src:" + last_packet_src + "\n")
                        log_file.write("last_packet_dst:" + last_packet_dst + "\n")
                        log_file.write("last_packet:" + str(last_packet) + "\n")
                    log_file.close()

                    print("Write " + str(write_counter) + " Finish")

                if (count_file_exist == False):
                    with open(count_file_path, 'w') as output_file:
                        output_file.write(str(counted_packets))
                    output_file.close()

        sys.exit()

    @staticmethod
    def filter_connections_based_on_length_into_separate_files_with_udp(threshold, path_to_iot_scenarios_folder, folder_to_store, experiment_name):

        threshold = threshold
        path_to_iot_scenarios_folder = path_to_iot_scenarios_folder
        folder_to_store = folder_to_store
        experiment_name = experiment_name

        to_skip_scenario = "CTU-IoT-Malware-Capture-60-1"

        new_folder_path = folder_to_store + "/" + experiment_name
        os.mkdir(new_folder_path)

        folders = sorted([f.path for f in os.scandir(path_to_iot_scenarios_folder) if f.is_dir()])
        folders = list(map(lambda x: (x, str(os.path.basename(x)).strip()), folders))

        filtered_folders = []

        for path, folder in folders:
            if folder != to_skip_scenario:
                filtered_folders.append(path)

        folders = filtered_folders

        scan_file_order_path = new_folder_path + "/" + "scan_order.txt"

        for index, folder in enumerate(folders):

            scenario_name = str(os.path.basename(folder)).strip()
            scenario_folder_storage = new_folder_path + "/" + scenario_name
            os.mkdir(scenario_folder_storage)

            print("Scenario: " + str(index + 1) + "/" + str(len(folders)))
            print("Scenario name: " + scenario_name)

            connections = {}
            pcap_files = glob.glob(folder + "/*.pcap")

            for index_file, pcap_file in enumerate(pcap_files):

                file_name = str(os.path.basename(pcap_file)).strip()
                file_folder = scenario_folder_storage + "/" + file_name
                os.mkdir(file_folder)

                print("File: " + str(index_file + 1) + "/" + str(len(pcap_files)))
                print("File name : " + file_name)

                with open(scan_file_order_path, 'a') as scan_file:
                    scan_file.write(scenario_name + "," + file_name + "\n")
                    scan_file.close()

                count_file_name = file_name + "_count.txt"
                count_file_path = path_to_iot_scenarios_folder + "/" + scenario_name + "/" + count_file_name
                count_file_exist = os.path.exists(count_file_path)

                write_counter = 1
                appended_packet_counter = 0

                if count_file_exist:
                    with open(count_file_path, 'r') as count_file:
                        total_number_packets = int(count_file.readline())
                        count_file.close()
                    start_time = time.time()

                last_packet = None
                last_packet_src = None
                last_packet_dst = None
                counted_packets = 0
                log_file_path = file_folder + "/" + file_name + "_log.txt"
                new_file_path = file_folder + "/" + file_name + "_" + experiment_name + ".pcap"

                with PcapReader(pcap_file) as packets:
                    for packet_count, packet in enumerate(packets):
                        counted_packets = packet_count + 1

                        if IP in packet:

                            src_ip = packet[IP].src
                            dst_ip = packet[IP].dst

                            last_packet = packet
                            last_packet_src = src_ip
                            last_packet_dst = dst_ip

                            if (src_ip, dst_ip) not in connections:
                                connections[(src_ip, dst_ip)] = [packet]
                                appended_packet_counter = appended_packet_counter + 1
                            else:
                                connections[(src_ip, dst_ip)].append(packet)
                                appended_packet_counter = appended_packet_counter + 1

                            if appended_packet_counter == 500000:

                                print("Write " + str(write_counter))
                                for address, packets_value in connections.items():
                                    amount = len(packets_value)
                                    if amount >= threshold:
                                        pktdump = PcapWriter(new_file_path, append=True, sync=True)
                                        for index, packet in enumerate(packets_value):
                                            pktdump.write(packet)
                                        pktdump.close()

                                with open(log_file_path, 'w') as log_file:
                                    log_file.write("last_packet_count:" + str(packet_count) + "\n")
                                    log_file.write("last_packet_src:" + last_packet_src + "\n")
                                    log_file.write("last_packet_dst:" + last_packet_dst + "\n")
                                    log_file.write("last_packet:" + str(last_packet) + "\n")
                                log_file.close()

                                connections.clear()
                                appended_packet_counter = 0
                                print("Write " + str(write_counter) + " Finish")
                                write_counter = write_counter + 1

                                if count_file_exist:
                                    end_time = time.time()
                                    passed_time = end_time - start_time
                                    progress_percent = int((counted_packets / total_number_packets) * 100)
                                    packets_remaining = total_number_packets - counted_packets
                                    average_time_packet = counted_packets / passed_time
                                    time_remaining = packets_remaining * average_time_packet
                                    time_remaining_minutes = round((time_remaining / 60), 2)

                                    print("Progress: " + str(progress_percent) + " %")
                                    print("Time remaining: " + str(time_remaining_minutes) + " minutes")

                packets.close()

                if (len(connections) > 0):
                    print("Write " + str(write_counter))

                    for address, packets_value in connections.items():
                        amount = len(packets_value)
                        if amount >= threshold:
                            pktdump = PcapWriter(new_file_path, append=True, sync=True)
                            for index, packet in enumerate(packets_value):
                                pktdump.write(packet)
                    connections.clear()

                    with open(log_file_path, 'w') as log_file:
                        log_file.write("last_packet_count:end\n")
                        log_file.write("last_packet_src:" + last_packet_src + "\n")
                        log_file.write("last_packet_dst:" + last_packet_dst + "\n")
                        log_file.write("last_packet:" + str(last_packet) + "\n")
                    log_file.close()

                    print("Write " + str(write_counter) + " Finish")

                if (count_file_exist == False):
                    with open(count_file_path, 'w') as output_file:
                        output_file.write(str(counted_packets))
                    output_file.close()

        sys.exit()

    @staticmethod
    def filter_connections_based_on_length_into_separate_files(threshold, path_to_iot_scenarios_folder, folder_to_store, slice=None):

        threshold = threshold

        if slice:
            slice = slice

        path_to_iot_scenarios_folder = path_to_iot_scenarios_folder
        folder_to_store = folder_to_store

        to_skip_scenario = "CTU-IoT-Malware-Capture-60-1"

        if slice:
            new_folder_name = str(threshold) + "_" + str(slice)
            new_folder_path = folder_to_store + "/" + new_folder_name

            if os.path.exists(new_folder_path):
                existing_runs = glob.glob(new_folder_path + "*")
                largest_version = 0
                for run in existing_runs:
                    base_name = os.path.basename(run).strip().split("_")
                    if len(base_name) > 2:
                        addition = int(base_name[2])
                        if addition > largest_version:
                            largest_version = addition

                addition = str(largest_version + 1)
                new_folder_name_addition = new_folder_name + "_" + addition
                new_folder_path = folder_to_store + "/" + new_folder_name_addition
                os.mkdir(new_folder_path)
            else:
                os.mkdir(new_folder_path)

        else:
            new_folder_name = str(threshold) + "_none"
            new_folder_path = folder_to_store + "/" + new_folder_name

            if os.path.exists(new_folder_path):
                existing_runs = glob.glob(new_folder_path + "*")
                largest_version = 0
                for run in existing_runs:
                    base_name = os.path.basename(run).strip().split("_")
                    if len(base_name) > 2:
                        addition = int(base_name[2])
                        if addition > largest_version:
                            largest_version = addition

                addition = str(largest_version + 1)
                new_folder_name_addition = new_folder_name + "_" + addition
                new_folder_path = folder_to_store + "/" + new_folder_name_addition
                os.mkdir(new_folder_path)

            else:
                os.mkdir(new_folder_path)

        folders = sorted([f.path for f in os.scandir(path_to_iot_scenarios_folder) if f.is_dir()])
        folders = list(map(lambda x: (x, str(os.path.basename(x)).strip()), folders))

        filtered_folders = []

        for path, folder in folders:
            if folder != to_skip_scenario:
                filtered_folders.append(path)

        folders = filtered_folders

        scan_file_order_path = new_folder_path + "/" + "scan_order.txt"

        for index, folder in enumerate(folders):

            scenario_name = str(os.path.basename(folder)).strip()
            scenario_folder_storage = new_folder_path + "/" + scenario_name
            os.mkdir(scenario_folder_storage)

            print("Scenario: " + str(index + 1) + "/" + str(len(folders)))
            print("Scenario name: " + scenario_name)

            connections = {}
            pcap_files = glob.glob(folder + "/*.pcap")

            for index_file, pcap_file in enumerate(pcap_files):

                file_name = str(os.path.basename(pcap_file)).strip()
                file_folder = scenario_folder_storage + "/" + file_name
                os.mkdir(file_folder)

                print("File: " + str(index_file + 1) + "/" + str(len(pcap_files)))
                print("File name : " + file_name)

                with open(scan_file_order_path, 'a') as scan_file:
                    scan_file.write(scenario_name + "," + file_name + "\n")
                    scan_file.close()

                count_file_name = file_name + "_count.txt"
                count_file_path = path_to_iot_scenarios_folder + "/" + scenario_name + "/" + count_file_name
                count_file_exist = os.path.exists(count_file_path)

                write_counter = 1
                appended_packet_counter = 0

                if count_file_exist:
                    with open(count_file_path, 'r') as count_file:
                        total_number_packets = int(count_file.readline())
                        count_file.close()
                    start_time = time.time()

                last_packet = None
                last_packet_src = None
                last_packet_dst = None
                counted_packets = 0
                log_file_path = file_folder + "/" + file_name + "_log.txt"
                new_file_path = file_folder + "/" + file_name + "_filtered_20.pcap"

                with PcapReader(pcap_file) as packets:
                    for packet_count, packet in enumerate(packets):
                        counted_packets = packet_count + 1

                        if IP in packet and not UDP in packet:

                            src_ip = packet[IP].src
                            dst_ip = packet[IP].dst

                            last_packet = packet
                            last_packet_src = src_ip
                            last_packet_dst = dst_ip

                            if (src_ip, dst_ip) not in connections:
                                connections[(src_ip, dst_ip)] = [packet]
                                appended_packet_counter = appended_packet_counter + 1
                            else:
                                connections[(src_ip, dst_ip)].append(packet)
                                appended_packet_counter = appended_packet_counter + 1

                            if appended_packet_counter == 500000:

                                print("Write " + str(write_counter))
                                for address, packets_value in connections.items():
                                    amount = len(packets_value)
                                    if amount >= threshold:
                                        pktdump = PcapWriter(new_file_path, append=True, sync=True)
                                        for index, packet in enumerate(packets_value):
                                            # if index < 100:
                                            pktdump.write(packet)
                                        # else:
                                        #   break
                                        pktdump.close()

                                with open(log_file_path, 'w') as log_file:
                                    log_file.write("last_packet_count:" + str(packet_count) + "\n")
                                    log_file.write("last_packet_src:" + last_packet_src + "\n")
                                    log_file.write("last_packet_dst:" + last_packet_dst + "\n")
                                    log_file.write("last_packet:" + str(last_packet) + "\n")
                                log_file.close()

                                connections.clear()
                                appended_packet_counter = 0
                                print("Write " + str(write_counter) + " Finish")
                                write_counter = write_counter + 1

                                if count_file_exist:
                                    end_time = time.time()
                                    passed_time = end_time - start_time
                                    progress_percent = int((counted_packets / total_number_packets) * 100)
                                    packets_remaining = total_number_packets - counted_packets
                                    average_time_packet = counted_packets / passed_time
                                    time_remaining = packets_remaining * average_time_packet
                                    time_remaining_minutes = round((time_remaining / 60), 2)

                                    print("Progress: " + str(progress_percent) + " %")
                                    print("Time remaining: " + str(time_remaining_minutes) + " minutes")

                packets.close()

                if (len(connections) > 0):
                    print("Write " + str(write_counter))

                    for address, packets_value in connections.items():
                        amount = len(packets_value)
                        if amount >= threshold:

                            pktdump = PcapWriter(new_file_path, append=True, sync=True)
                            for index, packet in enumerate(packets_value):
                                # if index < 100:
                                pktdump.write(packet)
                            # else:
                            #   last_packet = packet
                            #   break
                    connections.clear()

                    with open(log_file_path, 'w') as log_file:
                        log_file.write("last_packet_count:end\n")
                        log_file.write("last_packet_src:" + last_packet_src + "\n")
                        log_file.write("last_packet_dst:" + last_packet_dst + "\n")
                        log_file.write("last_packet:" + str(last_packet) + "\n")
                    log_file.close()

                    print("Write " + str(write_counter) + " Finish")

                if (count_file_exist == False):
                    with open(count_file_path, 'w') as output_file:
                        output_file.write(str(counted_packets))
                    output_file.close()

        sys.exit()

    @staticmethod
    def restart_process_into_multiple_files_with_to_skip_scenario(threshold, path_to_iot_scenarios_folder, folder_to_restart_store, slice=None):

        threshold = threshold

        if slice:
            slice = slice

        path_to_iot_scenarios_folder = path_to_iot_scenarios_folder
        folder_to_restart_store = folder_to_restart_store

        to_skip_scenario = "CTU-IoT-Malware-Capture-60-1"

        folders = sorted([f.path for f in os.scandir(path_to_iot_scenarios_folder) if f.is_dir()])
        folders = list(map(lambda x: (x, str(os.path.basename(x)).strip()), folders))

        scan_file_order_path = folder_to_restart_store + "/" + "scan_order.txt"

        with open(scan_file_order_path, 'r') as inputfile:
            scanned_files = inputfile.readlines()

        scanned_files_list = [x.strip() for x in scanned_files]
        scanned_files_set = set()

        for file in scanned_files_list:
            scanned_files_set.add(file.split(",")[0])

        folders_still_to_scan = []

        for path, folder in folders:
            if folder not in scanned_files_set and folder != to_skip_scenario:
                folders_still_to_scan.append(path)

        folders = folders_still_to_scan

        scan_file_order_path = folder_to_restart_store + "/" + "scan_order.txt"

        for index, folder in enumerate(folders):

            scenario_name = str(os.path.basename(folder)).strip()
            scenario_folder_storage = folder_to_restart_store + "/" + scenario_name
            os.mkdir(scenario_folder_storage)

            print("Scenario: " + str(index + 1) + "/" + str(len(folders)))
            print("Scenario name: " + scenario_name)

            connections = {}
            pcap_files = glob.glob(folder + "/*.pcap")

            for index_file, pcap_file in enumerate(pcap_files):

                file_name = str(os.path.basename(pcap_file)).strip()
                file_folder = scenario_folder_storage + "/" + file_name
                os.mkdir(file_folder)

                print("File: " + str(index_file + 1) + "/" + str(len(pcap_files)))
                print("File name : " + file_name)

                with open(scan_file_order_path, 'a') as scan_file:
                    scan_file.write(scenario_name + "," + file_name + "\n")
                    scan_file.close()

                count_file_name = file_name + "_count.txt"
                count_file_path = path_to_iot_scenarios_folder + "/" + scenario_name + "/" + count_file_name
                count_file_exist = os.path.exists(count_file_path)

                write_counter = 1
                appended_packet_counter = 0

                if count_file_exist:
                    with open(count_file_path, 'r') as count_file:
                        total_number_packets = int(count_file.readline())
                        count_file.close()
                    start_time = timer()

                last_packet = None
                last_packet_src = None
                last_packet_dst = None
                counted_packets = 0

                log_file_path = file_folder + "/" + file_name + "_log.txt"
                new_file_path = file_folder + "/" + file_name + "_filtered_20.pcap"

                with PcapReader(pcap_file) as packets:
                    for packet_count, packet in enumerate(packets):
                        counted_packets = packet_count + 1

                        if IP in packet and not UDP in packet:

                            src_ip = packet[IP].src
                            dst_ip = packet[IP].dst

                            last_packet = packet
                            last_packet_src = src_ip
                            last_packet_dst = dst_ip

                            if (src_ip, dst_ip) not in connections:
                                connections[(src_ip, dst_ip)] = [packet]
                                appended_packet_counter = appended_packet_counter + 1
                            else:
                                connections[(src_ip, dst_ip)].append(packet)
                                appended_packet_counter = appended_packet_counter + 1

                            if appended_packet_counter == 500000:

                                print("Write " + str(write_counter))
                                for address, packets_value in connections.items():
                                    amount = len(packets_value)
                                    if amount >= threshold:
                                        pktdump = PcapWriter(new_file_path, append=True, sync=True)
                                        for index, packet in enumerate(packets_value):
                                            pktdump.write(packet)
                                        pktdump.close()

                                with open(log_file_path, 'w') as log_file:
                                    log_file.write("last_packet_count:" + str(packet_count) + "\n")
                                    log_file.write("last_packet_src:" + last_packet_src + "\n")
                                    log_file.write("last_packet_dst:" + last_packet_dst + "\n")
                                    log_file.write("last_packet:" + str(last_packet) + "\n")
                                log_file.close()

                                connections.clear()
                                appended_packet_counter = 0
                                print("Write " + str(write_counter) + " Finish")
                                write_counter = write_counter + 1

                                if count_file_exist:
                                    end_time = timer()
                                    passed_time = end_time - start_time
                                    progress_percent = int((counted_packets / total_number_packets) * 100)
                                    packets_remaining = total_number_packets - counted_packets
                                    average_time_packet = counted_packets / passed_time
                                    time_remaining = packets_remaining * average_time_packet
                                    time_remaining_minutes = round((time_remaining / 60), 2)

                                    print("Progress: " + str(progress_percent) + " %")
                                    print("Time remaining: " + str(time_remaining_minutes) + " minutes")

                packets.close()

                if (len(connections) > 0):
                    print("Write " + str(write_counter))

                    for address, packets_value in connections.items():
                        amount = len(packets_value)
                        if amount >= threshold:
                            pktdump = PcapWriter(new_file_path, append=True, sync=True)
                            for index, packet in enumerate(packets_value):
                                pktdump.write(packet)
                    connections.clear()

                    with open(log_file_path, 'w') as log_file:
                        log_file.write("last_packet_count:end\n")
                        log_file.write("last_packet_src:" + last_packet_src + "\n")
                        log_file.write("last_packet_dst:" + last_packet_dst + "\n")
                        log_file.write("last_packet:" + str(last_packet) + "\n")
                    log_file.close()

                    print("Write " + str(write_counter) + " Finish")

                if (count_file_exist == False):
                    with open(count_file_path, 'w') as output_file:
                        output_file.write(str(counted_packets))
                    output_file.close()

        sys.exit()


