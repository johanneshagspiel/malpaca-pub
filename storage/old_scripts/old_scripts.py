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

class Old_Scripts():

    #
    #
    # old closest pair code
    #
    # for a in range(len(data.values())):
    #     data_point_1 = inv_mapping[mapping[keys[a]]]
    #
    #     data_point_1_scenario = data_point_1.split("->")[0].split("_", maxsplit=1)[0]
    #     data_point_1_filename = data_point_1.split("->")[0].split("_", maxsplit=1)[1]
    #     data_point_1_src_ip = data_point_1.split("->")[1]
    #     data_point_1_dst_ip = data_point_1.split("->")[2]
    #     data_point_1_cluster = csv_df[(csv_df["scenario"] == data_point_1_scenario) & (csv_df["file"] == data_point_1_filename) &(csv_df["src_ip"] == data_point_1_src_ip) & (csv_df["dst_ip"] == data_point_1_dst_ip)]["clusnum"].values[0]
    #
    #     for b in range(a + 1):
    #         data_point_2 = inv_mapping[mapping[keys[b]]]
    #
    #         data_point_2_scenario = data_point_2.split("->")[0].split("_", maxsplit=1)[0]
    #         data_point_2_filename = data_point_2.split("->")[0].split("_", maxsplit=1)[1]
    #         data_point_2_src_ip = data_point_2.split("->")[1]
    #         data_point_2_dst_ip = data_point_2.split("->")[2]
    #         data_point_2_cluster = csv_df[(csv_df["scenario"] == data_point_2_scenario) & (csv_df["file"] == data_point_2_filename) & (csv_df["src_ip"] == data_point_2_src_ip) & (csv_df["dst_ip"] == data_point_2_dst_ip)]["clusnum"].values[0]
    #
    #         if data_point_1_cluster == data_point_2_cluster:
    #             if data_point_1 != data_point_2:
    #
    #                 normalized_distance = ndistmB[a][b]
    #
    #                 if data_point_1_cluster not in cluster_distm:
    #                     cluster_distm[data_point_1_cluster] = []
    #                 cluster_distm[data_point_1_cluster].append((data_point_1, data_point_2, normalized_distance))

    @staticmethod
    def packet_test(path_to_pcap_file):

        pcap_file = glob.glob(path_to_pcap_file + "/*.pcap")[0]

        with PcapReader(pcap_file) as packets:
            for packet_count, packet in enumerate(packets):

                packet_string = packet.show(dump=True)
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
                        elif line[0] != '\\':
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

    @staticmethod
    def compare_original_ratios_to_current_ratios(path_to_additional_info, path_to_overall_summary):

        path_to_additional_info = path_to_additional_info
        path_to_overall_summary = path_to_overall_summary

        additonal_info_df = pd.read_csv(path_to_additional_info)
        additonal_info_df.columns = additonal_info_df.columns.to_series().apply(lambda x: x.strip())
        additonal_info_df = additonal_info_df[additonal_info_df["Name of Dataset"] != "CTU-IoT-Malware-Capture-60-1"]

        additonal_info_df["Attack"] = additonal_info_df["Attack"].apply(
            lambda x: (x / (additonal_info_df["Attack"].sum())))
        additonal_info_df["Benign"] = additonal_info_df["Benign"].apply(
            lambda x: (x / (additonal_info_df["Benign"].sum())))
        additonal_info_df["C&C"] = additonal_info_df["C&C"].apply(lambda x: (x / (additonal_info_df["C&C"].sum())))
        additonal_info_df["C&C-FileDownload"] = additonal_info_df["C&C-FileDownload"].apply(
            lambda x: (x / (additonal_info_df["C&C-FileDownload"].sum())))
        additonal_info_df["C&C-HeartBeat"] = additonal_info_df["C&C-HeartBeat"].apply(
            lambda x: (x / (additonal_info_df["C&C-HeartBeat"].sum())))
        additonal_info_df["C&C-HeartBeat-Attack"] = additonal_info_df["C&C-HeartBeat-Attack"].apply(
            lambda x: (x / (additonal_info_df["C&C-HeartBeat-Attack"].sum())))
        additonal_info_df["C&C-HeartBeat-FileDownload"] = additonal_info_df["C&C-HeartBeat-FileDownload"].apply(
            lambda x: (x / (additonal_info_df["C&C-HeartBeat-FileDownload"].sum())))
        additonal_info_df["C&C-Mirai"] = additonal_info_df["C&C-Mirai"].apply(
            lambda x: (x / (additonal_info_df["C&C-Mirai"].sum())))
        additonal_info_df["C&C-PartOfAHorizontalPortScan"] = additonal_info_df["C&C-PartOfAHorizontalPortScan"].apply(
            lambda x: (x / (additonal_info_df["C&C-PartOfAHorizontalPortScan"].sum())))
        additonal_info_df["C&C-Torii"] = additonal_info_df["C&C-Torii"].apply(
            lambda x: (x / (additonal_info_df["C&C-Torii"].sum())))
        additonal_info_df["FileDownload"] = additonal_info_df["FileDownload"].apply(
            lambda x: (x / (additonal_info_df["FileDownload"].sum())))
        additonal_info_df["Okiru"] = additonal_info_df["Okiru"].apply(
            lambda x: (x / (additonal_info_df["Okiru"].sum())))
        additonal_info_df["Okiru-Attack"] = additonal_info_df["Okiru-Attack"].apply(
            lambda x: (x / (additonal_info_df["Okiru-Attack"].sum())))
        additonal_info_df["PartOfAHorizontalPortScan"] = additonal_info_df["PartOfAHorizontalPortScan"].apply(
            lambda x: (x / (additonal_info_df["PartOfAHorizontalPortScan"].sum())))
        additonal_info_df["PartOfAHorizontalPortScan-Attack"] = additonal_info_df[
            "PartOfAHorizontalPortScan-Attack"].apply(
            lambda x: (x / (additonal_info_df["PartOfAHorizontalPortScan-Attack"].sum())))
        additonal_info_df["DDoS"] = additonal_info_df["DDoS"].apply(lambda x: (x / (additonal_info_df["DDoS"].sum())))

        additonal_info_df.columns = additonal_info_df.columns.to_series().apply(lambda x: x.upper())
        additonal_info_df = additonal_info_df.rename(columns={"NAME OF DATASET": "SCENARIO"})

        summary_df = pd.read_csv(path_to_overall_summary)

        detailed_label_df = summary_df.groupby("scenario")["detailed_label"].value_counts().to_frame()
        detailed_label_df = detailed_label_df.rename(columns={"detailed_label": "count"}).reset_index()

        test = pd.pivot_table(data=detailed_label_df, values="count", index="scenario", columns="detailed_label",
                              aggfunc=np.sum, fill_value=0)
        test.reset_index(drop=False, inplace=True)
        test = test.rename(columns={"Unknown": "Benign"})
        # test = test[test["scenario"] != "CTU-Honeypot-Capture-4-1"]
        # test = test[test["scenario"] != "CTU-Honeypot-Capture-5-1"]
        # test = test[test["scenario"] != "CTU-Honeypot-Capture-7-1"]
        test.columns = test.columns.to_series().apply(lambda x: x.strip().upper())

        missing_columns = list(set(additonal_info_df.columns.tolist()) - (set(test.columns.tolist())))
        for missing_column in missing_columns:
            test[missing_column] = 0

        missing_columns = list((set(test.columns.tolist())) - set(additonal_info_df.columns.tolist()))
        for missing_column in missing_columns:
            additonal_info_df[missing_column] = 0

        test = test[additonal_info_df.columns]
        test.sort_values(by='SCENARIO')
        additonal_info_df.sort_values(by='SCENARIO')

        result_path = r"C:\Users\Johannes\iCloudDrive\Uni\CSE\Year 3\Q4\Code\Dataset\Additional Info\current_dist_2.csv"
        test.to_csv(result_path, index=False)

        test["ATTACK"] = test["ATTACK"].apply(lambda x: (x / (test["ATTACK"].sum())))
        test["BENIGN"] = test["BENIGN"].apply(lambda x: (x / (test["BENIGN"].sum())))
        test["C&C"] = test["C&C"].apply(lambda x: (x / (test["C&C"].sum())))
        test["C&C-FILEDOWNLOAD"] = test["C&C-FILEDOWNLOAD"].apply(lambda x: (x / (test["C&C-FILEDOWNLOAD"].sum())))
        test["C&C-HEARTBEAT"] = test["C&C-HEARTBEAT"].apply(lambda x: (x / (test["C&C-HEARTBEAT"].sum())))
        test["C&C-HEARTBEAT-ATTACK"] = test["C&C-HEARTBEAT-ATTACK"].apply(
            lambda x: (x / (test["C&C-HEARTBEAT-ATTACK"].sum())))
        test["C&C-HEARTBEAT-FILEDOWNLOAD"] = test["C&C-HEARTBEAT-FILEDOWNLOAD"].apply(
            lambda x: (x / (test["C&C-HEARTBEAT-FILEDOWNLOAD"].sum())))
        test["C&C-MIRAI"] = test["C&C-MIRAI"].apply(lambda x: (x / (test["C&C-MIRAI"].sum())))
        test["C&C-PARTOFAHORIZONTALPORTSCAN"] = test["C&C-PARTOFAHORIZONTALPORTSCAN"].apply(
            lambda x: (x / (test["C&C-PARTOFAHORIZONTALPORTSCAN"].sum())))
        test["C&C-TORII"] = test["C&C-TORII"].apply(lambda x: (x / (test["C&C-TORII"].sum())))
        test["FILEDOWNLOAD"] = test["FILEDOWNLOAD"].apply(lambda x: (x / (test["FILEDOWNLOAD"].sum())))
        test["OKIRU"] = test["OKIRU"].apply(lambda x: (x / (test["OKIRU"].sum())))
        test["OKIRU-ATTACK"] = test["OKIRU-ATTACK"].apply(lambda x: (x / (test["OKIRU-ATTACK"].sum())))
        test["PARTOFAHORIZONTALPORTSCAN"] = test["PARTOFAHORIZONTALPORTSCAN"].apply(
            lambda x: (x / (test["PARTOFAHORIZONTALPORTSCAN"].sum())))
        test["PARTOFAHORIZONTALPORTSCAN-ATTACK"] = test["PARTOFAHORIZONTALPORTSCAN-ATTACK"].apply(
            lambda x: (x / (test["PARTOFAHORIZONTALPORTSCAN-ATTACK"].sum())))
        test["DDOS"] = test["DDOS"].apply(lambda x: (x / (test["DDOS"].sum())))

        test = test.fillna(0)
        result_path = r"C:\Users\Johannes\iCloudDrive\Uni\CSE\Year 3\Q4\Code\Dataset\Additional Info\current_dist_relative.csv"
        test = test.sort_values(by="SCENARIO")
        # test.to_csv(result_path, index=False)

        additonal_info_df = additonal_info_df.sort_values(by="SCENARIO")
        additional_info_temp_path = r"C:\Users\Johannes\iCloudDrive\Uni\CSE\Year 3\Q4\Code\Dataset\Additional Info\add_info_relative.csv"
        # additonal_info_df.to_csv(additional_info_temp_path, index=False)

        results = test.drop(columns="SCENARIO").subtract(additonal_info_df.drop(columns="SCENARIO"))
        # results = test.drop(columns="SCENARIO") - additonal_info_df.drop(columns="SCENARIO")
        results["SCENARIO"] = additonal_info_df["SCENARIO"]
        results = results.sort_values(by="SCENARIO")

        result_path = r"C:\Users\Johannes\iCloudDrive\Uni\CSE\Year 3\Q4\Code\Dataset\Additional Info\difference.csv"
        # results.to_csv(result_path, index=False)

    @staticmethod
    def analyze_two_filtered_files(path_to_filered_file_5, path_to_filered_file_20):

        filtered_5_df = pd.read_csv(path_to_filered_file_5)
        print(filtered_5_df["connection_length"].sum())

        filtered_20_df = pd.read_csv(path_to_filered_file_20)
        print(filtered_20_df["connection_length"].sum())

    @staticmethod
    def add_nfstream_results_to_filtered_dataset(path_to_root_folder, path_to_nfstream_results):

        path_to_root_folder = path_to_root_folder
        path_to_nfstream_results = path_to_nfstream_results

        nfstream_csv_glob = path_to_nfstream_results + "/*csv"
        nfstream_csv_files = glob.glob(nfstream_csv_glob)

        nfstream_csv_files = list(
            map(lambda x: (x.split("nf_stream_")[1].split(".csv")[0].split("_")[0], x.split("nf_stream_")[1].split(".csv")[0].split("_")[1], x), nfstream_csv_files))

        for index, (scenario_name, file_name, path_to_nfstream_file) in enumerate(nfstream_csv_files):

            path_to_summary_csv_file = path_to_root_folder + "/" + scenario_name + "/" + file_name + "/" + file_name + "_summary.csv"

            print("File: " + str(index + 1) + "/" + str(len(nfstream_csv_files)))

            nfstream_df = pd.read_csv(path_to_nfstream_file)
            summary_df = pd.read_csv(path_to_summary_csv_file)

            nfstream_src = nfstream_df[
                ["src_ip", "dst_ip", 'src2dst_syn_packets', 'src2dst_cwr_packets', 'src2dst_ece_packets',
                 'src2dst_urg_packets', 'src2dst_ack_packets', 'src2dst_psh_packets', 'src2dst_rst_packets',
                 'src2dst_fin_packets', 'application_name', 'application_category_name', 'application_is_guessed',
                 'requested_server_name', 'client_fingerprint', 'server_fingerprint', 'user_agent', 'content_type']]
            nfstream_src = nfstream_src.rename(
                columns={'src2dst_syn_packets': "syn_packets", 'src2dst_cwr_packets': "cwr_packets",
                         'src2dst_ece_packets': "ece_packets", 'src2dst_urg_packets': "urg_packets",
                         'src2dst_ack_packets': "ack_packets", 'src2dst_psh_packets': "psh_packets",
                         'src2dst_rst_packets': "rst_packets", 'src2dst_fin_packets': "fin_packets"})

            nfstream_dst = nfstream_df[
                ["src_ip", "dst_ip", 'dst2src_syn_packets', 'dst2src_cwr_packets', 'dst2src_ece_packets',
                 'dst2src_urg_packets', 'dst2src_ack_packets', 'dst2src_psh_packets', 'dst2src_rst_packets',
                 'dst2src_fin_packets', 'application_name', 'application_category_name', 'application_is_guessed',
                 'requested_server_name', 'client_fingerprint', 'server_fingerprint', 'user_agent', 'content_type']]
            nfstream_dst = nfstream_dst.rename(
                columns={"src_ip": "dst_ip", "dst_ip": "src_ip", 'dst2src_syn_packets': "syn_packets",
                         'dst2src_cwr_packets': "cwr_packets", 'dst2src_ece_packets': "ece_packets",
                         'dst2src_urg_packets': "urg_packets", 'dst2src_ack_packets': "ack_packets",
                         'dst2src_psh_packets': "psh_packets", 'dst2src_rst_packets': "rst_packets",
                         'dst2src_fin_packets': "fin_packets"})

            nfstream_combined = nfstream_src.append(nfstream_dst)

            nfstream_combined_num = nfstream_combined.groupby(["src_ip", "dst_ip"], as_index=False)[
                'syn_packets', 'cwr_packets', 'ece_packets', 'urg_packets', 'ack_packets', 'psh_packets', 'rst_packets', 'fin_packets'].sum()

            nfstream_combined_string = nfstream_combined[
                ["src_ip", "dst_ip", 'application_name', 'application_category_name', 'application_is_guessed',
                 'requested_server_name', 'client_fingerprint', 'server_fingerprint', 'user_agent', 'content_type']]
            nfstream_combined_string.fillna("Unknown", inplace=True)
            nfstream_combined_string = nfstream_combined_string.groupby(["src_ip", "dst_ip"], as_index=False).agg(
                lambda x: ','.join(set(x)))

            nfstream_combined = nfstream_combined_num.merge(right=nfstream_combined_string, on=["src_ip", "dst_ip"])
            nfstream_combined = nfstream_combined[
                ['src_ip', 'dst_ip', 'application_name', 'application_category_name', 'requested_server_name',
                 'client_fingerprint', 'server_fingerprint', 'user_agent', 'content_type', 'syn_packets', 'cwr_packets',
                 'ece_packets', 'urg_packets', 'ack_packets', 'psh_packets', 'rst_packets', 'fin_packets']]

            merged_df = summary_df.merge(right=nfstream_combined, on=["src_ip", "dst_ip"])

            test = merged_df[merged_df["label"] == "Malicious"][
                ["detailed_label", "application_name", "application_category_name"]]

            merged_df.to_csv(csv_summary_path, index=False)

    @staticmethod
    def split_connection_into_X_equal_parts_for_malpaca(threshold, parts, folder_to_filtered_files,
                                                        folder_to_move_data_to):

        # folder_to_filtered_files = "C:/Users/Johannes/iCloudDrive/Uni/CSE/Year 3/Q4/Code/Dataset/Filtered/20_none"
        # folder_to_move_data_to = "C:/Users/Johannes/iCloudDrive/Uni/CSE/Year 3/Q4/Code/Dataset/For Malpaca/Experiment 2 - Split Connection Into X Clusters"

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
                    part_written = 0

                    for index, packet in enumerate(packets_value):

                        if (index % threshold) == 0:
                            part_written = part_written + 1
                            new_file_path = new_folder_name + "/" + str(threshold) + "_threshold_" + str(
                                part_written) + "_part/" + scenario_name + file_name

                            if (part_written <= parts):
                                pktdump = PcapWriter(new_file_path, append=True, sync=True)

                        if (part_written <= parts):
                            pktdump.write(packet)
                        else:
                            break
            pktdump.close()

            print("Create csv file")

            csv_df = pd.read_csv(path_to_csv_file)
            csv_df["src_ip"] = csv_df["src_ip"].apply(lambda x: str(x))
            csv_df["dst_ip"] = csv_df["dst_ip"].apply(lambda x: str(x))

            for piece in range(1, (parts + 1)):

                new_csv_file_path = new_folder_name + "/" + str(threshold) + "_threshold_" + str(
                    piece) + "_part/" + scenario_name + file_name + "_summary.csv"

                with open(new_csv_file_path, 'w', newline='') as csvfile:

                    csv_writer = csv.writer(csvfile, delimiter=',', quotechar='|', quoting=csv.QUOTE_MINIMAL)

                    new_line = ["src_ip", "dst_ip", "connection_length", "scenario", "file", "label", "detailed_label"]
                    csv_writer.writerow(new_line)

                    for (src_ip, dst_ip) in connections_used:
                        src_ip = str(src_ip)
                        dst_ip = str(dst_ip)

                        label = csv_df[(csv_df["src_ip"] == src_ip) & (csv_df["dst_ip"] == dst_ip)]["label"].values[0]
                        detailed_label = \
                            csv_df[(csv_df["src_ip"] == src_ip) & (csv_df["dst_ip"] == dst_ip)][
                                "detailed_label"].values[0]

                        new_line = [str(src_ip), str(dst_ip), str(threshold), scenario_name, file_name, label,
                                    detailed_label]
                        csv_writer.writerow(new_line)

                csvfile.close()

            file_packet_dic.clear()
            connections_used.clear()

    @staticmethod
    def creating_updating_results_from_clustering():

        folder_to_results = "C:/Users/Johannes/iCloudDrive/Uni/CSE/Year 3/Q4/Code/Results/Results 1 - Different Default Values"

        folders = sorted([f.path for f in os.scandir(folder_to_results) if f.is_dir()])

        for index, folder in enumerate(folders):

            csv_file = glob.glob(folder + "/*.csv")[0]
            txt_file = glob.glob(folder + "/*.txt")[0]
            experiment_name = os.path.basename(csv_file).split("summary_")[1]

            summary_csv_df = pd.read_csv(csv_file)

            label_df = summary_csv_df.groupby("clusnum")["label"].value_counts().to_frame()
            label_df = label_df.rename(columns={"label":"count"})
            label_df = label_df.reset_index()

            labels = label_df["label"].unique()

            for label in labels:
                lower_label = label.lower()
                label_df[lower_label] = np.where(label_df["label"] == label, label_df["count"], 0)

            label_df = label_df.drop(["count", "label"], axis=1)
            label_df = label_df.rename(columns={"clusnum" : "Cluster"})

            columns = label_df.columns.tolist()
            labels = label_df.columns.tolist()
            labels.remove("Cluster")
            clusters = label_df["Cluster"].unique().tolist()

            data = []
            for cluster in clusters:
                cluster_column_data = []
                cluster_column_data.append(cluster)
                for label in labels:
                    count = int(label_df[(label_df["Cluster"] == cluster)][label].sum())
                    cluster_column_data.append(count)
                data.append(cluster_column_data)

            improved_label_df = pd.DataFrame(data, columns = columns)

            detailed_label_df = summary_csv_df.groupby("clusnum")["detailed_label"].value_counts().to_frame()
            detailed_label_df = detailed_label_df.rename(columns={"detailed_label":"count"})
            detailed_label_df = detailed_label_df.reset_index()

            detailed_labels = detailed_label_df["detailed_label"].unique()

            for detail_label in detailed_labels:
                lower_detail_label = detail_label.lower()
                detailed_label_df[lower_detail_label] = np.where(detailed_label_df["detailed_label"] == detail_label, detailed_label_df["count"], 0)

            detailed_label_df = detailed_label_df.drop(["count", "detailed_label"], axis=1)
            detailed_label_df = detailed_label_df.rename(columns={"clusnum" : "Cluster"})

            columns = detailed_label_df.columns.tolist()
            labels = detailed_label_df.columns.tolist()
            labels.remove("Cluster")
            clusters = detailed_label_df["Cluster"].unique().tolist()

            data = []
            for cluster in clusters:
                cluster_column_data = []
                cluster_column_data.append(cluster)
                for label in labels:
                    count = int(detailed_label_df[(detailed_label_df["Cluster"] == cluster)][label].sum())
                    cluster_column_data.append(count)
                data.append(cluster_column_data)

            improved_detail_label_df = pd.DataFrame(data, columns=columns)

            performance_matrix_folder = folder + "/performance_matrices"
            os.mkdir(performance_matrix_folder)

            label_performance_matrix = performance_matrix_folder + "/label_performance_matrix_" + experiment_name
            improved_label_df.to_csv(label_performance_matrix, index=False)

            label_performance_matrix_table = performance_matrix_folder + "/label_performance_matrix_" + experiment_name.split(".csv")[0] + ".png"
            fig, ax = plt.subplots()
            fig.patch.set_visible(False)
            ax.axis('off')
            ax.axis('tight')
            table = ax.table(cellText=improved_label_df.values, colLabels=improved_label_df.columns, loc='center', cellLoc='center')
            table.auto_set_column_width(col=list(range(len(improved_label_df.columns))))
            for (row, col), cell in table.get_celld().items():
                if (row == 0):
                    cell.set_text_props(fontproperties=FontProperties(weight='bold'))
            fig.tight_layout()
            plt.savefig(label_performance_matrix_table)

            detailed_label_performance_matrix = performance_matrix_folder + "/detailed_label_performance_matrix_" + experiment_name
            improved_detail_label_df.to_csv(detailed_label_performance_matrix, index=False)

            reduced_column_size_name = [x[0:10] for x in improved_detail_label_df.columns.tolist()]

            detailed_label_performance_matrix_table = performance_matrix_folder + "/detailed_label_performance_matrix_" + experiment_name.split(".csv")[0] + ".png"
            fig, ax = plt.subplots()
            fig.patch.set_visible(False)
            ax.axis('off')
            ax.axis('tight')
            table2 = ax.table(cellText=improved_detail_label_df.values, colLabels=reduced_column_size_name, loc='center', cellLoc='center')
            table2.auto_set_column_width(col=list(range(len(reduced_column_size_name))))
            for (row, col), cell in table2.get_celld().items():
                if (row == 0):
                    cell.set_text_props(fontproperties=FontProperties(weight='bold'))
            fig.tight_layout()
            plt.savefig(detailed_label_performance_matrix_table, dpi=1200, bbox_inches='tight')

    @staticmethod
    def adding_nfstream_info_to_clustering_result_csv():

        csv_file = "C:/Users/Johannes/iCloudDrive/Uni/CSE/Year 3/Q4/Code/Dataset/Test/20_threshold_1_part/summary_20_threshold_1_part_20.csv"
        csv_file_2 = "C:/Users/Johannes/iCloudDrive/Uni/CSE/Year 3/Q4/Code/Dataset/Test/20_threshold_1_part/test.csv"
        path_to_folder = "C:/Users/Johannes/iCloudDrive/Uni/CSE/Year 3/Q4/Code/Dataset/For Malpaca/Experiment 2 - Split Connection Into X Clusters/20_threshold_3_parts/20_threshold_1_part"

        csv_df = pd.read_csv(csv_file)
        labels = []
        detailed_labels = []

        application_names = []
        application_category_names = []
        requested_server_names = []
        client_fingerprints = []
        server_fingerprints = []
        user_agents = []
        content_types = []
        syn_packets = []
        cwr_packets = []
        ece_packets = []
        urg_packets = []
        ack_packets = []
        psh_packets = []
        rst_packets = []
        fin_packets = []

        for row in csv_df.iterrows():
            filename = row[1]["filename"]
            src_ip = row[1]["src_ip"]
            dst_ip = row[1]["dst_ip"]

            path_to_other_csv_file = path_to_folder + "/" + filename + "_summary.csv"
            other_csv_df = pd.read_csv(path_to_other_csv_file)

            labels.append(
                other_csv_df[(other_csv_df["src_ip"] == src_ip) & (other_csv_df["dst_ip"] == dst_ip)]["label"].values[
                    0])
            detailed_labels.append(
                other_csv_df[(other_csv_df["src_ip"] == src_ip) & (other_csv_df["dst_ip"] == dst_ip)][
                    "detailed_label"].values[0])

            application_names.append(
                other_csv_df[(other_csv_df["src_ip"] == src_ip) & (other_csv_df["dst_ip"] == dst_ip)][
                    "application_name"].values[0])
            application_category_names.append(
                other_csv_df[(other_csv_df["src_ip"] == src_ip) & (other_csv_df["dst_ip"] == dst_ip)][
                    "application_category_name"].values[0])
            requested_server_names.append(
                other_csv_df[(other_csv_df["src_ip"] == src_ip) & (other_csv_df["dst_ip"] == dst_ip)][
                    "requested_server_name"].values[0])
            client_fingerprints.append(
                other_csv_df[(other_csv_df["src_ip"] == src_ip) & (other_csv_df["dst_ip"] == dst_ip)][
                    "client_fingerprint"].values[0])
            server_fingerprints.append(
                other_csv_df[(other_csv_df["src_ip"] == src_ip) & (other_csv_df["dst_ip"] == dst_ip)][
                    "server_fingerprint"].values[0])
            user_agents.append(other_csv_df[(other_csv_df["src_ip"] == src_ip) & (other_csv_df["dst_ip"] == dst_ip)][
                                   "user_agent"].values[0])
            content_types.append(other_csv_df[(other_csv_df["src_ip"] == src_ip) & (other_csv_df["dst_ip"] == dst_ip)][
                                     "content_type"].values[0])
            syn_packets.append(other_csv_df[(other_csv_df["src_ip"] == src_ip) & (other_csv_df["dst_ip"] == dst_ip)][
                                   "syn_packets"].values[0])
            cwr_packets.append(other_csv_df[(other_csv_df["src_ip"] == src_ip) & (other_csv_df["dst_ip"] == dst_ip)][
                                   "cwr_packets"].values[0])
            ece_packets.append(other_csv_df[(other_csv_df["src_ip"] == src_ip) & (other_csv_df["dst_ip"] == dst_ip)][
                                   "ece_packets"].values[0])
            urg_packets.append(other_csv_df[(other_csv_df["src_ip"] == src_ip) & (other_csv_df["dst_ip"] == dst_ip)][
                                   "urg_packets"].values[0])
            ack_packets.append(other_csv_df[(other_csv_df["src_ip"] == src_ip) & (other_csv_df["dst_ip"] == dst_ip)][
                                   "ack_packets"].values[0])
            psh_packets.append(other_csv_df[(other_csv_df["src_ip"] == src_ip) & (other_csv_df["dst_ip"] == dst_ip)][
                                   "psh_packets"].values[0])
            rst_packets.append(other_csv_df[(other_csv_df["src_ip"] == src_ip) & (other_csv_df["dst_ip"] == dst_ip)][
                                   "rst_packets"].values[0])
            fin_packets.append(other_csv_df[(other_csv_df["src_ip"] == src_ip) & (other_csv_df["dst_ip"] == dst_ip)][
                                   "fin_packets"].values[0])

        csv_df["label"] = labels
        csv_df["detailed_label"] = detailed_labels

        csv_df["application_name"] = application_category_names
        csv_df["application_category_name"] = application_category_names
        csv_df["requested_server_name"] = requested_server_names
        csv_df["client_fingerprint"] = client_fingerprints
        csv_df["server_fingerprint"] = server_fingerprints
        csv_df["user_agent"] = user_agents
        csv_df["content_type"] = content_types
        csv_df["syn_packets"] = syn_packets
        csv_df["cwr_packets"] = cwr_packets
        csv_df["ece_packets"] = ece_packets
        csv_df["urg_packets"] = urg_packets
        csv_df["ack_packets"] = ack_packets
        csv_df["psh_packets"] = psh_packets
        csv_df["rst_packets"] = rst_packets
        csv_df["fin_packets"] = fin_packets

        csv_df.to_csv(csv_file_2, index=False)