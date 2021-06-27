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

class Adding_More_Information:

    @staticmethod
    def add_csv_info_for_one_file(path_to_root_folder, path_to_nfstream_file, scenario_name, file_name):

        path_to_root_folder = path_to_root_folder
        path_to_nfstream_file = path_to_nfstream_file

        path_to_summary_csv_file = path_to_root_folder + "/" + scenario_name + "/" + file_name + "/" + file_name + "_summary.csv"

        nfstream_df = pd.read_csv(path_to_nfstream_file)
        summary_df = pd.read_csv(path_to_summary_csv_file)

        nfstream_src = nfstream_df[
            ["src_ip", "dst_ip", 'application_name', 'application_category_name']]

        nfstream_dst = nfstream_df[
            ["src_ip", "dst_ip", 'application_name', 'application_category_name']]
        nfstream_dst = nfstream_dst.rename(
            columns={"src_ip": "dst_ip", "dst_ip": "src_ip"})

        nfstream_combined = nfstream_src.append(nfstream_dst)

        nfstream_combined.fillna("Unknown", inplace=True)
        nfstream_combined = nfstream_combined.groupby(["src_ip", "dst_ip"], as_index=False).agg(
            lambda x: ','.join(set(x)))

        merged_df = summary_df.merge(right=nfstream_combined, on=["src_ip", "dst_ip"])

        columns_list = ["src_ip", "dst_ip","connection_length", "label", "detailed_label",
                        "detailed_label_count", "name", 'application_name', 'application_category_name', "status"]
        merged_df = merged_df.reindex(columns=columns_list)

        merged_df.to_csv(path_to_summary_csv_file, index=False)


    @staticmethod
    def adding_name_info(path_to_filtered_files, path_to_name_info):

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

            columns_list = ["src_ip", "dst_ip", "scenario", "file", "connection_length", "label", "detailed_label",
                            "detailed_label_count", "name", "status"]
            summary_csv_df = summary_csv_df.reindex(columns=columns_list)

            summary_csv_df.to_csv(path_to_csv_file, index=False)

    @staticmethod
    def adding_name_info_and_rename_labels_of_benign_devices(path_to_filtered_files, path_to_name_info, path_to_benign_scenarios):

        path_to_filtered_files = path_to_filtered_files
        path_to_name_info = path_to_name_info
        path_to_benign_scenarios = path_to_benign_scenarios

        name_info_df = pd.read_csv(path_to_name_info)
        benign_scenarios = pd.read_csv(path_to_benign_scenarios)
        benign_scenarios_list = benign_scenarios["benign_scenario_name"].tolist()

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

            if scenario in benign_scenarios_list:
                summary_csv_df["label"] = np.where(summary_csv_df["label"] == "Unknown", "Benign", summary_csv_df["label"])
                summary_csv_df["detailed_label"] = np.where(summary_csv_df["detailed_label"] == "Unknown", "Benign", summary_csv_df["detailed_label"])
                summary_csv_df["status"] = np.where(summary_csv_df["status"] == "Unknown", "Keep", summary_csv_df["status"])

            columns_list = ["src_ip", "dst_ip", "scenario", "file", "connection_length", "label", "detailed_label",
                            "detailed_label_count", "name", "status"]
            summary_csv_df = summary_csv_df.reindex(columns=columns_list)

            summary_csv_df.to_csv(path_to_csv_file, index=False)

    @staticmethod
    def split_original_dataset_based_on_status(path_to_original_dataset, path_to_storage):

        path_to_original_dataset = path_to_original_dataset
        path_to_storage = path_to_storage

        keep_file_path = path_to_storage + "/keep.pcap"
        keep_csv_path = path_to_storage + "/keep.csv"

        delete_file_path = path_to_storage + "/delete.pcap"
        delete_csv_path = path_to_storage + "/delete.csv"

        unknown_file_path = path_to_storage + "/unknown.pcap"
        unknown_csv_path = path_to_storage + "/unknown.csv"

        pcap_file = glob.glob(path_to_original_dataset + "/*.pcap")[0]
        csv_summary = glob.glob(path_to_original_dataset + "/*.csv")[0]

        summary_df = pd.read_csv(csv_summary)

        keep_df = summary_df[summary_df["status"] == "keep"]
        keep_list = list(zip(keep_df["src_ip"], keep_df["dst_ip"]))

        delete_df = summary_df[summary_df["status"] == "delete"]
        delete_list = list(set(list(zip(delete_df["src_ip"], delete_df["dst_ip"]))))

        unknown_df = summary_df[summary_df["status"] == "unknown"]
        unknown_list = list(zip(unknown_df["src_ip"], unknown_df["dst_ip"]))

        keep_dic = {}
        delete_dic = {}
        unknown_dic = {}

        print("Reading PCAP Files")
        with PcapReader(pcap_file) as packets:
            for packet_count, packet in enumerate(packets):

                src_ip = packet[IP].src
                dst_ip = packet[IP].dst

                if (src_ip, dst_ip) in keep_list:
                    if (src_ip, dst_ip) not in keep_dic:
                        keep_dic[(src_ip, dst_ip)] = [packet]
                    else:
                        keep_dic[(src_ip, dst_ip)].append(packet)

                elif (src_ip, dst_ip) in delete_list:
                    if (src_ip, dst_ip) not in delete_dic:
                        delete_dic[(src_ip, dst_ip)] = [packet]
                    else:
                        delete_dic[(src_ip, dst_ip)].append(packet)

                else:
                    if (src_ip, dst_ip) not in unknown_dic:
                        unknown_dic[(src_ip, dst_ip)] = [packet]
                    else:
                        unknown_dic[(src_ip, dst_ip)].append(packet)

        print("Writing PCAP Files")
        pktdump = PcapWriter(keep_file_path, append=True, sync=True)
        for packet_list in keep_dic.values():
            for packet in packet_list:
                pktdump.write(packet)
        pktdump.close()
        keep_df.to_csv(keep_csv_path, index=False)

        pktdump = PcapWriter(delete_file_path, append=True, sync=True)
        for packet_list in delete_dic.values():
            for packet in packet_list:
                pktdump.write(packet)
        pktdump.close()
        delete_df.to_csv(delete_csv_path, index=False)

        pktdump = PcapWriter(unknown_file_path, append=True, sync=True)
        for packet_list in unknown_dic.values():
            for packet in packet_list:
                pktdump.write(packet)
        pktdump.close()
        unknown_df.to_csv(unknown_csv_path, index=False)



    @staticmethod
    def create_summary_from_separate_files(path_to_iot_scenarios_folder, folder_to_filtered_files, filename_addition):

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
            path_to_pcap_file = folder_to_filtered_files + "/" + scenario_name + "/" + file_name + "/" + file_name + filename_addition + ".pcap"
            path_to_original_folder =  path_to_iot_scenarios_folder + "/" + scenario_name

            file_packet_dic = {}
            with PcapReader(path_to_pcap_file) as packets:
                for packet_count, packet in enumerate(packets):

                    src_ip = packet[IP].src
                    dst_ip = packet[IP].dst

                    if (src_ip, dst_ip) in file_packet_dic:
                        old_value = file_packet_dic[(src_ip, dst_ip)]
                        new_value = old_value + 1
                        file_packet_dic[(src_ip, dst_ip)] = new_value
                    else:
                        file_packet_dic[(src_ip, dst_ip)] = 1
            packets.close()

            src_ip_list = []
            dst_ip_list = []
            connection_length_list = []

            for (src_ip, dst_ip), connection_length in file_packet_dic.items():
                src_ip_list.append(src_ip)
                dst_ip_list.append(dst_ip)
                connection_length_list.append(connection_length)

            data = {"src_ip": src_ip_list, "dst_ip": dst_ip_list, "connection_length": connection_length_list}
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
                bro_original_df = bro_original_df.reset_index()

                bro_original_df = bro_original_df.sort_values(by=['src_ip', 'dst_ip'])
                bro_original_df = bro_original_df.set_index(['src_ip', 'dst_ip'])
                old_info_df = old_info_df.sort_values(['src_ip', 'dst_ip'])
                old_info_df = old_info_df.set_index(['src_ip', 'dst_ip'])
                merged_df = old_info_df.merge(on=['src_ip', 'dst_ip'], right=bro_original_df, how="inner")
                merged_df = merged_df.reset_index()
                old_info_df = old_info_df.reset_index()

                detailed_label_df = merged_df.drop_duplicates(subset=['src_ip', 'dst_ip'], keep=False)
                detailed_label_df["status"] = "Found"
                deleted_df = merged_df[merged_df.duplicated(['src_ip', 'dst_ip'], keep=False)]
                deleted_df["status"] = "Mixed"

                to_check_df = pd.concat(
                    [old_info_df, merged_df.drop_duplicates(subset=['src_ip', 'dst_ip'], keep='last')]).drop_duplicates(
                    subset=['src_ip', 'dst_ip'], keep=False)
                to_check_df = to_check_df.rename(columns={"src_ip": "dst_ip", "dst_ip": "src_ip"}).drop(
                    columns=["detailed_label", "detailed_label_count"])
                merged_df_2 = to_check_df.merge(on=['src_ip', 'dst_ip'], right=bro_original_df, how="left")
                merged_df_2.reset_index()
                merged_df_2 = merged_df_2.rename(columns={"src_ip": "dst_ip", "dst_ip": "src_ip"})

                detailed_label_2_df = merged_df_2.dropna()
                detailed_label_2_df["status"] = "Response"

                deleted_2_df = merged_df_2[merged_df_2.duplicated(['src_ip', 'dst_ip'], keep=False)]
                deleted_2_df["status"] = "Mixed"

                unknown_df = merged_df_2[merged_df_2.isnull().any(axis=1)]
                unknown_df["status"] = "Unknown"

                combined_detailed_label_df = detailed_label_df.append(detailed_label_2_df)
                combined_detailed_label_2_df = combined_detailed_label_df.drop_duplicates(subset=['src_ip', 'dst_ip'],
                                                                                          keep=False)
                #combined_detailed_label_2_df["status"] = "Keep"
                deleted_3_df = combined_detailed_label_df[
                    combined_detailed_label_df.duplicated(['src_ip', 'dst_ip'], keep=False)]

                combined_deleted_df = deleted_df.append(deleted_2_df).append(deleted_3_df)
                combined_deleted_df = combined_deleted_df.drop_duplicates(subset=['src_ip', 'dst_ip', 'detailed_label'],
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

                columns_list = ["src_ip", "dst_ip", "scenario", "file", "connection_length", "label", "detailed_label", "detailed_label_count", "status"]

                combined_df = combined_df.reindex(columns=columns_list)

                combined_df.to_csv(path_to_csv_file, index=False)

            else:
                old_info_df["label"] = "Unknown"
                old_info_df["detailed_label"] = "Unknown"
                old_info_df["detailed_label_count"] = 0
                old_info_df["status"] = "Unknown"

                columns_list = ["src_ip", "dst_ip", "scenario", "file", "connection_length", "label", "detailed_label", "detailed_label_count", "status"]

                old_info_df = combined_df.reindex(columns=columns_list)
                old_info_df.to_csv(path_to_csv_file, index=False)

    # @staticmethod
    # def restart_create_summary(path_to_original_dataset, path_to_storage, filename_addition):
    #
        # path_to_original_dataset = path_to_original_dataset
        # path_to_storage = path_to_storage
        # filename_addition = filename_addition
        #
        # scan_file_order_path = path_to_storage + "/scan_order.txt"
        # log_order_path = path_to_storage + "/log_order.txt"
        #
        # with open(scan_file_order_path, 'r') as inputfile:
        #     scanned_files = inputfile.readlines()
        #
        # with open(log_order_path, 'r') as inputfile:
        #     logged_files = inputfile.readlines()
        #
        # scanned_files_list = [x.strip() for x in scanned_files]
        # logged_files_list = [x.strip() for x in logged_files]
        #
        # folders_still_to_scan = []
        #
        # for scanned_file in scanned_files_list:
        #     if scanned_file not in logged_files_list:
        #         folders_still_to_scan.append(scanned_file)
        #
        # folders = folders_still_to_scan
        # folders = list(map(lambda x: (x.split(",")[0], x.split(",")[1]), folders))
    #
    #     for index, (scenario_name, file_name) in enumerate(folders):
    #         print("Scenario name: " + scenario_name)
    #         print("File name : " + file_name)
    #         print("Number: " + str(index + 1) + "/" + str(len(folders)))
    #
    #         log_order_path = path_to_storage + "/" + "log_order.txt"
    #         with open(log_order_path, 'a') as log_order_file:
    #             log_order_file.write(scenario_name + "," + file_name + "\n")
    #             log_order_file.close()
    #
    #         print("Reading PCAP File")
    #
    #         path_to_csv_file = path_to_storage + "/" + scenario_name + "/" + file_name + "/" + file_name + "_summary.csv"
    #         path_to_pcap_file = path_to_storage + "/" + scenario_name + "/" + file_name + "/" + file_name + filename_addition +".pcap"
    #         path_to_original_folder =  path_to_original_dataset + "/" + scenario_name
    #
    #         file_packet_dic = {}
    #         with PcapReader(path_to_pcap_file) as packets:
    #             for packet_count, packet in enumerate(packets):
    #
    #                 src_ip = packet[IP].src
    #                 dst_ip = packet[IP].dst
    #
    #                 if (src_ip, dst_ip) in file_packet_dic:
    #                     old_value = file_packet_dic[(src_ip, dst_ip)]
    #                     new_value = old_value + 1
    #                     file_packet_dic[(src_ip, dst_ip)] = new_value
    #                 else:
    #                     file_packet_dic[(src_ip, dst_ip)] = 1
    #         packets.close()
    #
    #         src_ip_list = []
    #         dst_ip_list = []
    #         connection_length_list = []
    #
    #         for (src_ip, dst_ip), connection_length in file_packet_dic.items():
    #             src_ip_list.append(src_ip)
    #             dst_ip_list.append(dst_ip)
    #             connection_length_list.append(connection_length)
    #
    #         data = {"src_ip": src_ip_list, "dst_ip": dst_ip_list, "connection_length": connection_length_list}
    #         old_info_df = pd.DataFrame(data)
    #
    #
    #         print("Adding Logg Data")
    #         sub_folders = [f.path for f in os.scandir(path_to_original_folder) if f.is_dir()]
    #         bro_folder_found = False
    #
    #         for sub_folder in sub_folders:
    #             base_name = str(os.path.basename(sub_folder))
    #
    #             if base_name == "bro":
    #                 labeled_files = glob.glob(sub_folder + "/*.labeled")
    #                 bro_folder_found = True
    #                 break
    #
    #         if bro_folder_found and len(labeled_files) > 0:
    #
    #             logg_file = labeled_files[0]
    #
    #             zat = LogToDataFrame()
    #             bro_original_df = zat.create_dataframe(logg_file)
    #             bro_original_df["label"] = bro_original_df["tunnel_parents   label   detailed-label"].apply(
    #                 lambda x: x.split("  ")[1].strip())
    #             bro_original_df["detailed_label"] = bro_original_df["tunnel_parents   label   detailed-label"].apply(
    #                 lambda x: x.split("  ")[2].strip())
    #             bro_original_df = bro_original_df.rename(columns={"id.orig_h": "src_ip", "id.resp_h": "dst_ip"})
    #             bro_original_df = bro_original_df.drop(
    #                 columns=['uid', 'id.orig_p', 'id.resp_p', 'proto', 'service', 'duration', 'orig_bytes',
    #                          'resp_bytes',
    #                          'conn_state', 'local_orig', 'local_resp', 'missed_bytes', 'history', 'orig_pkts',
    #                          'orig_ip_bytes',
    #                          'resp_pkts', 'resp_ip_bytes', 'tunnel_parents   label   detailed-label'])
    #             bro_original_df.sort_values(["src_ip", "dst_ip"], inplace=True)
    #
    #             bro_original_df = bro_original_df.groupby(['src_ip', 'dst_ip'])[
    #                 'detailed_label'].value_counts().to_frame()
    #             bro_original_df = bro_original_df.rename(columns={"detailed_label": "detailed_label_count"})
    #             bro_original_df = bro_original_df.reset_index()
    #
    #             bro_original_df = bro_original_df.sort_values(by=['src_ip', 'dst_ip'])
    #             bro_original_df = bro_original_df.set_index(['src_ip', 'dst_ip'])
    #             old_info_df = old_info_df.sort_values(['src_ip', 'dst_ip'])
    #             old_info_df = old_info_df.set_index(['src_ip', 'dst_ip'])
    #             merged_df = old_info_df.merge(on=['src_ip', 'dst_ip'], right=bro_original_df, how="inner")
    #             merged_df = merged_df.reset_index()
    #             old_info_df = old_info_df.reset_index()
    #
    #             detailed_label_df = merged_df.drop_duplicates(subset=['src_ip', 'dst_ip'], keep=False)
    #             detailed_label_df["status"] = "Found"
    #             deleted_df = merged_df[merged_df.duplicated(['src_ip', 'dst_ip'], keep=False)]
    #             deleted_df["status"] = "Mixed"
    #
    #             to_check_df = pd.concat(
    #                 [old_info_df, merged_df.drop_duplicates(subset=['src_ip', 'dst_ip'], keep='last')]).drop_duplicates(
    #                 subset=['src_ip', 'dst_ip'], keep=False)
    #             to_check_df = to_check_df.rename(columns={"src_ip": "dst_ip", "dst_ip": "src_ip"}).drop(
    #                 columns=["detailed_label", "detailed_label_count"])
    #             merged_df_2 = to_check_df.merge(on=['src_ip', 'dst_ip'], right=bro_original_df, how="left")
    #             merged_df_2.reset_index()
    #             merged_df_2 = merged_df_2.rename(columns={"src_ip": "dst_ip", "dst_ip": "src_ip"})
    #
    #             detailed_label_2_df = merged_df_2.dropna()
    #             detailed_label_2_df["status"] = "Response"
    #
    #             deleted_2_df = merged_df_2[merged_df_2.duplicated(['src_ip', 'dst_ip'], keep=False)]
    #             deleted_2_df["status"] = "Mixed"
    #
    #             unknown_df = merged_df_2[merged_df_2.isnull().any(axis=1)]
    #             unknown_df["status"] = "Unknown"
    #
    #             combined_detailed_label_df = detailed_label_df.append(detailed_label_2_df)
    #             combined_detailed_label_2_df = combined_detailed_label_df.drop_duplicates(subset=['src_ip', 'dst_ip'],
    #                                                                                       keep=False)
    #             #combined_detailed_label_2_df["status"] = "Keep"
    #             deleted_3_df = combined_detailed_label_df[
    #                 combined_detailed_label_df.duplicated(['src_ip', 'dst_ip'], keep=False)]
    #             deleted_3_df["status"] = "Mixed"
    #
    #             combined_df = combined_detailed_label_2_df.append(deleted_df).append(deleted_2_df).append(
    #                 deleted_3_df).append(unknown_df)
    #
    #             combined_df["detailed_label"] = combined_df.detailed_label.astype(str)
    #
    #             combined_df["detailed_label"] = combined_df["detailed_label"].fillna(value="Unknown")
    #             combined_df["detailed_label_count"] = combined_df["detailed_label_count"].fillna(value="0")
    #
    #             combined_df["detailed_label"] = combined_df["detailed_label"].replace(to_replace="nan", value="Unknown")
    #             combined_df["detailed_label"] = combined_df["detailed_label"].replace(to_replace="-", value="Benign")
    #
    #             combined_df["label"] = np.where(combined_df["detailed_label"] == "Benign", "Benign", "Malicious")
    #             combined_df["label"] = np.where(combined_df["detailed_label"] == "Unknown", "Unknown",
    #                                             combined_df["label"])
    #
    #             columns_list = ["src_ip", "dst_ip", "scenario", "file", "connection_length", "label", "detailed_label",
    #                             "detailed_label_count", "status"]
    #             combined_df = combined_df.reindex(columns=columns_list)
    #
    #             combined_df.to_csv(path_to_csv_file, index=False)
    #
    #         else:
    #             old_info_df["label"] = "Unknown"
    #             old_info_df["detailed_label"] = "Unknown"
    #             old_info_df["detailed_label_count"] = 0
    #             old_info_df["status"] = "Unknown"
    #
    #             columns_list = ["src_ip", "dst_ip", "connection_length", "label", "detailed_label", "detailed_label_count", "status"]
    #
    #             old_info_df = combined_df.reindex(columns=columns_list)
    #             old_info_df.to_csv(path_to_csv_file, index=False)


    @staticmethod
    def create_summary_from_separate_files_individual(path_to_pcap_file, path_to_logg_file, path_to_storage):

        path_to_pcap_file = path_to_pcap_file
        path_to_logg_file = path_to_logg_file
        path_to_storage = path_to_storage

        file_packet_dic = {}
        with PcapReader(path_to_pcap_file) as packets:
            for packet_count, packet in enumerate(packets):

                src_ip = packet[IP].src
                dst_ip = packet[IP].dst

                if (src_ip, dst_ip) in file_packet_dic:
                    old_value = file_packet_dic[(src_ip, dst_ip)]
                    new_value = old_value + 1
                    file_packet_dic[(src_ip, dst_ip)] = new_value
                else:
                    file_packet_dic[(src_ip, dst_ip)] = 1
        packets.close()


        src_ip_list = []
        dst_ip_list = []
        connection_length_list = []

        for (src_ip, dst_ip), connection_length in file_packet_dic.items():
            src_ip_list.append(src_ip)
            dst_ip_list.append(dst_ip)
            connection_length_list.append(connection_length)

        data = {"src_ip" : src_ip_list, "dst_ip" : dst_ip_list, "connection_length" : connection_length_list}
        old_info_df = pd.DataFrame(data)


        zat = LogToDataFrame()
        bro_original_df = zat.create_dataframe(path_to_logg_file)
        bro_original_df["label"] = bro_original_df["tunnel_parents   label   detailed-label"].apply(
            lambda x: x.split("  ")[1].strip())
        bro_original_df["detailed_label"] = bro_original_df["tunnel_parents   label   detailed-label"].apply(
            lambda x: x.split("  ")[2].strip())
        bro_original_df = bro_original_df.rename(columns={"id.orig_h": "src_ip", "id.resp_h": "dst_ip"})
        bro_original_df = bro_original_df.drop(
            columns=['uid', 'id.orig_p', 'id.resp_p', 'proto', 'service', 'duration', 'orig_bytes', 'resp_bytes',
                     'conn_state', 'local_orig', 'local_resp', 'missed_bytes', 'history', 'orig_pkts', 'orig_ip_bytes',
                     'resp_pkts', 'resp_ip_bytes', 'tunnel_parents   label   detailed-label'])
        bro_original_df.sort_values(["src_ip", "dst_ip"], inplace=True)

        bro_original_df = bro_original_df.groupby(['src_ip', 'dst_ip'])['detailed_label'].value_counts().to_frame()
        bro_original_df = bro_original_df.rename(columns={"detailed_label": "detailed_label_count"})
        bro_original_df = bro_original_df.reset_index()

        bro_original_df = bro_original_df.sort_values(by=['src_ip','dst_ip'])
        bro_original_df = bro_original_df.set_index(['src_ip', 'dst_ip'])
        old_info_df = old_info_df.sort_values(['src_ip', 'dst_ip'])
        old_info_df = old_info_df.set_index(['src_ip', 'dst_ip'])
        merged_df = old_info_df.merge(on=['src_ip','dst_ip'], right=bro_original_df, how="inner")
        merged_df = merged_df.reset_index()
        old_info_df = old_info_df.reset_index()

        detailed_label_df = merged_df.drop_duplicates(subset=['src_ip','dst_ip'], keep=False)
        detailed_label_df["status"] = "keep"
        deleted_df = merged_df[merged_df.duplicated(['src_ip','dst_ip'], keep=False)]
        deleted_df["status"] = "delete"

        to_check_df = pd.concat([old_info_df, merged_df.drop_duplicates(subset=['src_ip','dst_ip'], keep='last')]).drop_duplicates(subset=['src_ip','dst_ip'], keep=False)
        to_check_df = to_check_df.rename(columns={"src_ip" : "dst_ip", "dst_ip" : "src_ip"}).drop(columns=["detailed_label", "detailed_label_count"])
        merged_df_2 = to_check_df.merge(on=['src_ip', 'dst_ip'], right=bro_original_df, how="left")
        merged_df_2.reset_index()
        merged_df_2 = merged_df_2.rename(columns={"src_ip" : "dst_ip", "dst_ip" : "src_ip"})

        detailed_label_2_df = merged_df_2.dropna()
        detailed_label_2_df["status"] = "keep"
        deleted_2_df = merged_df_2[merged_df_2.duplicated(['src_ip','dst_ip'], keep=False)]
        deleted_2_df["status"] = "delete"
        unknown_df = merged_df_2[merged_df_2.isnull().any(axis=1)]
        unknown_df["status"] = "unknown"

        combined_df = detailed_label_df.append(detailed_label_2_df).append(deleted_df).append(deleted_2_df).append(unknown_df)

        combined_df["detailed_label"] = combined_df.detailed_label.astype(str)

        combined_df["detailed_label"] = combined_df["detailed_label"].fillna(value="Unknown")
        combined_df["detailed_label"] = combined_df["detailed_label"].replace(to_replace="nan", value="Unknown")
        combined_df["detailed_label"] = combined_df["detailed_label"].replace(to_replace="-", value="Benign")

        combined_df["label"] = np.where(combined_df["detailed_label"] == "Benign", "Benign", "Malicious")
        combined_df["label"] = np.where(combined_df["detailed_label"] == "Unknown", "Unknown", combined_df["label"])

        columns_list = ["src_ip", "dst_ip", "connection_length", "label", "detailed_label", "detailed_label_count", "status"]
        combined_df = combined_df.reindex(columns=columns_list)

        combined_df.to_csv(path_to_storage, index=False)

    @staticmethod
    def create_summary_from_separate_files_old():

        path_to_iot_scenarios_folder = "C:/Users/Johannes/iCloudDrive/Uni/CSE/Year 3/Q4/Code/Dataset/Original/IoTScenarios"
        folder_to_filtered_files = "C:/Users/Johannes/iCloudDrive/Uni/CSE/Year 3/Q4/Code/Dataset/Filtered/5_none"

        to_skip_scenario = "CTU-IoT-Malware-Capture-60-1"

        folders = sorted([f.path for f in os.scandir(path_to_iot_scenarios_folder) if f.is_dir()])
        folders = list(map(lambda x: (x, str(os.path.basename(x)).strip()), folders))

        scan_file_order_path = folder_to_filtered_files + "/" + "scan_order.txt"
        scanned_files = []
        with open(scan_file_order_path, 'r') as inputfile:
            scanned_files = inputfile.readlines()

        scanned_files_list = [x.strip() for x in scanned_files]
        scanned_files_list = list(map(lambda x: (x.split(",")[0], x.split(",")[1]), scanned_files_list))
        scanned_files_list = sorted(list(set(scanned_files_list)))

        for index, (scenario_name, file_name) in enumerate(scanned_files_list):

            print("Creating csv file")
            print("Scenario name: " + scenario_name)
            print("File name : " + file_name)
            print("Number: " + str(index + 1) + "/" + str(len(scanned_files_list)))

            log_order_path = folder_to_filtered_files + "/" + "log_order.txt"
            with open(log_order_path, 'a') as log_order_file:
                log_order_file.write(scenario_name + "," + file_name + "\n")
                log_order_file.close()

            path_to_csv_file = folder_to_filtered_files + "/" + scenario_name + "/" + file_name + "/" + file_name + "_summary.csv"
            path_to_pcap_file = folder_to_filtered_files + "/" + scenario_name + "/" + file_name + "/" + file_name + "_filtered_20.pcap"

            file_packet_dic = {}

            with PcapReader(path_to_pcap_file) as packets:
                for packet_count, packet in enumerate(packets):

                    src_ip = packet[IP].src
                    dst_ip = packet[IP].dst

                    if (src_ip, dst_ip) in file_packet_dic:
                        old_value = file_packet_dic[(src_ip, dst_ip)]
                        new_value = old_value + 1
                        file_packet_dic[(src_ip, dst_ip)] = new_value
                    else:
                        file_packet_dic[(src_ip, dst_ip)] = 1
            packets.close()

            with open(path_to_csv_file, 'w', newline='') as csvfile:
                csv_writer = csv.writer(csvfile, delimiter=',', quotechar='|', quoting=csv.QUOTE_MINIMAL)

                new_line = ["src_ip", "dst_ip", "connection_length", "scenario", "file", "label", "detailed_label"]
                csv_writer.writerow(new_line)

                for index, value in file_packet_dic.items():
                    new_line = [str(index[0]), str(index[1]), str(value), scenario_name, file_name, "Unknown", "-"]
                    csv_writer.writerow(new_line)
            csvfile.close()

        for index, (scenario_name, file_name) in enumerate(scanned_files_list):

            path_to_original_folder =  path_to_iot_scenarios_folder + "/" + scenario_name
            csv_summary_file_path = folder_to_filtered_files + "/" + scenario_name + "/" + file_name + "/" + file_name + "_summary.csv"

            print("Updating csv file")
            print("Scenario name: " + scenario_name)
            print("File name : " + file_name)
            print("Number: " + str(index + 1) + "/" + str(len(scanned_files_list)))

            bro_addition_order_path = folder_to_filtered_files + "/" + "bro_addition_order.txt"
            with open(bro_addition_order_path, 'a') as bro_addition_file:
                bro_addition_file.write(scenario_name + "," + file_name + "\n")
                bro_addition_file.close()

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
                bro_original_df["src_ip"] = bro_original_df["id.orig_h"].apply(lambda x: str(x))
                bro_original_df["dst_ip"] = bro_original_df["id.resp_h"].apply(lambda x: str(x))

                bro_original_df = bro_original_df.drop(
                    columns=["uid", "id.orig_p", "id.resp_p", "id.resp_h", "id.orig_h", "proto", 'service', 'duration',
                             'orig_bytes', 'resp_bytes', 'conn_state', 'local_orig', 'local_resp', 'missed_bytes',
                             'history', 'orig_pkts', 'orig_ip_bytes', 'resp_pkts', 'resp_ip_bytes',
                             'tunnel_parents   label   detailed-label'])
                bro_original_df.sort_values("src_ip", inplace=True)
                bro_original_df.drop_duplicates(subset=["src_ip", "dst_ip"], inplace=True)

                csv_df = pd.read_csv(csv_summary_file_path)
                csv_df["src_ip"] = csv_df["src_ip"].apply(lambda x: str(x))
                csv_df["dst_ip"] = csv_df["dst_ip"].apply(lambda x: str(x))

                to_merge_csv_df = csv_df.drop(columns=["detailed_label", "label"])
                merged_df = to_merge_csv_df.merge(bro_original_df, on=["src_ip", "dst_ip"], how="left")

                without_na = merged_df.dropna()
                rows_with_missing_label_data = merged_df[merged_df["label"].isna()]
                rows_with_missing_label_data_changed_src_dst = rows_with_missing_label_data.rename(
                    columns={"src_ip": "dst_ip", "dst_ip": "src_ip"})
                rows_with_merged_label_data_changed_src_dst = rows_with_missing_label_data_changed_src_dst.drop(
                    columns=["label", "detailed_label"]).merge(right=bro_original_df, on=["src_ip", "dst_ip"], how="left")
                rows_with_merged_label_data = rows_with_merged_label_data_changed_src_dst.rename(
                    columns={"src_ip": "dst_ip", "dst_ip": "src_ip"})

                merged_df = without_na.append(rows_with_merged_label_data)

                merged_df["label"] = merged_df["label"].astype(str)
                merged_df["detailed_label"] = merged_df["detailed_label"].astype(str)

                merged_df["label"] = merged_df["label"].fillna(value="Unknown")
                merged_df["label"] = merged_df["label"].replace(to_replace ="nan", value ="Unknown")
                merged_df["label"] = merged_df["label"].str.capitalize()

                merged_df["detailed_label"] = merged_df["detailed_label"].fillna(value="-")
                merged_df["detailed_label"] = merged_df["detailed_label"].replace(to_replace="nan", value="-")
                merged_df["detailed_label"] = merged_df["detailed_label"].replace(to_replace="Unknown", value="-")
                merged_df["detailed_label"] = merged_df["detailed_label"].str.capitalize()

                merged_df.to_csv(csv_summary_file_path, index=False)

            else:
                csv_df = pd.read_csv(csv_summary_file_path)

                csv_df["label"] = "Unknown"
                csv_df["detailed_label"] = "-"
                csv_df = csv_df[["src_ip", "dst_ip", "connection_length", "scenario", "file", "label", "detailed_label"]]
                csv_df.to_csv(csv_summary_file_path, index=False)

    @staticmethod
    def create_summary_for_one_file(path_to_pcap_file, logg_file, path_to_csv_file, scenario_name, file_name):

        path_to_pcap_file = path_to_pcap_file
        logg_file = logg_file
        path_to_csv_file = path_to_csv_file

        file_packet_dic = {}
        with PcapReader(path_to_pcap_file) as packets:
            for packet_count, packet in enumerate(packets):

                src_ip = packet[IP].src
                dst_ip = packet[IP].dst

                if (src_ip, dst_ip) in file_packet_dic:
                    old_value = file_packet_dic[(src_ip, dst_ip)]
                    new_value = old_value + 1
                    file_packet_dic[(src_ip, dst_ip)] = new_value
                else:
                    file_packet_dic[(src_ip, dst_ip)] = 1
        packets.close()

        src_ip_list = []
        dst_ip_list = []
        connection_length_list = []

        for (src_ip, dst_ip), connection_length in file_packet_dic.items():
            src_ip_list.append(src_ip)
            dst_ip_list.append(dst_ip)
            connection_length_list.append(connection_length)

        data = {"src_ip": src_ip_list, "dst_ip": dst_ip_list, "connection_length": connection_length_list}
        old_info_df = pd.DataFrame(data)
        old_info_df["scenario"] = scenario_name
        old_info_df["file"] = file_name

        zat = LogToDataFrame()
        bro_original_df = zat.create_dataframe(logg_file)
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
        bro_original_df = bro_original_df.reset_index()

        bro_original_df = bro_original_df.sort_values(by=['src_ip', 'dst_ip'])
        bro_original_df = bro_original_df.set_index(['src_ip', 'dst_ip'])
        old_info_df = old_info_df.sort_values(['src_ip', 'dst_ip'])
        old_info_df = old_info_df.set_index(['src_ip', 'dst_ip'])
        merged_df = old_info_df.merge(on=['src_ip', 'dst_ip'], right=bro_original_df, how="inner")
        merged_df = merged_df.reset_index()
        old_info_df = old_info_df.reset_index()

        detailed_label_df = merged_df.drop_duplicates(subset=['src_ip', 'dst_ip'], keep=False)
        detailed_label_df["status"] = "Found"
        deleted_df = merged_df[merged_df.duplicated(['src_ip', 'dst_ip'], keep=False)]
        deleted_df["status"] = "Mixed"

        to_check_df = pd.concat(
            [old_info_df, merged_df.drop_duplicates(subset=['src_ip', 'dst_ip'], keep='last')]).drop_duplicates(
            subset=['src_ip', 'dst_ip'], keep=False)
        to_check_df = to_check_df.rename(columns={"src_ip": "dst_ip", "dst_ip": "src_ip"}).drop(
            columns=["detailed_label", "detailed_label_count"])
        merged_df_2 = to_check_df.merge(on=['src_ip', 'dst_ip'], right=bro_original_df, how="left")
        merged_df_2.reset_index()
        merged_df_2 = merged_df_2.rename(columns={"src_ip": "dst_ip", "dst_ip": "src_ip"})

        detailed_label_2_df = merged_df_2.dropna()
        detailed_label_2_df["status"] = "Response"

        deleted_2_df = merged_df_2[merged_df_2.duplicated(['src_ip', 'dst_ip'], keep=False)]
        deleted_2_df["status"] = "Mixed"

        unknown_df = merged_df_2[merged_df_2.isnull().any(axis=1)]
        unknown_df["status"] = "Unknown"

        combined_detailed_label_df = detailed_label_df.append(detailed_label_2_df)
        combined_detailed_label_2_df = combined_detailed_label_df.drop_duplicates(subset=['src_ip', 'dst_ip'],
                                                                                  keep=False)
        # combined_detailed_label_2_df["status"] = "Keep"
        deleted_3_df = combined_detailed_label_df[
            combined_detailed_label_df.duplicated(['src_ip', 'dst_ip'], keep=False)]

        combined_deleted_df = deleted_df.append(deleted_2_df).append(deleted_3_df)
        combined_deleted_df = combined_deleted_df.drop_duplicates(subset=['src_ip', 'dst_ip', 'detailed_label'],
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

        columns_list = ["src_ip", "dst_ip", "scenario", "file", "connection_length", "label", "detailed_label",
                        "detailed_label_count", "status"]

        combined_df = combined_df.reindex(columns=columns_list)

        combined_df.to_csv(path_to_csv_file, index=False)

    @staticmethod
    def logged_file_experimentation(path_to_logg_file, path_to_storage):

        zat = LogToDataFrame()
        bro_original_df = zat.create_dataframe(path_to_logg_file)

        bro_original_df["label"] = bro_original_df["tunnel_parents   label   detailed-label"].apply(
            lambda x: x.split("  ")[1].strip())
        bro_original_df["detailed_label"] = bro_original_df["tunnel_parents   label   detailed-label"].apply(
            lambda x: x.split("  ")[2].strip())
        bro_original_df["src_ip"] = bro_original_df["id.orig_h"].apply(lambda x: str(x))
        bro_original_df["dst_ip"] = bro_original_df["id.resp_h"].apply(lambda x: str(x))

        bro_original_df = bro_original_df.drop(
            columns=["uid", "id.orig_p", "id.resp_p", "id.resp_h", "id.orig_h", "proto", 'service', 'duration',
                     'orig_bytes', 'resp_bytes', 'conn_state', 'local_orig', 'local_resp', 'missed_bytes',
                     'history', 'orig_pkts', 'orig_ip_bytes', 'resp_pkts', 'resp_ip_bytes',
                     'tunnel_parents   label   detailed-label'])
        bro_original_df.sort_values("src_ip", inplace=True)
        bro_original_df.groupby(["src_ip", "dst_ip"], as_index=False).agg(lambda x: ','.join(set(x)))

        bro_original_df.to_csv(path_to_storage, index=False)
