import glob
import os
import pandas as pd
import shutil

from src.util.util import Util


class Nfstream_Operations():


    @staticmethod
    def move_pcacp_files_to_nfstream_repository(path_to_original_folder, path_to_nfstream_repository, filename_addition):

        path_to_original_folder = path_to_original_folder
        path_to_nfstream_repository = path_to_nfstream_repository
        filename_addition = filename_addition

        scan_file_order_path = path_to_original_folder + "/" + "scan_order.txt"

        with open(scan_file_order_path, 'r') as inputfile:
            scanned_files = inputfile.readlines()

        scanned_files_list = [x.strip() for x in scanned_files]
        to_move_files_path = []

        for file in scanned_files_list:
            scenario_name = file.split(",")[0]
            file_name = file.split(",")[1]
            new_file_name = scenario_name + "_" + file_name
            new_path = path_to_original_folder + "/" + scenario_name + "/" + file_name + "/" + file_name + "_" + filename_addition + ".pcap"
            to_move_files_path.append((new_path, new_file_name))

        for path, new_file_name in to_move_files_path:
            new_file_path = path_to_nfstream_repository + "/" + new_file_name
            shutil.copy(path, new_file_path)

    @staticmethod
    def add_nfstream_results_to_filtered_dataset_netflow(path_to_root_folder, path_to_nfstream_results):

        path_to_root_folder = path_to_root_folder
        path_to_nfstream_results = path_to_nfstream_results

        nfstream_csv_glob = path_to_nfstream_results + "/*.csv"
        nfstream_csv_files = glob.glob(nfstream_csv_glob)

        nfstream_csv_files = list(
            map(lambda x: (os.path.basename(x).split(".csv")[0].split("_", 3)[2],
                           os.path.basename(x).split(".csv")[0].split("_", 3)[3], x), nfstream_csv_files))

        for index, (scenario_name, file_name, path_to_nfstream_file) in enumerate(nfstream_csv_files):
            path_to_summary_csv_file = path_to_root_folder + "/" + scenario_name + "/" + file_name + "/" + file_name + "_summary.csv"

            print("File: " + str(index + 1) + "/" + str(len(nfstream_csv_files)))

            nfstream_df = pd.read_csv(path_to_nfstream_file)
            summary_df = pd.read_csv(path_to_summary_csv_file)

            nfstream_df = pd.read_csv(path_to_nfstream_file)
            summary_df = pd.read_csv(path_to_summary_csv_file)

            nfstream_src = nfstream_df[
                ["src_ip", "dst_ip", "src_port", "dst_port", "protocol", 'application_name',
                 'application_category_name']]

            nfstream_dst = nfstream_df[
                ["src_ip", "dst_ip", "src_port", "dst_port", "protocol", 'application_name',
                 'application_category_name']]
            nfstream_dst = nfstream_dst.rename(
                columns={"src_ip": "dst_ip", "dst_ip": "src_ip", "src_port": "dst_port", "dst_port": "src_port"})

            nfstream_combined = nfstream_src.append(nfstream_dst)

            nfstream_combined.fillna("Unknown", inplace=True)
            nfstream_combined = nfstream_combined.groupby(["src_ip", "dst_ip", "src_port", "dst_port", "protocol"],
                                                          as_index=False).agg(
                lambda x: ','.join(set(x)))

            nfstream_combined["ip_protocol"] = nfstream_combined["protocol"].apply(
                lambda x: Util.get_protocol_name_from_protocol_number(x))
            nfstream_combined = nfstream_combined.drop(columns="protocol")

            nfstream_combined["src_ip"] = nfstream_combined["src_ip"].apply(lambda x: str(x).strip())
            nfstream_combined["dst_ip"] = nfstream_combined["dst_ip"].apply(lambda x: str(x).strip())
            nfstream_combined["src_port"] = nfstream_combined["src_port"].apply(lambda x: str(x).strip())
            nfstream_combined["dst_port"] = nfstream_combined["dst_port"].apply(lambda x: str(x).strip())
            nfstream_combined["ip_protocol"] = nfstream_combined["ip_protocol"].apply(lambda x: str(x).strip())
            nfstream_combined["src_ip"] = nfstream_combined["src_ip"].astype(str)
            nfstream_combined["dst_ip"] = nfstream_combined["dst_ip"].astype(str)
            nfstream_combined["src_port"] = nfstream_combined["src_port"].astype(str)
            nfstream_combined["dst_port"] = nfstream_combined["dst_port"].astype(str)
            nfstream_combined["ip_protocol"] = nfstream_combined["ip_protocol"].astype(str)

            summary_df["src_ip"] = summary_df["src_ip"].apply(lambda x: str(x).strip())
            summary_df["dst_ip"] = summary_df["dst_ip"].apply(lambda x: str(x).strip())
            summary_df["src_port"] = summary_df["src_port"].apply(lambda x: str(x).strip())
            summary_df["dst_port"] = summary_df["dst_port"].apply(lambda x: str(x).strip())
            summary_df["ip_protocol"] = summary_df["ip_protocol"].apply(lambda x: str(x).strip())
            summary_df["src_ip"] = summary_df["src_ip"].astype(str)
            summary_df["dst_ip"] = summary_df["dst_ip"].astype(str)
            summary_df["src_port"] = summary_df["src_port"].astype(str)
            summary_df["dst_port"] = summary_df["dst_port"].astype(str)
            summary_df["ip_protocol"] = summary_df["ip_protocol"].astype(str)

            merged_df = summary_df.merge(right=nfstream_combined,
                                         on=["src_ip", "dst_ip", "src_port", "dst_port", "ip_protocol"])

            columns_list = ["src_ip", "dst_ip", "src_port", "dst_port", "ip_protocol", "scenario", "file",
                            "connection_length", "label", "detailed_label",
                            "detailed_label_count", "name", 'application_name', 'application_category_name', "status"]

            merged_df = merged_df.reindex(columns=columns_list)

            merged_df.to_csv(path_to_summary_csv_file, index=False)

    @staticmethod
    def add_nfstream_results_to_filtered_dataset(path_to_root_folder, path_to_nfstream_results):

        path_to_root_folder = path_to_root_folder
        path_to_nfstream_results = path_to_nfstream_results

        nfstream_csv_glob = path_to_nfstream_results + "/*.csv"
        nfstream_csv_files = glob.glob(nfstream_csv_glob)

        nfstream_csv_files = list(
            map(lambda x: (os.path.basename(x).split(".csv")[0].split("_", 1)[0], os.path.basename(x).split(".csv")[0].split("_", 1)[1], x), nfstream_csv_files))

        for index, (scenario_name, file_name, path_to_nfstream_file) in enumerate(nfstream_csv_files):

            path_to_summary_csv_file = path_to_root_folder + "/" + scenario_name + "/" + file_name + "/" + file_name + "_summary.csv"

            print("File: " + str(index + 1) + "/" + str(len(nfstream_csv_files)))

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

            columns_list = ["src_ip", "dst_ip", "scenario", "file", "connection_length", "label", "detailed_label",
                            "detailed_label_count", "name", 'application_name', 'application_category_name', "status"]
            merged_df = merged_df.reindex(columns=columns_list)

            merged_df.to_csv(path_to_summary_csv_file, index=False)

    @staticmethod
    def analyze_nfstream_results(path_to_nfstream_results, path_to_application_name_file, path_to_application_category_name):

        path_to_nfstream_results = path_to_nfstream_results

        path_to_application_name_file = path_to_application_name_file
        path_to_application_category_name = path_to_application_category_name

        to_exclude_1 = path_to_nfstream_results + r"\nf_stream_CTU-IoT-Malware-Capture-48-1_2019-02-28-19-15-13-192.168.1.200.pcap.csv"
        to_exclude_2 = path_to_nfstream_results + r"\nf_stream_CTU-IoT-Malware-Capture-49-1_2019-02-28-20-50-15-192.168.1.193.pcap.csv"
        to_exclude_3 = path_to_nfstream_results + r"\nf_stream_CTU-IoT-Malware-Capture-35-1_2018-12-21-15-33-59-192.168.1.196.pcap.csv"
        to_exclude_4 = path_to_nfstream_results + r"\nf_stream_CTU-IoT-Malware-Capture-1-1_2018-05-09-192.168.100.103.pcap.csv"


        path_to_csv_files = path_to_nfstream_results + "/*.csv"
        csv_files = glob.glob(path_to_csv_files)

        cleaned_files = []

        for file in csv_files:
            if file != to_exclude_1:
                if file != to_exclude_2:
                    if file != to_exclude_3:
                        if file != to_exclude_4:
                            cleaned_files.append(file)

        for index, csv_file in enumerate(cleaned_files):
            print("File " + str(index + 1) + "/" + str(len(cleaned_files)))
            print("Start Read")
            nfstream_df = pd.read_csv(csv_file)

            nfstream_src = nfstream_df[
                ["src_ip", "dst_ip", 'application_name', 'application_category_name']]

            nfstream_dst = nfstream_df[
                ["src_ip", "dst_ip", 'application_name', 'application_category_name']]

            nfstream_combined = nfstream_src.append(nfstream_dst)

            nfstream_combined.fillna("Unknown", inplace=True)
            nfstream_combined = nfstream_combined.groupby(["src_ip", "dst_ip"], as_index=False).agg(
                lambda x: ','.join(x))

            print("Print Write")
            with open(path_to_application_name_file, 'a+') as application_name_file, open(path_to_application_category_name, 'a+') as application_category_file:
                for application_name, application_category_name in zip(nfstream_combined["application_name"], nfstream_combined["application_category_name"]):
                    application_name_file.write(application_name + "\n")
                    application_category_file.write(application_category_name + "\n")
            application_name_file.close()
            application_category_file.close()


        num_application_name_list = []

        with open(path_to_application_name_file, 'a+') as application_name_file:
            line = application_name_file.readline().split(",")
            num_application_name = len(list(set(line)))
            num_application_name_list.append(num_application_name)

        num_application_name_series = pd.Series(num_application_name_list)
        average_num_application_name = num_application_name_series.mean()

        print(average_num_application_name)
