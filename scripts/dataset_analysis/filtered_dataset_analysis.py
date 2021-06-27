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

class Filtered_Dataset_Analysis():


    @staticmethod
    def original_dataset_detailed_label_info_to_ratio(path_to_original_files, path_to_detailed_label_overview_file, path_to_storage, to_check_file_name_without_extension, data_set_name):

        folders = [f.path for f in os.scandir(path_to_original_files) if f.is_dir()]

        total_ratio_path = path_to_storage + "/" + data_set_name+"_total_ratio.csv"
        relative_ratio_path = path_to_storage + "/" + data_set_name + "_relative_ratio.csv"


        for index, folder in enumerate(folders):
            scenario_name = os.path.basename(folder)

            print("Scenario " + str(index + 1) + "/" + str(len(folders)))

            subfolders = [f.path for f in os.scandir(folder) if f.is_dir()]

            for subfolder in subfolders:
                if os.path.basename(subfolder) == "bro":

                    path_to_csv = subfolder + "/" + to_check_file_name_without_extension + ".csv"

                    total_detailed_label_list = pd.read_csv(path_to_detailed_label_overview_file)["detailed_label"].tolist()
                    total_detailed_label_list.sort()

                    summary_df = pd.read_csv(path_to_csv)
                    summary_df["detailed_label"] = summary_df["detailed_label"].str.lower()

                    scenario_name = scenario_name

                    summary_df["detailed_label"] = np.where(summary_df["detailed_label"] == '-', "benign", summary_df["detailed_label"])


                    for detailed_label in total_detailed_label_list:

                        if (detailed_label in summary_df.detailed_label.unique().tolist()) == False:
                            new_row = {"detailed_label" : detailed_label, "connection_count" : 0, "scenario" : scenario_name}
                            summary_df = summary_df.append(new_row, ignore_index=True)

                    summary_df = summary_df.sort_values(by="detailed_label")

                    detailed_label_pt = pd.pivot_table(data=summary_df, values="connection_count", index="scenario", columns="detailed_label", aggfunc=np.sum, fill_value=0)

                    if index == 0:
                        combined_df = detailed_label_pt
                    else:
                        combined_df = combined_df.append(detailed_label_pt)

        combined_df = combined_df.sort_values(by="scenario")
        combined_df = combined_df.reset_index()
        combined_df.to_csv(total_ratio_path, index=False)

        relative_ratio_df = combined_df

        for detailed_label in total_detailed_label_list:
            if relative_ratio_df[detailed_label].sum() != 0:
                relative_ratio_df[detailed_label] = relative_ratio_df[detailed_label].apply(
                    lambda x: (x / (relative_ratio_df[detailed_label].sum())))

        relative_ratio_df.to_csv(relative_ratio_path, index=False)

    @staticmethod
    def ratio_summary_creation(path_to_combined_summary, path_to_detailed_label_folder, path_to_storage, data_set_name):

        path_to_combined_summary = path_to_combined_summary
        path_to_detailed_label_folder = path_to_detailed_label_folder
        path_to_storage = path_to_storage
        data_set_name = data_set_name

        total_ratio_path = path_to_storage + "/" + data_set_name+"_total_ratio.csv"
        relative_ratio_path = path_to_storage + "/" + data_set_name + "_relative_ratio.csv"
        total_difference_path = path_to_storage + "/" + data_set_name + "_total_difference.csv"

        total_detailed_label_list = pd.read_csv(path_to_detailed_label_folder)["detailed_label"].tolist()
        total_detailed_label_list.sort()

        summary_df = pd.read_csv(path_to_combined_summary)
        summary_df["detailed_label"].str.lower()

        summary_df["detailed_label"] = summary_df['detailed_label'].replace(["Unknown", "-"], 'Benign')

        print("Creating Absolut Ratio File")

        detailed_label_df = summary_df.groupby("scenario")["detailed_label"].value_counts().to_frame()
        detailed_label_df = detailed_label_df.rename(columns={"detailed_label" : "count"}).reset_index()
        detailed_label_df = detailed_label_df.reindex(sorted(detailed_label_df.columns), axis=1)

        detailed_label_pt = pd.pivot_table(data=detailed_label_df, values="count", index="scenario", columns="detailed_label", aggfunc=np.sum, fill_value=0)
        detailed_label_pt.reset_index(drop=False, inplace=True)

        if "Unknown" in detailed_label_pt.columns:
            detailed_label_pt = detailed_label_pt.rename(columns={"Unknown" : "Benign"})

        detailed_label_pt.columns = detailed_label_pt.columns.to_series().apply(lambda x: x.lower())

        for detailed_label in total_detailed_label_list:
            if detailed_label not in detailed_label_pt.columns:
                detailed_label_pt[detailed_label] = 0

        column_order_list = total_detailed_label_list.copy()
        column_order_list.insert(0, "scenario")

        total_ratio_df = detailed_label_pt.reindex(columns=column_order_list)
        total_ratio_df = total_ratio_df.sort_values(by="scenario")

        total_ratio_df.to_csv(total_ratio_path, index = False)

        print("Creating Relative Ratio File")

        relative_ratio_df = detailed_label_pt

        for detailed_label in total_detailed_label_list:
            if relative_ratio_df[detailed_label].sum() != 0:
                relative_ratio_df[detailed_label] = relative_ratio_df[detailed_label].apply(lambda x: (x / (relative_ratio_df[detailed_label].sum())))

        relative_ratio_df = relative_ratio_df.reindex(columns=column_order_list)
        relative_ratio_df = relative_ratio_df.sort_values(by="scenario")

        relative_ratio_df.to_csv(relative_ratio_path, index=False)

    @staticmethod
    def length_analysis(length_summary_path, path_to_summary, addition):

        path_detailed_label_csv = length_summary_path + "/detailed_label_summary_" + addition + ".csv"
        path_label_csv = length_summary_path + "/label_summary_" + addition + ".csv"
        path_application_name_csv = length_summary_path + "/application_name_summary_" + addition + ".csv"
        path_application_category_name_csv = length_summary_path + "/application_category_name_summary_" + addition + ".csv"
        path_name_csv = length_summary_path + "/name_summary_" + addition + ".csv"
        path_detailed_label_table = length_summary_path + "/detailed_label_info_" + addition + ".png"
        path_label_table = length_summary_path + "/label_info_" + addition + ".png"
        path_application_name_table = length_summary_path + "/application_name_info_" + addition + ".png"
        path_application_category_name_table = length_summary_path + "/application_category_name_info_" + addition + ".png"
        path_name_table = length_summary_path + "/name_info_" + addition + ".png"

        combined_summary_df = pd.read_csv(path_to_summary)

        # length analysis

        total_amount_connections = len(combined_summary_df.index)

        dl_average_length_df = combined_summary_df.groupby("detailed_label")[
            "connection_length"].mean().to_frame().reset_index()
        dl_average_length_df = dl_average_length_df.rename(columns={"connection_length": "avg_connection_length"})
        dl_average_length_df["avg_connection_length"] = dl_average_length_df["avg_connection_length"].apply(
            lambda x: round(x, 2))
        dl_con_count_df = combined_summary_df.groupby("detailed_label")[
            "connection_length"].count().to_frame().reset_index()
        dl_con_count_df = dl_con_count_df.rename(columns={"connection_length": "connection_count"})
        detailed_label_info_df = dl_average_length_df.merge(right=dl_con_count_df, on="detailed_label")
        detailed_label_info_df["ratio"] = round(
            (detailed_label_info_df["connection_count"] / total_amount_connections) * 100, 4)
        detailed_label_info_df = detailed_label_info_df.sort_values(by="connection_count", ascending=False)
        detailed_label_info_df.to_csv(path_detailed_label_csv, index=False)

        fig, ax = plt.subplots()
        fig.patch.set_visible(False)
        ax.axis('off')
        ax.axis('tight')
        table = ax.table(cellText=detailed_label_info_df.values, colLabels=detailed_label_info_df.columns, loc='center',
                         cellLoc='center')
        table.auto_set_column_width(col=list(range(len(detailed_label_info_df.columns))))
        for (row, col), cell in table.get_celld().items():
            if (row == 0):
                cell.set_text_props(fontproperties=FontProperties(weight='bold'))
        fig.tight_layout(pad=3.0)
        plt.savefig(path_detailed_label_table, dpi=1200, bbox_inches='tight')
        plt.close()
        plt.clf()

        l_average_length_df = combined_summary_df.groupby("label")["connection_length"].mean().to_frame().reset_index()
        l_average_length_df = l_average_length_df.rename(columns={"connection_length": "avg_connection_length"})
        l_average_length_df["avg_connection_length"] = l_average_length_df["avg_connection_length"].apply(
            lambda x: round(x, 2))
        l_con_count_df = combined_summary_df.groupby("label")["connection_length"].count().to_frame().reset_index()
        l_con_count_df = l_con_count_df.rename(columns={"connection_length": "connection_count"})
        label_info_df = l_average_length_df.merge(right=l_con_count_df, on="label")
        label_info_df["ratio"] = round((label_info_df["connection_count"] / total_amount_connections) * 100, 4)
        label_info_df = label_info_df.sort_values(by="connection_count", ascending=False)
        label_info_df.to_csv(path_label_csv, index=False)

        fig, ax = plt.subplots()
        fig.patch.set_visible(False)
        ax.axis('off')
        ax.axis('tight')
        table = ax.table(cellText=label_info_df.values, colLabels=label_info_df.columns, loc='center',
                         cellLoc='center')
        table.auto_set_column_width(col=list(range(len(label_info_df.columns))))
        for (row, col), cell in table.get_celld().items():
            if (row == 0):
                cell.set_text_props(fontproperties=FontProperties(weight='bold'))
        fig.tight_layout(pad=3.0)
        plt.savefig(path_label_table, dpi=1200, bbox_inches='tight')
        plt.close()
        plt.clf()

        name_average_length_df = combined_summary_df.groupby("name")[
            "connection_length"].mean().to_frame().reset_index()
        name_average_length_df = name_average_length_df.rename(columns={"connection_length": "avg_connection_length"})
        name_average_length_df["avg_connection_length"] = name_average_length_df["avg_connection_length"].apply(
            lambda x: round(x, 2))
        name_con_count_df = combined_summary_df.groupby("name")["connection_length"].count().to_frame().reset_index()
        name_con_count_df = name_con_count_df.rename(columns={"connection_length": "connection_count"})
        name_info_df = name_average_length_df.merge(right=name_con_count_df, on="name")
        name_info_df["ratio"] = round((name_info_df["connection_count"] / total_amount_connections) * 100, 4)
        name_info_df = name_info_df.sort_values(by="connection_count", ascending=False)
        name_info_df.to_csv(path_name_csv, index=False)
        name_info_df["name"] = name_info_df["name"].apply(lambda x: x[0:30])

        fig, ax = plt.subplots()
        fig.patch.set_visible(False)
        ax.axis('off')
        ax.axis('tight')
        table = ax.table(cellText=name_info_df.values, colLabels=name_info_df.columns, loc='center',
                         cellLoc='center')
        table.auto_set_column_width(col=list(range(len(name_info_df.columns))))
        for (row, col), cell in table.get_celld().items():
            if (row == 0):
                cell.set_text_props(fontproperties=FontProperties(weight='bold'))
        fig.tight_layout(pad=3.0)
        plt.savefig(path_name_table, dpi=1200, bbox_inches='tight')
        plt.close()
        plt.clf()

        acn_average_length_df = combined_summary_df.groupby("application_category_name")[
            "connection_length"].mean().to_frame().reset_index()
        acn_average_length_df = acn_average_length_df.rename(columns={"connection_length": "avg_connection_length"})
        acn_average_length_df["avg_connection_length"] = acn_average_length_df["avg_connection_length"].apply(
            lambda x: round(x, 2))
        acn_con_count_df = combined_summary_df.groupby("application_category_name")[
            "connection_length"].count().to_frame().reset_index()
        acn_con_count_df = acn_con_count_df.rename(columns={"connection_length": "connection_count"})
        application_category_name_info_df = acn_average_length_df.merge(right=acn_con_count_df,
                                                                        on="application_category_name")
        application_category_name_info_df["ratio"] = round(
            (application_category_name_info_df["connection_count"] / total_amount_connections) * 100, 4)
        application_category_name_info_df = application_category_name_info_df.sort_values(by="connection_count",
                                                                                          ascending=False)
        application_category_name_info_df.to_csv(path_application_category_name_csv, index=False)
        application_category_name_info_df["application_category_name"] = application_category_name_info_df[
            "application_category_name"].apply(lambda x: x[0:30])

        fig, ax = plt.subplots()
        fig.patch.set_visible(False)
        ax.axis('off')
        ax.axis('tight')
        table = ax.table(cellText=application_category_name_info_df.values,
                         colLabels=application_category_name_info_df.columns, loc='center',
                         cellLoc='center')
        table.auto_set_column_width(col=list(range(len(application_category_name_info_df.columns))))
        for (row, col), cell in table.get_celld().items():
            if (row == 0):
                cell.set_text_props(fontproperties=FontProperties(weight='bold'))
            cell.set_height(0.15)
        fig.tight_layout(pad=3.0)
        plt.savefig(path_application_category_name_table, dpi=fig.dpi, bbox_inches='tight')
        plt.close()
        plt.clf()

        an_average_length_df = combined_summary_df.groupby("application_name")[
            "connection_length"].mean().to_frame().reset_index()
        an_average_length_df = an_average_length_df.rename(columns={"connection_length": "avg_connection_length"})
        an_average_length_df["avg_connection_length"] = an_average_length_df["avg_connection_length"].apply(
            lambda x: round(x, 2))
        an_con_count_df = combined_summary_df.groupby("application_name")[
            "connection_length"].count().to_frame().reset_index()
        an_con_count_df = an_con_count_df.rename(columns={"connection_length": "connection_count"})
        application_name_info_df = an_average_length_df.merge(right=an_con_count_df, on="application_name")
        application_name_info_df["ratio"] = round(
            (application_name_info_df["connection_count"] / total_amount_connections) * 100, 4)
        application_name_info_df = application_name_info_df.sort_values(by="connection_count", ascending=False)
        application_name_info_df.to_csv(path_application_name_csv, index=False)
        application_name_info_df["application_name"] = application_name_info_df["application_name"].apply(
            lambda x: x[0:30])

        fig, ax = plt.subplots()
        fig.patch.set_visible(False)
        ax.axis('off')
        ax.axis('tight')
        table = ax.table(cellText=application_name_info_df.values, colLabels=application_name_info_df.columns,
                         loc='center',
                         cellLoc='center')
        table.auto_set_column_width(col=list(range(len(application_name_info_df.columns))))
        for (row, col), cell in table.get_celld().items():
            if (row == 0):
                cell.set_text_props(fontproperties=FontProperties(weight='bold'))
            cell.set_height(0.1)
        fig.tight_layout(pad=3.0)
        plt.savefig(path_application_name_table, dpi=fig.dpi, bbox_inches='tight')
        plt.close()
        plt.clf()

    @staticmethod
    def ratio_summary_creation_with_difference_to_original(path_to_combined_summary, path_to_detailed_label_folder, path_to_original_total_ratio, path_to_storage, data_set_name):

        path_to_combined_summary = path_to_combined_summary
        path_to_detailed_label_folder = path_to_detailed_label_folder
        path_to_original_total_ratio = path_to_original_total_ratio
        path_to_storage = path_to_storage
        data_set_name = data_set_name

        total_ratio_path = path_to_storage + "/" + data_set_name+"_total_ratio.csv"
        relative_ratio_path = path_to_storage + "/" + data_set_name + "_relative_ratio.csv"
        total_difference_path = path_to_storage + "/" + data_set_name + "_total_difference.csv"

        total_detailed_label_list = pd.read_csv(path_to_detailed_label_folder)["detailed_label"].tolist()
        total_detailed_label_list.sort()

        summary_df = pd.read_csv(path_to_combined_summary)
        summary_df["detailed_label"].str.lower()

        summary_df["detailed_label"] = summary_df['detailed_label'].replace(["Unknown", "-"], 'Benign')

        print("Creating Absolut Ratio File")

        detailed_label_df = summary_df.groupby("scenario")["detailed_label"].value_counts().to_frame()
        detailed_label_df = detailed_label_df.rename(columns={"detailed_label" : "count"}).reset_index()
        detailed_label_df = detailed_label_df.reindex(sorted(detailed_label_df.columns), axis=1)

        detailed_label_pt = pd.pivot_table(data=detailed_label_df, values="count", index="scenario", columns="detailed_label", aggfunc=np.sum, fill_value=0)
        detailed_label_pt.reset_index(drop=False, inplace=True)

        if "Unknown" in detailed_label_pt.columns:
            detailed_label_pt = detailed_label_pt.rename(columns={"Unknown" : "Benign"})

        detailed_label_pt.columns = detailed_label_pt.columns.to_series().apply(lambda x: x.lower())

        for detailed_label in total_detailed_label_list:
            if detailed_label not in detailed_label_pt.columns:
                detailed_label_pt[detailed_label] = 0

        column_order_list = total_detailed_label_list.copy()
        column_order_list.insert(0, "scenario")

        total_ratio_df = detailed_label_pt.reindex(columns=column_order_list)
        total_ratio_df = total_ratio_df.sort_values(by="scenario")

        total_ratio_df.to_csv(total_ratio_path, index = False)

        print("Creating Relative Ratio File")

        relative_ratio_df = detailed_label_pt

        for detailed_label in total_detailed_label_list:
            if relative_ratio_df[detailed_label].sum() != 0:
                relative_ratio_df[detailed_label] = relative_ratio_df[detailed_label].apply(lambda x: (x / (relative_ratio_df[detailed_label].sum())))

        relative_ratio_df = relative_ratio_df.reindex(columns=column_order_list)
        relative_ratio_df = relative_ratio_df.sort_values(by="scenario")

        relative_ratio_df.to_csv(relative_ratio_path, index=False)

        print("Creating Total Difference File")

        total_distribution_df = pd.read_csv(path_to_original_total_ratio)

        total_difference_df = total_ratio_df.drop(columns="scenario").subtract(total_distribution_df.drop(columns="scenario"))
        total_difference_df["scenario"] = total_ratio_df["scenario"]
        total_difference_df = total_difference_df.reindex(columns=column_order_list)
        total_difference_df = total_difference_df.sort_values(by="scenario")

        total_difference_df = total_difference_df.reindex(columns=column_order_list)
        total_difference_df = total_difference_df.sort_values(by="scenario")

        total_difference_df.to_csv(total_difference_path, index=False)


    @staticmethod
    def ratio_summary_creation_with_min_size(path_to_combined_summary, path_to_detailed_label_folder, path_to_storage, data_set_name, min_ratio):

        path_to_combined_summary = path_to_combined_summary
        path_to_detailed_label_folder = path_to_detailed_label_folder
        path_to_storage = path_to_storage
        data_set_name = data_set_name
        min_ratio = int(min_ratio)

        total_ratio_path = path_to_storage + "/" + data_set_name+"_total_ratio.csv"
        relative_ratio_path = path_to_storage + "/" + data_set_name + "_relative_ratio.csv"

        total_detailed_label_list = pd.read_csv(path_to_detailed_label_folder)["detailed_label"].tolist()
        total_detailed_label_list.sort()

        summary_df = pd.read_csv(path_to_combined_summary)
        summary_df = summary_df[summary_df["connection_length"] >= min_ratio]
        summary_df["detailed_label"].str.lower()

        summary_df["detailed_label"] = summary_df['detailed_label'].replace(["Unknown", "-"], 'Benign')

        print("Creating Absolut Ratio File")

        detailed_label_df = summary_df.groupby("scenario")["detailed_label"].value_counts().to_frame()
        detailed_label_df = detailed_label_df.rename(columns={"detailed_label" : "count"}).reset_index()

        detailed_label_pt = pd.pivot_table(data=detailed_label_df, values="count", index="scenario", columns="detailed_label", aggfunc=np.sum, fill_value=0)
        detailed_label_pt.reset_index(drop=False, inplace=True)

        if "Unknown" in detailed_label_pt.columns:
            detailed_label_pt = detailed_label_pt.rename(columns={"Unknown" : "Benign"})

        detailed_label_pt.columns = detailed_label_pt.columns.to_series().apply(lambda x: x.lower())

        for detailed_label in total_detailed_label_list:
            if detailed_label not in detailed_label_pt.columns:
                detailed_label_pt[detailed_label] = 0

        column_order_list = total_detailed_label_list.copy()
        column_order_list.insert(0, "scenario")

        total_ratio_df = detailed_label_pt.reindex(columns=column_order_list)
        total_ratio_df = total_ratio_df.sort_values(by="scenario")

        total_ratio_df.to_csv(total_ratio_path, index = False)

        print("Creating Relative Ratio File")

        relative_ratio_df = detailed_label_pt

        for detailed_label in total_detailed_label_list:
            if relative_ratio_df[detailed_label].sum() != 0:
                relative_ratio_df[detailed_label] = relative_ratio_df[detailed_label].apply(lambda x: (x / (relative_ratio_df[detailed_label].sum())))

        relative_ratio_df = relative_ratio_df.reindex(columns=column_order_list)
        relative_ratio_df = relative_ratio_df.sort_values(by="scenario")

        relative_ratio_df.to_csv(relative_ratio_path, index=False)




    @staticmethod
    def create_combined_csf_from_all_summary_csv(path_to_filtered_files, path_to_storage):
        folder_to_filtered_files = path_to_filtered_files

        scan_file_order_path = folder_to_filtered_files + "/" + "scan_order.txt"
        scanned_files = []
        with open(scan_file_order_path, 'r') as inputfile:
            scanned_files = inputfile.readlines()

        scanned_files_list = [x.strip() for x in scanned_files]
        scanned_files_list = list(map(lambda x: (x.split(",")[0], x.split(",")[1]), scanned_files_list))
        scanned_files_list = sorted(scanned_files_list)

        df_list = []

        for index, (scenario_name, file_name) in enumerate(scanned_files_list):
            path_to_csv_file = folder_to_filtered_files + "/" + scenario_name + "/" + file_name + "/" + file_name + "_summary.csv"
            csv_df = pd.read_csv(path_to_csv_file)
            df_list.append(csv_df)

        summary_df = df_list.pop()
        loop_length = len(df_list)
        for to_add_df in range(loop_length):
            summary_df = summary_df.append(df_list.pop())

        storage_file = path_to_storage + "/combined_summary.csv"
        summary_df.to_csv(index=False, path_or_buf=storage_file)


    @staticmethod
    def create_combined_csf_for_status_from_all_summary_csv(path_to_filtered_files, path_to_storage, status, old_file_addition):
        folder_to_filtered_files = path_to_filtered_files

        scan_file_order_path = folder_to_filtered_files + "/" + "scan_order.txt"
        scanned_files = []
        with open(scan_file_order_path, 'r') as inputfile:
            scanned_files = inputfile.readlines()

        scanned_files_list = [x.strip() for x in scanned_files]
        scanned_files_list = list(map(lambda x: (x.split(",")[0], x.split(",")[1]), scanned_files_list))
        scanned_files_list = sorted(scanned_files_list)

        df_list = []

        for index, (scenario_name, file_name) in enumerate(scanned_files_list):

            print("File " + str(index + 1) + "/" + str(len(scanned_files_list)))

            #path_to_csv_file = folder_to_filtered_files + "/" + scenario_name + "/" + file_name + "/" + file_name + "_" + old_file_addition + "_summary.csv"
            path_to_csv_file = folder_to_filtered_files + "/" + scenario_name + "/" + file_name + "/" + file_name + "_summary.csv"
            csv_df = pd.read_csv(path_to_csv_file)

            if len(status) == 1:
                status_to_find = status[0]
                keep_df = csv_df[csv_df["status"] == status_to_find]

            else:
                for status_index, to_get in enumerate(status):
                    temp_df = csv_df[csv_df["status"] == to_get]

                    if status_index == 0:
                        keep_df = temp_df
                    else:
                        keep_df = keep_df.append(temp_df)

            if index == 0:
                combined_df = keep_df
            else:
                combined_df = combined_df.append(keep_df)

        print("Writing to File")

        if len(status) == 1:
            status_addition = status[0].lower()
        else:
            status = [x.lower() for x in status]
            status_addition = ("_").join(status)

        storage_file = path_to_storage + "/summary_" + status_addition + ".csv"
        combined_df.to_csv(index=False, path_or_buf=storage_file)

    @staticmethod
    def create_combined_csf_for_status_from_all_summary_csv_with_min_size(path_to_filtered_files, path_to_storage, status, min_size, old_file_addition):

        folder_to_filtered_files = path_to_filtered_files

        scan_file_order_path = folder_to_filtered_files + "/" + "scan_order.txt"
        scanned_files = []
        with open(scan_file_order_path, 'r') as inputfile:
            scanned_files = inputfile.readlines()

        scanned_files_list = [x.strip() for x in scanned_files]
        scanned_files_list = list(map(lambda x: (x.split(",")[0], x.split(",")[1]), scanned_files_list))
        scanned_files_list = sorted(scanned_files_list)

        df_list = []

        for index, (scenario_name, file_name) in enumerate(scanned_files_list):

            print("File " + str(index + 1) + "/" + str(len(scanned_files_list)))

            # path_to_csv_file = folder_to_filtered_files + "/" + scenario_name + "/" + file_name + "/" + file_name + "_" + old_file_addition + "_summary.csv"
            path_to_csv_file = folder_to_filtered_files + "/" + scenario_name + "/" + file_name + "/" + file_name + "_summary.csv"
            csv_df = pd.read_csv(path_to_csv_file)

            if len(status) == 1:
                status_to_find = status[0]
                keep_df = csv_df[csv_df["status"] == status_to_find]

            else:
                for status_index, to_get in enumerate(status):
                    temp_df = csv_df[csv_df["status"] == to_get]

                    if status_index == 0:
                        keep_df = temp_df
                    else:
                        keep_df = keep_df.append(temp_df)

            if index == 0:
                combined_df = keep_df
            else:
                combined_df = combined_df.append(keep_df)

        print("Writing to File")

        if len(status) == 1:
            status_addition = status[0].lower()
        else:
            status = [x.lower() for x in status]
            status_addition = ("_").join(status)

        storage_file = path_to_storage + "/summary_" + status_addition + ".csv"

        print(len(combined_df.index))
        combined_df = combined_df[combined_df["connection_length"] >= min_size]
        print(len(combined_df.index))

        combined_df.to_csv(index=False, path_or_buf=storage_file)


    @staticmethod
    def create_analysis_from_summary_csv(path_to_summary_csv, path_to_storage, dataset_name):

        summary_csv_df = pd.read_csv(path_to_summary_csv)

        total_amount_connections = len(summary_csv_df.index)

        path_detailed_label_csv = path_to_storage + "/detailed_label_summary_" + dataset_name + ".csv"
        path_label_csv = path_to_storage + "/label_summary_" + dataset_name + ".csv"
        path_application_name_csv = path_to_storage + "/application_name_summary_" + dataset_name + ".csv"
        path_application_category_name_csv = path_to_storage + "/application_category_name_summary_" + dataset_name + ".csv"
        path_name_csv = path_to_storage + "/name_summary_" + dataset_name + ".csv"

        path_detailed_label_table = path_to_storage + "/detailed_label_info_" + dataset_name + ".png"
        path_label_table = path_to_storage + "/label_info_" + dataset_name + ".png"
        path_application_name_table = path_to_storage + "/application_name_info_" + dataset_name + ".png"
        path_application_category_name_table = path_to_storage + "/application_category_name_info_" + dataset_name + ".png"
        path_name_table = path_to_storage + "/name_info_" + dataset_name + ".png"



        dl_average_length_df = summary_csv_df.groupby("detailed_label")["connection_length"].mean().to_frame().reset_index()
        dl_average_length_df = dl_average_length_df.rename(columns={"connection_length" : "avg_connection_length"})
        dl_average_length_df["avg_connection_length"] = dl_average_length_df["avg_connection_length"].apply(lambda x: round(x, 2))
        dl_con_count_df = summary_csv_df.groupby("detailed_label")["connection_length"].count().to_frame().reset_index()
        dl_con_count_df = dl_con_count_df.rename(columns={"connection_length" : "connection_count"})
        detailed_label_info_df = dl_average_length_df.merge(right=dl_con_count_df, on="detailed_label")
        detailed_label_info_df["ratio"] = round((detailed_label_info_df["connection_count"] / total_amount_connections) * 100, 4)
        detailed_label_info_df.to_csv(path_detailed_label_csv, index=False)

        fig, ax = plt.subplots()
        fig.patch.set_visible(False)
        ax.axis('off')
        ax.axis('tight')
        table = ax.table(cellText=detailed_label_info_df.values, colLabels=detailed_label_info_df.columns, loc='center',
                         cellLoc='center')
        table.auto_set_column_width(col=list(range(len(detailed_label_info_df.columns))))
        for (row, col), cell in table.get_celld().items():
            if (row == 0):
                cell.set_text_props(fontproperties=FontProperties(weight='bold'))
        fig.tight_layout(pad=3.0)
        plt.savefig(path_detailed_label_table, dpi=1200, bbox_inches='tight')
        plt.close()
        plt.clf()



        l_average_length_df = summary_csv_df.groupby("label")["connection_length"].mean().to_frame().reset_index()
        l_average_length_df = l_average_length_df.rename(columns={"connection_length" : "avg_connection_length"})
        l_average_length_df["avg_connection_length"] = l_average_length_df["avg_connection_length"].apply(lambda x: round(x, 2))
        l_con_count_df = summary_csv_df.groupby("label")["connection_length"].count().to_frame().reset_index()
        l_con_count_df = l_con_count_df.rename(columns={"connection_length" : "connection_count"})
        label_info_df = l_average_length_df.merge(right=l_con_count_df, on="label")
        label_info_df["ratio"] = round((label_info_df["connection_count"] / total_amount_connections) * 100, 4)
        label_info_df.to_csv(path_label_csv, index=False)

        fig, ax = plt.subplots()
        fig.patch.set_visible(False)
        ax.axis('off')
        ax.axis('tight')
        table = ax.table(cellText=label_info_df.values, colLabels=label_info_df.columns, loc='center',
                         cellLoc='center')
        table.auto_set_column_width(col=list(range(len(label_info_df.columns))))
        for (row, col), cell in table.get_celld().items():
            if (row == 0):
                cell.set_text_props(fontproperties=FontProperties(weight='bold'))
        fig.tight_layout(pad=3.0)
        plt.savefig(path_label_table, dpi=1200, bbox_inches='tight')
        plt.close()
        plt.clf()



        name_average_length_df = summary_csv_df.groupby("name")["connection_length"].mean().to_frame().reset_index()
        name_average_length_df = name_average_length_df.rename(columns={"connection_length" : "avg_connection_length"})
        name_average_length_df["avg_connection_length"] = name_average_length_df["avg_connection_length"].apply(lambda x: round(x, 2))
        name_con_count_df = summary_csv_df.groupby("name")["connection_length"].count().to_frame().reset_index()
        name_con_count_df = name_con_count_df.rename(columns={"connection_length" : "connection_count"})
        name_info_df = name_average_length_df.merge(right=name_con_count_df, on="name")
        name_info_df["ratio"] = round((name_info_df["connection_count"] / total_amount_connections) * 100, 4)
        name_info_df.to_csv(path_name_csv, index=False)
        name_info_df["name"] = name_info_df["name"].apply(lambda x: x[0:30])


        fig, ax = plt.subplots()
        fig.patch.set_visible(False)
        ax.axis('off')
        ax.axis('tight')
        table = ax.table(cellText=name_info_df.values, colLabels=name_info_df.columns, loc='center',
                         cellLoc='center')
        table.auto_set_column_width(col=list(range(len(name_info_df.columns))))
        for (row, col), cell in table.get_celld().items():
            if (row == 0):
                cell.set_text_props(fontproperties=FontProperties(weight='bold'))
        fig.tight_layout(pad=3.0)
        plt.savefig(path_name_table, dpi=1200, bbox_inches='tight')
        plt.close()
        plt.clf()

        acn_average_length_df = summary_csv_df.groupby("application_category_name")[
            "connection_length"].mean().to_frame().reset_index()
        acn_average_length_df = acn_average_length_df.rename(columns={"connection_length": "avg_connection_length"})
        acn_average_length_df["avg_connection_length"] = acn_average_length_df["avg_connection_length"].apply(
            lambda x: round(x, 2))
        acn_con_count_df = summary_csv_df.groupby("application_category_name")[
            "connection_length"].count().to_frame().reset_index()
        acn_con_count_df = acn_con_count_df.rename(columns={"connection_length": "connection_count"})
        application_category_name_info_df = acn_average_length_df.merge(right=acn_con_count_df,
                                                                        on="application_category_name")
        application_category_name_info_df["ratio"] = round(
            (application_category_name_info_df["connection_count"] / total_amount_connections) * 100, 4)
        application_category_name_info_df.to_csv(path_application_category_name_csv, index=False)
        application_category_name_info_df["application_category_name"] = application_category_name_info_df[
            "application_category_name"].apply(lambda x: x[0:30])

        fig, ax = plt.subplots()
        fig.patch.set_visible(False)
        ax.axis('off')
        ax.axis('tight')
        table = ax.table(cellText=application_category_name_info_df.values,
                         colLabels=application_category_name_info_df.columns, loc='center',
                         cellLoc='center')
        table.auto_set_column_width(col=list(range(len(application_category_name_info_df.columns))))
        for (row, col), cell in table.get_celld().items():
            if (row == 0):
                cell.set_text_props(fontproperties=FontProperties(weight='bold'))
            cell.set_height(0.1)
        fig.tight_layout(pad=3.0)
        plt.savefig(path_application_category_name_table, dpi=fig.dpi, bbox_inches='tight')
        plt.close()
        plt.clf()


        an_average_length_df = summary_csv_df.groupby("application_name")[
            "connection_length"].mean().to_frame().reset_index()
        an_average_length_df = an_average_length_df.rename(columns={"connection_length": "avg_connection_length"})
        an_average_length_df["avg_connection_length"] = an_average_length_df["avg_connection_length"].apply(
            lambda x: round(x, 2))
        an_con_count_df = summary_csv_df.groupby("application_name")[
            "connection_length"].count().to_frame().reset_index()
        an_con_count_df = an_con_count_df.rename(columns={"connection_length": "connection_count"})
        application_name_info_df = an_average_length_df.merge(right=an_con_count_df, on="application_name")
        application_name_info_df["ratio"] = round(
            (application_name_info_df["connection_count"] / total_amount_connections) * 100, 4)
        application_name_info_df.to_csv(path_application_name_csv, index=False)
        application_name_info_df["application_name"] = application_name_info_df["application_name"].apply(
            lambda x: x[0:30])

        fig, ax = plt.subplots()
        fig.patch.set_visible(False)
        ax.axis('off')
        ax.axis('tight')
        table = ax.table(cellText=application_name_info_df.values, colLabels=application_name_info_df.columns,
                         loc='center',
                         cellLoc='center')
        table.auto_set_column_width(col=list(range(len(application_name_info_df.columns))))
        for (row, col), cell in table.get_celld().items():
            if (row == 0):
                cell.set_text_props(fontproperties=FontProperties(weight='bold'))
            cell.set_height(0.1)
        fig.tight_layout(pad=3.0)
        plt.savefig(path_application_name_table, dpi=fig.dpi, bbox_inches='tight')
        plt.close()
        plt.clf()