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
from PIL import Image
from matplotlib.colors import ListedColormap
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
from matplotlib.text import Text
from adjustText import adjust_text

class Graph_Multiple_Experiments():

    @staticmethod
    def create_experiment_overview_graphs(experiment_name, path_to_results, path_to_storage):

        experiment_name = experiment_name
        path_to_results = path_to_results
        path_to_storage = path_to_storage

        folders = sorted([f.path for f in os.scandir(path_to_results) if f.is_dir()])
        folders = list(map(lambda x: (x, str(os.path.basename(x)).strip()), folders))

        max_num_clusters = 0

        for experiment, (path, folder_name) in enumerate(folders):

            #csv_filepath = path + "/*csv"
            csv_filepath = path + "/summaries/summary*"
            csv_summary_file = glob.glob(csv_filepath)[0]

            csv_df = pd.read_csv(csv_summary_file)

            num_clusters = len(csv_df["clusnum"].unique().tolist())

            if num_clusters > max_num_clusters:
                max_num_clusters = num_clusters

        number_columns = max_num_clusters + 1
        number_rows = len(folders)

        application_name_graph_path = path_to_storage + "/" + experiment_name + "_application_name_graph.png"
        path_to_application_name_legend_storage = path_to_storage + "/" + experiment_name + "_application_name_legend.png"
        path_to_application_name_combined = path_to_storage + "/" + experiment_name + "_application_name_combined.png"

        application_category_name_graph_path = path_to_storage + "/" + experiment_name + "_application_category_name_graph.png"
        path_to_application_category_name_legend_storage = path_to_storage + "/" + experiment_name + "_application_category_name_legend.png"
        path_to_application_category_name_combined = path_to_storage + "/" + experiment_name + "_application_category_name_combined.png"

        path_to_label_legend_storage = path_to_storage + "/" + experiment_name + "_label_legend.png"
        label_graph_path = path_to_storage + "/" + experiment_name + "_label_graph.png"
        path_to_label_combined = path_to_storage + "/" + experiment_name + "_label_combined.png"

        detailed_label_graph_path = path_to_storage + "/" + experiment_name + "_detailed_label_graph.png"
        path_to_detailed_label_legend_storage = path_to_storage + "/" + experiment_name + "_detailed_label_legend.png"
        path_to_detailed_label_combined = path_to_storage + "/" + experiment_name + "_detailed_label_combined.png"

        name_graph_path = path_to_storage + "/" + experiment_name + "_name_graph.png"
        path_to_name_legend_storage = path_to_storage + "/" + experiment_name + "_name_legend.png"
        path_to_name_combined = path_to_storage + "/" + experiment_name + "_name_combined.png"


        ####################
        # application name #
        ####################

        fig, ax = plt.subplots(nrows=number_rows, ncols=number_columns)

        for experiment, (path, folder_name) in enumerate(folders):

            #csv_filepath = path + "/*csv"
            csv_filepath = path + "/summaries/summary*"
            csv_summary_file = glob.glob(csv_filepath)[0]

            csv_df = pd.read_csv(csv_summary_file)

            overall_detailed_label_df = csv_df.groupby("clusnum")["application_name"].value_counts().to_frame()
            overall_detailed_label_df = overall_detailed_label_df.rename(columns={"application_name": "count"})
            overall_detailed_label_df = overall_detailed_label_df.reset_index()

            clusters = overall_detailed_label_df["clusnum"].unique().tolist()

            list_of_names_dfs = []

            for cluster in clusters:
                cluster_df = overall_detailed_label_df[overall_detailed_label_df["clusnum"] == cluster][
                    ["application_name", "count"]]
                cluster_df["application_name"] = np.where(cluster_df["count"] <= 4, "Other", cluster_df.application_name)

                cluster_df = cluster_df.groupby("application_name")["count"].aggregate(sum).reset_index().sort_values(
                    by=["count"], ascending=False)

                list_of_names_dfs.append(cluster_df)

            detailed_label_name_df = list_of_names_dfs.pop()

            for name_df in list_of_names_dfs:
                detailed_label_name_df = detailed_label_name_df.append(name_df)

            detailed_label_name_df = detailed_label_name_df.groupby("application_name")["count"].aggregate(
                sum).reset_index().sort_values(by=["count"])
            unique_application_category_names = detailed_label_name_df["application_name"].tolist()

            colors = {}
            cmap = cm.tab20c(np.linspace(0, 1, len(unique_application_category_names)))

            for index, color in enumerate(cmap):
                application_name = unique_application_category_names.pop()
                colors[application_name] = color


            for index, cluster in enumerate(clusters):
                cluster_df = overall_detailed_label_df[overall_detailed_label_df["clusnum"] == cluster][
                    ["application_name", "count"]]

                cluster_df["application_name"] = np.where(cluster_df["count"] <= 4, "Other", cluster_df.application_name)

                cluster_df = cluster_df.groupby("application_name")["count"].aggregate(sum).reset_index().sort_values(
                    by=["count"])
                cluster_df["relative_count"] = round((cluster_df["count"] / cluster_df["count"].sum()) * 100, 2)

                patches, texts = ax[experiment, index].pie(cluster_df["count"], labels=cluster_df["relative_count"],
                                          colors=[colors[key] for key in cluster_df["application_name"]])
                amount_skip = 0
                new_labels = []
                for text_index, text in enumerate(texts):
                    if (text_index == 0):
                        new_labels.append(text.get_text())
                    else:
                        current_xy = text.get_position()
                        current_str = text.get_text()

                        past_text = texts[text_index - 1]
                        past_xy = past_text.get_position()
                        past_str = new_labels[text_index - 1]

                        distance = math.sqrt(pow((current_xy[0] - past_xy[0]), 2) + pow((current_xy[1] - past_xy[1]), 2))

                        if distance < 0.3:
                            if distance < 0.2:
                                if amount_skip < 2:
                                    new_labels.append(" ")
                                    amount_skip = amount_skip + 1
                                else:
                                    new_labels.append(current_str)
                                    amount_skip = 0
                            else:
                                if past_str != " ":
                                    new_labels.append(" ")
                                    amount_skip = amount_skip + 1
                                else:
                                    new_labels.append(current_str)
                                    amount_skip = 0
                        else:
                            new_labels.append(current_str)
                            amount_skip = 0

                ax[experiment, index].clear()
                ax[experiment, index].pie(cluster_df["count"], labels=new_labels,colors=[colors[key] for key in cluster_df["application_name"]], labeldistance=1.15, textprops={'fontsize': 8})
                ax[experiment, index].set_title("Cluster " + str(cluster))

            if len(clusters) < number_columns:
                for missing_axis in range(len(clusters), number_columns):
                    ax[experiment, missing_axis].axis('off')

        markers = [plt.Line2D([0, 0], [0, 0], color=color, marker='o', linestyle='') for color in colors.values()]
        fig.subplots_adjust(bottom=0.25)

        for experiment, (path, folder_name) in enumerate(folders):
            ax[experiment, number_columns - 1].text(y=0.5, x=0, s='Experiment ' + str(1 + experiment))

        plt.suptitle("Application Name Distribution per Cluster", y=0.96, x=0.5, fontweight='bold')

        # rearange the axes for no overlap
        fig.tight_layout()

        # Get the bounding boxes of the axes including text decorations
        r = fig.canvas.get_renderer()
        get_bbox = lambda ax: ax.get_tightbbox(r).transformed(fig.transFigure.inverted())
        bboxes = np.array(list(map(get_bbox, ax.flat)), mtrans.Bbox).reshape(ax.shape)

        # Get the minimum and maximum extent, get the coordinate half-way between those
        ymax = np.array(list(map(lambda b: b.y1, bboxes.flat))).reshape(ax.shape).max(axis=1)
        ymin = np.array(list(map(lambda b: b.y0, bboxes.flat))).reshape(ax.shape).min(axis=1)
        ys = np.c_[ymax[1:], ymin[:-1]].mean(axis=1)

        # Draw a horizontal lines at those coordinates
        for y in ys:
            line = plt.Line2D([0, 1], [y, y], transform=fig.transFigure, color="black")
            fig.add_artist(line)

        #plt.show()
        plt.savefig(application_name_graph_path, dpi=1200, bbox_inches='tight')

        fig.tight_layout()
        fig.canvas.draw()

        label_list = colors.keys()
        label_list = [x[0:40] for x in label_list]
        legend = plt.legend(handles=markers, labels=label_list, loc=3, framealpha=1, frameon=True, bbox_to_anchor=(2, 0))

        separate_legend = legend.figure
        separate_legend.canvas.draw()
        bbox = legend.get_window_extent()
        bbox = bbox.from_extents(*(bbox.extents + np.array([-4 ,-4 ,4 ,4])))
        bbox = bbox.transformed(fig.dpi_scale_trans.inverted())

        fig.savefig(path_to_application_name_legend_storage, dpi=1200, bbox_inches=bbox)
        legend.remove()


        graph_img = Image.open(application_name_graph_path)
        legend_im = Image.open(path_to_application_name_legend_storage)

        widths_graph = graph_img.width
        heights_graph = graph_img.height

        widths_legend = legend_im.width
        heights_legend = legend_im.height

        if heights_legend > heights_graph:
            resize_percentage = heights_graph / heights_legend
            new_width = int(resize_percentage * widths_legend)

            legend_im = legend_im.resize((new_width, heights_graph), Image.ANTIALIAS)

        total_width = widths_graph + widths_legend

        y_offset = int((heights_graph - heights_legend) / 2)

        combined_im = Image.new('RGB', (total_width, heights_graph), color=(255, 255, 255, 1))
        combined_im.paste(graph_img, (0, 0))
        combined_im.paste(legend_im, (widths_graph, y_offset))
        combined_im.save(path_to_application_name_combined)
        plt.close()

        #############################
        # application category name #
        #############################

        fig, ax = plt.subplots(nrows=number_rows, ncols=number_columns)

        for experiment, (path, folder_name) in enumerate(folders):

            #csv_filepath = path + "/*csv"
            csv_filepath = path + "/summaries/summary*"
            csv_summary_file = glob.glob(csv_filepath)[0]

            csv_df = pd.read_csv(csv_summary_file)

            overall_detailed_label_df = csv_df.groupby("clusnum")["application_category_name"].value_counts().to_frame()
            overall_detailed_label_df = overall_detailed_label_df.rename(columns={"application_category_name": "count"})
            overall_detailed_label_df = overall_detailed_label_df.reset_index()

            clusters = overall_detailed_label_df["clusnum"].unique().tolist()

            list_of_names_dfs = []

            for cluster in clusters:
                cluster_df = overall_detailed_label_df[overall_detailed_label_df["clusnum"] == cluster][
                    ["application_category_name", "count"]]

                cluster_df = cluster_df.groupby("application_category_name")["count"].aggregate(sum).reset_index().sort_values(
                    by=["count"], ascending=False)

                list_of_names_dfs.append(cluster_df)

            detailed_label_name_df = list_of_names_dfs.pop()

            for name_df in list_of_names_dfs:
                detailed_label_name_df = detailed_label_name_df.append(name_df)

            detailed_label_name_df = detailed_label_name_df.groupby("application_category_name")["count"].aggregate(
                sum).reset_index().sort_values(by=["count"])
            unique_application_category_names = detailed_label_name_df["application_category_name"].tolist()

            colors = {}
            cmap = cm.gist_rainbow(np.linspace(0, 1, len(unique_application_category_names)))

            for index, color in enumerate(cmap):
                application_name = unique_application_category_names.pop()
                colors[application_name] = color


            for index, cluster in enumerate(clusters):
                cluster_df = overall_detailed_label_df[overall_detailed_label_df["clusnum"] == cluster][
                    ["application_category_name", "count"]]

                cluster_df = cluster_df.groupby("application_category_name")["count"].aggregate(sum).reset_index().sort_values(
                    by=["count"])
                cluster_df["relative_count"] = round((cluster_df["count"] / cluster_df["count"].sum()) * 100, 2)

                patches, texts = ax[experiment, index].pie(cluster_df["count"], labels=cluster_df["relative_count"],colors=[colors[key] for key in cluster_df["application_category_name"]])
                amount_skip = 0
                new_labels = []
                for text_index, text in enumerate(texts):
                    if (text_index == 0):
                        new_labels.append(text.get_text())
                    else:
                        current_xy = text.get_position()
                        current_str = text.get_text()

                        past_text = texts[text_index - 1]
                        past_xy = past_text.get_position()
                        past_str = new_labels[text_index - 1]

                        distance = math.sqrt(
                            pow((current_xy[0] - past_xy[0]), 2) + pow((current_xy[1] - past_xy[1]), 2))

                        if distance < 0.3:
                            if distance < 0.2:
                                if amount_skip < 2:
                                    new_labels.append(" ")
                                    amount_skip = amount_skip + 1
                                else:
                                    new_labels.append(current_str)
                                    amount_skip = 0
                            else:
                                if past_str != " ":
                                    new_labels.append(" ")
                                    amount_skip = amount_skip + 1
                                else:
                                    new_labels.append(current_str)
                                    amount_skip = 0
                        else:
                            new_labels.append(current_str)
                            amount_skip = 0

                ax[experiment, index].clear()
                ax[experiment, index].pie(cluster_df["count"], labels=new_labels,
                                          colors=[colors[key] for key in cluster_df["application_category_name"]],
                                          labeldistance=1.15, textprops={'fontsize': 8})
                ax[experiment, index].set_title("Cluster " + str(cluster))

            if len(clusters) < number_columns:
                for missing_axis in range(len(clusters), number_columns):
                    ax[experiment, missing_axis].axis('off')

        markers = [plt.Line2D([0, 0], [0, 0], color=color, marker='o', linestyle='') for color in colors.values()]
        fig.subplots_adjust(bottom=0.25)

        for experiment, (path, folder_name) in enumerate(folders):
            ax[experiment, number_columns - 1].text(y=0.5, x=0, s='Experiment ' + str(1 + experiment))

        plt.suptitle("Application Category Name Distribution per Cluster", y=0.96, x=0.5, fontweight='bold')

        # rearange the axes for no overlap
        fig.tight_layout()

        # Get the bounding boxes of the axes including text decorations
        r = fig.canvas.get_renderer()
        get_bbox = lambda ax: ax.get_tightbbox(r).transformed(fig.transFigure.inverted())
        bboxes = np.array(list(map(get_bbox, ax.flat)), mtrans.Bbox).reshape(ax.shape)

        # Get the minimum and maximum extent, get the coordinate half-way between those
        ymax = np.array(list(map(lambda b: b.y1, bboxes.flat))).reshape(ax.shape).max(axis=1)
        ymin = np.array(list(map(lambda b: b.y0, bboxes.flat))).reshape(ax.shape).min(axis=1)
        ys = np.c_[ymax[1:], ymin[:-1]].mean(axis=1)

        # Draw a horizontal lines at those coordinates
        for y in ys:
            line = plt.Line2D([0, 1], [y, y], transform=fig.transFigure, color="black")
            fig.add_artist(line)

        plt.savefig(application_category_name_graph_path, bbox_inches='tight', dpi=1200)

        label_list = colors.keys()
        label_list = [x[0:40] for x in label_list]
        legend = plt.legend(handles=markers, labels=label_list, loc=3, framealpha=1, frameon=True, bbox_to_anchor=(2, 0))

        separate_legend = legend.figure
        separate_legend.canvas.draw()
        bbox = legend.get_window_extent()
        bbox = bbox.from_extents(*(bbox.extents + np.array([-4, -4, 4, 4])))
        bbox = bbox.transformed(fig.dpi_scale_trans.inverted())
        fig.savefig(path_to_application_category_name_legend_storage, dpi=1200, bbox_inches=bbox)
        legend.remove()



        graph_img = Image.open(application_category_name_graph_path)
        legend_im = Image.open(path_to_application_category_name_legend_storage)

        widths_graph = graph_img.width
        heights_graph = graph_img.height

        widths_legend = legend_im.width
        heights_legend = legend_im.height

        if heights_legend > heights_graph:
            resize_percentage = heights_graph / heights_legend
            new_width = int(resize_percentage * widths_legend)

            legend_im = legend_im.resize((new_width, heights_graph), Image.ANTIALIAS)

        total_width = widths_graph + widths_legend

        y_offset = int((heights_graph - heights_legend) / 2)

        combined_im = Image.new('RGB', (total_width, heights_graph), color=(255, 255, 255, 1))
        combined_im.paste(graph_img, (0, 0))
        combined_im.paste(legend_im, (widths_graph, y_offset))
        combined_im.save(path_to_application_category_name_combined)


        ##################
        # label category #
        ##################

        fig, ax = plt.subplots(nrows=number_rows, ncols=number_columns)

        for experiment, (path, folder_name) in enumerate(folders):

            #csv_filepath = path + "/*csv"
            csv_filepath = path + "/summaries/summary*"
            csv_summary_file = glob.glob(csv_filepath)[0]

            csv_df = pd.read_csv(csv_summary_file)

            overall_detailed_label_df = csv_df.groupby("clusnum")["label"].value_counts().to_frame()
            overall_detailed_label_df = overall_detailed_label_df.rename(columns={"label": "count"})
            overall_detailed_label_df = overall_detailed_label_df.reset_index()

            clusters = overall_detailed_label_df["clusnum"].unique().tolist()

            list_of_names_dfs = []

            for cluster in clusters:
                cluster_df = overall_detailed_label_df[overall_detailed_label_df["clusnum"] == cluster][
                    ["label", "count"]]

                cluster_df = cluster_df.groupby("label")["count"].aggregate(sum).reset_index().sort_values(
                    by=["count"], ascending=False)

                list_of_names_dfs.append(cluster_df)

            detailed_label_name_df = list_of_names_dfs.pop()

            for name_df in list_of_names_dfs:
                detailed_label_name_df = detailed_label_name_df.append(name_df)

            detailed_label_name_df = detailed_label_name_df.groupby("label")["count"].aggregate(
                sum).reset_index().sort_values(by=["count"])
            unique_application_category_names = detailed_label_name_df["label"].tolist()

            colors = {}
            colors["Malicious"] = "r"
            colors["Benign"] = "g"
            colors["Unknown"] = "grey"

            for index, cluster in enumerate(clusters):
                cluster_df = overall_detailed_label_df[overall_detailed_label_df["clusnum"] == cluster][
                    ["label", "count"]]

                cluster_df = cluster_df.groupby("label")["count"].aggregate(sum).reset_index().sort_values(
                    by=["count"])
                cluster_df["relative_count"] = round((cluster_df["count"] / cluster_df["count"].sum()) * 100, 2)

                patches, texts = ax[experiment, index].pie(cluster_df["count"], labels=cluster_df["relative_count"],colors=[colors[key] for key in cluster_df["label"]])
                amount_skip = 0
                new_labels = []
                for text_index, text in enumerate(texts):
                    if (text_index == 0):
                        new_labels.append(text.get_text())
                    else:
                        current_xy = text.get_position()
                        current_str = text.get_text()

                        past_text = texts[text_index - 1]
                        past_xy = past_text.get_position()
                        past_str = new_labels[text_index - 1]

                        distance = math.sqrt(
                            pow((current_xy[0] - past_xy[0]), 2) + pow((current_xy[1] - past_xy[1]), 2))

                        if distance < 0.3:
                            if distance < 0.2:
                                if amount_skip < 2:
                                    new_labels.append(" ")
                                    amount_skip = amount_skip + 1
                                else:
                                    new_labels.append(current_str)
                                    amount_skip = 0
                            else:
                                if past_str != " ":
                                    new_labels.append(" ")
                                    amount_skip = amount_skip + 1
                                else:
                                    new_labels.append(current_str)
                                    amount_skip = 0
                        else:
                            new_labels.append(current_str)
                            amount_skip = 0

                ax[experiment, index].clear()
                ax[experiment, index].pie(cluster_df["count"], labels=new_labels,
                                          colors=[colors[key] for key in cluster_df["label"]],
                                          labeldistance=1.15, textprops={'fontsize': 8})
                ax[experiment, index].set_title("Cluster " + str(cluster))

            if len(clusters) < number_columns:
                for missing_axis in range(len(clusters), number_columns):
                    ax[experiment, missing_axis].axis('off')

        markers = [plt.Line2D([0, 0], [0, 0], color=color, marker='o', linestyle='') for color in colors.values()]
        fig.subplots_adjust(bottom=0.25)


        for experiment, (path, folder_name) in enumerate(folders):
            ax[experiment, number_columns - 1].text(y=0.5, x=0, s='Experiment ' + str(1 + experiment))

        plt.suptitle("Label Distribution per Cluster", y=0.96, x=0.5, fontweight='bold')

        # rearange the axes for no overlap
        fig.tight_layout()

        # Get the bounding boxes of the axes including text decorations
        r = fig.canvas.get_renderer()
        get_bbox = lambda ax: ax.get_tightbbox(r).transformed(fig.transFigure.inverted())
        bboxes = np.array(list(map(get_bbox, ax.flat)), mtrans.Bbox).reshape(ax.shape)

        # Get the minimum and maximum extent, get the coordinate half-way between those
        ymax = np.array(list(map(lambda b: b.y1, bboxes.flat))).reshape(ax.shape).max(axis=1)
        ymin = np.array(list(map(lambda b: b.y0, bboxes.flat))).reshape(ax.shape).min(axis=1)
        ys = np.c_[ymax[1:], ymin[:-1]].mean(axis=1)

        # Draw a horizontal lines at those coordinates
        for y in ys:
            line = plt.Line2D([0, 1], [y, y], transform=fig.transFigure, color="black")
            fig.add_artist(line)
        plt.savefig(label_graph_path, bbox_inches='tight', dpi=1200)

        label_list = colors.keys()
        label_list = [x[0:40] for x in label_list]
        legend = plt.legend(handles=markers, labels=label_list, loc=3, framealpha=1, frameon=True, bbox_to_anchor=(2, 0))

        separate_legend = legend.figure
        separate_legend.canvas.draw()
        bbox = legend.get_window_extent()
        bbox = bbox.from_extents(*(bbox.extents + np.array([-4 ,-4 ,4 ,4])))
        bbox = bbox.transformed(fig.dpi_scale_trans.inverted())
        fig.savefig(path_to_label_legend_storage, bbox_inches=bbox, dpi=1200)
        legend.remove()


        graph_img = Image.open(label_graph_path)
        legend_im = Image.open(path_to_label_legend_storage)

        widths_graph = graph_img.width
        heights_graph = graph_img.height

        widths_legend = legend_im.width
        heights_legend = legend_im.height

        if heights_legend > heights_graph:
            resize_percentage = heights_graph / heights_legend
            new_width = int(resize_percentage * widths_legend)

            legend_im = legend_im.resize((new_width, heights_graph), Image.ANTIALIAS)

        total_width = widths_graph + widths_legend

        y_offset = int((heights_graph - heights_legend) / 2)

        combined_im = Image.new('RGB', (total_width, heights_graph), color=(255, 255, 255, 1))
        combined_im.paste(graph_img, (0, 0))
        combined_im.paste(legend_im, (widths_graph, y_offset))
        combined_im.save(path_to_label_combined)

        ##################
        # detailed label #
        ##################

        fig, ax = plt.subplots(nrows=number_rows, ncols=number_columns)

        for experiment, (path, folder_name) in enumerate(folders):

            #csv_filepath = path + "/*csv"
            csv_filepath = path + "/summaries/summary*"
            csv_summary_file = glob.glob(csv_filepath)[0]

            csv_df = pd.read_csv(csv_summary_file)

            overall_detailed_label_df = csv_df.groupby("clusnum")["detailed_label"].value_counts().to_frame()
            overall_detailed_label_df = overall_detailed_label_df.rename(columns={"detailed_label": "count"})
            overall_detailed_label_df = overall_detailed_label_df.reset_index()

            clusters = overall_detailed_label_df["clusnum"].unique().tolist()

            list_of_names_dfs = []

            for cluster in clusters:
                cluster_df = overall_detailed_label_df[overall_detailed_label_df["clusnum"] == cluster][
                    ["detailed_label", "count"]]
                cluster_df["detailed_label"] = np.where(cluster_df["detailed_label"] == "-", "Unknown",
                                                        cluster_df.detailed_label)

                cluster_df = cluster_df.groupby("detailed_label")["count"].aggregate(sum).reset_index().sort_values(
                    by=["count"], ascending=False)

                list_of_names_dfs.append(cluster_df)

            detailed_label_name_df = list_of_names_dfs.pop()

            for name_df in list_of_names_dfs:
                detailed_label_name_df = detailed_label_name_df.append(name_df)

            detailed_label_name_df = detailed_label_name_df.groupby("detailed_label")["count"].aggregate(
                sum).reset_index().sort_values(by=["count"])
            unique_application_category_names = detailed_label_name_df["detailed_label"].tolist()

            colors = {}
            cmap = cm.terrain(np.linspace(0, 1, len(unique_application_category_names)))

            for index, color in enumerate(cmap):
                application_name = unique_application_category_names.pop()
                colors[application_name] = color


            for index, cluster in enumerate(clusters):
                cluster_df = overall_detailed_label_df[overall_detailed_label_df["clusnum"] == cluster][
                    ["detailed_label", "count"]]

                cluster_df = cluster_df.groupby("detailed_label")["count"].aggregate(sum).reset_index().sort_values(
                    by=["count"])
                cluster_df["relative_count"] = round((cluster_df["count"] / cluster_df["count"].sum()) * 100, 2)

                patches, texts = ax[experiment, index].pie(cluster_df["count"], labels=cluster_df["relative_count"],colors=[colors[key] for key in cluster_df["detailed_label"]])
                amount_skip = 0
                new_labels = []
                for text_index, text in enumerate(texts):
                    if (text_index == 0):
                        new_labels.append(text.get_text())
                    else:
                        current_xy = text.get_position()
                        current_str = text.get_text()

                        past_text = texts[text_index - 1]
                        past_xy = past_text.get_position()
                        past_str = new_labels[text_index - 1]

                        distance = math.sqrt(
                            pow((current_xy[0] - past_xy[0]), 2) + pow((current_xy[1] - past_xy[1]), 2))

                        if distance < 0.3:
                            if distance < 0.2:
                                if amount_skip < 2:
                                    new_labels.append(" ")
                                    amount_skip = amount_skip + 1
                                else:
                                    new_labels.append(current_str)
                                    amount_skip = 0
                            else:
                                if past_str != " ":
                                    new_labels.append(" ")
                                    amount_skip = amount_skip + 1
                                else:
                                    new_labels.append(current_str)
                                    amount_skip = 0
                        else:
                            new_labels.append(current_str)
                            amount_skip = 0

                ax[experiment, index].clear()
                ax[experiment, index].pie(cluster_df["count"], labels=new_labels,
                                          colors=[colors[key] for key in cluster_df["detailed_label"]],
                                          labeldistance=1.15, textprops={'fontsize': 8})
                ax[experiment, index].set_title("Cluster " + str(cluster))

            if len(clusters) < number_columns:
                for missing_axis in range(len(clusters), number_columns):
                    ax[experiment, missing_axis].axis('off')

        markers = [plt.Line2D([0, 0], [0, 0], color=color, marker='o', linestyle='') for color in colors.values()]
        fig.subplots_adjust(bottom=0.25)

        for experiment, (path, folder_name) in enumerate(folders):
            ax[experiment, number_columns - 1].text(y=0.5, x=0, s='Experiment ' + str(1 + experiment))

        plt.suptitle("Detailed Label Distribution per Cluster", y=0.96, x=0.5, fontweight='bold')

        # rearange the axes for no overlap
        fig.tight_layout()

        # Get the bounding boxes of the axes including text decorations
        r = fig.canvas.get_renderer()
        get_bbox = lambda ax: ax.get_tightbbox(r).transformed(fig.transFigure.inverted())
        bboxes = np.array(list(map(get_bbox, ax.flat)), mtrans.Bbox).reshape(ax.shape)

        # Get the minimum and maximum extent, get the coordinate half-way between those
        ymax = np.array(list(map(lambda b: b.y1, bboxes.flat))).reshape(ax.shape).max(axis=1)
        ymin = np.array(list(map(lambda b: b.y0, bboxes.flat))).reshape(ax.shape).min(axis=1)
        ys = np.c_[ymax[1:], ymin[:-1]].mean(axis=1)

        # Draw a horizontal lines at those coordinates
        for y in ys:
            line = plt.Line2D([0, 1], [y, y], transform=fig.transFigure, color="black")
            fig.add_artist(line)
        plt.savefig(detailed_label_graph_path, bbox_inches='tight', dpi=1200)

        label_list = colors.keys()
        label_list = [x[0:40] for x in label_list]
        legend = plt.legend(handles=markers, labels=label_list, loc=3, framealpha=1, frameon=True, bbox_to_anchor=(2, 0))

        separate_legend = legend.figure
        separate_legend.canvas.draw()
        bbox = legend.get_window_extent()
        bbox = bbox.from_extents(*(bbox.extents + np.array([-4, -4, 4, 4])))
        bbox = bbox.transformed(fig.dpi_scale_trans.inverted())
        fig.savefig(path_to_detailed_label_legend_storage, bbox_inches=bbox, dpi=1200)
        legend.remove()

        graph_img = Image.open(detailed_label_graph_path)
        legend_im = Image.open(path_to_detailed_label_legend_storage)

        widths_graph = graph_img.width
        heights_graph = graph_img.height

        widths_legend = legend_im.width
        heights_legend = legend_im.height

        if heights_legend > heights_graph:
            resize_percentage = heights_graph / heights_legend
            new_width = int(resize_percentage * widths_legend)

            legend_im = legend_im.resize((new_width, heights_graph), Image.ANTIALIAS)

        total_width = widths_graph + widths_legend

        y_offset = int((heights_graph - heights_legend) / 2)

        combined_im = Image.new('RGB', (total_width, heights_graph), color=(255, 255, 255, 1))
        combined_im.paste(graph_img, (0, 0))
        combined_im.paste(legend_im, (widths_graph, y_offset))
        combined_im.save(path_to_detailed_label_combined)

        ##############
        # name graph #
        ##############

        fig, ax = plt.subplots(nrows=number_rows, ncols=number_columns)

        for experiment, (path, folder_name) in enumerate(folders):

            #csv_filepath = path + "/*csv"
            csv_filepath = path + "/summaries/summary*"
            csv_summary_file = glob.glob(csv_filepath)[0]

            csv_df = pd.read_csv(csv_summary_file)

            overall_detailed_label_df = csv_df.groupby("clusnum")["name"].value_counts().to_frame()
            overall_detailed_label_df = overall_detailed_label_df.rename(columns={"name": "count"})
            overall_detailed_label_df = overall_detailed_label_df.reset_index()

            clusters = overall_detailed_label_df["clusnum"].unique().tolist()

            list_of_names_dfs = []

            for cluster in clusters:
                cluster_df = overall_detailed_label_df[overall_detailed_label_df["clusnum"] == cluster][
                    ["name", "count"]]

                cluster_df = cluster_df.groupby("name")["count"].aggregate(sum).reset_index().sort_values(
                    by=["count"], ascending=False)

                list_of_names_dfs.append(cluster_df)

            detailed_label_name_df = list_of_names_dfs.pop()

            for name_df in list_of_names_dfs:
                detailed_label_name_df = detailed_label_name_df.append(name_df)

            detailed_label_name_df = detailed_label_name_df.groupby("name")["count"].aggregate(
                sum).reset_index().sort_values(by=["count"])
            unique_application_category_names = detailed_label_name_df["name"].tolist()

            colors = {}
            cmap = cm.ocean(np.linspace(0, 1, len(unique_application_category_names)))

            for index, color in enumerate(cmap):
                application_name = unique_application_category_names.pop()
                colors[application_name] = color

            for index, cluster in enumerate(clusters):
                cluster_df = overall_detailed_label_df[overall_detailed_label_df["clusnum"] == cluster][
                    ["name", "count"]]

                cluster_df = cluster_df.groupby("name")["count"].aggregate(sum).reset_index().sort_values(
                    by=["count"])
                cluster_df["relative_count"] = round((cluster_df["count"] / cluster_df["count"].sum()) * 100, 2)

                patches, texts = ax[experiment, index].pie(cluster_df["count"], labels=cluster_df["relative_count"],
                                                           colors=[colors[key] for key in cluster_df["name"]])
                amount_skip = 0
                new_labels = []
                for text_index, text in enumerate(texts):
                    if (text_index == 0):
                        new_labels.append(text.get_text())
                    else:
                        current_xy = text.get_position()
                        current_str = text.get_text()

                        past_text = texts[text_index - 1]
                        past_xy = past_text.get_position()
                        past_str = new_labels[text_index - 1]

                        distance = math.sqrt(
                            pow((current_xy[0] - past_xy[0]), 2) + pow((current_xy[1] - past_xy[1]), 2))

                        if distance < 0.3:
                            if distance < 0.2:
                                if amount_skip < 2:
                                    new_labels.append(" ")
                                    amount_skip = amount_skip + 1
                                else:
                                    new_labels.append(current_str)
                                    amount_skip = 0
                            else:
                                if past_str != " ":
                                    new_labels.append(" ")
                                    amount_skip = amount_skip + 1
                                else:
                                    new_labels.append(current_str)
                                    amount_skip = 0
                        else:
                            new_labels.append(current_str)
                            amount_skip = 0

                ax[experiment, index].clear()
                ax[experiment, index].pie(cluster_df["count"], labels=new_labels,
                                          colors=[colors[key] for key in cluster_df["name"]],
                                          labeldistance=1.15, textprops={'fontsize': 8})
                ax[experiment, index].set_title("Cluster " + str(cluster))

            if len(clusters) < number_columns:
                for missing_axis in range(len(clusters), number_columns):
                    ax[experiment, missing_axis].axis('off')

        markers = [plt.Line2D([0, 0], [0, 0], color=color, marker='o', linestyle='') for color in colors.values()]
        fig.subplots_adjust(bottom=0.25)

        for experiment, (path, folder_name) in enumerate(folders):
            ax[experiment, number_columns - 1].text(y=0.5, x=0, s='Experiment ' + str(1 + experiment))

        plt.suptitle("Name Distribution per Cluster", y=0.96, x=0.5, fontweight='bold')

        # rearange the axes for no overlap
        fig.tight_layout()

        # Get the bounding boxes of the axes including text decorations
        r = fig.canvas.get_renderer()
        get_bbox = lambda ax: ax.get_tightbbox(r).transformed(fig.transFigure.inverted())
        bboxes = np.array(list(map(get_bbox, ax.flat)), mtrans.Bbox).reshape(ax.shape)

        # Get the minimum and maximum extent, get the coordinate half-way between those
        ymax = np.array(list(map(lambda b: b.y1, bboxes.flat))).reshape(ax.shape).max(axis=1)
        ymin = np.array(list(map(lambda b: b.y0, bboxes.flat))).reshape(ax.shape).min(axis=1)
        ys = np.c_[ymax[1:], ymin[:-1]].mean(axis=1)

        # Draw a horizontal lines at those coordinates
        for y in ys:
            line = plt.Line2D([0, 1], [y, y], transform=fig.transFigure, color="black")
            fig.add_artist(line)
        plt.savefig(name_graph_path, bbox_inches='tight', dpi=1200)

        label_list = colors.keys()
        label_list = [x[0:40] for x in label_list]
        legend = plt.legend(handles=markers, labels=label_list, loc=3, framealpha=1, frameon=True,
                            bbox_to_anchor=(2, 0))

        separate_legend = legend.figure
        separate_legend.canvas.draw()
        bbox = legend.get_window_extent()
        bbox = bbox.from_extents(*(bbox.extents + np.array([-4, -4, 4, 4])))
        bbox = bbox.transformed(fig.dpi_scale_trans.inverted())
        fig.savefig(path_to_name_legend_storage, bbox_inches=bbox, dpi=1200)
        legend.remove()

        graph_img = Image.open(name_graph_path)
        legend_im = Image.open(path_to_name_legend_storage)

        widths_graph = graph_img.width
        heights_graph = graph_img.height

        widths_legend = legend_im.width
        heights_legend = legend_im.height

        if heights_legend > heights_graph:
            resize_percentage = heights_graph / heights_legend
            new_width = int(resize_percentage * widths_legend)

            legend_im = legend_im.resize((new_width, heights_graph), Image.ANTIALIAS)

        total_width = widths_graph + widths_legend

        y_offset = int((heights_graph - heights_legend) / 2)

        combined_im = Image.new('RGB', (total_width, heights_graph), color=(255, 255, 255, 1))
        combined_im.paste(graph_img, (0, 0))
        combined_im.paste(legend_im, (widths_graph, y_offset))
        combined_im.save(path_to_name_combined)

    @staticmethod
    def create_cluster_transition_graph(experiment_name, path_to_results, path_to_storage):

        experiment_name = experiment_name
        path_to_results = path_to_results
        path_to_storage = path_to_storage

        folders = sorted([f.path for f in os.scandir(path_to_results) if f.is_dir()])
        folders = list(map(lambda x: (x, str(os.path.basename(x)).strip()), folders))

        transition_graph_path = path_to_storage + "/" + experiment_name + "_transition_graph.png"

        nodes = []
        node_sizes = []
        labels = {}
        node_colors = []
        node_position = {}
        label_position = {}

        max_columns = 0

        fig, ax = plt.subplots()
        g = nx.Graph()

        from_dic = {}
        to_dic = {}
        overall_weights = []
        overall_edges = []
        overall_edge_label = {}

        for y_position, (path, folder_name) in enumerate(folders):
            part = int(folder_name.split("_")[2])
            #csv_filepath = path + "/*csv"
            csv_filepath = path + "/summaries/summary*"

            csv_summary_file = glob.glob(csv_filepath)[0]

            csv_df = pd.read_csv(csv_summary_file)

            plt.axhline(y=y_position * (-1) + 0.5, color='lightgrey', linestyle=':')
            ax.text(1 + (len(folders) * 2), (-1) * y_position, 'Experiment ' + str(1 + y_position))

            cluster_membership = csv_df.groupby("clusnum")["connnum"].count().reset_index()
            cluster_membership = cluster_membership.rename(columns={"clusnum" : "label", "connnum" : "node_size"})

            clusters = 0
            for x_position, row in enumerate(cluster_membership.iterrows()):
                clusters = clusters + 1
                label = int(row[1]["label"])
                node_size = row[1]["node_size"]

                if label == -1:
                    node_colors.append("grey")
                else:
                    node_colors.append("blue")

                node_name =  (str(y_position + 1), str(label)) # (experiment, cluster)

                nodes.append(node_name)
                node_sizes.append(float(node_size * 5))
                labels[node_name] = "clus " + str(label)
                node_position[node_name] = (( 1 +x_position) * 2, (y_position) * (-1))

                label_position[node_name] = (node_position[node_name][0] - max((node_size / 700), 0.7), node_position[node_name][1])

            if clusters > max_columns:
                max_columns = clusters


            edge_df = csv_df[["clusnum", "file", "src_ip", "dst_ip"]]
            edge_df["name"] = edge_df["file"] + edge_df["src_ip"] + edge_df["dst_ip"]
            edge_df = edge_df[["clusnum", "name"]]

            if y_position == 0:
                for row in edge_df.iterrows():
                    name = row[1]["name"]
                    from_cluster = int(row[1]["clusnum"])
                    from_dic[name] = (str(y_position + 1), str(from_cluster))
            else:
                for row in edge_df.iterrows():
                    name = row[1]["name"]
                    to_cluster = int(row[1]["clusnum"])
                    to_dic[name] = (str(y_position + 1), str(to_cluster))

                edges_dic = {}

                for connection_name, from_node in from_dic.items():
                    to_node = to_dic[connection_name]

                    if (from_node, to_node) in edges_dic:
                        old_entry = edges_dic[(from_node, to_node)]
                        new_entry = old_entry + 1
                        edges_dic[(from_node, to_node)] = new_entry
                    else:
                        edges_dic[(from_node, to_node)] = 1


                total_weight = 0
                edges_this_experiment = []
                outgoing_edges_per_vector = {}

                for edge_name, weight in edges_dic.items():
                    overall_weights.append(weight)
                    overall_edges.append(edge_name)

                    overall_edge_label[edge_name] = weight
                    total_weight = total_weight + weight
                    edges_this_experiment.append(edge_name)

                    if edge_name[0] in outgoing_edges_per_vector:
                        old_entry = outgoing_edges_per_vector[edge_name[0]]
                        new_entry = old_entry + weight
                        outgoing_edges_per_vector[edge_name[0]] = new_entry
                    else:
                        outgoing_edges_per_vector[edge_name[0]] = weight

                for edge_this_game in edges_this_experiment:
                    absolut_weight = overall_edge_label[edge_this_game]
                    relative_weight = round(absolut_weight / outgoing_edges_per_vector[edge_this_game[0]], 3)
                    overall_edge_label[edge_this_game] = relative_weight

                from_dic = to_dic
                to_dic = {}

        g.add_nodes_from(nodes)
        nodes = nx.draw_networkx_nodes(g, nodelist=nodes, pos=node_position, node_color=node_colors, node_size=node_sizes, alpha=0.35)

        nx.draw_networkx_labels(g, pos=label_position, labels=labels)

        normalized_weights = [(float(i ) /sum(overall_weights) * 30) for i in overall_weights]
        nx.draw_networkx_edges(g, pos=node_position, width=normalized_weights, edgelist=overall_edges, style='dotted')

        edge_label = nx.draw_networkx_edge_labels(g, pos=node_position, edge_labels=overall_edge_label, label_pos=0.65, horizontalalignment = 'center', verticalalignment = 'baseline')

        y_levels = {}
        x_levels = {}
        for _, text in edge_label.items():
            current_x = text.get_position()[0]
            current_y = text.get_position()[1]

            if current_y not in y_levels:
                y_levels[current_y] = 1
                new_y = current_y + 0.075
            else:
                current_amount = y_levels[current_y]
                new_amount = current_amount + 1
                y_levels[current_y] = new_amount

                if current_amount % 2 == 0:
                    new_y = current_y + 0.075
                else:
                    new_y = current_y - 0.075


            if current_x not in x_levels:
                x_levels[current_x] = 1
                new_x = current_x + 0.02
            else:
                current_amount = x_levels[current_x]
                new_amount = current_amount + 1
                x_levels[current_x] = new_amount

                if current_amount % 2 == 0:
                    new_x = current_x + 0.02
                else:
                    new_x = current_x - 0.02

            text.set_position((new_x, new_y))
            text.set_rotation('horizontal')

        # ax.tick_params(left=True, bottom=True, labelleft=True, labelbottom=True)
        plt.ylim([-2.5, -2.5 + len(folders)])
        plt.xlim([0, 2.5 + (max_columns * 2)])

        plt.suptitle("Transition Graph", y=0.96, x=0.5, fontweight='bold')

        plt.tight_layout()

        #plt.show()
        plt.savefig(transition_graph_path, bbox_inches='tight')

        plt.close()
