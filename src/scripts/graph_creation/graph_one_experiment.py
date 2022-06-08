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
from adjustText import adjust_text
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
from PIL import Image

class Graph_One_Experiment():


    @staticmethod
    def creating_graphs_for_one_experiment(path_to_csv_file):

        path_to_csv_file = path_to_csv_file

        summary_csv_df = pd.read_csv(path_to_csv_file)

        application_name_graph = "application_name_graph.png"
        path_to_application_name_legend_storage = "application_name_legend.png"
        path_to_application_name_combined = 'application_name_combined.png'

        application_category_name_graph = "application_category_name_graph.png"
        path_to_application_category_name_legend_storage = "application_category_name_legend.png"
        path_to_application_category_name_combined = 'application_category_name_combined.png'

        label_distribution_graph = "label_graph.png"
        path_to_label_legend_storage = "label_legend.png"
        path_to_label_combined = 'label_combined.png'

        detailed_label_distribution_graph = "detailed_label_graph.png"
        path_to_detailed_label_legend_storage = "detailed_label_legend.png"
        path_to_detailed_label_combined = 'detailed_label_combined.png'

        name_distribution_graph = "name_graph.png"
        path_to_name_legend_storage = "name_legend.png"
        path_to_name_combined = 'name_combined.png'


        overall_detailed_label_df = summary_csv_df.groupby("clusnum")["application_name"].value_counts().to_frame()
        overall_detailed_label_df = overall_detailed_label_df.rename(columns={"application_name": "count"})
        overall_detailed_label_df = overall_detailed_label_df.reset_index()

        clusters = overall_detailed_label_df["clusnum"].unique().tolist()

        if len(clusters) < 4:
            ncols = len(clusters)
        else:
            ncols = 4
        nrows = math.ceil(len(clusters) / 4)

        fig, ax = plt.subplots(nrows=nrows, ncols=ncols, figsize=(7, 7))


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
        cmap = cm.get_cmap('viridis', len(unique_application_category_names))

        for index, color in enumerate(cmap.colors):
            application_name = unique_application_category_names.pop()
            colors[application_name] = color

        if len(clusters) == 1:
            cluster_df["relative_count"] = round((cluster_df["count"] / cluster_df["count"].sum()) * 100, 2)
            ax.pie(cluster_df["count"], labels=cluster_df["relative_count"],
                   colors=[colors[key] for key in cluster_df["application_name"]])
            ax.set_title("Cluster " + str(cluster))

        else:

            for index, cluster in enumerate(clusters):
                cluster_df = overall_detailed_label_df[overall_detailed_label_df["clusnum"] == cluster][
                    ["application_name", "count"]]

                cluster_df["application_name"] = np.where(cluster_df["count"] <= 4, "Other", cluster_df.application_name)

                cluster_df = cluster_df.groupby("application_name")["count"].aggregate(sum).reset_index().sort_values(
                    by=["count"])
                cluster_df["relative_count"] = round((cluster_df["count"] / cluster_df["count"].sum()) * 100, 2)

                if (len(cluster_df.index) > 7):
                    cluster_df["relative_count"] = np.where(cluster_df["relative_count"] <= 5, "", cluster_df["relative_count"])

                ax[math.floor(index / 4), index % 4].pie(cluster_df["count"], labels=cluster_df["relative_count"],
                              colors=[colors[key] for key in cluster_df["application_name"]], labeldistance=1.25)
                ax[math.floor(index / 4), index % 4].set_title("Cluster " + str(cluster))

            if len(clusters) % 4 != 0:
                if len(clusters) > 1:
                    for missing_axis in range(4 - len(clusters) % 4, 4):
                        ax[nrows-1, missing_axis].axis('off')

        markers = [plt.Line2D([0, 0], [0, 0], color=color, marker='o', linestyle='') for color in colors.values()]

        plt.suptitle("Application Name Distribution per Cluster", y=0.985, x=0.5)


        fig.tight_layout()
        fig.canvas.draw()
        fig.savefig(application_name_graph, dpi=1200)

        legend = plt.legend(handles=markers, labels=colors.keys(), loc=3, framealpha=1, frameon=True, bbox_to_anchor=(2, 0))
        separate_legend = legend.figure
        separate_legend.canvas.draw()
        bbox = legend.get_window_extent()
        bbox = bbox.from_extents(*(bbox.extents + np.array([-4 ,-4 ,4 ,4])))
        bbox = bbox.transformed(fig.dpi_scale_trans.inverted())
        fig.savefig(path_to_application_name_legend_storage, dpi=1200, bbox_inches=bbox)
        legend.remove()

        plt.close()
        plt.clf()

        graph_img = Image.open(application_name_graph)
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






        overall_detailed_label_df = summary_csv_df.groupby("clusnum")[
            "application_category_name"].value_counts().to_frame()
        overall_detailed_label_df = overall_detailed_label_df.rename(columns={"application_category_name": "count"})
        overall_detailed_label_df = overall_detailed_label_df.reset_index()

        clusters = overall_detailed_label_df["clusnum"].unique().tolist()

        if len(clusters) < 4:
            ncols = len(clusters)
        else:
            ncols = 4
        nrows = math.ceil(len(clusters) / 4)

        fig, ax = plt.subplots(nrows=nrows, ncols=ncols, figsize=(7, 7))

        list_of_names_dfs = []

        for cluster in clusters:
            cluster_df = overall_detailed_label_df[overall_detailed_label_df["clusnum"] == cluster][
                ["application_category_name", "count"]]

            cluster_df = cluster_df.groupby("application_category_name")["count"].aggregate(
                sum).reset_index().sort_values(
                by=["count"], ascending=False)

            list_of_names_dfs.append(cluster_df)

        detailed_label_name_df = list_of_names_dfs.pop()

        for name_df in list_of_names_dfs:
            detailed_label_name_df = detailed_label_name_df.append(name_df)

        detailed_label_name_df = detailed_label_name_df.groupby("application_category_name")["count"].aggregate(
            sum).reset_index().sort_values(by=["count"])
        unique_application_category_names = detailed_label_name_df["application_category_name"].tolist()

        colors = {}
        cmap = cm.get_cmap('cividis', len(unique_application_category_names))

        for index, color in enumerate(cmap.colors):
            application_name = unique_application_category_names.pop()
            colors[application_name] = color

        for index, cluster in enumerate(clusters):
            cluster_df = overall_detailed_label_df[overall_detailed_label_df["clusnum"] == cluster][
                ["application_category_name", "count"]]

            cluster_df = cluster_df.groupby("application_category_name")["count"].aggregate(
                sum).reset_index().sort_values(
                by=["count"])
            cluster_df["relative_count"] = round((cluster_df["count"] / cluster_df["count"].sum()) * 100, 2)

            if (len(cluster_df.index) > 7):
                cluster_df["relative_count"] = np.where(cluster_df["relative_count"] <= 5, "",
                                                        cluster_df["relative_count"])

            if len(clusters) == 1:
                ax.pie(cluster_df["count"], labels=cluster_df["relative_count"],
                       colors=[colors[key] for key in cluster_df["application_category_name"]])
                ax.set_title("Cluster " + str(cluster))
            else:
                ax[math.floor(index / 4), index % 4].pie(cluster_df["count"], labels=cluster_df["relative_count"],
                              colors=[colors[key] for key in cluster_df["application_category_name"]], labeldistance=1.25)
                ax[math.floor(index / 4), index % 4].set_title("Cluster " + str(cluster))

            if len(clusters) % 4 != 0:
                if len(clusters) > 1:
                    for missing_axis in range(4 - len(clusters) % 4, 4):
                        ax[nrows-1, missing_axis].axis('off')

        markers = [plt.Line2D([0, 0], [0, 0], color=color, marker='o', linestyle='') for color in colors.values()]
        fig.subplots_adjust(bottom=0.25)

        plt.suptitle("Application Category Name Distribution per Cluster", y=0.985, x=0.5)

        fig.tight_layout()
        fig.canvas.draw()
        fig.savefig(application_category_name_graph, dpi=1200)

        legend = plt.legend(handles=markers, labels=colors.keys(), loc=3, framealpha=1, frameon=True, bbox_to_anchor=(2, 0))
        separate_legend = legend.figure
        separate_legend.canvas.draw()
        bbox = legend.get_window_extent()
        bbox = bbox.from_extents(*(bbox.extents + np.array([-4 ,-4 ,4 ,4])))
        bbox = bbox.transformed(fig.dpi_scale_trans.inverted())
        fig.savefig(path_to_application_category_name_legend_storage, dpi=1200, bbox_inches=bbox)
        legend.remove()

        plt.close()
        plt.clf()

        graph_img = Image.open(application_category_name_graph)
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








        overall_detailed_label_df = summary_csv_df.groupby("clusnum")["label"].value_counts().to_frame()
        overall_detailed_label_df = overall_detailed_label_df.rename(columns={"label": "count"})
        overall_detailed_label_df = overall_detailed_label_df.reset_index()

        clusters = overall_detailed_label_df["clusnum"].unique().tolist()

        if len(clusters) < 4:
            ncols = len(clusters)
        else:
            ncols = 4
        nrows = math.ceil(len(clusters) / 4)

        fig, ax = plt.subplots(nrows=nrows, ncols=ncols, figsize=(7, 7))

        colors = {}
        colors["Malicious"] = "r"
        colors["Benign"] = "g"
        colors["Unknown"] = "grey"

        for index, cluster in enumerate(clusters):
            cluster_df = \
                overall_detailed_label_df[overall_detailed_label_df["clusnum"] == cluster][
                    ["label", "count"]]

            cluster_df = cluster_df.groupby("label")["count"].aggregate(
                sum).reset_index().sort_values(
                by=["count"])
            cluster_df["relative_count"] = round((cluster_df["count"] / cluster_df["count"].sum()) * 100, 2)
            if (len(cluster_df.index) > 7):
                cluster_df["relative_count"] = np.where(cluster_df["relative_count"] <= 5, "",
                                                        cluster_df["relative_count"])

            if len(clusters) == 1:
                ax.pie(cluster_df["count"], labels=cluster_df["relative_count"],
                       colors=[colors[key] for key in cluster_df["label"]])
                ax.set_title("Cluster " + str(cluster))
            else:
                ax[math.floor(index / 4), index % 4].pie(cluster_df["count"], labels=cluster_df["relative_count"],
                              colors=[colors[key] for key in cluster_df["label"]], labeldistance=1.25)
                ax[math.floor(index / 4), index % 4].set_title("Cluster " + str(cluster))

            if len(clusters) % 4 != 0:
                if len(clusters) > 1:
                    for missing_axis in range(4 - len(clusters) % 4, 4):
                        ax[nrows-1, missing_axis].axis('off')


        markers = [plt.Line2D([0, 0], [0, 0], color=color, marker='o', linestyle='') for color in colors.values()]
        fig.subplots_adjust(bottom=0.25)

        plt.suptitle("Label Distribution per Cluster", y=0.985, x=0.5)

        fig.tight_layout()
        fig.canvas.draw()
        fig.savefig(label_distribution_graph, dpi=1200)

        legend = plt.legend(handles=markers, labels=colors.keys(), loc=3, framealpha=1, frameon=True,
                            bbox_to_anchor=(2, 0))
        separate_legend = legend.figure
        separate_legend.canvas.draw()
        bbox = legend.get_window_extent()
        bbox = bbox.from_extents(*(bbox.extents + np.array([-4, -4, 4, 4])))
        bbox = bbox.transformed(fig.dpi_scale_trans.inverted())
        fig.savefig(path_to_label_legend_storage, dpi=1200, bbox_inches=bbox)
        legend.remove()

        plt.close()
        plt.clf()

        graph_img = Image.open(label_distribution_graph)
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






        overall_detailed_label_df = summary_csv_df.groupby("clusnum")["detailed_label"].value_counts().to_frame()
        overall_detailed_label_df = overall_detailed_label_df.rename(columns={"detailed_label": "count"})
        overall_detailed_label_df = overall_detailed_label_df.reset_index()

        clusters = overall_detailed_label_df["clusnum"].unique().tolist()

        if len(clusters) < 4:
            ncols = len(clusters)
        else:
            ncols = 4
        nrows = math.ceil(len(clusters) / 4)

        fig, ax = plt.subplots(nrows=nrows, ncols=ncols, figsize=(7, 7))
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
        cmap = cm.get_cmap('plasma', len(unique_application_category_names))

        for index, color in enumerate(cmap.colors):
            application_name = unique_application_category_names.pop()
            colors[application_name] = color

        for index, cluster in enumerate(clusters):
            cluster_df = overall_detailed_label_df[overall_detailed_label_df["clusnum"] == cluster][
                ["detailed_label", "count"]]

            cluster_df["detailed_label"] = np.where(cluster_df["detailed_label"] == "-", "Unknown",
                                                    cluster_df.detailed_label)

            cluster_df = cluster_df.groupby("detailed_label")["count"].aggregate(sum).reset_index().sort_values(
                by=["count"])
            cluster_df["relative_count"] = round((cluster_df["count"] / cluster_df["count"].sum()) * 100, 2)

            if (len(cluster_df.index) > 7):
                cluster_df["relative_count"] = np.where(cluster_df["relative_count"] <= 5, "",
                                                        cluster_df["relative_count"])

            if len(clusters) == 1:
                ax.pie(cluster_df["count"], labels=cluster_df["relative_count"],
                       colors=[colors[key] for key in cluster_df["detailed_label"]])
                ax.set_title("Cluster " + str(cluster))
            else:
                ax[math.floor(index / 4), index % 4].pie(cluster_df["count"], labels=cluster_df["relative_count"],
                              colors=[colors[key] for key in cluster_df["detailed_label"]], labeldistance=1.25)
                ax[math.floor(index / 4), index % 4].set_title("Cluster " + str(cluster))
            if len(clusters) % 4 != 0:
                if len(clusters) > 1:
                    for missing_axis in range(4 - len(clusters) % 4, 4):
                        ax[nrows-1, missing_axis].axis('off')

        markers = [plt.Line2D([0, 0], [0, 0], color=color, marker='o', linestyle='') for color in colors.values()]
        fig.subplots_adjust(bottom=0.25)

        plt.suptitle("Detailed Label Distribution per Cluster", y=0.985, x=0.5)

        fig.tight_layout()
        fig.canvas.draw()
        fig.savefig(detailed_label_distribution_graph, dpi=1200)

        legend = plt.legend(handles=markers, labels=colors.keys(), loc=3, framealpha=1, frameon=True,
                            bbox_to_anchor=(2, 0))
        separate_legend = legend.figure
        separate_legend.canvas.draw()
        bbox = legend.get_window_extent()
        bbox = bbox.from_extents(*(bbox.extents + np.array([-4, -4, 4, 4])))
        bbox = bbox.transformed(fig.dpi_scale_trans.inverted())
        fig.savefig(path_to_detailed_label_legend_storage, dpi=1200, bbox_inches=bbox)
        legend.remove()

        plt.close()
        plt.clf()

        graph_img = Image.open(detailed_label_distribution_graph)
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








        overall_name_df = summary_csv_df.groupby("clusnum")["name"].value_counts().to_frame()
        overall_name_df = overall_name_df.rename(columns={"name": "count"})
        overall_name_df = overall_name_df.reset_index()

        clusters = overall_name_df["clusnum"].unique().tolist()

        if len(clusters) < 4:
            ncols = len(clusters)
        else:
            ncols = 4
        nrows = math.ceil(len(clusters) / 4)

        fig, ax = plt.subplots(nrows=nrows, ncols=ncols, figsize=(7, 7))
        list_of_names_dfs = []

        for cluster in clusters:
            cluster_df = overall_name_df[overall_name_df["clusnum"] == cluster][
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
        cmap = cm.get_cmap('inferno', len(unique_application_category_names))

        for index, color in enumerate(cmap.colors):
            application_name = unique_application_category_names.pop()
            colors[application_name] = color

        for index, cluster in enumerate(clusters):
            cluster_df = overall_name_df[overall_name_df["clusnum"] == cluster][
                ["name", "count"]]

            cluster_df = cluster_df.groupby("name")["count"].aggregate(sum).reset_index().sort_values(
                by=["count"])
            cluster_df["relative_count"] = round((cluster_df["count"] / cluster_df["count"].sum()) * 100, 2)

            if (len(cluster_df.index) >= 7):
                cluster_df["relative_count"] = np.where(cluster_df["relative_count"] <= 7, "",
                                                        cluster_df["relative_count"])

            if len(clusters) == 1:
                ax.pie(cluster_df["count"], labels=cluster_df["relative_count"],
                       colors=[colors[key] for key in cluster_df["name"]])
                ax.set_title("Cluster " + str(cluster))
            else:
                ax[math.floor(index / 4), index % 4].pie(cluster_df["count"], labels=cluster_df["relative_count"],
                              colors=[colors[key] for key in cluster_df["name"]], labeldistance=1.25)
                ax[math.floor(index / 4), index % 4].set_title("Cluster " + str(cluster))
            if len(clusters) % 4 != 0:
                if len(clusters) > 1:
                    for missing_axis in range(4 - len(clusters) % 4, 4):
                        ax[nrows-1, missing_axis].axis('off')

        markers = [plt.Line2D([0, 0], [0, 0], color=color, marker='o', linestyle='') for color in colors.values()]
        fig.subplots_adjust(bottom=0.25)

        plt.suptitle("Device / Malware Distribution per Cluster", y=0.985, x=0.5)

        fig.tight_layout()
        fig.canvas.draw()
        fig.savefig(name_distribution_graph, dpi=1200)

        legend = plt.legend(handles=markers, labels=colors.keys(), loc=3, framealpha=1, frameon=True,
                            bbox_to_anchor=(2, 0))
        separate_legend = legend.figure
        separate_legend.canvas.draw()
        bbox = legend.get_window_extent()
        bbox = bbox.from_extents(*(bbox.extents + np.array([-4, -4, 4, 4])))
        bbox = bbox.transformed(fig.dpi_scale_trans.inverted())
        fig.savefig(path_to_name_legend_storage, dpi=1200, bbox_inches=bbox)
        legend.remove()

        plt.close()
        plt.clf()

        graph_img = Image.open(name_distribution_graph)
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
    def per_cluster_get_application_pie_chart(path_to_csv_file):

        path_to_csv_file = path_to_csv_file
        csv_df = pd.read_csv(path_to_csv_file)

        overall_detailed_label_df = csv_df.groupby("clusnum")["application_name"].value_counts().to_frame()
        overall_detailed_label_df = overall_detailed_label_df.rename(columns={"application_name": "count"})
        overall_detailed_label_df = overall_detailed_label_df.reset_index()

        clusters = overall_detailed_label_df["clusnum"].unique().tolist()

        fig, ax = plt.subplots(nrows=1, ncols=len(clusters))

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
        cmap = cm.get_cmap('viridis', len(unique_application_category_names))

        for index, color in enumerate(cmap.colors):
            application_name = unique_application_category_names.pop()
            colors[application_name] = color

        for index, cluster in enumerate(clusters):
            cluster_df = overall_detailed_label_df[overall_detailed_label_df["clusnum"] == cluster][
                ["application_name", "count"]]

            cluster_df["application_name"] = np.where(cluster_df["count"] <= 4, "Other", cluster_df.application_name)

            cluster_df = cluster_df.groupby("application_name")["count"].aggregate(sum).reset_index().sort_values(
                by=["count"])
            cluster_df["relative_count"] = round((cluster_df["count"] / cluster_df["count"].sum()) * 100, 2)

            ax[index].pie(cluster_df["count"], labels=cluster_df["relative_count"],
                          colors=[colors[key] for key in cluster_df["application_name"]])
            ax[index].set_title("Cluster " + str(cluster))

        markers = [plt.Line2D([0, 0], [0, 0], color=color, marker='o', linestyle='') for color in colors.values()]
        fig.subplots_adjust(bottom=0.25)

        central_axis = int(len(clusters) / 2)
        ax[central_axis].legend(markers, colors.keys(), numpoints=1, loc="lower center", bbox_to_anchor=(0.5, -1))

        plt.suptitle("Application Name Distribution per Cluster", y=0.9, x=0.5)
        plt.show()
        plt.close()

        overall_detailed_label_df = csv_df.groupby("clusnum")["application_category_name"].value_counts().to_frame()
        overall_detailed_label_df = overall_detailed_label_df.rename(columns={"application_category_name": "count"})
        overall_detailed_label_df = overall_detailed_label_df.reset_index()

        clusters = overall_detailed_label_df["clusnum"].unique().tolist()

        fig, ax = plt.subplots(nrows=1, ncols=len(clusters))

        list_of_names_dfs = []

        for cluster in clusters:
            cluster_df = overall_detailed_label_df[overall_detailed_label_df["clusnum"] == cluster][
                ["application_category_name", "count"]]
            cluster_df["application_category_name"] = np.where(cluster_df["count"] <= 4, "Other",
                                                               cluster_df.application_category_name)

            cluster_df = cluster_df.groupby("application_category_name")["count"].aggregate(
                sum).reset_index().sort_values(
                by=["count"], ascending=False)

            list_of_names_dfs.append(cluster_df)

        detailed_label_name_df = list_of_names_dfs.pop()

        for name_df in list_of_names_dfs:
            detailed_label_name_df = detailed_label_name_df.append(name_df)

        detailed_label_name_df = detailed_label_name_df.groupby("application_category_name")["count"].aggregate(
            sum).reset_index().sort_values(by=["count"])
        unique_application_category_names = detailed_label_name_df["application_category_name"].tolist()

        colors = {}
        cmap = cm.get_cmap('cividis', len(unique_application_category_names))

        for index, color in enumerate(cmap.colors):
            application_name = unique_application_category_names.pop()
            colors[application_name] = color

        for index, cluster in enumerate(clusters):
            cluster_df = overall_detailed_label_df[overall_detailed_label_df["clusnum"] == cluster][
                ["application_category_name", "count"]]

            cluster_df["application_category_name"] = np.where(cluster_df["count"] <= 4, "Other",
                                                               cluster_df.application_category_name)

            cluster_df = cluster_df.groupby("application_category_name")["count"].aggregate(
                sum).reset_index().sort_values(
                by=["count"])
            cluster_df["relative_count"] = round((cluster_df["count"] / cluster_df["count"].sum()) * 100, 2)

            ax[index].pie(cluster_df["count"], labels=cluster_df["relative_count"],
                          colors=[colors[key] for key in cluster_df["application_category_name"]])
            ax[index].set_title("Cluster " + str(cluster))

        markers = [plt.Line2D([0, 0], [0, 0], color=color, marker='o', linestyle='') for color in colors.values()]
        fig.subplots_adjust(bottom=0.25)

        central_axis = int(len(clusters) / 2)
        ax[central_axis].legend(markers, colors.keys(), numpoints=1, loc="lower center", bbox_to_anchor=(0.5, -1))

        plt.suptitle("Application Name Category Distribution per Cluster", y=0.9, x=0.5)
        plt.show()
        plt.close()

        overall_detailed_label_df = csv_df.groupby("clusnum")["label"].value_counts().to_frame()
        overall_detailed_label_df = overall_detailed_label_df.rename(columns={"label": "count"})
        overall_detailed_label_df = overall_detailed_label_df.reset_index()

        clusters = overall_detailed_label_df["clusnum"].unique().tolist()

        fig, ax = plt.subplots(nrows=1, ncols=len(clusters))

        colors = {}
        colors["Malicious"] = "r"
        colors["Benign"] = "g"
        colors["Unknown"] = "grey"

        for index, cluster in enumerate(clusters):
            cluster_df = \
                overall_detailed_label_df[overall_detailed_label_df["clusnum"] == cluster][
                    ["label", "count"]]

            cluster_df = cluster_df.groupby("label")["count"].aggregate(
                sum).reset_index().sort_values(
                by=["count"])
            cluster_df["relative_count"] = round((cluster_df["count"] / cluster_df["count"].sum()) * 100, 2)

            ax[index].pie(cluster_df["count"], labels=cluster_df["relative_count"],
                          colors=[colors[key] for key in cluster_df["label"]])
            ax[index].set_title("Cluster " + str(cluster))

        markers = [plt.Line2D([0, 0], [0, 0], color=color, marker='o', linestyle='') for color in colors.values()]
        fig.subplots_adjust(bottom=0.25)

        central_axis = int(len(clusters) / 2)
        ax[central_axis].legend(markers, colors.keys(), numpoints=1, loc="lower center", bbox_to_anchor=(0.5, -0.6))

        plt.suptitle("Label Distribution per Cluster", y=0.9, x=0.5)
        plt.show()
        plt.close()

        overall_detailed_label_df = csv_df.groupby("clusnum")["detailed_label"].value_counts().to_frame()
        overall_detailed_label_df = overall_detailed_label_df.rename(columns={"detailed_label": "count"})
        overall_detailed_label_df = overall_detailed_label_df.reset_index()

        clusters = overall_detailed_label_df["clusnum"].unique().tolist()

        fig, ax = plt.subplots(nrows=1, ncols=len(clusters))

        list_of_names_dfs = []

        for cluster in clusters:
            cluster_df = overall_detailed_label_df[overall_detailed_label_df["clusnum"] == cluster][
                ["detailed_label", "count"]]
            cluster_df["detailed_label"] = np.where(cluster_df["count"] <= 3, "Other", cluster_df.detailed_label)
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
        cmap = cm.get_cmap('plasma', len(unique_application_category_names))

        for index, color in enumerate(cmap.colors):
            application_name = unique_application_category_names.pop()
            colors[application_name] = color

        for index, cluster in enumerate(clusters):
            cluster_df = overall_detailed_label_df[overall_detailed_label_df["clusnum"] == cluster][
                ["detailed_label", "count"]]

            cluster_df["detailed_label"] = np.where(cluster_df["count"] <= 3, "Other", cluster_df.detailed_label)
            cluster_df["detailed_label"] = np.where(cluster_df["detailed_label"] == "-", "Unknown",
                                                    cluster_df.detailed_label)

            cluster_df = cluster_df.groupby("detailed_label")["count"].aggregate(sum).reset_index().sort_values(
                by=["count"])
            cluster_df["relative_count"] = round((cluster_df["count"] / cluster_df["count"].sum()) * 100, 2)

            ax[index].pie(cluster_df["count"], labels=cluster_df["relative_count"],
                          colors=[colors[key] for key in cluster_df["detailed_label"]])
            ax[index].set_title("Cluster " + str(cluster))

        markers = [plt.Line2D([0, 0], [0, 0], color=color, marker='o', linestyle='') for color in colors.values()]
        fig.subplots_adjust(bottom=0.25)

        central_axis = int(len(clusters) / 2)
        ax[central_axis].legend(markers, colors.keys(), numpoints=1, loc="lower center", bbox_to_anchor=(0.5, -1.3))

        plt.suptitle("Detailed Label Distribution per Cluster", y=0.9, x=0.5)
        plt.show()
        plt.close()