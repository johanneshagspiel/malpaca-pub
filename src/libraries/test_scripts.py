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

class Test_Scripts():



    @staticmethod
    def test_csv_file_creation(path_to_csv_file):

        path_to_csv_file = path_to_csv_file
        path_to_pcap_files = path_to_pcap_files
        new_csv_file_path = new_csv_file_path

        connections_used = {}

        print("Read pcap")
        with PcapReader(path_to_pcap_files) as packets:
            for packet in packets:

                src_ip = packet[IP].src
                dst_ip = packet[IP].dst

                if (src_ip, dst_ip) not in connections_used:
                    connections_used[(src_ip, dst_ip)] = True

        csv_df = pd.read_csv(path_to_csv_file)
        csv_df["src_ip"] = csv_df["src_ip"].apply(lambda x: str(x))
        csv_df["dst_ip"] = csv_df["dst_ip"].apply(lambda x: str(x))

        with open(new_csv_file_path, 'w', newline='') as csvfile:
            csv_writer = csv.writer(csvfile, delimiter=',', quotechar='|', quoting=csv.QUOTE_MINIMAL)

            new_line = ["src_ip", "dst_ip", "connection_length", "scenario", "file", "label", "detailed_label"]
            csv_writer.writerow(new_line)

            for index, (src_ip, dst_ip) in enumerate(connections_used.keys()):
                print("Connection " + str(index + 1) + "/" + str(len(connections_used.keys())))

                src_ip = str(src_ip)
                dst_ip = str(dst_ip)

                label = csv_df[(csv_df["src_ip"] == src_ip) & (csv_df["dst_ip"] == dst_ip)]["label"].values[0]
                detailed_label = \
                    csv_df[(csv_df["src_ip"] == src_ip) & (csv_df["dst_ip"] == dst_ip)]["detailed_label"].values[0]

                new_line = [str(src_ip), str(dst_ip), str(5), "CTU-IoT-Malware-Capture-48-1",
                            "2019-02-28-19-15-13-192.168.1.200.pcap", label,
                            detailed_label]
                csv_writer.writerow(new_line)

        csvfile.close()

        connections_used.clear()