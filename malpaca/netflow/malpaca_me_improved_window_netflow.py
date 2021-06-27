#!/usr/bin/python3
import math
from statistics import mean

import dpkt, datetime, glob, os, csv
import socket
from pathlib import Path

import matplotlib
from PIL import Image
from matplotlib.colors import Normalize
from matplotlib.pyplot import cm
from collections import deque

from sklearn import metrics
import numpy as np
import pandas as pd
import joblib
import matplotlib.pyplot as plt
from matplotlib.font_manager import FontProperties
from sklearn.manifold import TSNE
import seaborn as sns
import hdbscan
import time

from graphviz import render

from util.numba_cosine import cosine_similarity_numba
from util.odtw import _dtw_distance


class MalpacaMeImprovedWindowNetflow():
    expname = 'exp'
    window_size = 20
    RPY2 = False
    totalconn = 0

    def __init__(self, path_to_folder, path_to_results, path_to_detailed_label_folder, expname, window_size, RPY2):
        self.path_to_folder = path_to_folder
        self.path_to_detailed_label_folder = path_to_detailed_label_folder
        self.expname = expname
        self.window_size = window_size
        self.RPY2 = RPY2

        path_to_results = path_to_results
        os.mkdir(path_to_results + "/" + expname)
        self.path_to_store = str(Path.joinpath(Path(path_to_results), expname)) + "/"

        self.readfolde_window()

        if RPY2 == True:
            pass

    def difference(self, str1, str2):
        return sum([str1[x] != str2[x] for x in range(len(str1))])

    # @profile
    def connlevel_sequence(self, metadata, mapping):
        inv_mapping = {v: k for k, v in mapping.items()}
        data = metadata
        timing = {}

        values = list(data.values())
        keys = list(data.keys())
        distm = []
        labels = []
        ipmapping = []

        # save intermediate results

        path_to_intermediate_results = self.path_to_store + "/intermediate_results/"
        os.mkdir(path_to_intermediate_results)

        path_to_features = path_to_intermediate_results  +"/features/"
        os.mkdir(path_to_features)

        path_to_distances = path_to_intermediate_results  +"/distances/"
        os.mkdir(path_to_distances)


        addition = '_' + self.expname + '_' + str(self.window_size)

        # ----- start porting -------

        utils, r = None, None

        for n, feat in [(1, 'bytes'), (0, 'gaps'), (3, 'sport'), (4, 'dport')]:
            f = open(path_to_features + feat + '-features' + addition + '.txt', 'w')
            for val in values:
                vi = [str(x[n]) for x in val]
                f.write(','.join(vi))
                f.write("\n")
            f.close()

        startb = time.time()
        start_time = time.time()

        filename = path_to_distances + 'bytesDist' + addition + '.txt'

        print("Starting bytes dist")

        distm = [-1] * len(data.values())
        distm = [[-1] * len(data.values()) for i in distm]

        for a in range(len(data.values())):  # range(10):

            labels.append(mapping[keys[a]])
            ipmapping.append((mapping[keys[a]], inv_mapping[mapping[keys[a]]]))
            for b in range(a + 1):

                i = [x[1] for x in values[a]][:self.window_size]
                j = [x[1] for x in values[b]][:self.window_size]
                if len(i) == 0 or len(j) == 0: continue

                if a == b:
                    distm[a][b] = 0.0
                else:
                    first_array = np.array(i)
                    second_array = np.array(j)

                    dist = _dtw_distance(first_array, second_array)
                    distm[a][b] = dist
                    distm[b][a] = dist

        with open(filename, 'w') as outfile:
            for a in range(len(distm)):  # len(data.values())): #range(10):
                outfile.write(' '.join([str(e) for e in distm[a]]) + "\n")
        outfile.close()
        with open(path_to_intermediate_results + 'labels' + addition + '.txt', 'w') as outfile:
            outfile.write(' '.join([str(l) for l in labels]) + '\n')
        outfile.close()
        with open(path_to_intermediate_results + 'mapping' + addition + '.txt', 'w') as outfile:
            outfile.write(' '.join([str(l) for l in ipmapping]) + '\n')
        outfile.close()

        endb = time.time()
        print('Time bytes: ' + str(round((endb - startb), 3)))
        ndistmB = []
        mini = min(min(distm))
        maxi = max(max(distm))

        for a in range(len(distm)):
            ndistmB.append([])
            for b in range(len(distm)):
                normed = (distm[a][b] - mini) / (maxi - mini)
                ndistmB[a].append(normed)

        startg = time.time()
        distm = []

        filename = path_to_distances + 'gapsDist' + addition + '.txt'

        print("Starting gaps dist")
        distm = [-1] * len(data.values())
        distm = [[-1] * len(data.values()) for i in distm]

        for a in range(len(data.values())):  # range(10):

            for b in range(a + 1):

                i = [x[0] for x in values[a]][:self.window_size]
                j = [x[0] for x in values[b]][:self.window_size]

                if len(i) == 0 or len(j) == 0: continue

                if a == b:
                    distm[a][b] = 0.0
                else:
                    first_array = np.array(i)
                    second_array = np.array(j)

                    dist = _dtw_distance(first_array, second_array)
                    distm[a][b] = dist
                    distm[b][a] = dist

        with open(filename, 'w') as outfile:
            for a in range(len(distm)):  # len(data.values())): #range(10):
                # print distm[a]
                outfile.write(' '.join([str(e) for e in distm[a]]) + "\n")

        endg = time.time()
        print('Time gaps: ' + str(round((endg - startg), 3)))
        ndistmG = []
        mini = min(min(distm))
        maxi = max(max(distm))

        for a in range(len(distm)):  # len(data.values())): #range(10):
            ndistmG.append([])
            for b in range(len(distm)):
                normed = (distm[a][b] - mini) / (maxi - mini)
                ndistmG[a].append(normed)

        # source port
        ndistmS = []
        distm = []

        starts = time.time()

        filename = path_to_distances + 'sportDist' + addition + '.txt'
        same, diff = set(), set()

        print("Starting sport dist")
        distm = [-1] * len(data.values())
        distm = [[-1] * len(data.values()) for i in distm]

        ngrams = []
        for a in range(len(values)):
            profile = dict()

            dat = [x[3] for x in values[a]][:self.window_size]

            li = zip(dat, dat[1:], dat[2:])
            for b in li:
                if b not in profile.keys():
                    profile[b] = 0

                profile[b] += 1

            ngrams.append(profile)

        profiles = []
        # update for arrays

        assert len(ngrams) == len(values)
        for a in range(len(ngrams)):
            for b in range(a + 1):
                if a == b:
                    distm[a][b] = 0.0
                else:
                    i = ngrams[a]
                    j = ngrams[b]
                    ngram_all = list(set(i.keys()) | set(j.keys()))
                    i_vec = [(i[item] if item in i.keys() else 0) for item in ngram_all]
                    j_vec = [(j[item] if item in j.keys() else 0) for item in ngram_all]
                    #dist = cosine(i_vec, j_vec)

                    first_array = np.array(i_vec)
                    second_array = np.array(j_vec)

                    dist = round(cosine_similarity_numba(first_array, second_array), 8)

                    distm[a][b] = dist
                    distm[b][a] = dist

        with open(filename, 'w') as outfile:
            for a in range(len(distm)):
                outfile.write(' '.join([str(e) for e in distm[a]]) + "\n")

        ends = time.time()
        print('Sport time: ' + str(round((ends - starts), 3)))


        for a in range(len(distm)):
            ndistmS.append([])
            for b in range(len(distm)):
                ndistmS[a].append(distm[a][b])

        # dest port
        ndistmD = []
        distm = []

        startd = time.time()

        filename = path_to_distances + 'dportDist' + addition + '.txt'

        print("Starting dport dist")
        distm = [-1] * len(data.values())
        distm = [[-1] * len(data.values()) for i in distm]

        ngrams = []
        for a in range(len(values)):

            profile = dict()
            dat = [x[4] for x in values[a]][:self.window_size]

            li = zip(dat, dat[1:], dat[2:])

            for b in li:
                if b not in profile.keys():
                    profile[b] = 0
                profile[b] += 1
            ngrams.append(profile)

        assert len(ngrams) == len(values)
        for a in range(len(ngrams)):
            for b in range(a + 1):
                if a == b:
                    distm[a][b] = 0.0
                else:
                    i = ngrams[a]
                    j = ngrams[b]
                    ngram_all = list(set(i.keys()) | set(j.keys()))
                    i_vec = [(i[item] if item in i.keys() else 0) for item in ngram_all]
                    j_vec = [(j[item] if item in j.keys() else 0) for item in ngram_all]
                    #dist = round(cosine(i_vec, j_vec), 8)

                    first_array = np.array(i_vec)
                    second_array = np.array(j_vec)

                    dist = round(cosine_similarity_numba(first_array, second_array), 8)

                    distm[a][b] = dist
                    distm[b][a] = dist

        with open(filename, 'w') as outfile:
            for a in range(len(distm)):
                outfile.write(' '.join([str(e) for e in distm[a]]) + "\n")

        endd = time.time()
        print('Time dport: ' + str(round((endd - startd), 3)))
        mini = min(min(distm))
        maxi = max(max(distm))

        for a in range(len(distm)):
            ndistmD.append([])
            for b in range(len(distm)):
                ndistmD[a].append(distm[a][b])

        ndistm = []

        for a in range(len(ndistmS)):
            ndistm.append([])
            for b in range(len(ndistmS)):
                ndistm[a].append((ndistmB[a][b] + ndistmG[a][b] + ndistmD[a][b] + ndistmS[a][b]) / 4.0)

        print("Done with distance measurement")
        print("----------------")

        ###################
        # Data Clustering #
        ###################

        print("TSNE Projection 1")

        graphs_folder = self.path_to_store + "/graphs_folder"
        os.mkdir(graphs_folder)

        path_clustering_results = graphs_folder + "/clustering_results/"
        os.mkdir(path_clustering_results)

        plot_kwds = {'alpha': 0.5, 's': 80, 'linewidths': 0}
        RS = 3072018
        projection = TSNE(random_state=RS).fit_transform(ndistm)
        plt.scatter(*projection.T)
        plt.savefig(path_clustering_results + "tsne-result" + addition)

        plt.close()
        plt.clf()

        #########
        # Model #
        #########

        path_to_model = path_to_intermediate_results +"/model/"
        os.mkdir(path_to_model)

        size = 7
        sample = 7

        model = hdbscan.HDBSCAN(min_cluster_size=size, min_samples=sample, cluster_selection_method='leaf',
                                metric='precomputed')
        clu = model.fit(np.array([np.array(x) for x in ndistm]))  # final for citadel and dridex

        input_array = np.array([np.array(x) for x in ndistm])
        validity_index = hdbscan.validity_index(X=input_array, labels=clu.labels_, metric='precomputed', d=4)

        unique_labels = np.unique(np.array(clu.labels_))
        if (len(unique_labels) >= 2):
            silhouette_score = round(metrics.silhouette_score(X=input_array, labels=np.array(clu.labels_), metric='precomputed'), 3)
        else:
            silhouette_score = "nan"

        joblib.dump(clu, path_to_model + 'model' + addition + '.pkl')

        print("Num clusters: " + str(len(set(clu.labels_)) - 1))

        end_time = time.time()

        avg = 0.0
        for l in list(set(clu.labels_)):
            if l != -1:
                avg += sum([(1 if x == l else 0) for x in clu.labels_])
        #print("average size of cluster:" + str(float(avg) / float(len(set(clu.labels_)) - 1)))
        print("Samples in noise: " + str(sum([(1 if x == -1 else 0) for x in clu.labels_])))

        ########################
        # Creating Projections #
        ########################

        print("Creating projections")

        cols = ['royalblue', 'red', 'darksalmon', 'sienna', 'mediumpurple', 'palevioletred', 'plum', 'darkgreen',
                'lightseagreen', 'mediumvioletred', 'gold', 'navy', 'sandybrown', 'darkorchid', 'olivedrab', 'rosybrown',
                'maroon', 'deepskyblue', 'silver']
        pal = sns.color_palette(cols)  #

        extra_cols = len(set(clu.labels_)) - 18

        pal_extra = sns.color_palette('Paired', extra_cols)
        pal.extend(pal_extra)
        col = [pal[x] for x in clu.labels_]
        assert len(clu.labels_) == len(ndistm)

        mem_col = [sns.desaturate(x, p) for x, p in zip(col, clu.probabilities_)]

        plt.scatter(*projection.T, s=50, linewidth=0, c=col, alpha=0.2)

        for i, txt in enumerate(clu.labels_):

            realind = labels[i]
            name = inv_mapping[realind]
            plt.scatter(projection.T[0][i], projection.T[1][i], color=col[i], alpha=0.6)
            if txt == -1:
                continue

            plt.annotate(txt, (projection.T[0][i], projection.T[1][i]), color=col[i], alpha=0.6)

        plt.savefig(path_clustering_results + "clustering-result" + addition)
        plt.close()
        plt.clf()

        print("----------------")

        #####################
        # Creating CSV file #
        #####################

        print("Writing csv file")

        path_to_summaries = self.path_to_store + "/summaries/"
        os.mkdir(path_to_summaries)

        summary_csv_file_path = path_to_summaries + 'summary' + addition + '.csv'

        summary_list = []

        final_clusters = {}
        final_probs = {}
        for lab in set(clu.labels_):
            occ = [i for i, x in enumerate(clu.labels_) if x == lab]
            final_probs[lab] = [x for i, x in zip(clu.labels_, clu.probabilities_) if i == lab]
            print("cluster: " + str(lab) + " num items: " + str(len([labels[x] for x in occ])))
            final_clusters[lab] = [labels[x] for x in occ]

        outfile = open(summary_csv_file_path, 'w')
        outfile.write("clusnum,connnum,probability,scenario,file,src_ip,dst_ip,ip_protocol,src_port,dst_port,window\n")

        for n, clus in final_clusters.items():

            for idx, el in enumerate([inv_mapping[x] for x in clus]):

                ip = el.split('->')
                name = ip[0]
                scenario = name.split("_", maxsplit=1)[0]
                filename = name.split("_", maxsplit=1)[1]

                src_ip = ip[1]
                dst_ip = ip[2]
                protocol = ip[3]
                src_port = ip[4]
                dst_port = ip[5]
                window = ip[6]

                new_line = str(n) + "," + str(mapping[el]) + "," + str(final_probs[n][idx]) + "," + str(scenario) + "," + str(filename) + "," + src_ip + "," + dst_ip + "," + str(protocol) + "," + str(src_port) + "," + str(dst_port) + "," + window + "\n"
                outfile.write(new_line)

                new_line_summary = [n, mapping[el], final_probs[n][idx], scenario, filename, src_ip, dst_ip, protocol, src_port, dst_port, window, 0]
                summary_list.append(new_line_summary)


        outfile.close()

        other_csv_files = glob.glob(self.path_to_folder + "/*.csv")

        for index, csv_file_path in enumerate(other_csv_files):

            temp_df = pd.read_csv(csv_file_path)

            if index == 0:
                combined_df = temp_df
            else:
                combined_df = combined_df.append(temp_df)


        csv_df = pd.read_csv(summary_csv_file_path)
        csv_df = csv_df.sort_values(by=['src_ip', 'dst_ip', "ip_protocol", "src_port", "dst_port"])
        combined_df = combined_df.sort_values(by=['src_ip', 'dst_ip', "ip_protocol", "src_port", "dst_port"])

        combined_df["src_ip"] = combined_df["src_ip"].apply(lambda x: str(x).strip())
        combined_df["dst_ip"] = combined_df["dst_ip"].apply(lambda x: str(x).strip())
        combined_df["src_port"] = combined_df["src_port"].apply(lambda x: str(x).strip())
        combined_df["dst_port"] = combined_df["dst_port"].apply(lambda x: str(x).strip())
        combined_df["ip_protocol"] = combined_df["ip_protocol"].apply(lambda x: str(x).strip())
        combined_df["src_ip"] = combined_df["src_ip"].astype(str)
        combined_df["dst_ip"] = combined_df["dst_ip"].astype(str)
        combined_df["src_port"] = combined_df["src_port"].astype(str)
        combined_df["dst_port"] = combined_df["dst_port"].astype(str)
        combined_df["ip_protocol"] = combined_df["ip_protocol"].astype(str)

        csv_df["src_ip"] = csv_df["src_ip"].apply(lambda x: str(x).strip())
        csv_df["dst_ip"] = csv_df["dst_ip"].apply(lambda x: str(x).strip())
        csv_df["src_port"] = csv_df["src_port"].apply(lambda x: str(x).strip())
        csv_df["dst_port"] = csv_df["dst_port"].apply(lambda x: str(x).strip())
        csv_df["ip_protocol"] = csv_df["ip_protocol"].apply(lambda x: str(x).strip())
        csv_df["src_ip"] = csv_df["src_ip"].astype(str)
        csv_df["dst_ip"] = csv_df["dst_ip"].astype(str)
        csv_df["src_port"] = csv_df["src_port"].astype(str)
        csv_df["dst_port"] = csv_df["dst_port"].astype(str)
        csv_df["ip_protocol"] = csv_df["ip_protocol"].astype(str)

        csv_df = csv_df.merge(right=combined_df, on=['src_ip', 'dst_ip', 'window', "ip_protocol", "src_port", "dst_port", 'scenario', 'file'], how="left")

        csv_df = csv_df.sort_values(by="clusnum")
        csv_df.to_csv(summary_csv_file_path, index=False)

        ###############
        # Reliability #
        ###############

        print("Determining Reliability")

        path_to_reliability = self.path_to_store +"/reliability/"
        os.mkdir(path_to_reliability)

        path_to_reliability_summary = path_to_summaries + 'reliability_summary' + addition + '.csv'
        reliability_info_csv_file = path_to_reliability + 'reliability_info' + addition + '.csv'


        summary_list_columns = ["clusnum", "connnum", "probability", "scenario", "file", "src_ip", "dst_ip", "ip_protocol", "src_port", "dst_port", "window", "run"]

        for run_index in range(1, 10):

            size = 7
            sample = 7

            temp_model = hdbscan.HDBSCAN(min_cluster_size=size, min_samples=sample, cluster_selection_method='leaf',
                                    metric='precomputed')

            new_clu = temp_model.fit(np.array([np.array(x) for x in ndistm]))

            final_clusters = {}
            final_probs = {}
            for lab in set(new_clu.labels_):
                occ = [i for i, x in enumerate(new_clu.labels_) if x == lab]
                final_probs[lab] = [x for i, x in zip(new_clu.labels_, new_clu.probabilities_) if i == lab]
                final_clusters[lab] = [labels[x] for x in occ]

            for n, clus in final_clusters.items():

                for idx, el in enumerate([inv_mapping[x] for x in clus]):
                    ip = el.split('->')
                    name = ip[0]

                    scenario = name.split("_", maxsplit=1)[0]
                    filename = name.split("_", maxsplit=1)[1]

                    src_ip = ip[1]
                    dst_ip = ip[2]
                    protocol = ip[3]
                    src_port = ip[4]
                    dst_port = ip[5]
                    window = ip[6]
                    run = run_index

                    new_line_summary_list = [n, mapping[el], final_probs[n][idx], scenario, filename, src_ip, dst_ip, protocol, src_port, dst_port, window, run]

                    summary_list.append(new_line_summary_list)

        reliability_df = pd.DataFrame.from_records(summary_list, columns=summary_list_columns)
        reliability_df.to_csv(reliability_info_csv_file, index=False)

        cluster_distribution_df = reliability_df.groupby("connnum")["clusnum"].value_counts().to_frame()
        cluster_distribution_df = cluster_distribution_df.rename(columns={"clusnum": "#_occurrences_clusnum"})
        cluster_distribution_df = cluster_distribution_df.reset_index()
        less_ten_same_cluster_df = cluster_distribution_df[cluster_distribution_df["#_occurrences_clusnum"] < 10]
        percentage_cluster_change = round((len(less_ten_same_cluster_df) / len(reliability_df[reliability_df["run"] == 0])) * 100, 3)

        cluster_probability_df = reliability_df.groupby("connnum")["probability"].value_counts().to_frame()
        cluster_probability_df = cluster_probability_df.rename(columns={"probability": "#_occurrences_probability"})
        cluster_probability_df = cluster_probability_df.reset_index()
        less_ten_same_probability_df = cluster_probability_df[cluster_probability_df["#_occurrences_probability"] < 10]
        percentage_probability_change = round((len(less_ten_same_probability_df) / len(reliability_df[reliability_df["run"] == 0])) * 100, 3)


        data = {"percentage_cluster_change": percentage_cluster_change, "percentage_probability_change": percentage_probability_change}

        reliability_summary_df = pd.DataFrame(data, index=[0])
        reliability_summary_df.to_csv(path_to_reliability_summary, index=False)


        #################
        # Producing DAG #
        #################

        print('Producing DAG with relationships between pcaps')

        os.mkdir(Path.joinpath(Path(graphs_folder), "dag"))
        path_to_dag_results = str(Path.joinpath(Path(graphs_folder), "dag")) + "/"

        clusters = {}
        numclus = len(set(clu.labels_))
        with open(summary_csv_file_path, 'r') as f1:
            reader = csv.reader(f1, delimiter=',')
            for i, line in enumerate(reader):  # f1.readlines()[1:]:
                if i > 0:
                    if line[3] not in clusters.keys():
                        clusters[line[3]] = []
                    clusters[line[3]].append((line[6], line[0]))  # classname, cluster#
        # print(clusters)
        f1.close()
        array = [str(x) for x in range(numclus - 1)]
        array.append("-1")

        treeprep = dict()
        for filename, val in clusters.items():
            arr = [0] * numclus
            for fam, clus in val:
                ind = array.index(clus)
                arr[ind] = 1
            # print(filename, )
            mas = ''.join([str(x) for x in arr[:-1]])
            famname = fam
            if mas not in treeprep.keys():
                treeprep[mas] = dict()
            if famname not in treeprep[mas].keys():
                treeprep[mas][famname] = set()
            treeprep[mas][famname].add(str(filename))

        f2 = open(path_to_dag_results + 'mas-details' + addition + '.csv', 'w')
        for k, v in treeprep.items():
            for kv, vv in v.items():
                f2.write(str(k) + ';' + str(kv) + ';' + str(len(vv)) + '\n')
        f2.close()

        with open(path_to_dag_results + 'mas-details' + addition + '.csv', 'rU') as f3:
            csv_reader = csv.reader(f3, delimiter=';')

            graph = {}

            names = {}
            for line in csv_reader:
                graph[line[0]] = set()
                if line[0] not in names.keys():
                    names[line[0]] = []
                names[line[0]].append(line[1] + "(" + line[2] + ")")

            zeros = ''.join(['0'] * (numclus - 1))
            if zeros not in graph.keys():
                graph[zeros] = set()

            ulist = graph.keys()
            covered = set()
            next = deque()

            specials = []

            next.append(zeros)

            while (len(next) > 0):
                l1 = next.popleft()
                covered.add(l1)
                for l2 in ulist:
                    if l2 not in covered and self.difference(l1, l2) == 1:
                        graph[l1].add(l2)

                        if l2 not in next:
                            next.append(l2)

            val = set()
            for v in graph.values():
                val.update(v)

            notmain = [x for x in ulist if x not in val]
            notmain.remove(zeros)
            nums = [sum([int(y) for y in x]) for x in notmain]
            notmain = [x for _, x in sorted(zip(nums, notmain))]

            specials = notmain

            extras = set()

            for nm in notmain:
                comp = set()
                comp.update(val)
                comp.update(extras)

                mindist = 1000
                minli1, minli2 = None, None
                for l in comp:
                    if nm != l:
                        diff = self.difference(nm, l)
                        if diff < mindist:
                            mindist = diff
                            minli = l

                diffbase = self.difference(nm, zeros)
                if diffbase <= mindist:
                    mindist = diffbase
                    minli = zeros

                num1 = sum([int(s) for s in nm])
                num2 = sum([int(s) for s in minli])
                if num1 < num2:
                    graph[nm].add(minli)
                else:
                    graph[minli].add(nm)

                extras.add(nm)

            val = set()
            for v in graph.values():
                val.update(v)
                f2 = open(path_to_dag_results + 'relation-tree' + addition + '.dot', 'w')
                f2.write("digraph dag {\n")
                f2.write("rankdir=LR;\n")
                num = 0
                for idx, li in names.items():
                    text = ''
                    name = str(idx) + '\n'

                    for l in li:
                        name += l + ',\n'
                    if idx not in specials:
                        text = str(idx) + " [label=\"" + name + "\" , shape=box;]"
                    else:  # treat in a special way. For now, leaving intact
                        text = str(idx) + " [shape=box label=\"" + name + "\"]"
                    f2.write(text)
                    f2.write('\n')
                for k, v in graph.items():
                    for vi in v:
                        f2.write(str(k) + "->" + str(vi))
                        f2.write('\n')
                f2.write("}")
                f2.close()
            # Rendering DAG

            try:
                filename = path_to_dag_results + 'relation-tree' + addition + '.dot'
                # src = Source(source=test)
                # new_name = self.path_to_store + "DAG" + addition + '.png'
                # src.render(new_name, view=True)

                render('dot', 'png', filename)
            except:
                print('Rendering DAG')
                # os.system('dot -Tpng relation-tree' + addition + '.dot -o DAG' + addition + '.png')
                # print('Done')

        #############################
        # Original Dataset Analysis #
        #############################

        print("Analyzing Original Dataset")

        original_dataset_analysis = self.path_to_store + "/original_dataset_analysis/"
        os.mkdir(original_dataset_analysis)

        combined_summary_path = original_dataset_analysis + "/combined_summary/"
        os.mkdir(combined_summary_path)
        length_summary_path = original_dataset_analysis + "/length_summary/"
        os.mkdir(length_summary_path)
        ratios_path = original_dataset_analysis + "/ratios/"
        os.mkdir(ratios_path)

        combined_csv_path = combined_summary_path + "/combined_summary.csv"

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

        total_ratio_path = ratios_path + "/" + addition + "_total_ratio.csv"
        relative_ratio_path = ratios_path + "/" + addition + "_relative_ratio.csv"

        # summary creation

        csv_files = glob.glob(self.path_to_folder + "/*.csv")
        df_list = []
        for csv_file_path in csv_files:
            temp_df = pd.read_csv(csv_file_path)
            df_list.append(temp_df)

        combined_summary_df = df_list.pop()
        loop_length = len(df_list)
        for to_add_df in range(loop_length):
            combined_summary_df = combined_summary_df.append(df_list.pop())

        combined_summary_df.to_csv(index=False, path_or_buf=combined_csv_path)

        # length analysis

        total_amount_connections = len(combined_summary_df.index)

        dl_average_length_df = combined_summary_df.groupby("detailed_label")[
            "connection_length"].mean().to_frame().reset_index()
        dl_average_length_df = dl_average_length_df.rename(columns={"connection_length": "avg_connection_length"})
        dl_average_length_df["avg_connection_length"] = dl_average_length_df["avg_connection_length"].apply(
            lambda x: round(x, 2))
        dl_con_count_df = combined_summary_df.groupby("detailed_label")["connection_length"].count().to_frame().reset_index()
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

        name_average_length_df = combined_summary_df.groupby("name")["connection_length"].mean().to_frame().reset_index()
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
        application_category_name_info_df = application_category_name_info_df.sort_values(by="connection_count", ascending=False)
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

        # ratio analysis

        total_detailed_label_list = pd.read_csv(self.path_to_detailed_label_folder)["detailed_label"].tolist()
        total_detailed_label_list.sort()

        combined_summary_df["detailed_label"].str.lower()
        combined_summary_df["detailed_label"] = combined_summary_df['detailed_label'].replace(["Unknown", "-"], 'Benign')

        detailed_label_df = combined_summary_df.groupby("scenario")["detailed_label"].value_counts().to_frame()
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

        relative_ratio_df = detailed_label_pt

        for detailed_label in total_detailed_label_list:
            if relative_ratio_df[detailed_label].sum() != 0:
                relative_ratio_df[detailed_label] = relative_ratio_df[detailed_label].apply(lambda x: (x / (relative_ratio_df[detailed_label].sum())))

        relative_ratio_df = relative_ratio_df.reindex(columns=column_order_list)
        relative_ratio_df = relative_ratio_df.sort_values(by="scenario")

        relative_ratio_df.to_csv(relative_ratio_path, index=False)



        ###################
        # Cluster Summary #
        ###################

        print("Creating cluster summary file")

        summary_csv_df = pd.read_csv(summary_csv_file_path)

        cluster_summary_path = path_to_summaries + "cluster_summary" + addition + '.csv'

        total_number_connections = len(summary_csv_df.index)
        total_number_packets = total_number_connections * self.window_size

        cluster_numbers = sorted(summary_csv_df["clusnum"].unique().tolist())
        cluster_numbers = list(map(lambda x: str(x), cluster_numbers))

        # clustering_error_list_df = []
        # clustering_error_list = []
        #
        # for cluster_number in cluster_numbers:
        #
        #     if cluster_number != '-1':
        #         if cluster_number in error_packets_per_cluster:
        #             error_packets = len(error_packets_per_cluster[cluster_number])
        #             correct_packets = len(correct_packets_per_cluster[cluster_number])
        #             per_cluster_error = error_packets / (correct_packets + error_packets)
        #
        #         else:
        #             per_cluster_error = 0
        #
        #         clustering_error_list.append(per_cluster_error)
        #         clustering_error_list_df.append(per_cluster_error)
        #
        # clustering_error_list_df.insert(0, "nan")

        clustering_error_list_df = []
        for cluster_number in cluster_numbers:
            clustering_error_list_df.append("na")

        packets_per_cluster_list = summary_csv_df.groupby("clusnum")["connection_length"].sum().tolist()

        connections_per_cluster_list = summary_csv_df.groupby("clusnum")["connection_length"].count().tolist()

        avg_cluster_probability_list = summary_csv_df.groupby("clusnum")["probability"].mean().tolist()

        per_cluster_label_count = summary_csv_df.groupby("clusnum")["label"].value_counts(normalize=True)
        max_label_per_cluster = per_cluster_label_count.groupby("clusnum").idxmax().to_frame().reset_index()
        max_label_per_cluster["label"] = max_label_per_cluster["label"].apply(lambda x: x[1])

        max_label_percentage_per_cluster = per_cluster_label_count.groupby("clusnum").max().to_frame().reset_index()
        max_label_percentage_per_cluster = max_label_percentage_per_cluster.rename(columns={"label": "percentage"})
        label_merged_df_1 = max_label_per_cluster.merge(right=max_label_percentage_per_cluster, on="clusnum")
        avg_label_cluster_purity_list = label_merged_df_1["percentage"].tolist()

        per_cluster_detailed_label_count = summary_csv_df.groupby("clusnum")["detailed_label"].value_counts(
            normalize=True)
        max_detailed_label_per_cluster = per_cluster_detailed_label_count.groupby(
            "clusnum").idxmax().to_frame().reset_index()
        max_detailed_label_per_cluster["detailed_label"] = max_detailed_label_per_cluster["detailed_label"].apply(
            lambda x: x[1])

        max_detailed_label_percentage_per_cluster = per_cluster_detailed_label_count.groupby(
            "clusnum").max().to_frame().reset_index()
        max_detailed_label_percentage_per_cluster = max_detailed_label_percentage_per_cluster.rename(
            columns={"detailed_label": "percentage"})
        detailed_label_merged_df_1 = max_detailed_label_per_cluster.merge(
            right=max_detailed_label_percentage_per_cluster, on="clusnum")
        avg_detailed_label_cluster_purity_list = detailed_label_merged_df_1["percentage"].tolist()

        per_cluster_application_name_count = summary_csv_df.groupby("clusnum")["application_name"].value_counts(
            normalize=True)
        max_cluster_application_name_per_cluster = per_cluster_application_name_count.groupby(
            "clusnum").idxmax().to_frame().reset_index()
        max_cluster_application_name_per_cluster["application_name"] = max_cluster_application_name_per_cluster[
            "application_name"].apply(lambda x: x[1])

        max_cluster_application_name_percentage_per_cluster = per_cluster_application_name_count.groupby(
            "clusnum").max().to_frame().reset_index()
        max_cluster_application_name_percentage_per_cluster = max_cluster_application_name_percentage_per_cluster.rename(
            columns={"application_name": "percentage"})
        application_name_merged_df_1 = max_cluster_application_name_per_cluster.merge(
            right=max_cluster_application_name_percentage_per_cluster, on="clusnum")
        avg_application_name_cluster_purity_list = application_name_merged_df_1["percentage"].tolist()

        per_cluster_application_category_name_count = summary_csv_df.groupby("clusnum")[
            "application_category_name"].value_counts(normalize=True)
        max_cluster_application_category_name_per_cluster = per_cluster_application_category_name_count.groupby(
            "clusnum").idxmax().to_frame().reset_index()
        max_cluster_application_category_name_per_cluster["application_category_name"] = \
        max_cluster_application_category_name_per_cluster["application_category_name"].apply(lambda x: x[1])

        max_cluster_application_category_name_percentage_per_cluster = per_cluster_application_category_name_count.groupby(
            "clusnum").max().to_frame().reset_index()
        max_cluster_application_category_name_percentage_per_cluster = max_cluster_application_category_name_percentage_per_cluster.rename(
            columns={"application_category_name": "percentage"})
        application_category_name_merged_df_1 = max_cluster_application_category_name_per_cluster.merge(
            right=max_cluster_application_category_name_percentage_per_cluster, on="clusnum")
        avg_application_category_name_cluster_purity_list = application_category_name_merged_df_1["percentage"].tolist()

        # application_category_name_per_cluster = summary_csv_df.groupby("clusnum")["application_category_name"].count().to_frame().reset_index()
        # application_category_name_per_cluster = application_category_name_per_cluster.rename(columns={"application_category_name": "packet_count"})
        # application_category_name_merged_df_2 = application_category_name_merged_df_1.merge(right=application_category_name_per_cluster, on="clusnum")
        # application_category_name_merged_df_2["av_application_category_name_cluster_purity"] = \
        #     application_category_name_merged_df_2["percentage"] * application_category_name_merged_df_2["packet_count"]
        # avg_application_category_name_cluster_purity_list = application_category_name_merged_df_2["av_application_category_name_cluster_purity"].tolist()

        #avg_cluster_error

        per_cluster_name_count = summary_csv_df.groupby("clusnum")["name"].value_counts(normalize=True)
        max_name_per_cluster = per_cluster_name_count.groupby("clusnum").idxmax().to_frame().reset_index()
        max_name_per_cluster["label"] = max_name_per_cluster["name"].apply(lambda x: x[1])

        max_name_percentage_per_cluster = per_cluster_name_count.groupby("clusnum").max().to_frame().reset_index()
        max_name_percentage_per_cluster = max_name_percentage_per_cluster.rename(columns={"name": "percentage"})
        name_merged_df_1 = max_name_per_cluster.merge(right=max_name_percentage_per_cluster, on="clusnum")
        avg_name_purity_list = name_merged_df_1["percentage"].tolist()

        data = {"cluster": cluster_numbers,
                "clustering_error": clustering_error_list_df,
                "num_packets": packets_per_cluster_list,
                "num_connections": connections_per_cluster_list,
                "avg_cluster_probability": avg_cluster_probability_list,
                "avg_label_purity": avg_label_cluster_purity_list,
                "avg_detailed_label_purity": avg_detailed_label_cluster_purity_list,
                "avg_application_name_purity": avg_application_name_cluster_purity_list,
                "avg_application_category_name_purity": avg_application_category_name_cluster_purity_list,
                "avg_name_purity": avg_name_purity_list}

        cluster_summary_df = pd.DataFrame(data)
        cluster_summary_df.to_csv(cluster_summary_path, index=False)

        ###################
        # Overall Summary #
        ###################

        print("Creating overall summary file")

        overall_summary_path = path_to_summaries + "overall_summary" + addition + '.csv'

        time_for_processing = round(end_time - start_time, 2)
        validity_index = round(validity_index, 3)

        number_of_clusters = len(summary_csv_df["clusnum"].unique())
        avg_size_of_cluster = int(summary_csv_df.groupby("clusnum")["label"].count().mean())
        if number_of_clusters > 1:
            std_size_of_cluster = round(summary_csv_df.groupby("clusnum")["label"].count().std(), 2)
        else:
            std_size_of_cluster = "nan"

        number_of_connections_in_noise_cluster = summary_csv_df[summary_csv_df["clusnum"] == -1]["clusnum"].count()
        noise_percentage = round((number_of_connections_in_noise_cluster / total_number_connections) * 100, 3)

        percentage_detailed_labels_in_noise_cluster = round(((summary_csv_df[
                                                                  (summary_csv_df["detailed_label"] != "-") & (
                                                                          summary_csv_df["clusnum"] == -1)][
                                                                  "clusnum"].count()) / (
                                                                 summary_csv_df[
                                                                     summary_csv_df["detailed_label"] != "-"][
                                                                     "clusnum"].count())) * 100, 3)

        avg_overall_label_purity = mean(avg_label_cluster_purity_list)
        avg_overall_detailed_label_purity = mean(avg_detailed_label_cluster_purity_list)
        avg_overall_application_name_purity = mean(avg_application_name_cluster_purity_list)
        avg_overall_application_category_name_purity = mean(avg_application_category_name_cluster_purity_list)
        avg_overall_name_purity = mean(avg_name_purity_list)

        labels_present = summary_csv_df["label"].unique()
        avg_label_separation_list = []
        avg_label_separation_list_df = []

        for label in labels_present:
            label_count_per_cluster = \
                summary_csv_df[summary_csv_df["label"] == label].groupby("clusnum")[
                    "label"].count().to_frame().reset_index()
            label_count_per_cluster_as_tuple = list(
                label_count_per_cluster.itertuples(index=False, name=None))

            max_value = 0
            total_count = 0
            for clusname, count_labels in label_count_per_cluster_as_tuple:
                if count_labels > max_value:
                    max_value = count_labels
                total_count = total_count + count_labels
            separation = max_value / total_count
            avg_label_separation_list_df.append((separation, total_count, label))
            avg_label_separation_list.append(separation)

        avg_label_cohesion = round(mean(avg_label_separation_list), 3)

        detailed_labels_present = summary_csv_df["detailed_label"].unique()
        avg_detailed_label_separation_list = []
        avg_detailed_label_separation_list_df = []

        for detailed_label in detailed_labels_present:
            detailled_label_count_per_cluster = \
                summary_csv_df[summary_csv_df["detailed_label"] == detailed_label].groupby("clusnum")[
                    "detailed_label"].count().to_frame().reset_index()
            detailled_label_count_per_cluster_as_tuple = list(
                detailled_label_count_per_cluster.itertuples(index=False, name=None))

            max_value = 0
            total_count = 0
            for clusname, count_detailed_labels in detailled_label_count_per_cluster_as_tuple:
                if count_detailed_labels > max_value:
                    max_value = count_detailed_labels
                total_count = total_count + count_detailed_labels
            separation = max_value / total_count
            avg_detailed_label_separation_list_df.append((separation, total_count, detailed_label))
            avg_detailed_label_separation_list.append(separation)

        avg_detailed_label_cohesion = round(mean(avg_detailed_label_separation_list), 3)

        application_name_present = summary_csv_df["application_name"].unique()
        avg_application_name_separation_list = []
        avg_application_name_separation_list_df = []

        for application_name in application_name_present:
            application_name_count_per_cluster = \
                summary_csv_df[summary_csv_df["application_name"] == application_name].groupby("clusnum")[
                    "application_name"].count().to_frame().reset_index()
            application_name_count_per_cluster_as_tuple = list(
                application_name_count_per_cluster.itertuples(index=False, name=None))

            max_value = 0
            total_count = 0
            for clusname, count_application_name in application_name_count_per_cluster_as_tuple:
                if count_application_name > max_value:
                    max_value = count_application_name
                total_count = total_count + count_application_name
            separation = max_value / total_count
            avg_application_name_separation_list_df.append((separation, total_count, application_name))
            avg_application_name_separation_list.append(separation)

        avg_application_name_cohesion = round(mean(avg_application_name_separation_list), 3)

        application_category_name_present = summary_csv_df["application_category_name"].unique()
        avg_application_category_name_separation_list = []
        avg_application_category_name_separation_list_df = []

        for application_category_name in application_category_name_present:
            application_category_name_count_per_cluster = \
                summary_csv_df[summary_csv_df["application_category_name"] == application_category_name].groupby(
                    "clusnum")[
                    "application_category_name"].count().to_frame().reset_index()
            application_category_name_count_per_cluster_as_tuple = list(
                application_category_name_count_per_cluster.itertuples(index=False, name=None))

            max_value = 0
            total_count = 0
            for clusname, count_application_category_name in application_category_name_count_per_cluster_as_tuple:
                if count_application_category_name > max_value:
                    max_value = count_application_category_name
                total_count = total_count + count_application_category_name
            separation = max_value / total_count
            avg_application_category_name_separation_list_df.append(
                (separation, total_count, application_category_name))
            avg_application_category_name_separation_list.append(separation)

        avg_application_category_name_cohesion = round(mean(avg_application_category_name_separation_list), 3)

        name_present = summary_csv_df["name"].unique()
        avg_name_separation_list = []
        avg_name_separation_list_df = []

        for name in name_present:
            name_count_per_cluster = \
                summary_csv_df[summary_csv_df["name"] == name].groupby("clusnum")[
                    "name"].count().to_frame().reset_index()
            name_count_per_cluster_as_tuple = list(
                name_count_per_cluster.itertuples(index=False, name=None))

            max_value = 0
            total_count = 0
            for clusname, count_name in name_count_per_cluster_as_tuple:
                if count_name > max_value:
                    max_value = count_name
                total_count = total_count + count_name
            separation = max_value / total_count
            avg_name_separation_list_df.append((separation, total_count, count_name))
            avg_name_separation_list.append(separation)

        avg_name_cohesion = round(mean(avg_name_separation_list), 3)
        probablity_no_noise = summary_csv_df[summary_csv_df["clusnum"] != -1]

        avg_cluster_probability = round(probablity_no_noise["probability"].mean(), 3)

        # if len(clustering_error_list) > 1:
        #     avg_clustering_error = round(mean(clustering_error_list), 3)
        # else:
        #     avg_clustering_error = "nan"

        avg_clustering_error = "nan"

        data_overall = {"total_time_processing": time_for_processing,
                        "validity_index": validity_index,
                        "shilouette_score": silhouette_score,
                        "total_number_connections": total_number_connections,
                        "total_number_packets": total_number_packets,
                        "total_number_clusters": number_of_clusters,
                        "avg_cluster_size": avg_size_of_cluster,
                        "std_cluster_size": std_size_of_cluster,
                        "noise_percentage": noise_percentage,

                        "avg_label_cohesion": avg_label_cohesion,
                        "avg_detailed_label_cohesion": avg_detailed_label_cohesion,
                        "avg_application_name_cohesion": avg_application_name_cohesion,
                        "avg_application_category_name_cohesion": avg_application_category_name_cohesion,
                        "avg_name_cohesion": avg_name_cohesion,

                        "avg_label_purity": avg_overall_label_purity,
                        "avg_detailed_label_purity": avg_overall_detailed_label_purity,
                        "avg_application_name_purity": avg_overall_application_name_purity,
                        "avg_application_category_name_purity": avg_overall_application_category_name_purity,
                        "avg_name_purity": avg_overall_name_purity,

                        "avg_cluster_probability": avg_cluster_probability,

                        "avg_clustering_error": avg_clustering_error}

        summary_overall_df = pd.DataFrame(data_overall, index=[0])
        summary_overall_df.to_csv(overall_summary_path, index=False)

        #####################
        # shortened summary #
        #####################

        print("Creating shortened summary")

        shortened_summary_path = path_to_summaries + "shortened_summary" + addition + '.csv'

        cohesion_score = 0.35 * avg_label_cohesion + 0.45 * avg_detailed_label_cohesion + 0.05 * avg_application_name_cohesion + 0.05 * avg_application_category_name_cohesion + 0.1 * avg_name_cohesion
        purity_score = 0.35 * avg_overall_label_purity + 0.45 * avg_overall_detailed_label_purity + 0.05 * avg_overall_application_name_purity + 0.05 * avg_overall_application_category_name_purity + 0.1 * avg_overall_name_purity

        data_shortened = {
                "validity_index": validity_index,
                "shilouette_score": silhouette_score,

                "noise_percentage": noise_percentage,
                "number_clusters": number_of_clusters,

                "cohesion_score" : cohesion_score,
                "purity_score" : purity_score,

                "avg_cluster_probability": avg_cluster_probability,
                "avg_clustering_error": avg_clustering_error}

        shortened_summary = pd.DataFrame(data_shortened, index=[0])
        shortened_summary.to_csv(shortened_summary_path, index=False)

        ###################
        # Window Analysis #
        ###################

        print("Analyzing window info")

        window_info_path = path_to_summaries + "window_info" + addition + '.csv'

        summary_csv_df = pd.read_csv(summary_csv_file_path)

        summary_csv_df["combined_address"] = summary_csv_df["scenario"] + "_" + summary_csv_df["file"] + "->" + summary_csv_df["src_ip"] + "->" + summary_csv_df["dst_ip"]


        per_connection_cluster_count = summary_csv_df.groupby("combined_address")["clusnum"].value_counts(
            normalize=True)
        max_cluster_per_connection = per_connection_cluster_count.groupby(
            "combined_address").idxmax().to_frame().reset_index()
        max_cluster_per_connection["clusnum"] = max_cluster_per_connection["clusnum"].apply(
            lambda x: x[1])

        max_cluster_percentage_per_connection = per_connection_cluster_count.groupby(
            "combined_address").max().to_frame().reset_index()
        max_cluster_percentage_per_connection = max_cluster_percentage_per_connection.rename(
            columns={"clusnum": "percentage"})
        connection_cluster_merged_df_1 = max_cluster_per_connection.merge(
            right=max_cluster_percentage_per_connection, on="combined_address")
        avg_window_cohesion_list = connection_cluster_merged_df_1["percentage"].tolist()

        avg_window_cohesion = round(mean(avg_window_cohesion_list), 3)

        data_window = {
            "avg_window_cohesion" : avg_window_cohesion
        }

        window_summary = pd.DataFrame(data_window, index=[0])
        window_summary.to_csv(window_info_path, index=False)

        ###############################
        # Performance Matrix Creation #
        ###############################

        print("Creating performance matrices")

        performance_matrix_folder = graphs_folder + "/performance_matrices"
        os.mkdir(performance_matrix_folder)

        label_performance_matrix = performance_matrix_folder + "/label_performance_matrix" + addition + ".csv"
        label_performance_matrix_table = performance_matrix_folder + "/label_performance_matrix" + addition + ".png"

        detailed_label_performance_matrix = performance_matrix_folder + "/detailed_label_performance_matrix" + addition + ".csv"
        detailed_label_performance_matrix_table = performance_matrix_folder + "/detailed_label_performance_matrix" + addition + ".png"

        label_df = summary_csv_df.groupby("clusnum")["label"].value_counts().to_frame()
        label_df = label_df.rename(columns={"label": "count"})
        label_df = label_df.reset_index()

        labels = label_df["label"].unique()

        for label in labels:
            lower_label = label.lower()
            label_df[lower_label] = np.where(label_df["label"] == label, label_df["count"], 0)

        label_df = label_df.drop(["count", "label"], axis=1)
        label_df = label_df.rename(columns={"clusnum": "Cluster"})

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

        improved_label_df = pd.DataFrame(data, columns=columns)

        detailed_label_df = summary_csv_df.groupby("clusnum")["detailed_label"].value_counts().to_frame()
        detailed_label_df = detailed_label_df.rename(columns={"detailed_label": "count"})
        detailed_label_df = detailed_label_df.reset_index()

        detailed_labels = detailed_label_df["detailed_label"].unique()

        for detail_label in detailed_labels:
            lower_detail_label = detail_label.lower()
            detailed_label_df[lower_detail_label] = np.where(detailed_label_df["detailed_label"] == detail_label,
                                                             detailed_label_df["count"], 0)

        detailed_label_df = detailed_label_df.drop(["count", "detailed_label"], axis=1)
        detailed_label_df = detailed_label_df.rename(columns={"clusnum": "Cluster"})

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

        improved_label_df.to_csv(label_performance_matrix, index=False)

        fig, ax = plt.subplots()
        fig.patch.set_visible(False)
        ax.axis('off')
        ax.axis('tight')
        table = ax.table(cellText=improved_label_df.values, colLabels=improved_label_df.columns, loc='center',
                         cellLoc='center')
        table.auto_set_column_width(col=list(range(len(improved_label_df.columns))))
        for (row, col), cell in table.get_celld().items():
            if (row == 0):
                cell.set_text_props(fontproperties=FontProperties(weight='bold'))
        fig.tight_layout()
        plt.savefig(label_performance_matrix_table)
        plt.close()
        plt.clf()

        improved_detail_label_df.to_csv(detailed_label_performance_matrix, index=False)

        reduced_column_size_name = [x[0:10] for x in improved_detail_label_df.columns.tolist()]

        fig, ax = plt.subplots()
        fig.patch.set_visible(False)
        ax.axis('off')
        ax.axis('tight')
        table2 = ax.table(cellText=improved_detail_label_df.values, colLabels=reduced_column_size_name, loc='center',
                          cellLoc='center')
        table2.auto_set_column_width(col=list(range(len(reduced_column_size_name))))
        for (row, col), cell in table2.get_celld().items():
            if (row == 0):
                cell.set_text_props(fontproperties=FontProperties(weight='bold'))
        fig.tight_layout()
        plt.savefig(detailed_label_performance_matrix_table, dpi=1200, bbox_inches='tight')
        plt.close()
        plt.clf()

        ##################
        # Graph Creation #
        #################

        print("Creating graphs")

        cluster_graphs_path = graphs_folder + "/cluster_graphs/"
        os.mkdir(cluster_graphs_path)

        summary_csv_df = pd.read_csv(summary_csv_file_path)

        application_name_graph = cluster_graphs_path + "/application_name_graph" + addition + ".png"
        path_to_application_name_legend_storage = cluster_graphs_path + "/application_name_legend" + addition + ".png"
        path_to_application_name_combined = cluster_graphs_path + "/application_name_combined" + addition + ".png"

        application_category_name_graph = cluster_graphs_path + "/application_category_name_graph" + addition + ".png"
        path_to_application_category_name_legend_storage = cluster_graphs_path + "/application_category_name_legend" + addition + ".png"
        path_to_application_category_name_combined = cluster_graphs_path + "/application_category_name_combined" + addition + ".png"

        label_distribution_graph = cluster_graphs_path + "/label_graph" + addition + ".png"
        path_to_label_legend_storage = cluster_graphs_path + "/label_legend" + addition + ".png"
        path_to_label_combined = cluster_graphs_path + "/label_combined" + addition + ".png"

        detailed_label_distribution_graph = cluster_graphs_path + "/detailed_label_graph" + addition + ".png"
        path_to_detailed_label_legend_storage = cluster_graphs_path + "/detailed_label_legend" + addition + ".png"
        path_to_detailed_label_combined = cluster_graphs_path + "/detailed_label_combined" + addition + ".png"

        name_distribution_graph = cluster_graphs_path + "/name_graph" + addition + ".png"
        path_to_name_legend_storage = cluster_graphs_path + "/name_legend" + addition + ".png"
        path_to_name_combined = cluster_graphs_path + "/name_combined" + addition + ".png"

        ####################
        # application name #
        ####################

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
        cmap = cm.tab20c(np.linspace(0, 1, len(unique_application_category_names)))

        for index, color in enumerate(cmap):
            application_name = unique_application_category_names.pop()
            colors[application_name] = color

        for index, cluster in enumerate(clusters):
            cluster_df = overall_detailed_label_df[overall_detailed_label_df["clusnum"] == cluster][
                ["application_name", "count"]]

            cluster_df["application_name"] = np.where(cluster_df["count"] <= 4, "Other",
                                                      cluster_df.application_name)

            cluster_df = cluster_df.groupby("application_name")["count"].aggregate(sum).reset_index().sort_values(
                by=["count"])
            cluster_df["relative_count"] = round((cluster_df["count"] / cluster_df["count"].sum()) * 100, 2)

            if len(clusters) == 1:
                patches, texts = ax.pie(cluster_df["count"], labels=cluster_df["relative_count"],
                                        colors=[colors[key] for key in cluster_df["application_name"]])
                new_labels = self.clean_up_labels(texts)
                ax.clear()
                ax.pie(cluster_df["count"], labels=new_labels,
                       colors=[colors[key] for key in cluster_df["application_name"]],
                       labeldistance=1.15, textprops={'fontsize': 8})
                ax.set_title("Cluster " + str(cluster) + " (N=" + str(cluster_df["count"].sum()) + ")")

            elif len(clusters) <= 4:
                patches, texts = ax[index].pie(cluster_df["count"], labels=cluster_df["relative_count"],
                                               colors=[colors[key] for key in
                                                       cluster_df["application_name"]],
                                               labeldistance=1.25)
                new_labels = self.clean_up_labels(texts)
                ax[index].clear()
                ax[index].pie(cluster_df["count"], labels=new_labels,
                              colors=[colors[key] for key in cluster_df["application_name"]],
                              labeldistance=1.15, textprops={'fontsize': 8})
                ax[index].set_title("Cluster " + str(cluster) + " (N=" + str(cluster_df["count"].sum()) + ")")
            else:
                patches, texts = ax[math.floor(index / 4), index % 4].pie(cluster_df["count"],
                                                                          labels=cluster_df["relative_count"],
                                                                          colors=[colors[key] for key in
                                                                                  cluster_df[
                                                                                      "application_name"]],
                                                                          labeldistance=1.25)
                new_labels = self.clean_up_labels(texts)
                ax[math.floor(index / 4), index % 4].clear()
                ax[math.floor(index / 4), index % 4].pie(cluster_df["count"], labels=new_labels,
                                                         colors=[colors[key] for key in
                                                                 cluster_df["application_name"]],
                                                         labeldistance=1.15, textprops={'fontsize': 8})
                ax[math.floor(index / 4), index % 4].set_title(
                    "Cluster " + str(cluster) + " (N=" + str(cluster_df["count"].sum()) + ")")

        if len(clusters) % 4 != 0:
            if len(clusters) > 4:
                for missing_axis in range(4 - len(clusters) % 4, 4):
                    ax[nrows - 1, missing_axis].axis('off')

        markers = [plt.Line2D([0, 0], [0, 0], color=color, marker='o', linestyle='') for color in colors.values()]

        plt.suptitle("Application Name Distribution per Cluster", y=0.985, x=0.5, fontweight='bold')

        fig.tight_layout()
        fig.canvas.draw()
        fig.savefig(application_name_graph, dpi=1200)

        label_list = colors.keys()
        label_list = [x[0:40] for x in label_list]
        legend = plt.legend(handles=markers, labels=label_list, loc=3, framealpha=1, frameon=True,
                            bbox_to_anchor=(2, 0))
        separate_legend = legend.figure
        separate_legend.canvas.draw()
        bbox = legend.get_window_extent()
        bbox = bbox.from_extents(*(bbox.extents + np.array([-4, -4, 4, 4])))
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

        #############################
        # application category name #
        #############################

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
        cmap = cm.gist_rainbow(np.linspace(0, 1, len(unique_application_category_names)))

        for index, color in enumerate(cmap):
            application_name = unique_application_category_names.pop()
            colors[application_name] = color

        for index, cluster in enumerate(clusters):
            cluster_df = overall_detailed_label_df[overall_detailed_label_df["clusnum"] == cluster][
                ["application_category_name", "count"]]

            cluster_df = cluster_df.groupby("application_category_name")["count"].aggregate(
                sum).reset_index().sort_values(
                by=["count"])
            cluster_df["relative_count"] = round((cluster_df["count"] / cluster_df["count"].sum()) * 100, 2)

            if len(clusters) == 1:
                patches, texts = ax.pie(cluster_df["count"], labels=cluster_df["relative_count"],
                                        colors=[colors[key] for key in cluster_df["application_category_name"]])
                new_labels = self.clean_up_labels(texts)
                ax.clear()
                ax.pie(cluster_df["count"], labels=new_labels,
                       colors=[colors[key] for key in cluster_df["application_category_name"]],
                       labeldistance=1.15, textprops={'fontsize': 8})
                ax.set_title("Cluster " + str(cluster) + " (N=" + str(cluster_df["count"].sum()) + ")")

            elif len(clusters) <= 4:
                patches, texts = ax[index].pie(cluster_df["count"], labels=cluster_df["relative_count"],
                                               colors=[colors[key] for key in
                                                       cluster_df["application_category_name"]],
                                               labeldistance=1.25)
                new_labels = self.clean_up_labels(texts)
                ax[index].clear()
                ax[index].pie(cluster_df["count"], labels=new_labels,
                              colors=[colors[key] for key in cluster_df["application_category_name"]],
                              labeldistance=1.15, textprops={'fontsize': 8})
                ax[index].set_title("Cluster " + str(cluster) + " (N=" + str(cluster_df["count"].sum()) + ")")

            else:
                patches, texts = ax[math.floor(index / 4), index % 4].pie(cluster_df["count"],
                                                                          labels=cluster_df["relative_count"],
                                                                          colors=[colors[key] for key in
                                                                                  cluster_df[
                                                                                      "application_category_name"]],
                                                                          labeldistance=1.25)
                new_labels = self.clean_up_labels(texts)
                ax[math.floor(index / 4), index % 4].clear()
                ax[math.floor(index / 4), index % 4].pie(cluster_df["count"], labels=new_labels,
                                                         colors=[colors[key] for key in
                                                                 cluster_df["application_category_name"]],
                                                         labeldistance=1.15, textprops={'fontsize': 8})
                ax[math.floor(index / 4), index % 4].set_title(
                    "Cluster " + str(cluster) + " (N=" + str(cluster_df["count"].sum()) + ")")

            if len(clusters) % 4 != 0:
                if len(clusters) > 4:
                    for missing_axis in range(4 - len(clusters) % 4, 4):
                        ax[nrows - 1, missing_axis].axis('off')

        markers = [plt.Line2D([0, 0], [0, 0], color=color, marker='o', linestyle='') for color in colors.values()]
        fig.subplots_adjust(bottom=0.25)

        plt.suptitle("Application Category Name Distribution per Cluster", y=0.985, x=0.5, fontweight='bold')

        fig.tight_layout()
        fig.canvas.draw()
        fig.savefig(application_category_name_graph, dpi=1200)

        label_list = colors.keys()
        label_list = [x[0:40] for x in label_list]

        legend = plt.legend(handles=markers, labels=label_list, loc=3, framealpha=1, frameon=True,
                            bbox_to_anchor=(2, 0))
        separate_legend = legend.figure
        separate_legend.canvas.draw()
        bbox = legend.get_window_extent()
        bbox = bbox.from_extents(*(bbox.extents + np.array([-4, -4, 4, 4])))
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

        #########
        # label #
        #########

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
                patches, texts = ax.pie(cluster_df["count"], labels=cluster_df["relative_count"],
                                        colors=[colors[key] for key in cluster_df["label"]])
                new_labels = self.clean_up_labels(texts)
                ax.clear()
                ax.pie(cluster_df["count"], labels=new_labels,
                       colors=[colors[key] for key in cluster_df["label"]],
                       labeldistance=1.15, textprops={'fontsize': 8})
                ax.set_title("Cluster " + str(cluster) + " (N=" + str(cluster_df["count"].sum()) + ")")

            elif len(clusters) <= 4:
                patches, texts = ax[index].pie(cluster_df["count"], labels=cluster_df["relative_count"],
                                               colors=[colors[key] for key in
                                                       cluster_df["label"]],
                                               labeldistance=1.25)
                new_labels = self.clean_up_labels(texts)
                ax[index].clear()
                ax[index].pie(cluster_df["count"], labels=new_labels,
                              colors=[colors[key] for key in cluster_df["label"]],
                              labeldistance=1.15, textprops={'fontsize': 8})
                ax[index].set_title("Cluster " + str(cluster) + " (N=" + str(cluster_df["count"].sum()) + ")")
            else:
                patches, texts = ax[math.floor(index / 4), index % 4].pie(cluster_df["count"],
                                                                          labels=cluster_df["relative_count"],
                                                                          colors=[colors[key] for key in
                                                                                  cluster_df[
                                                                                      "label"]],
                                                                          labeldistance=1.25)
                new_labels = self.clean_up_labels(texts)
                ax[math.floor(index / 4), index % 4].clear()
                ax[math.floor(index / 4), index % 4].pie(cluster_df["count"], labels=new_labels,
                                                         colors=[colors[key] for key in
                                                                 cluster_df["label"]],
                                                         labeldistance=1.15, textprops={'fontsize': 8})
                ax[math.floor(index / 4), index % 4].set_title(
                    "Cluster " + str(cluster) + " (N=" + str(cluster_df["count"].sum()) + ")")

            if len(clusters) % 4 != 0:
                if len(clusters) > 4:
                    for missing_axis in range(4 - len(clusters) % 4, 4):
                        ax[nrows - 1, missing_axis].axis('off')

        markers = [plt.Line2D([0, 0], [0, 0], color=color, marker='o', linestyle='') for color in colors.values()]
        fig.subplots_adjust(bottom=0.25)

        plt.suptitle("Label Distribution per Cluster", y=0.985, x=0.5, fontweight='bold')

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

        ##################
        # detailed label #
        ##################

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

            if len(clusters) == 1:
                patches, texts = ax.pie(cluster_df["count"], labels=cluster_df["relative_count"],
                                        colors=[colors[key] for key in cluster_df["detailed_label"]])
                new_labels = self.clean_up_labels(texts)
                ax.clear()
                ax.pie(cluster_df["count"], labels=new_labels,
                       colors=[colors[key] for key in cluster_df["detailed_label"]],
                       labeldistance=1.15, textprops={'fontsize': 8})
                ax.set_title("Cluster " + str(cluster) + " (N=" + str(cluster_df["count"].sum()) + ")")

            elif len(clusters) <= 4:
                patches, texts = ax[index].pie(cluster_df["count"], labels=cluster_df["relative_count"],
                                               colors=[colors[key] for key in
                                                       cluster_df["detailed_label"]],
                                               labeldistance=1.25)
                new_labels = self.clean_up_labels(texts)
                ax[index].clear()
                ax[index].pie(cluster_df["count"], labels=new_labels,
                              colors=[colors[key] for key in cluster_df["detailed_label"]],
                              labeldistance=1.15, textprops={'fontsize': 8})
                ax[index].set_title("Cluster " + str(cluster) + " (N=" + str(cluster_df["count"].sum()) + ")")
            else:
                patches, texts = ax[math.floor(index / 4), index % 4].pie(cluster_df["count"],
                                                                          labels=cluster_df["relative_count"],
                                                                          colors=[colors[key] for key in
                                                                                  cluster_df[
                                                                                      "detailed_label"]],
                                                                          labeldistance=1.25)
                new_labels = self.clean_up_labels(texts)
                ax[math.floor(index / 4), index % 4].clear()
                ax[math.floor(index / 4), index % 4].pie(cluster_df["count"], labels=new_labels,
                                                         colors=[colors[key] for key in
                                                                 cluster_df["detailed_label"]],
                                                         labeldistance=1.15, textprops={'fontsize': 8})
                ax[math.floor(index / 4), index % 4].set_title(
                    "Cluster " + str(cluster) + " (N=" + str(cluster_df["count"].sum()) + ")")

            if len(clusters) % 4 != 0:
                if len(clusters) > 4:
                    for missing_axis in range(4 - len(clusters) % 4, 4):
                        ax[nrows - 1, missing_axis].axis('off')

        markers = [plt.Line2D([0, 0], [0, 0], color=color, marker='o', linestyle='') for color in colors.values()]
        fig.subplots_adjust(bottom=0.25)

        plt.suptitle("Detailed Label Distribution per Cluster", y=0.985, x=0.5, fontweight='bold')

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

        ########
        # name #
        ########

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
        cmap = cm.ocean(np.linspace(0, 1, len(unique_application_category_names)))

        for index, color in enumerate(cmap):
            application_name = unique_application_category_names.pop()
            colors[application_name] = color

        for index, cluster in enumerate(clusters):
            cluster_df = overall_name_df[overall_name_df["clusnum"] == cluster][
                ["name", "count"]]

            cluster_df = cluster_df.groupby("name")["count"].aggregate(sum).reset_index().sort_values(
                by=["count"])
            cluster_df["relative_count"] = round((cluster_df["count"] / cluster_df["count"].sum()) * 100, 2)

            if len(clusters) == 1:
                patches, texts = ax.pie(cluster_df["count"], labels=cluster_df["relative_count"],
                                        colors=[colors[key] for key in cluster_df["name"]])
                new_labels = self.clean_up_labels(texts)
                ax.clear()
                ax.pie(cluster_df["count"], labels=new_labels,
                       colors=[colors[key] for key in cluster_df["name"]],
                       labeldistance=1.15, textprops={'fontsize': 8})
                ax.set_title("Cluster " + str(cluster) + " (N=" + str(cluster_df["count"].sum()) + ")")

            elif len(clusters) <= 4:
                patches, texts = ax[index].pie(cluster_df["count"], labels=cluster_df["relative_count"],
                                               colors=[colors[key] for key in
                                                       cluster_df["name"]],
                                               labeldistance=1.25)
                new_labels = self.clean_up_labels(texts)
                ax[index].clear()
                ax[index].pie(cluster_df["count"], labels=new_labels,
                              colors=[colors[key] for key in cluster_df["name"]],
                              labeldistance=1.15, textprops={'fontsize': 8})
                ax[index].set_title("Cluster " + str(cluster) + " (N=" + str(cluster_df["count"].sum()) + ")")
            else:
                patches, texts = ax[math.floor(index / 4), index % 4].pie(cluster_df["count"],
                                                                          labels=cluster_df["relative_count"],
                                                                          colors=[colors[key] for key in
                                                                                  cluster_df[
                                                                                      "name"]],
                                                                          labeldistance=1.25)
                new_labels = self.clean_up_labels(texts)
                ax[math.floor(index / 4), index % 4].clear()
                ax[math.floor(index / 4), index % 4].pie(cluster_df["count"], labels=new_labels,
                                                         colors=[colors[key] for key in
                                                                 cluster_df["name"]],
                                                         labeldistance=1.15, textprops={'fontsize': 8})
                ax[math.floor(index / 4), index % 4].set_title(
                    "Cluster " + str(cluster) + " (N=" + str(cluster_df["count"].sum()) + ")")

            if len(clusters) % 4 != 0:
                if len(clusters) > 4:
                    for missing_axis in range(4 - len(clusters) % 4, 4):
                        ax[nrows - 1, missing_axis].axis('off')

        markers = [plt.Line2D([0, 0], [0, 0], color=color, marker='o', linestyle='') for color in colors.values()]
        fig.subplots_adjust(bottom=0.25)

        plt.suptitle("Device / Malware Distribution per Cluster", y=0.985, x=0.5, fontweight='bold')

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

        #####################
        # temporal heatmaps #
        #####################

        print("Writing temporal heatmaps")

        heatmap_path = graphs_folder + "/heatmaps/"
        os.mkdir(heatmap_path)

        overall_heatmap_path = heatmap_path + "/overall_heatmaps/"
        os.mkdir(overall_heatmap_path)
        error_heatmap_path = heatmap_path + "/error_heatmaps/"
        os.mkdir(error_heatmap_path)
        correct_heatmap_path = heatmap_path + "/correct_heatmaps/"
        os.mkdir(correct_heatmap_path)

        for sub_folder in [overall_heatmap_path, error_heatmap_path, correct_heatmap_path]:
            bytes_heatmap_path = sub_folder + "/bytes/"
            os.mkdir(bytes_heatmap_path)
            gaps_heatmap_path = sub_folder + "/gaps/"
            os.mkdir(gaps_heatmap_path)
            sport_heatmap_path = sub_folder + "/sport/"
            os.mkdir(sport_heatmap_path)
            dport_heatmap_path = sub_folder + '/dport'
            os.mkdir(dport_heatmap_path)

        actlabels = []
        for a in range(len(values)):  # range(10):
            actlabels.append(mapping[keys[a]])

        clusterinfo = {}
        cluster_info_dic = {}

        seqclufile = summary_csv_file_path
        lines = []
        lines = open(seqclufile).readlines()[1:]

        for line in lines:
            li = line.split(",")  # clusnum,connnum,probability,scenario,file,src_ip,dst_ip,window

            clusnum = li[0]
            has = int(li[1])
            scenario_name = li[3]
            file_name = li[4]
            srcip = li[5]
            dstip = li[6]
            window = li[7]

            name = scenario_name + "_" + file_name + "->" + str(srcip) + "->" + str(dstip) + "->" + str(window)
            # name = str('%12s->%12s' % (srcip, dstip))
            if li[0] not in clusterinfo.keys():
                clusterinfo[li[0]] = []
            clusterinfo[li[0]].append((has, name))
            cluster_info_dic[name] = has

        cluster_error_dic = {}

        error_packets_per_cluster = {}
        correct_packets_per_cluster = {}

        sns.set(font_scale=0.9)
        matplotlib.rcParams.update({'font.size': 10})

        vmax_dic = {}
        vmin_dic = {}

        color_amount_dic = {}
        connection_color_dic = {}

        for names, sname, q in [("Packet sizes", "bytes", 1), ("Interval", "gaps", 0), ("Source Port", "sport", 3),
                                ("Dest. Port", "dport", 4)]:
            for clusnum, cluster in clusterinfo.items():

                cluster.sort(key=lambda tuple: tuple[0])

                items = [int(x[0]) for x in cluster]
                labels = [x[1] for x in cluster]

                acha = [actlabels.index(int(x[0])) for x in cluster]

                blah = [values[a] for a in acha]

                dataf = []

                for b in blah:
                    dataf.append([x[q] for x in b][:self.window_size])

                df = pd.DataFrame(dataf, index=labels)
                df = df.sort_index()

                g = sns.clustermap(df, xticklabels=False, col_cluster=False)  # , vmin= minb, vmax=maxb)
                ind = g.dendrogram_row.reordered_ind
                fig = plt.figure(figsize=(10.0, 9.0))
                plt.suptitle("Overall Exp: " + self.expname + " | Cluster: " + clusnum + " | Feature: " + names)
                ax = fig.add_subplot(111)
                datanew = []
                labelsnew = []
                labels_heatmap = []
                lol = []
                for it in sorted(ind):
                    labelsnew.append(labels[it])
                    labels_heatmap.append(labels[it].split("->", maxsplit=1)[1])
                    lol.append(cluster[[x[1] for x in cluster].index(labels[it])][0])

                acha = [actlabels.index(int(x)) for x in lol]
                blah = [values[a] for a in acha]

                dataf = []

                for b in blah:
                    dataf.append([x[q] for x in b][:self.window_size])
                vmax = max(max(dataf))
                vmin = min(min(dataf))

                if sname not in vmax_dic:
                    vmax_dic[sname] = {}
                vmax_dic[sname][clusnum] = vmax
                if sname not in vmin_dic:
                    vmin_dic[sname] = {}
                vmin_dic[sname][clusnum] = vmin

                df = pd.DataFrame(dataf, index=labels_heatmap)
                df = df.sort_index()

                cmap = cm.get_cmap('rocket_r')
                g = sns.heatmap(df, xticklabels=False, cmap=cmap, vmax=vmax, vmin=vmin)
                norm = Normalize(vmin=vmin, vmax=vmax)
                rgba_values = cmap(norm(dataf)).tolist()

                color_df = pd.DataFrame(rgba_values, index=labelsnew)

                for row in color_df.iterrows():
                    row_color = row[1].values.tolist()
                    row_index = row[0]

                    row_color = ' '.join([str(elem) for elem in row_color])

                    if clusnum not in color_amount_dic:
                        color_amount_dic[clusnum] = {}

                    if sname not in color_amount_dic[clusnum]:
                        color_amount_dic[clusnum][sname] = {}

                    if row_color not in color_amount_dic[clusnum][sname]:
                        color_amount_dic[clusnum][sname][row_color] = 0

                    old_value = color_amount_dic[clusnum][sname][row_color]
                    new_value = old_value + 1
                    color_amount_dic[clusnum][sname][row_color] = new_value

                    if clusnum not in connection_color_dic:
                        connection_color_dic[clusnum] = {}

                    if sname not in connection_color_dic[clusnum]:
                        connection_color_dic[clusnum][sname] = {}

                    connection_color_dic[clusnum][sname][row_index] = row_color

                plt.setp(g.get_yticklabels(), rotation=0)
                plt.subplots_adjust(top=0.92, bottom=0.02, left=0.25, right=1, hspace=0.94)
                plt.savefig(overall_heatmap_path + "/" + sname + "/" + clusnum)

                plt.close()
                plt.clf()

        ################################
        # Clustering Error Preparation #
        ################################

        rightfull_owner_search_dic = {}

        for cluster_name, sname_dic in connection_color_dic.items():
            rightfull_owner_search_dic[cluster_name] = {}

            for sname_name, row_dic in sname_dic.items():
                for row_name, row_color in row_dic.items():
                    amount = color_amount_dic[cluster_name][sname_name][row_color]

                    if row_name not in rightfull_owner_search_dic[cluster_name]:
                        rightfull_owner_search_dic[cluster_name][row_name] = 0

                    old_amount = rightfull_owner_search_dic[cluster_name][row_name]
                    new_amount = old_amount + amount
                    rightfull_owner_search_dic[cluster_name][row_name] = new_amount

        max_amount_dic = {}
        rightfull_owner_dic = {}

        for cluster_name, row_dic in rightfull_owner_search_dic.items():
            max_amount_dic[cluster_name] = 0
            rightfull_owner_dic[cluster_name] = []

            for row_name, amount in row_dic.items():
                if amount > max_amount_dic[cluster_name]:
                    rightfull_owner_dic[cluster_name] = []
                    rightfull_owner_dic[cluster_name].append(row_name)
                    max_amount_dic[cluster_name] = amount
                if amount == max_amount_dic[cluster_name]:
                    rightfull_owner_dic[cluster_name].append(row_name)

        rightfull_color_dic = {}

        sname_list = ["bytes", "gaps", "sport", "dport"]

        for cluster_name, owner_list in rightfull_owner_dic.items():
            rightfull_color_dic[cluster_name] = {}

            for owner_name in owner_list:
                for sname in sname_list:
                    color_owner = connection_color_dic[cluster_name][sname][owner_name]

                    if sname not in rightfull_color_dic[cluster_name]:
                        rightfull_color_dic[cluster_name][sname] = set()

                    rightfull_color_dic[cluster_name][sname].add(color_owner)

        for names, sname, q in [("Packet sizes", "bytes", 1), ("Interval", "gaps", 0), ("Source Port", "sport", 3),
                                ("Dest. Port", "dport", 4)]:
            for clusnum, cluster in clusterinfo.items():

                cluster.sort(key=lambda tuple: tuple[0])

                items = [int(x[0]) for x in cluster]
                labels = [x[1] for x in cluster]

                acha = [actlabels.index(int(x[0])) for x in cluster]

                blah = [values[a] for a in acha]

                dataf = []

                for b in blah:
                    dataf.append([x[q] for x in b][:self.window_size])

                df = pd.DataFrame(dataf, index=labels)
                df = df.sort_index()

                g = sns.clustermap(df, xticklabels=False, col_cluster=False)  # , vmin= minb, vmax=maxb)
                ind = g.dendrogram_row.reordered_ind
                fig = plt.figure(figsize=(10.0, 9.0))
                plt.suptitle("Overall Exp: " + self.expname + " | Cluster: " + clusnum + " | Feature: " + names)
                ax = fig.add_subplot(111)
                datanew = []
                labelsnew = []
                labels_heatmap = []
                lol = []
                for it in sorted(ind):
                    labelsnew.append(labels[it])
                    labels_heatmap.append(labels[it].split("->", maxsplit=1)[1])
                    lol.append(cluster[[x[1] for x in cluster].index(labels[it])][0])

                acha = [actlabels.index(int(x)) for x in lol]
                blah = [values[a] for a in acha]

                dataf = []

                for b in blah:
                    dataf.append([x[q] for x in b][:self.window_size])
                vmax = vmax_dic[sname][clusnum]
                vmin = vmin_dic[sname][clusnum]

                df = pd.DataFrame(dataf, index=labels_heatmap)
                df = df.sort_index()

                cmap = cm.get_cmap('rocket_r')
                g = sns.heatmap(df, xticklabels=False, cmap=cmap, vmax=vmax, vmin=vmin)
                norm = Normalize(vmin=vmin, vmax=vmax)
                rgba_values = cmap(norm(dataf)).tolist()

                color_df = pd.DataFrame(rgba_values, index=labelsnew)

                for row in color_df.iterrows():
                    row_color = row[1].values.tolist()
                    row_index = row[0]
                    error = 0

                    row_color_as_string = ' '.join([str(elem) for elem in row_color])

                    if row_color_as_string in rightfull_color_dic[clusnum][sname]:
                        error = 0
                    else:
                        error = 1

                    if clusnum not in error_packets_per_cluster:
                        error_packets_per_cluster[clusnum] = {}
                    if clusnum not in correct_packets_per_cluster:
                        correct_packets_per_cluster[clusnum] = {}

                    if row_index in error_packets_per_cluster[clusnum]:
                        old_entry = error_packets_per_cluster[clusnum][row_index]
                        new_entry = old_entry + error
                        error_packets_per_cluster[clusnum][row_index] = new_entry

                    elif row_index in correct_packets_per_cluster[clusnum]:
                        old_entry = correct_packets_per_cluster[clusnum][row_index]
                        new_entry = old_entry + error

                        if new_entry > 2:
                            error_packets_per_cluster[clusnum][row_index] = new_entry
                            correct_packets_per_cluster[clusnum].pop(row_index)
                        else:
                            correct_packets_per_cluster[clusnum][row_index] = new_entry
                    else:
                        correct_packets_per_cluster[clusnum][row_index] = error

        ############################
        # Error / Correct Heatmaps #
        ############################

        print("Creating correct and error heatmaps")

        for names, sname, q in [("Packet sizes", "bytes", 1), ("Interval", "gaps", 0), ("Source Port", "sport", 3),
                                ("Dest. Port", "dport", 4)]:
            for clusnum, error_cluster in error_packets_per_cluster.items():

                if len(error_cluster) > 1:

                    cluster = []
                    for name in error_cluster.keys():
                        cluster.append((cluster_info_dic[name], name))

                    cluster.sort(key=lambda tuple: tuple[0])

                    items = [int(x[0]) for x in cluster]
                    labels = [x[1] for x in cluster]

                    acha = [actlabels.index(int(x[0])) for x in cluster]

                    blah = [values[a] for a in acha]

                    dataf = []

                    for b in blah:
                        dataf.append([x[q] for x in b][:self.window_size])

                    df = pd.DataFrame(dataf, index=labels)

                    g = sns.clustermap(df, xticklabels=False, col_cluster=False)  # , vmin= minb, vmax=maxb)
                    ind = g.dendrogram_row.reordered_ind
                    fig = plt.figure(figsize=(10.0, 9.0))
                    plt.suptitle("Error Exp: " + self.expname + " | Cluster: " + clusnum + " | Feature: " + names)
                    ax = fig.add_subplot(111)
                    datanew = []
                    labelsnew = []
                    labels_heatmap = []
                    lol = []
                    for it in sorted(ind):
                        labelsnew.append(labels[it])
                        labels_heatmap.append(labels[it].split("->", maxsplit=1)[1])
                        lol.append(cluster[[x[1] for x in cluster].index(labels[it])][0])

                    acha = [actlabels.index(int(x)) for x in lol]
                    blah = [values[a] for a in acha]

                    dataf = []

                    for b in blah:
                        dataf.append([x[q] for x in b][:self.window_size])
                    vmax = vmax_dic[sname][clusnum]
                    vmin = vmin_dic[sname][clusnum]
                    df = pd.DataFrame(dataf, index=labels_heatmap)
                    df = df.sort_index()

                    cmap = cm.get_cmap('rocket_r')
                    g = sns.heatmap(df, xticklabels=False, cmap=cmap, vmax=vmax, vmin=vmin)

                    plt.setp(g.get_yticklabels(), rotation=0)
                    plt.subplots_adjust(top=0.92, bottom=0.02, left=0.25, right=1, hspace=0.94)
                    plt.savefig(error_heatmap_path + "/" + sname + "/" + clusnum)

                    plt.close()
                    plt.clf()

        for names, sname, q in [("Packet sizes", "bytes", 1), ("Interval", "gaps", 0), ("Source Port", "sport", 3),
                                ("Dest. Port", "dport", 4)]:
            for clusnum, corect_cluster in correct_packets_per_cluster.items():

                if len(corect_cluster) > 1:

                    cluster = []
                    for name in corect_cluster.keys():
                        cluster.append((cluster_info_dic[name], name))

                    cluster.sort(key=lambda tuple: tuple[0])

                    items = [int(x[0]) for x in cluster]
                    labels = [x[1] for x in cluster]

                    acha = [actlabels.index(int(x[0])) for x in cluster]

                    blah = [values[a] for a in acha]

                    dataf = []

                    for b in blah:
                        dataf.append([x[q] for x in b][:self.window_size])

                    df = pd.DataFrame(dataf, index=labels)

                    g = sns.clustermap(df, xticklabels=False, col_cluster=False)  # , vmin= minb, vmax=maxb)
                    ind = g.dendrogram_row.reordered_ind
                    fig = plt.figure(figsize=(10.0, 9.0))
                    plt.suptitle("Correct Exp: " + self.expname + " | Cluster: " + clusnum + " | Feature: " + names)
                    ax = fig.add_subplot(111)
                    datanew = []
                    labelsnew = []
                    labels_heatmap = []
                    lol = []

                    for it in sorted(ind):
                        labelsnew.append(labels[it])
                        labels_heatmap.append(labels[it].split("->", maxsplit=1)[1])
                        lol.append(cluster[[x[1] for x in cluster].index(labels[it])][0])

                    acha = [actlabels.index(int(x)) for x in lol]
                    blah = [values[a] for a in acha]

                    dataf = []

                    for b in blah:
                        dataf.append([x[q] for x in b][:self.window_size])
                    vmax = vmax_dic[sname][clusnum]
                    vmin = vmin_dic[sname][clusnum]
                    df = pd.DataFrame(dataf, index=labels_heatmap)
                    df = df.sort_index()

                    cmap = cm.get_cmap('rocket_r')
                    g = sns.heatmap(df, xticklabels=False, cmap=cmap, vmax=vmax, vmin=vmin)

                    plt.setp(g.get_yticklabels(), rotation=0)
                    plt.subplots_adjust(top=0.92, bottom=0.02, left=0.25, right=1, hspace=0.94)
                    plt.savefig(correct_heatmap_path + "/" + sname + "/" + clusnum)

                    plt.close()
                    plt.clf()

        ###########################
        # adding clustering error #
        ###########################

        clustering_error_list_df = []
        clustering_error_list = []

        for cluster_number in cluster_numbers:
            if cluster_number != '-1':
                if cluster_number in error_packets_per_cluster:
                    error_packets = len(error_packets_per_cluster[cluster_number])
                    correct_packets = len(correct_packets_per_cluster[cluster_number])
                    per_cluster_error = error_packets / (correct_packets + error_packets)
                else:
                    per_cluster_error = 0
                clustering_error_list.append(per_cluster_error)
                clustering_error_list_df.append(per_cluster_error)
        clustering_error_list_df.insert(0, "nan")

        cluster_summary_df = pd.read_csv(cluster_summary_path)
        cluster_summary_df["clustering_error"] = clustering_error_list_df
        cluster_summary_df.to_csv(cluster_summary_path, index=False)


        if len(clustering_error_list) > 1:
            avg_clustering_error = round(mean(clustering_error_list), 3)
        else:
            avg_clustering_error = "nan"

        summary_overall_df = pd.read_csv(overall_summary_path)
        summary_overall_df["avg_clustering_error"] = avg_clustering_error
        summary_overall_df.to_csv(overall_summary_path, index=False)

        shortened_summary = pd.read_csv(shortened_summary_path)
        shortened_summary["avg_clustering_error"] = avg_clustering_error
        shortened_summary.to_csv(shortened_summary_path, index=False)


    def clean_up_labels(self, texts):

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

        return new_labels

    def inet_to_str(self, inet):
        """Convert inet object to a string
            Args:
                inet (inet struct): inet network address
            Returns:
                str: Printable/readable IP address
        """
        # First try ipv4 and then ipv6
        try:
            return socket.inet_ntop(socket.AF_INET, inet)
        except ValueError:
            return socket.inet_ntop(socket.AF_INET6, inet)


    src_set, dst_set, gap_set, proto_set, bytes_set, events_set, ip_set, dns_set, port_set = set(), set(), set(), set(), set(), set(), set(), set(), set()
    src_dict, dst_dict, proto_dict, events_dict, dns_dict, port_dict = {}, {}, {}, {}, {}, {}
    bytes, gap_list = [], []


    def readpcap_window(self, filename):

        print("Window mode")
        print("Reading", os.path.basename(filename))
        mal = 0
        ben = 0
        tot = 0
        counter = 0
        ipcounter = 0
        tcpcounter = 0
        udpcounter = 0

        data = []
        connections = {}
        packetspersecond = []
        bytesperhost = {}
        count = 0
        previousTimestamp = {}
        bytespersec = 0
        gaps = []
        incoming = []
        outgoing = []
        period = 0
        bla = 0
        f = open(filename, 'rb')
        pcap = dpkt.pcap.Reader(f)
        for ts, pkt in pcap:
            counter += 1
            eth = None
            bla += 1
            try:
                eth = dpkt.ethernet.Ethernet(pkt)
            except:
                continue

            if eth.type != dpkt.ethernet.ETH_TYPE_IP:
                continue

            ip = eth.data

            src_ip = self.inet_to_str(ip.src)
            dst_ip = self.inet_to_str(ip.dst)

            sport = 0
            dport = 0

            try:
                if ip.p == dpkt.ip.IP_PROTO_TCP or ip.p == dpkt.ip.IP_PROTO_UDP:
                    sport = ip.data.sport
                    dport = ip.data.dport
            except:
                continue

            proto = ip.get_proto(ip.p).__name__.strip()

            src_ip_key = str(src_ip).strip()
            dst_ip_key = str(dst_ip).strip()
            proto_key = str(proto).strip()
            sport_key = str(sport).strip()
            dport_key = str(dport).strip()

            key = (src_ip_key, dst_ip_key, proto_key, sport_key, dport_key)

            timestamp = datetime.datetime.utcfromtimestamp(ts)

            if key in previousTimestamp:
                gap = (timestamp - previousTimestamp[key]).microseconds / 1000
            else:
                gap = 0

            previousTimestamp[key] = timestamp

            tupple = (gap, ip.len, ip.p)

            gaps.append(tupple)



            if key not in connections.keys():
                connections[key] = []
            connections[key].append((gap, ip.len, ip.p, sport, dport))

        print(os.path.basename(filename), " num connections: ", len(connections))

        values = []
        todel = []
        print('Before cleanup: Total packets: ', len(gaps), ' in ', len(connections), ' connections.')

        final_connections = {}

        for (src_ip_key, dst_ip_key, proto_key, sport_key, dport_key), packets in connections.items():  # clean it up

            window = 0
            loop_packet_list = []

            for index, packet in enumerate(packets):
                loop_packet_list.append(packet)
                if len(loop_packet_list) == self.window_size:
                    final_connections[(src_ip_key, dst_ip_key, proto_key, sport_key, dport_key, str(window))] = loop_packet_list
                    loop_packet_list = []
                    window = window + 1

        print("Remaining connections after clean up ", len(connections))

        return (gaps, final_connections)

    def readfolde_window(self):
        fno = 0
        meta = {}
        mapping = {}
        files = glob.glob(self.path_to_folder + "/*.pcap")
        print('About to read pcap...')
        for f in files:
            key = os.path.basename(f)  # [:-5].split('-')

            data, connections = self.readpcap_window(f)
            if len(connections.items()) < 1:
                continue

            for i, v in connections.items():
                name = key + "->" + i[0] + "->" + i[1] + "->" + i[2] + "->" + i[3] + "->" + i[4] + "->" + i[5]
                mapping[name] = fno
                fno += 1
                meta[name] = v

            print("Average conn length: ", np.mean([len(x) for i, x in connections.items()]))
            print("Minimum conn length: ", np.min([len(x) for i, x in connections.items()]))
            print("Maximum conn length: ", np.max([len(x) for i, x in connections.items()]))
            print('----------------')

        print('++++++++++++++++')
        print('----------------')
        print('Done reading pcaps...')
        print('Collective surviving connections ', len(meta))

        self.connlevel_sequence(meta, mapping)


    def readfile(self, path_to_pcap_file):
        startf = time.time()
        mapping = {}
        print('About to read pcap...')
        data, connections = self.readpcap(path_to_pcap_file)
        print('Done reading pcaps...')
        if len(connections.items()) < 1:
            return

        endf = time.time()
        print('file reading ', (endf - startf))
        fno = 0
        meta = {}
        nconnections = {}
        print("Average conn length: ", np.mean([len(x) for i, x in connections.items()]))
        print("Minimum conn length: ", np.min([len(x) for i, x in connections.items()]))
        print("Maximum conn length: ", np.max([len(x) for i, x in connections.items()]))

        for i, v in connections.items():
            name = i[0] + "->" + i[1]
            mapping[name] = fno
            fno += 1
            meta[name] = v
        print('Surviving connections ', len(meta))
        startc = time.time()
        self.connlevel_sequence(meta, mapping)
        endc = time.time()
        print('Total time ', (endc - startc))
