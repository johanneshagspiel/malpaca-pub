#!/usr/bin/python3

import sys, dpkt, datetime, glob, os, operator, subprocess, csv
import socket
from pathlib import Path

import matplotlib
from collections import deque
from itertools import permutations
from dtw import dtw
from fastdtw import fastdtw
from math import log

from rpy2 import robjects
from sklearn.preprocessing import OneHotEncoder
from sklearn.cluster import KMeans
from sklearn import metrics
from scipy.spatial.distance import cdist, pdist, cosine, euclidean, cityblock
import numpy as np
import pandas as pd
import joblib
import matplotlib.pyplot as plt
from sklearn.cluster import DBSCAN
import json
from sklearn.manifold import TSNE
from pandas import Series
from statsmodels.graphics.tsaplots import plot_acf
import seaborn as sns
from scipy.cluster.hierarchy import dendrogram, linkage
import scipy.spatial.distance as ssd
import scipy
from itertools import groupby
import itertools
from sklearn.metrics.pairwise import euclidean_distances, manhattan_distances
import hdbscan
import time
import rpy2.robjects.packages as rpackages

import numba

class MalpacaMe():
    expname = 'exp'
    thresh = 20
    RPY2 = False
    totalconn = 0

    def __init__(self, path_to_folder, expname, thresh, RPY2):
        self.path_to_folder = path_to_folder
        self.expname = expname
        self.thresh = thresh
        self.RPY2 = RPY2

        path_to_results = str(Path.joinpath(Path(os.getcwd()).parents[1], "results"))
        os.mkdir(path_to_results + "/" + expname)
        self.path_to_store = str(Path.joinpath(Path(path_to_results), expname)) + "/"

        self.readfolder()

        if RPY2 == True:
            import rpy2.robjects as robjects
            import rpy2.robjects.packages as rpackages
            from rpy2.robjects.vectors import StrVector
            from rpy2.robjects.packages import importr
            from rpy2.robjects import r
            from rpy2.robjects import ListVector

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
        '''for i,v in data.items():
            fig = plt.figure(figsize=(10.0,9.0))
            ax = fig.add_subplot(111)
            ax.set_title(i)
            plt.plot([x[1] for x in v][:75], 'b')
            plt.plot([x[1] for x in v][:75], 'b.')
            cid = keys.index(i)
            plt.savefig('unzipped/malevol/data/connections/'+str(cid)+'.png')'''

        # save intermediate results

        addition = '-' + self.expname + '-' + str(self.thresh)

        # ----- start porting -------

        utils, r = None, None

        for n, feat in [(1, 'bytes'), (0, 'gaps'), (3, 'sport'), (4, 'dport')]:
            f = open(self.path_to_store + feat + '-features' + addition, 'w')
            for val in values:
                vi = [str(x[n]) for x in val]
                f.write(','.join(vi))
                f.write("\n")
            f.close()

        startb = time.time()

        filename = self.path_to_store + 'bytesDist' + addition + '.txt'

        print("starting bytes dist")

        distm = [-1] * len(data.values())
        distm = [[-1] * len(data.values()) for i in distm]

        for a in range(len(data.values())):  # range(10):

            labels.append(mapping[keys[a]])
            ipmapping.append((mapping[keys[a]], inv_mapping[mapping[keys[a]]]))
            for b in range(a + 1):

                i = [x[1] for x in values[a]][:self.thresh]
                j = [x[1] for x in values[b]][:self.thresh]
                if len(i) == 0 or len(j) == 0: continue

                if a == b:
                    distm[a][b] = 0.0
                else:
                    dist, _ = fastdtw(i, j, dist=euclidean)
                    distm[a][b] = dist
                    distm[b][a] = dist

        with open(filename, 'w') as outfile:
            for a in range(len(distm)):  # len(data.values())): #range(10):
                outfile.write(' '.join([str(e) for e in distm[a]]) + "\n")
        with open(self.path_to_store + 'labels' + addition + '.txt', 'w') as outfile:
            outfile.write(' '.join([str(l) for l in labels]) + '\n')
        with open(self.path_to_store + 'mapping' + addition + '.txt', 'w') as outfile:
            outfile.write(' '.join([str(l) for l in ipmapping]) + '\n')

        endb = time.time()
        print('bytes ', (endb - startb))
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

        filename = self.path_to_store + 'gapsDist' + addition + '.txt'

        print("starting gaps dist")
        distm = [-1] * len(data.values())
        distm = [[-1] * len(data.values()) for i in distm]

        for a in range(len(data.values())):  # range(10):

            for b in range(a + 1):

                i = [x[0] for x in values[a]][:self.thresh]
                j = [x[0] for x in values[b]][:self.thresh]

                if len(i) == 0 or len(j) == 0: continue

                if a == b:
                    distm[a][b] = 0.0
                else:
                    dist, _ = fastdtw(i, j, dist=euclidean)
                    distm[a][b] = dist
                    distm[b][a] = dist

        with open(filename, 'w') as outfile:
            for a in range(len(distm)):  # len(data.values())): #range(10):
                # print distm[a]
                outfile.write(' '.join([str(e) for e in distm[a]]) + "\n")

        endg = time.time()
        print('gaps ', (endg - startg))
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

        filename = self.path_to_store + 'sportDist' + addition + '.txt'
        same, diff = set(), set()

        print("starting sport dist")
        distm = [-1] * len(data.values())
        distm = [[-1] * len(data.values()) for i in distm]

        ngrams = []
        for a in range(len(values)):
            profile = dict()

            dat = [x[3] for x in values[a]][:self.thresh]

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
                    dist = cosine(i_vec, j_vec)
                    distm[a][b] = dist
                    distm[b][a] = dist

        with open(filename, 'w') as outfile:
            for a in range(len(distm)):
                outfile.write(' '.join([str(e) for e in distm[a]]) + "\n")

        ends = time.time()
        print('sport ', (ends - starts))


        for a in range(len(distm)):
            ndistmS.append([])
            for b in range(len(distm)):
                ndistmS[a].append(distm[a][b])

        # dest port
        ndistmD = []
        distm = []

        startd = time.time()

        filename = self.path_to_store + 'dportDist' + addition + '.txt'

        print("starting dport dist")
        distm = [-1] * len(data.values())
        distm = [[-1] * len(data.values()) for i in distm]

        ngrams = []
        for a in range(len(values)):

            profile = dict()
            dat = [x[4] for x in values[a]][:self.thresh]

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
                    dist = round(cosine(i_vec, j_vec), 8)
                    distm[a][b] = dist
                    distm[b][a] = dist

        with open(filename, 'w') as outfile:
            for a in range(len(distm)):
                outfile.write(' '.join([str(e) for e in distm[a]]) + "\n")

        endd = time.time()
        print('time dport ', (endd - startd))
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

        print("done distance meaurement")
        print(len(ndistm))
        print(len(ndistm[0]))

        plot_kwds = {'alpha': 0.5, 's': 80, 'linewidths': 0}
        RS = 3072018
        projection = TSNE(random_state=RS).fit_transform(ndistm)
        plt.scatter(*projection.T)
        plt.savefig(self.path_to_store + "tsne-result" + addition)

        size = 7
        sample = 7

        model = hdbscan.HDBSCAN(min_cluster_size=size, min_samples=sample, cluster_selection_method='leaf',
                                metric='precomputed')
        clu = model.fit(np.array([np.array(x) for x in ndistm]))  # final for citadel and dridex
        joblib.dump(clu, self.path_to_store + 'model' + addition + '.pkl')

        print("num clusters: " + str(len(set(clu.labels_)) - 1))

        avg = 0.0
        for l in list(set(clu.labels_)):
            if l != -1:
                avg += sum([(1 if x == l else 0) for x in clu.labels_])
        print("average size of cluster:" + str(float(avg) / float(len(set(clu.labels_)) - 1)))
        print("samples in noise: " + str(sum([(1 if x == -1 else 0) for x in clu.labels_])))

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
            '''thiscol = None
            thislab = None
            for cdx, cc in enumerate(classes):
                if cc in name:
                    thiscol = col[cdx]
                    thislab = cc
                    break'''
            plt.scatter(projection.T[0][i], projection.T[1][i], color=col[i], alpha=0.6)
            if txt == -1:
                continue

            plt.annotate(txt, (projection.T[0][i], projection.T[1][i]), color=col[i], alpha=0.6)

        plt.savefig(self.path_to_store + "clustering-result" + addition)

        # writing csv file
        print("writing csv file")
        final_clusters = {}
        final_probs = {}
        for lab in set(clu.labels_):
            occ = [i for i, x in enumerate(clu.labels_) if x == lab]
            final_probs[lab] = [x for i, x in zip(clu.labels_, clu.probabilities_) if i == lab]
            print("cluster: " + str(lab) + " num items: " + str(len([labels[x] for x in occ])))
            final_clusters[lab] = [labels[x] for x in occ]

        csv_file = self.path_to_store + 'clusters' + addition + '.csv'
        outfile = open(csv_file, 'w')
        outfile.write("clusnum,connnum,probability,class,filename,srcip,dstip\n")

        for n, clus in final_clusters.items():

            for idx, el in enumerate([inv_mapping[x] for x in clus]):

                ip = el.split('->')
                if '-' in ip[0]:
                    classname = el.split('-')[1]
                else:
                    classname = el.split('.pcap')[0]

                filename = el.split('.pcap')[0]

                outfile.write(
                    str(n) + "," + str(mapping[el]) + "," + str(final_probs[n][idx]) + "," + str(classname) + "," + str(
                        filename) + "," + ip[0] + "," + ip[1] + "\n")
        outfile.close()

        # Making tree
        print('Producing DAG with relationships between pcaps')
        clusters = {}
        numclus = len(set(clu.labels_))
        with open(csv_file, 'r') as f1:
            reader = csv.reader(f1, delimiter=',')
            for i, line in enumerate(reader):  # f1.readlines()[1:]:
                if i > 0:
                    if line[4] not in clusters.keys():
                        clusters[line[4]] = []
                    clusters[line[4]].append((line[3], line[0]))  # classname, cluster#
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
            print(filename + "\t" + fam + "\t" + ''.join([str(x) for x in arr[:-1]]))
            if mas not in treeprep.keys():
                treeprep[mas] = dict()
            if famname not in treeprep[mas].keys():
                treeprep[mas][famname] = set()
            treeprep[mas][famname].add(str(filename))

        f2 = open(self.path_to_store +'mas-details' + addition + '.csv', 'w')
        for k, v in treeprep.items():
            for kv, vv in v.items():
                f2.write(str(k) + ';' + str(kv) + ';' + str(len(vv)) + '\n')
        f2.close()

        with open(self.path_to_store +'mas-details' + addition + '.csv', 'rU') as f3:
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
                f2 = open(self.path_to_store +'relation-tree' + addition + '.dot', 'w')
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
            print('Rendering DAG -- needs graphviz dot')
            try:
                os.system('dot -Tpng relation-tree' + addition + '.dot -o DAG' + addition + '.png')
                print('Done')
            except:
                print('Failed')
                pass

        # temporal heatmaps start

        print("writing temporal heatmaps")
        if not os.path.exists(self.path_to_store + 'figs' + addition + '/'):
            os.mkdir(self.path_to_store + 'figs' + addition + '/')
            os.mkdir(self.path_to_store + 'figs' + addition + '/bytes')
            os.mkdir(self.path_to_store + 'figs' + addition + '/gaps')
            os.mkdir(self.path_to_store + 'figs' + addition + '/sport')
            os.mkdir(self.path_to_store + 'figs' + addition + '/dport')

        actlabels = []
        for a in range(len(values)):  # range(10):
            actlabels.append(mapping[keys[a]])

        clusterinfo = {}
        seqclufile = csv_file
        lines = []
        lines = open(seqclufile).readlines()[1:]

        for line in lines:
            li = line.split(",")  # clusnum, connnum, prob, srcip, dstip

            srcip = li[5]
            dstip = li[6][:-1]
            has = int(li[1])

            name = str('%12s->%12s' % (srcip, dstip))
            if li[0] not in clusterinfo.keys():
                clusterinfo[li[0]] = []
            clusterinfo[li[0]].append((has, name))
        print("rendering ... ")

        sns.set(font_scale=0.9)
        matplotlib.rcParams.update({'font.size': 10})
        for names, sname, q in [("Packet sizes", "bytes", 1), ("Interval", "gaps", 0), ("Source Port", "sport", 3),
                                ("Dest. Port", "dport", 4)]:
            for clusnum, cluster in clusterinfo.items():
                items = [int(x[0]) for x in cluster]
                labels = [x[1] for x in cluster]

                acha = [actlabels.index(int(x[0])) for x in cluster]

                blah = [values[a] for a in acha]

                dataf = []

                for b in blah:
                    dataf.append([x[q] for x in b][:self.thresh])

                df = pd.DataFrame(dataf, index=labels)

                g = sns.clustermap(df, xticklabels=False, col_cluster=False)  # , vmin= minb, vmax=maxb)
                ind = g.dendrogram_row.reordered_ind
                fig = plt.figure(figsize=(10.0, 9.0))
                plt.suptitle("Exp: " + self.expname + " | Cluster: " + clusnum + " | Feature: " + names)
                ax = fig.add_subplot(111)
                datanew = []
                labelsnew = []
                lol = []
                for it in ind:
                    labelsnew.append(labels[it])
                    lol.append(cluster[[x[1] for x in cluster].index(labels[it])][0])

                acha = [actlabels.index(int(x)) for x in lol]
                blah = [values[a] for a in acha]

                dataf = []

                for b in blah:
                    dataf.append([x[q] for x in b][:20])
                df = pd.DataFrame(dataf, index=labelsnew)
                g = sns.heatmap(df, xticklabels=False)
                plt.setp(g.get_yticklabels(), rotation=0)
                plt.subplots_adjust(top=0.92, bottom=0.02, left=0.25, right=1, hspace=0.94)
                plt.savefig(self.path_to_store + "figs" + addition + "/" + sname + "/" + clusnum)


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


    def readpcap(self, filename):
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

            key = (src_ip, dst_ip)

            timestamp = datetime.datetime.utcfromtimestamp(ts)

            if key in previousTimestamp:
                gap = (timestamp - previousTimestamp[key]).microseconds / 1000
            else:
                gap = 0

            previousTimestamp[key] = timestamp

            tupple = (gap, ip.len, ip.p)

            gaps.append(tupple)

            sport = 0
            dport = 0

            try:
                if ip.p == dpkt.ip.IP_PROTO_TCP or ip.p == dpkt.ip.IP_PROTO_UDP:
                    sport = ip.data.sport
                    dport = ip.data.dport
            except:
                continue

            if key not in connections.keys():
                connections[key] = []
            connections[key].append((gap, ip.len, ip.p, sport, dport))

        print(os.path.basename(filename), " num connections: ", len(connections))

        values = []
        todel = []
        print('Before cleanup: Total packets: ', len(gaps), ' in ', len(connections), ' connections.')
        for i, v in connections.items():  # clean it up
            if len(v) < self.thresh:
                todel.append(i)

        for item in todel:
            del connections[item]

        print("Remaining connections after clean up ", len(connections))

        return (gaps, connections)


    def readfolder(self):
        fno = 0
        meta = {}
        mapping = {}
        files = glob.glob(self.path_to_folder + "/*.pcap")
        print('About to read pcap...')
        for f in files:
            key = os.path.basename(f)  # [:-5].split('-')

            data, connections = (self.readpcap(f))
            if len(connections.items()) < 1:
                continue

            for i, v in connections.items():
                name = key + i[0] + "->" + i[1]
                print(name)
                # name = meta[key[len(key)-1]]['threat']+"|" +key[len(key)-1][:5]+"|"+i[0]+"->"+i[1]
                mapping[name] = fno
                fno += 1
                meta[name] = v

            print("Average conn length: ", np.mean([len(x) for i, x in connections.items()]))
            print("Minimum conn length: ", np.min([len(x) for i, x in connections.items()]))
            print("Maximum conn length: ", np.max([len(x) for i, x in connections.items()]))
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
        # print("num connections survived ", len(connections))
        # print(sum([1 for i,x in connections.items() if len(x)>=50]))
        for i, v in connections.items():
            name = i[0] + "->" + i[1]
            mapping[name] = fno
            fno += 1
            meta[name] = v

            '''fig = plt.figure()
            plt.title(''+name)
            plt.plot([x[0] for x in v], 'r')
            plt.plot([x[0] for x in v], 'r.')
            plt.savefig('figs/'+str(mapping[name])+'.png')'''
        print('Surviving connections ', len(meta))
        startc = time.time()
        self.connlevel_sequence(meta, mapping)
        endc = time.time()
        print('Total time ', (endc - startc))
