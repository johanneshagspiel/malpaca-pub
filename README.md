<img src=img/malpaca_seq_logo.JPG alt="The MalPaCA Seq Logo" width="199" height="173">

--------------------------------------------------------------------------------
[![MIT License](https://img.shields.io/github/license/johanneshagspiel/malpaca-pub)](LICENSE)
[![Top Language](https://img.shields.io/github/languages/top/johanneshagspiel/malpaca-pub)](https://github.com/johanneshagspiel/malpaca-pub)
[![Latest Release](https://img.shields.io/github/v/release/johanneshagspiel/malpaca-pub)](https://github.com/johanneshagspiel/malpaca-pub/releases/)

# MalPaCA Seq+

This repository contains an updated version of the [MalPaCA](https://github.com/tudelft-cda-lab/malpaca-pub) algorithm, 
which is a novel, unsupervised clustering algorithm that creates, based on the network flow of a software a behavioral profile representing its actual capabilities.
It takes as an input one or multiple pcap files from which it then:
1. splits them into uni-directional connections
2. extracts from each connection 4 sequential features, namely the packet sizes (bytes), inter-arrival-times (ms), source ports and dest ports
3. computes each feature the pairwise distance between all connections and stores them in their respective distance matrix
4. combines the distance matrices using a simple weighted average, where all features have equal weights
5. inputs the final distance matrix into the HDBScan clustering algorithm
6. post-processes the final clusters and exports them in .csv and in temporal heatmaps form 

In addition to the original version, "MalPaCa Seq+" contains a number of improvements that either facilitate research into the impact of different sequence lengths on the clustering performance or that make "MalPaCA" a more viable tool for cybersecurity research in general. 
In particular:
- The time needed for step 3 was greatly reduced by switching the pairwise distance algorithms to versions that support the [Numba](https://numba.pydata.org/) JIT compiler.
- The clustering error metric introduced in the [original article](https://arxiv.org/abs/1904.01371) was further improved through the automatic generation of graphs that represent the presumed correct and incorrect elements of a cluster
- In addition to the temporal heatmaps, "MalPaCA" now can generate a variety of different graphs such as:
  - transition graphs that reveal how different segments of the same connection are clustered together differently in subsequent experiments

<p align="center">
	<img src=img/example_transition_graph.png alt="Example Transition Graph" width="312" height="228">
</p>

  - graphs detailing the make-up of each clusters in terms of label or application category if such information is provided through prior network analysis with [NFStream](https://github.com/nfstream/nfstream). 

<p align="center">
	<img src=img/example_detailed_labels_overview.png alt="Example Detailed Labels Overview Graph" width="388" height="201">
</p>


## Features

With "MalPaCA Seq+", the user can:
- run the upgraded MalPaCA algorithm on one or multiple pcap files  
- run five different experiments to answer foundational questions about the influence of the sequencing length on clustering perfomrance such as:
  - Experiment 1 - What sequence length taken from the start of a connection leads to the best clustering results?
  - Experiment 2 - Is there a difference in the clustering results depending on which part of a connection is being selected?
  - Experiment 3 - What is the effect of taking packets from the end of a connection and of skipping some packets?
  - Experiment 4 - What is the effect of breaking up one connection into multiple smaller connections of equal length?
  - Experiment 5 - What is the effect of defining behavior according to Netflow v5?

## Tools

| Purpose               | Name                                                                       |
|-----------------------|----------------------------------------------------------------------------|
| Programming language  | [Python](https://www.python.org/)                                          |
| Dependency manager    | [Anaconda](https://www.anaconda.com/products/distribution)                 |
| Version control system | [Git](https://git-scm.com/)                                                |
| Clustering Algorithm 	| [HDBScan](https://hdbscan.readthedocs.io/en/latest/how_hdbscan_works.html) |
| Graph Library 		    | [Matplotlib](https://matplotlib.org/)                                   |


## Installation Process

If you want to import this project and resolve all the dependencies associated with it, it is assumed that you have already installed [Anaconda](https://docs.conda.io/projects/conda/en/latest/user-guide/install/index.html), [Python](https://www.python.org/downloads/windows/), an IDE like [PyCharm](https://www.jetbrains.com/pycharm/download/#section=windows) and that your operating system is Windows.
Re-create the original `MalPaCA` environment from the `environment.yml` file with this command:

	conda env create -f environment.yml

Activate the new environment:
 
	conda activate MalPaCA

Lastly, check that the new environment was installed correctly:
	
	conda env list

## Contributors

The original author of "MalPaCA" was [Azqa Nadeem](https://github.com/azqa) and the original source code can be found [here](https://github.com/tudelft-cda-lab/malpaca-pub).

## Licence

The original "MalPaCA" framework was published under the MIT license, which can be found in the [License](LICENSE) file. 

**If you use MalPaCA in a scientific work, consider citing the following paper:**

    @article{nadeembeyond,
      title={Beyond Labeling: Using Clustering to Build Network Behavioral Profiles of Malware Families},
      author={Nadeem, Azqa and Hammerschmidt, Christian and Ga{\~n}{\'a}n, Carlos H and Verwer, Sicco},
      journal={Malware Analysis Using Artificial Intelligence and Deep Learning},
      pages={381},
      publisher={Springer}
    }

## References

The clustering result image in the logo was taken from the [HDBSCAN website](https://hdbscan.readthedocs.io/en/latest/_images/soft_clustering_explanation_6_0.png). 