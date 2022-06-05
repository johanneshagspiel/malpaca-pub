<img src=img/malpaca_logo.JPG alt="The Green Thumb Logo" width="194" height="180">

--------------------------------------------------------------------------------
[![MIT License](https://img.shields.io/github/license/johanneshagspiel/malpaca-pub)](LICENSE)
[![Top Language](https://img.shields.io/github/languages/top/johanneshagspiel/malpaca-pub)](https://github.com/johanneshagspiel/malpaca-pub)
[![Latest Release](https://img.shields.io/github/v/release/johanneshagspiel/malpaca-pub)](https://github.com/johanneshagspiel/malpaca-pub/releases/)

# MalPaCA

This repository contains  

## Features

With the "G-Code Viewer", printer when executing a G-Code file in both a static and dynamic 2D layer-by-layer view

## Tools

| Purpose               | Name                                                                       |
|-----------------------|----------------------------------------------------------------------------|
| Programming language  | [Python](https://www.python.org/)                                          |
| Dependency manager    | [Anaconda](https://www.anaconda.com/products/distribution)                 |
| Version control system | [Git](https://git-scm.com/)                                                |
| Clustering Algorithm 	| [HDBSCAN](https://hdbscan.readthedocs.io/en/latest/how_hdbscan_works.html) |
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

_@article{nadeembeyond,
  title={Beyond Labeling: Using Clustering to Build Network Behavioral Profiles of Malware Families},
  author={Nadeem, Azqa and Hammerschmidt, Christian and Ga{\~n}{\'a}n, Carlos H and Verwer, Sicco},
  journal={Malware Analysis Using Artificial Intelligence and Deep Learning},
  pages={381},
  publisher={Springer}
}_

## References

The clustering result image in the logo was taken from the [HDBSCAN website](https://hdbscan.readthedocs.io/en/latest/_images/soft_clustering_explanation_6_0.png). 