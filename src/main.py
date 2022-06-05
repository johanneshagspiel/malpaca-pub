from libraries.script_library import Script_Library
from scripts.adding_more_information.adding_more_information import Adding_More_Information
from scripts.adding_more_information.adding_more_information_netflow import Adding_More_Information_Netflow
from scripts.dataset_analysis.filtered_dataset_analysis import Filtered_Dataset_Analysis
from scripts.dataset_analysis.original_dataset_analysis import Original_Dataset_Analysis
from scripts.filtered_dataset_creation.dataset_balancing import Dataset_Balancing
from scripts.filtered_dataset_creation.filtered_dataset_creation import Filtered_Dataset_Creation
from scripts.filtered_dataset_creation.scaling_down_dataset import Scaling_Down_Dataset
from scripts.for_malpaca_preparation.for_malpaca_preparation import For_Malpaca_Preparation
from scripts.for_malpaca_preparation.for_malpaca_preparation_enriched import For_Malpaca_Preparation_Enriched
from scripts.graph_creation.graph_filtered_data_set import Graph_Filtered_Data_Set
from scripts.graph_creation.graph_one_experiment import Graph_One_Experiment
from scripts.nfstream_operations.nfstream_operations import Nfstream_Operations
from scripts.result_analysis.failed_experiments_analysis import Failed_Experiment_Analysis
from scripts.result_analysis.multiple_experiment_results_combination import Multiple_Experiment_Results_Combination
from scripts.result_analysis.regression_analysis import Regression_Analysis
from util.util import Util
import pandas as pd
import numpy as np
from scapy.all import *


if __name__ == '__main__':



    # path_to_experiment_1 = r"C:\Users\Johannes\iCloudDrive\Uni\CSE\Year 3\Q4\Code\Dataset\Results\5_netflow_max_1000\5_netflow_balanced_min_20\Experiment 1 - Best Fixed Length"
    # Multiple_Experiment_Results_Combination.combine_results_from_experiment_1_3_4(path_to_experiment_1)


    # path_to_regression = r"C:\Users\Johannes\iCloudDrive\Uni\CSE\Year 3\Q4\Code\Dataset\Analysis\Regression"
    # Regression_Analysis.regression_analysis(path_to_regression)




    path_to_folder = r"C:\Users\Johannes\iCloudDrive\Uni\CSE\Year 3\Q4\Code\Dataset\For Malpaca\5_netflow_max_1000\5_netflow_balanced_10000\Experiment 4 - Window Experimentation"
    path_to_storage = r"C:\Users\Johannes\iCloudDrive\Uni\CSE\Year 3\Q4\Code\Dataset\Results\5_netflow_max_1000\5_netflow_balanced_10000\Experiment 4 - Window Experimentation"
    Script_Library.run_experiment_4_netflow(path_to_folder, path_to_storage)