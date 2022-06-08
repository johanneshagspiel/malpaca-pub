import os
from src.malpaca.malpaca_me_improved import MalpacaMeImproved
from src.malpaca.malpaca_me_improved_window import MalpacaMeImprovedWindow
from src.malpaca.netflow.malpaca_me_improved_netflow import MalpacaMeImprovedNetflow
from src.malpaca.netflow.malpaca_me_improved_window_netflow import MalpacaMeImprovedWindowNetflow
from src.scripts.for_malpaca_preparation.for_malpaca_preparation_netflow import For_Malpaca_Preparation_Netflow
from src.scripts.graph_creation.graph_multiple_experiments import Graph_Multiple_Experiments
from src.scripts.for_malpaca_preparation.for_malpaca_preparation import For_Malpaca_Preparation
from src.scripts.for_malpaca_preparation.for_malpaca_preparation_enriched import For_Malpaca_Preparation_Enriched
from src.scripts.nfstream_operations.nfstream_operations import Nfstream_Operations


class Script_Library():

    @staticmethod
    def move_pcap_files_into_nfstream_repository(path_to_original_folder, path_to_nfstream_repository):

        Nfstream_Operations.move_pcacp_files_to_nfstream_repository(path_to_original_folder=path_to_original_folder, path_to_nfstream_repository=path_to_nfstream_repository)

    ###
    # ip src / ip dst / ip protocol / src port/ dst port
    ##

    @staticmethod
    def run_one_malpaca_netflow_experiment(path_to_folder, path_to_results, path_to_detailed_label_folder):

        experiment_name = os.path.basename(path_to_folder)

        expname = experiment_name
        thresh = int(experiment_name.split("_")[0])
        RPY2 = False

        malpaca = MalpacaMeImprovedNetflow(path_to_folder, path_to_results, path_to_detailed_label_folder, expname, thresh, RPY2)


    @staticmethod
    def run_one_malpaca_netflow_window_experiment(path_to_folder, path_to_results, path_to_detailed_label_folder):

        experiment_name = os.path.basename(path_to_folder)

        expname = experiment_name
        thresh = int(experiment_name.split("_")[0])
        RPY2 = False

        malpaca = MalpacaMeImprovedWindowNetflow(path_to_folder, path_to_results, path_to_detailed_label_folder, expname, thresh, RPY2)


    @staticmethod
    def create_data_set_for_experiment_1_netflow(path_to_filtered_files, path_to_storage, old_file_addition):

        path_to_filtered_files = path_to_filtered_files
        path_to_storage = path_to_storage

        print("Determining optimal amount")

        amounts = [5, 6, 7, 8, 9, 10, 15, 20, 30, 40, 100]

        for run, amount in enumerate(amounts):
            print("Run " + str(run + 1) + "/" + str(len(amounts)))
            For_Malpaca_Preparation_Netflow.get_data_equal_to_fixed_threshold_for_malpaca_enriched(threshold=amount,
                                                                                                   folder_to_filtered_files=path_to_filtered_files,
                                                                                                   folder_to_move_data_to=path_to_storage,
                                                                                                   old_file_addition=old_file_addition)


    @staticmethod
    def create_data_set_for_experiment_3_netflow(path_to_filtered_files, path_to_storage, old_file_addition):
        path_to_filtered_files = path_to_filtered_files
        path_to_storage = path_to_storage

        amounts = [5, 6, 7, 8, 9, 10, 15, 20, 30, 40, 100]
        skip_amounts = [5, 10]

        for run, amount in enumerate(amounts):
            print("Run " + str(run + 1) + "/" + str(len(amounts)))

            For_Malpaca_Preparation_Netflow.get_data_equal_to_fixed_threshold_from_end_for_malpaca_enriched(
                threshold=amount,
                folder_to_filtered_files=path_to_filtered_files,
                folder_to_move_data_to=path_to_storage,
                old_file_addition=old_file_addition)

            for skip in skip_amounts:
                For_Malpaca_Preparation_Netflow.get_data_skip_x_then_take_fixed_threshold_for_malpaca_enriched(
                    threshold=amount,
                    skip=skip,
                    folder_to_filtered_files=path_to_filtered_files,
                    folder_to_move_data_to=path_to_storage,
                    old_file_addition=old_file_addition)

                For_Malpaca_Preparation_Netflow.get_data_skip_x_then_take_fixed_threshold_from_end_for_malpaca_enriched(
                    threshold=amount,
                    skip=skip,
                    folder_to_filtered_files=path_to_filtered_files,
                    folder_to_move_data_to=path_to_storage,
                    old_file_addition=old_file_addition)


    @staticmethod
    def run_experiment_1_and_3_netflow(path_to_folder, path_to_storage, path_to_detailed_label_folder):

        path_to_folder = path_to_folder
        path_to_storage = path_to_storage
        path_to_detailed_label_folder = path_to_detailed_label_folder

        folders = [f.path for f in os.scandir(path_to_folder) if f.is_dir()]
        folders = [(x, int(os.path.basename(x).split("_", maxsplit=1)[0])) for x in folders]
        folders.sort(key=lambda tuple: tuple[1], reverse=True)
        folders = [x[0] for x in folders]

        for experiment in folders:
            experiment_name = os.path.basename(experiment)

            path_to_folder = experiment
            path_to_results = path_to_storage
            path_to_detailed_label_folder = path_to_detailed_label_folder
            expname = experiment_name
            window_size = int(experiment_name.split("_")[0])
            RPY2 = False

            malpaca = MalpacaMeImprovedNetflow(path_to_folder, path_to_results, path_to_detailed_label_folder, expname, window_size, RPY2)


    @staticmethod
    def run_experiment_4_netflow(path_to_folder, path_to_storage, path_to_detailed_label_folder):

        path_to_folder = path_to_folder
        path_to_storage = path_to_storage
        path_to_detailed_label_folder = path_to_detailed_label_folder

        folders = [f.path for f in os.scandir(path_to_folder) if f.is_dir()]
        folders = [(x, int(os.path.basename(x).split("_", maxsplit=1)[0])) for x in folders]
        folders.sort(key=lambda tuple: tuple[1], reverse=True)
        folders = [x[0] for x in folders]

        for experiment in folders:
            experiment_name = os.path.basename(experiment)

            path_to_folder = experiment
            path_to_results = path_to_storage
            path_to_detailed_label_folder = path_to_detailed_label_folder
            expname = experiment_name
            window_size = int(experiment_name.split("_")[0])
            RPY2 = False

            malpaca = MalpacaMeImprovedWindowNetflow(path_to_folder, path_to_results, path_to_detailed_label_folder, expname, window_size, RPY2)


    @staticmethod
    def create_data_set_for_experiment_4_netflow(path_to_filtered_files, path_to_storage, old_file_addition):
        path_to_filtered_files = path_to_filtered_files
        path_to_storage = path_to_storage

        amounts = [5, 6, 7, 8, 9, 10, 15, 20, 30, 40, 100]

        for run, amount in enumerate(amounts):
            print("Run " + str(run + 1) + "/" + str(len(amounts)))
            For_Malpaca_Preparation_Netflow.get_data_equal_to_fixed_window_size_for_malpaca(
                folder_to_filtered_files=path_to_filtered_files,
                folder_to_move_data_to=path_to_storage,
                window_size=amount,
                old_file_addition=old_file_addition)

    ################
    # ip src / dst #
    ################


    @staticmethod
    def run_experiments_small(path_to_folder, path_to_storage):

        folders = sorted([f.path for f in os.scandir(path_to_folder) if f.is_dir()])

        for experiment in folders:
            experiment_name = os.path.basename(experiment)

            path_to_folder = experiment
            path_to_results = path_to_storage
            expname = experiment_name
            thresh = int(experiment_name.split("_")[0])
            RPY2 = False

            malpaca = MalpacaMeImproved(path_to_folder, path_to_results, expname, thresh, RPY2)


    @staticmethod
    def run_experiments_large(path_to_folder, path_to_storage):

        folders = sorted([f.path for f in os.scandir(path_to_folder) if f.is_dir()])

        for experiment in folders:
            experiment_name = os.path.basename(experiment)

            path_to_folder = experiment
            path_to_results = path_to_storage
            expname = experiment_name
            thresh = int(experiment_name.split("_")[0])
            RPY2 = False

            malpaca = MalpacaMeImproved(path_to_folder, path_to_results, expname, thresh, RPY2)


    @staticmethod
    def run_one_experiment(path_to_folder, path_to_results, path_to_detailed_label_folder):

        experiment_name = os.path.basename(path_to_folder)

        expname = experiment_name
        thresh = int(experiment_name.split("_")[0])
        RPY2 = False

        malpaca = MalpacaMeImproved(path_to_folder, path_to_results, path_to_detailed_label_folder, expname, thresh, RPY2)


    @staticmethod
    def run_window_experiment(path_to_folder, path_to_storage, path_to_detailed_label_folder):

        experiment_name = os.path.basename(path_to_folder)

        path_to_results = path_to_storage
        expname = experiment_name
        window_size = int(experiment_name.split("_")[0])
        RPY2 = False

        malpaca = MalpacaMeImprovedWindow(path_to_folder, path_to_results, path_to_detailed_label_folder, expname, window_size, RPY2)


    @staticmethod
    def re_run_failed_experiment_1_and_3(path_to_for_malpaca_files, path_to_results, path_to_detailed_label_folder):

        for_malpaca_folders = [f.path for f in os.scandir(path_to_for_malpaca_files) if f.is_dir()]
        for_malpaca_folders = [(x, os.path.basename(x)) for x in for_malpaca_folders]

        results_folders = [f.path for f in os.scandir(path_to_results) if f.is_dir()]
        results_folders = [os.path.basename(x) for x in results_folders]

        failed_experiments = []

        for path, for_malpaca_name in for_malpaca_folders:
            if for_malpaca_name not in results_folders:
                failed_experiments.append((path, for_malpaca_name))

        for path, for_malpaca_name in failed_experiments:

            experiment_name = for_malpaca_name
            path_to_for_malpaca_folder = path
            path_to_results = path_to_results
            path_to_detailed_label_folder = path_to_detailed_label_folder
            expname = experiment_name
            window_size = int(experiment_name.split("_")[0])
            RPY2 = False

            malpaca = MalpacaMeImproved(path_to_for_malpaca_folder, path_to_results, path_to_detailed_label_folder, expname, window_size, RPY2)


    @staticmethod
    def re_run_failed_experiment_4_window(path_to_for_malpaca_files, path_to_results, path_to_detailed_label_folder):

        for_malpaca_folders = [f.path for f in os.scandir(path_to_for_malpaca_files) if f.is_dir()]
        for_malpaca_folders = [(x, os.path.basename(x)) for x in for_malpaca_folders]

        results_folders = [f.path for f in os.scandir(path_to_results) if f.is_dir()]
        results_folders = [os.path.basename(x) for x in results_folders]

        failed_experiments = []

        for path, for_malpaca_name in for_malpaca_folders:
            if for_malpaca_name not in results_folders:
                failed_experiments.append((path, for_malpaca_name))

        for path, for_malpaca_name in failed_experiments:

            experiment_name = for_malpaca_name
            path_to_for_malpaca_folder = path
            path_to_results = path_to_results
            path_to_detailed_label_folder = path_to_detailed_label_folder
            expname = experiment_name
            window_size = int(experiment_name.split("_")[0])
            RPY2 = False

            malpaca = MalpacaMeImprovedWindow(path_to_for_malpaca_folder, path_to_results, path_to_detailed_label_folder, expname, window_size, RPY2)


    @staticmethod
    def run_experiment_1(path_to_folder, path_to_storage, path_to_detailed_label_folder):

        path_to_folder = path_to_folder
        path_to_storage = path_to_storage
        path_to_detailed_label_folder = path_to_detailed_label_folder

        folders = [f.path for f in os.scandir(path_to_folder) if f.is_dir()]
        folders = [(x, int(os.path.basename(x).split("_", maxsplit=1)[0])) for x in folders]
        folders.sort(key=lambda tuple: tuple[1], reverse=True)
        folders = [x[0] for x in folders]

        for experiment in folders:
            experiment_name = os.path.basename(experiment)

            path_to_folder = experiment
            path_to_results = path_to_storage
            path_to_detailed_label_folder = path_to_detailed_label_folder
            expname = experiment_name
            window_size = int(experiment_name.split("_")[0])
            RPY2 = False

            malpaca = MalpacaMeImproved(path_to_folder, path_to_results, path_to_detailed_label_folder, expname, window_size, RPY2)


    @staticmethod
    def run_experiment_2(path_to_folder, path_to_storage, path_to_detailed_label_folder):

        path_to_folder = path_to_folder
        path_to_storage = path_to_storage
        path_to_detailed_label_folder = path_to_detailed_label_folder

        folders = [f.path for f in os.scandir(path_to_folder) if f.is_dir()]
        folders = [(x, int(os.path.basename(x).split("_", maxsplit=1)[0])) for x in folders]
        folders.sort(key=lambda tuple: tuple[1], reverse=True)
        folders = [x[0] for x in folders]

        for experiment_path in folders:
            experiment_name = os.path.basename(experiment_path)

            new_experiment_path = path_to_storage + "/" + experiment_name
            os.mkdir(new_experiment_path)

            subfolders = sorted([f.path for f in os.scandir(experiment_path) if f.is_dir()])

            for subfolder in subfolders:

                part_experiment_name = os.path.basename(subfolder)

                path_to_folder = subfolder
                path_to_results = new_experiment_path
                path_to_detailed_label_folder = path_to_detailed_label_folder
                expname = part_experiment_name
                window_size = int(part_experiment_name.split("_")[0])
                RPY2 = False

                malpaca = MalpacaMeImproved(path_to_folder, path_to_results, path_to_detailed_label_folder, expname, window_size, RPY2)

    @staticmethod
    def run_experiment_3(path_to_folder, path_to_storage, path_to_detailed_label_folder):

        path_to_folder = path_to_folder
        path_to_storage = path_to_storage
        path_to_detailed_label_folder = path_to_detailed_label_folder

        folders = [f.path for f in os.scandir(path_to_folder) if f.is_dir()]
        folders = [(x, int(os.path.basename(x).split("_", maxsplit=1)[0])) for x in folders]
        folders.sort(key=lambda tuple: tuple[1], reverse=True)
        folders = [x[0] for x in folders]

        for experiment in folders:
            experiment_name = os.path.basename(experiment)

            path_to_folder = experiment
            path_to_results = path_to_storage
            path_to_detailed_label_folder = path_to_detailed_label_folder
            expname = experiment_name
            window_size = int(experiment_name.split("_")[0])
            RPY2 = False

            malpaca = MalpacaMeImproved(path_to_folder, path_to_results, path_to_detailed_label_folder, expname, window_size, RPY2)

    @staticmethod
    def run_experiment_4(path_to_folder, path_to_storage, path_to_detailed_label_folder):

        path_to_folder = path_to_folder
        path_to_storage = path_to_storage
        path_to_detailed_label_folder = path_to_detailed_label_folder

        folders = [f.path for f in os.scandir(path_to_folder) if f.is_dir()]
        folders = [(x, int(os.path.basename(x).split("_", maxsplit=1)[0])) for x in folders]
        folders.sort(key=lambda tuple: tuple[1], reverse=True)
        folders = [x[0] for x in folders]

        for experiment in folders:
            experiment_name = os.path.basename(experiment)

            path_to_folder = experiment
            path_to_results = path_to_storage
            path_to_detailed_label_folder = path_to_detailed_label_folder
            expname = experiment_name
            window_size = int(experiment_name.split("_")[0])
            RPY2 = False

            malpaca = MalpacaMeImprovedWindow(path_to_folder, path_to_results, path_to_detailed_label_folder, expname, window_size, RPY2)


    @staticmethod
    def create_data_set_for_experiment_1(path_to_filtered_files, path_to_storage, old_file_addition):

        path_to_filtered_files = path_to_filtered_files
        path_to_storage = path_to_storage

        print("Determining optimal amount")
        optimal_amount = For_Malpaca_Preparation.determine_optimal_threshold(
            folder_to_filtered_files=path_to_filtered_files)

        amounts = [5, 6, 7, 8, 9, 10, 15, 20, 30, 40, 100]
        if optimal_amount not in amounts:
            amounts.append(optimal_amount)

        for run, amount in enumerate(amounts):
            print("Run " + str(run + 1) + "/" + str(len(amounts)))
            For_Malpaca_Preparation_Enriched.get_data_equal_to_fixed_threshold_for_malpaca_enriched(threshold=amount,
                                                                                                    folder_to_filtered_files=path_to_filtered_files,
                                                                                                    folder_to_move_data_to=path_to_storage,
                                                                                                    old_file_addition=old_file_addition)

    @staticmethod
    def create_data_set_for_experiment_2(path_to_filtered_files, path_to_storage, old_file_addition):

        path_to_filtered_files = path_to_filtered_files
        path_to_storage = path_to_storage

        print("Determining optimal amount")
        optimal_amount = For_Malpaca_Preparation.determine_optimal_threshold(
            folder_to_filtered_files=path_to_filtered_files)

        parts = 3
        amounts = [5, 6, 7, 8, 9, 10, 15, 20, 30, 40, 100]
        if optimal_amount not in amounts:
            amounts.append(optimal_amount)

        for run, amount in enumerate(amounts):
            print("Run " + str(run + 1) + "/" + str(len(amounts)))
            For_Malpaca_Preparation_Enriched.split_connection_into_X_equal_parts_for_malpaca(threshold=amount,
                                                                                             parts=parts,
                                                                                             folder_to_filtered_files=path_to_filtered_files,
                                                                                             folder_to_move_data_to=path_to_storage,
                                                                                             old_file_addition=old_file_addition)


    @staticmethod
    def create_data_set_for_experiment_3(path_to_filtered_files, path_to_storage, old_file_addition):
        path_to_filtered_files = path_to_filtered_files
        path_to_storage = path_to_storage

        print("Determining optimal amount")
        optimal_amount = For_Malpaca_Preparation.determine_optimal_threshold(
            folder_to_filtered_files=path_to_filtered_files)

        amounts = [5, 6, 7, 8, 9, 10, 15, 20, 30, 40, 100]
        if optimal_amount not in amounts:
            amounts.append(optimal_amount)
        skip_amounts = [5, 10]

        for run, amount in enumerate(amounts):
            print("Run " + str(run + 1) + "/" + str(len(amounts)))

            For_Malpaca_Preparation_Enriched.get_data_equal_to_fixed_threshold_from_end_for_malpaca_enriched(
                threshold=amount,
                folder_to_filtered_files=path_to_filtered_files,
                folder_to_move_data_to=path_to_storage,
                old_file_addition=old_file_addition)

            for skip in skip_amounts:
                For_Malpaca_Preparation_Enriched.get_data_skip_x_then_take_fixed_threshold_for_malpaca_enriched(
                    threshold=amount,
                    skip=skip,
                    folder_to_filtered_files=path_to_filtered_files,
                    folder_to_move_data_to=path_to_storage,
                    old_file_addition=old_file_addition)

                For_Malpaca_Preparation_Enriched.get_data_skip_x_then_take_fixed_threshold_from_end_for_malpaca_enriched(
                    threshold=amount,
                    skip=skip,
                    folder_to_filtered_files=path_to_filtered_files,
                    folder_to_move_data_to=path_to_storage,
                    old_file_addition=old_file_addition)


    @staticmethod
    def create_data_set_for_experiment_4(path_to_filtered_files, path_to_storage, old_file_addition):
        path_to_filtered_files = path_to_filtered_files
        path_to_storage = path_to_storage

        print("Determining optimal amount")
        optimal_amount = For_Malpaca_Preparation.determine_optimal_threshold(
            folder_to_filtered_files=path_to_filtered_files)

        amounts = [5, 6, 7, 8, 9, 10, 15, 20, 30, 40, 100]
        if optimal_amount not in amounts:
            amounts.append(optimal_amount)

        for run, amount in enumerate(amounts):
            print("Run " + str(run + 1) + "/" + str(len(amounts)))
            For_Malpaca_Preparation_Enriched.get_data_equal_to_fixed_window_size_for_malpaca(
                folder_to_filtered_files=path_to_filtered_files,
                folder_to_move_data_to=path_to_storage,
                window_size=amount,
                old_file_addition=old_file_addition)


    @staticmethod
    def create_graphs_for_section_experiments(experiment_name, path_to_results, path_to_storage):
        experiment_name = experiment_name
        path_to_results = path_to_results
        path_to_storage = path_to_storage

        print("Create Transition Graph")
        Graph_Multiple_Experiments.create_cluster_transition_graph(experiment_name, path_to_results, path_to_storage)

        print("Create Overview Graphs")
        Graph_Multiple_Experiments.create_experiment_overview_graphs(experiment_name, path_to_results, path_to_storage)
