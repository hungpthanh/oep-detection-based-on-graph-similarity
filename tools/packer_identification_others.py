log_files = glob.glob(args.log_path + '/*.*')
    results = {}
    prediction_data = {}
    packer_identification_data = {}
    for log_file in log_files:
        # if not ("winupack" in log_file):
        #     continue
        print("Processing on {}".format(log_file))
        with open(log_file, "r") as f:
            lines = [line for line in f]
            avg_score = []
            for line in tqdm(lines):
                if "The accuracy of packer" in line:
                    packer_name, accuracy = get_result(line)
                    results[packer_name] = accuracy
                if "Final decision" in line:
                    end_of_unpacking_result, packer_name, file_name, predicted_end_of_unpacking, score, packer_identification = get_final_decision(
                        line)
                    # print("node : {}".format(predicted_end_of_unpacking))
                    predicted_oep, msg = get_OEP(packer_name, file_name, predicted_end_of_unpacking)
                    if end_of_unpacking_result == "True":
                        avg_score.append(float(score))
                    if not packer_name in prediction_data:
                        prediction_data[packer_name] = {}
                    if end_of_unpacking_result == "True":
                        prediction_data[packer_name][file_name] = predicted_oep
                    else:
                        prediction_data[packer_name][file_name] = None

                    if not (packer_name in packer_identification_data):
                        packer_identification_data[packer_name] = []
                    packer_name_BE_PUM = get_packer_name_BE_PUM(packer_name, file_name)
                    packer_identification_data[packer_name].append((packer_identification, packer_name_BE_PUM))

            print("avarage score is {}".format(np.mean(avg_score)))
    for packer_name, file_names in prediction_data.items():
        n_sample = len(prediction_data[packer_name])
        n_correct = 0
        for filename, predicted_oep in file_names.items():
            if (predicted_oep is not None) and (predicted_oep == oep_dictionary_2["{}_{}".format(packer_name, filename)]):
                n_correct += 1
        n_correct_predict_packer = sum(
            [int(packer_name == predicted_name[0]) for predicted_name in packer_identification_data[packer_name]])
        n_correct_predict_packer_be_pum = sum(
            [int(packer_name == predicted_name[1]) for predicted_name in packer_identification_data[packer_name]])
        print(
            "Packer: {}, end-of-unpacking accuracy: {:.3f}, OEP detection accuracy: {:.3f}, packer_identification accuracy: {}, be-pum: {}, of sample: {}".format(
                packer_name,
                float(results[packer_name]),
                1.0 * n_correct ,
                1.0 * n_correct_predict_packer,
                1.0 * n_correct_predict_packer_be_pum ,
                n_sample))