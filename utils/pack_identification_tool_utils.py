import json
import os

virus_total_response_path = "logs/virustotal"


def get_packer_name_from_detectiteasy_of_virustotal(response):
    packer_names = []
    for item in response:
        if ('type' in item) and ((item['type'] == 'Protector') or (item['type'] == 'Packer')):
            packer_names.append(item['name'])
    return packer_names


def packer_identification_virus_total(file_name):
    response_path = os.path.join(virus_total_response_path, "{}.json".format(file_name))
    if not os.path.exists(response_path):
        return []
    with open(response_path, "r") as response:
        response = json.loads(response.read())
    answers = []
    try:
        peid = response["data"]["attributes"]["packers"]["PEiD"]
        answers.append(peid)
    except Exception:
        pass
    try:
        detectiteasy = response["data"]["attributes"]["detectiteasy"]["values"]
        answers += get_packer_name_from_detectiteasy_of_virustotal(detectiteasy)
    except Exception:
        pass
    return answers
