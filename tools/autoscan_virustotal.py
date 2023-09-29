# upload PE file to VirusTotal
# then get info about the results
# of analysis, print if malicious
import glob
import os
import sys
import time
import json
import requests
import argparse
import hashlib

from tqdm import tqdm


# for terminal colors
class Colors:
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    PURPLE = '\033[95m'
    ENDC = '\033[0m'


# VirusTotal API key
VT_API_KEY = "b28069df4ba529c1c1848699a7b39c98e44f92ee871844f1c118829386af4721"

# VirusTotal API v3 URL
VT_API_URL = "https://www.virustotal.com/api/v3/"


# upload malicious file to VirusTotal and analyse
class VTScan:
    def __init__(self):
        self.headers = {
            "x-apikey": VT_API_KEY,
            "User-Agent": "vtscan v.1.0",
            "Accept-Encoding": "gzip, deflate",
        }

    def upload(self, malware_path):
        print(Colors.BLUE + "upload file: " + malware_path + "..." + Colors.ENDC)
        self.malware_path = malware_path
        upload_url = VT_API_URL + "files"
        files = {"file": (
            os.path.basename(malware_path),
            open(os.path.abspath(malware_path), "rb"))
        }
        print(Colors.YELLOW + "upload to " + upload_url + Colors.ENDC)
        res = requests.post(upload_url, headers=self.headers, files=files)
        if res.status_code == 200:
            result = res.json()
            self.file_id = result.get("data").get("id")
            print(Colors.YELLOW + self.file_id + Colors.ENDC)
            print(Colors.GREEN + "successfully upload PE file: OK" + Colors.ENDC)
        else:
            print(Colors.RED + "failed to upload PE file :(" + Colors.ENDC)
            print(Colors.RED + "status code: " + str(res.status_code) + Colors.ENDC)
            # sys.exit()

    def analyse(self):
        print(Colors.BLUE + "get info about the results of analysis..." + Colors.ENDC)
        analysis_url = VT_API_URL + "analyses/" + self.file_id
        res = requests.get(analysis_url, headers=self.headers)
        if res.status_code == 200:
            result = res.json()
            print("pass 1")
            print("result : {}".format(result))
            status = result.get("data").get("attributes").get("status")
            if status == "completed":
                print("pass 2")
                print("result : {}".format(result))
                with open(os.path.abspath(self.malware_path), "rb") as malware_path:
                    b = malware_path.read()
                    hashsum = hashlib.sha256(b).hexdigest()
                    return self.info(hashsum)
                # entry_point = result.get("data").get("attributes").get("pe_info").get("entry_point")
                # return entry_point
            elif status == "queued":
                print(Colors.BLUE + "status QUEUED..." + Colors.ENDC)
                with open(os.path.abspath(self.malware_path), "rb") as malware_path:
                    b = malware_path.read()
                    hashsum = hashlib.sha256(b).hexdigest()
                    return self.info(hashsum)
        else:
            print(Colors.RED + "failed to get results of analysis :(" + Colors.ENDC)
            print(Colors.RED + "status code: " + str(res.status_code) + Colors.ENDC)
            return None

    def run(self, malware_path):
        self.upload(malware_path)
        return self.analyse()

    def info(self, file_hash):
        print(Colors.BLUE + "get file info by ID: " + file_hash + Colors.ENDC)
        info_url = VT_API_URL + "files/" + file_hash
        res = requests.get(info_url, headers=self.headers)
        if res.status_code == 200:
            result = res.json()
            print("pass 3")
            print("result : {}".format(result))
            entry_point = result.get("data").get("attributes").get("pe_info").get("entry_point")
            packer_name_detectiteasy = None
            packer_name_peid = None
            # try:
            #     packer_name_detectiteasy = result.get("data").get("attributes").get("detectiteasy").get("values").get("name")
            # except Exception:
            #     pass
            #
            # try:
            #     packer_name_PEiD = result.get("data").get("attributes").get("packers").get("PEiD")
            # except Exception:
            #     pass

            # print("entry_point: {}".format(entry_point))
            return entry_point, packer_name_detectiteasy, packer_name_peid, result
        else:
            print(Colors.RED + "failed to get information :(" + Colors.ENDC)
            print(Colors.RED + "status code: " + str(res.status_code) + Colors.ENDC)
            return None

vtscan = VTScan()
def get_done_files():
    done_lists = []
    for idx in range(1, 7):
        with open("/home/hungpt/workspace/research/oep-detection/logs/entry_point_{}.txt".format(idx), "r") as f:
            for line in f:
                line = line.strip()
                name, add = line.split(",")
                done_lists.append(name)
    return done_lists

def test_packer():
    import requests

    api_key = "b28069df4ba529c1c1848699a7b39c98e44f92ee871844f1c118829386af4721"
    resource = "/home/hungpt/Downloads/PackingData-master/PackingData/UPX/upx_AccessEnum.exe"
    url = f"https://www.virustotal.com/vtapi/v2/file/report"

    params = {"apikey": api_key, "resource": resource}

    response = requests.get(url, params=params)
    json_response = response.json()

    if response.status_code == 200:
        print(json_response)
        if "packers" in json_response:
            packers = json_response["packers"]
            if packers:
                packer_name = packers[0]
                print(f"Packer Name: {packer_name}")
            else:
                print("No packer information available for the file.")
        else:
            print("Packer information not found in the response.")
    else:
        print("Error occurred while making the request.")


# Python program to find SHA256 hash string of a file
import hashlib

# filename = input("Enter the input file name: ")

def get_infor_by_hash(filename):
    name_file = os.path.basename(filename)
    name_save = "logs/virustotal/{}.json".format(name_file)
    if os.path.exists(name_save):
        return
    sha256_hash = hashlib.sha256()
    with open(filename, "rb") as f:
        # Read and update hash string value in blocks of 4K
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
        print(sha256_hash.hexdigest())
    # print(vtscan.info(sha256_hash.hexdigest()))
    try:
        entry_point, packer_name_detectiteasy, packer_name_peid, result = vtscan.info(sha256_hash.hexdigest())
        # print("pathhh: {}".format("logs/virustotal/{}.json".format(name_file)))
        with open("logs/virustotal/{}.json".format(name_file), "w") as outfile:
            json.dump(result, outfile, indent=4)
    except Exception as e:
        print(e)
        pass
def run_by_hash():
    # file_name = "/home/hungpt/Desktop/check_virustotal/petitepacked_EventLogChannelsView.exe"
    # folder_path = "/home/hungpt/Desktop/check_virustotal"
    # folder_path = "/home/hungpt/Downloads/PackingData-master/PackingData/MPRESS"
    folder_path = "/media/hungpt/SSD-HUNG/29_samples_telocks/packed"
    files = glob.glob(folder_path + "/*.exe")
    for file in tqdm(files):
        name_file = os.path.basename(file)
        # if name_file != "MPRESS_Desktops.exe":
        #     continue
        name_save = "logs/virustotal/{}.json".format(name_file)
        if os.path.exists(name_save):
            continue
        # vtscan.upload(file)
        # time.sleep(30)
        get_infor_by_hash(file)
        time.sleep(30)

if __name__ == "__main__":
    # parser = argparse.ArgumentParser()
    # # parser.add_argument('-m', '--mal', required=True, help="PE file path for scanning")
    # # args = vars(parser.parse_args())
    # vtscan = VTScan()
    # # print(hex(vtscan.run("/home/hungpt/Downloads/PackingData-master/PackingData/UPX/upx_ADExplorer.exe")))
    # done_lists = get_done_files()
    # with open("logs/file_virustotal_information.txt", "a") as f:
    #     # folder_path = "/home/hungpt/Downloads/win32exe-20230620T135255Z-001/win32exe"
    #     folder_path = "/home/hungpt/Desktop/check_virustotal"
    #
    #     files = glob.glob(folder_path + "/*.exe")
    #     for file in tqdm(files):
    #
    #         try:
    #             name_file = os.path.basename(file)
    #
    #             if name_file in done_lists:
    #                 continue
    #             print(file)
    #             print(name_file)
    #             entry_point, packer_name_detectiteasy, packer_name_PEiD, result = vtscan.run(file)
    #             with open("logs/virustotal/{}.json".format(name_file), "w") as outfile:
    #                 json.dump(result, outfile, indent=4)
    #             print("{}, {}, {}, {}".format(name_file, entry_point, packer_name_detectiteasy, packer_name_PEiD))
    #             f.writelines("{},{},{},{}\n".format(name_file, hex(entry_point), packer_name_detectiteasy, packer_name_PEiD))
    #
    #         except Exception as e:
    #             print(e)
    #             pass
    #         time.sleep(20)
    # #  test_packer()
    run_by_hash()
    # vtscan.info("4732e0d3020e02102adad81eee09141de6b399ca44e39b498831c1a77aba963d")