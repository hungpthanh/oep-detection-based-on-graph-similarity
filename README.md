# Original Entry Point detection based on graph similarity
- The official source code for the paper "Original Entry Point detection based on graph similarity"
- This code is undering refactoring process
- This code is for research purpose only
## Requirements
- Python >= 3.7
- networkx 2.6.3

## Usage:
### Dataset
- data: https://drive.google.com/file/d/1PPfADJnTPACcaqwzl1F6PdSsCzDPoloU/view?usp=sharing. (Put it under oep-detection folder)
- test_Gunpacker: https://drive.google.com/file/d/1Mt7ob_eYatPsKxCBPTq6qBMVSH660bjR/view?usp=sharing 
- check_virustotal: https://drive.google.com/file/d/1pDg04V_NoXagZSj97nghNXz7Q5K5dpfp/view?usp=sharing
- log_be_pum_malware_all: https://drive.google.com/file/d/1t4NBAfvUEu8h417HeQ3CY4RY4BWTdC_N/view?usp=sharing

### Evaluation 
- Our method and BE-PUM run this command line:
```bash
python graph_based_method.py --log_path logs/graph_based_method9
```
- Packer identification by VirusTotal and PyPackerDetect <br />
Note: Change the path of folder "check_virustotal" and "test_Gunpacker" in the code.

```bash
python tools/packer_identification_others.py
```

- OEP detection by Gunpacker and QuickUnpack <br />
Note: Change the path of folder "check_virustotal" and "test_Gunpacker" in the code.
```bash
Gunpacker:
python tools/packer_identification_others.py
QuickUnpack:
python tools/OEP_detection_QuickUnpack.py
```

- Packer identification and OEP detection on malware samples: <br />
Change the path of "log_be_pum_malware_all" in the code
```bash
python tools/malware_inference.py
```
### Template matching
```bash
sh scripts/running_[packer_name].sh
```
For example:
```bash
sh scripts/running_upx.sh
```

### Template setup
```bash
python standard_graph_construction.py
```