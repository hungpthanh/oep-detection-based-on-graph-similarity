import requests

url = "https://www.virustotal.com/api/v3/files"

files = {"file": ("upx_Cacheset.exe", open("upx_Cacheset.exe", "rb"), "application/x-ms-dos-executable")}
headers = {
    "accept": "application/json",
    "x-apikey": "asdassdasd"
}

response = requests.post(url, files=files, headers=headers)

print(response.text)