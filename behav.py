import requests, json, time, shutil

url = "https://www.virustotal.com/api/v3/files"

files = {'file': (open(r"C:\Users\cherif\Documents\pestudio.exe", 'rb'))}

headers = {'x-apikey': 'f18862dd85b0ec074530c0931faab8b9471df84513c521c282b1b3004ba0095d'}

response = requests.post(url, headers=headers, files=files)
#print(response.json())
analysis_id = str(response.json()['data']['id'])

### Summary of behaviour analysis
hash_file = "f3e891a2a39dd948cd85e1c8335a83e640d0987dbd48c16001a02f6b7c1733ae"
#hash_file = "b4e132df99e6920177592fbcd5d6196ffdce836f254863d21839750cf7068251"
url = f"https://www.virustotal.com/api/v3/files/{hash_file}/behaviours"

headers = {
    "accept": "application/json",
    "x-apikey": "f18862dd85b0ec074530c0931faab8b9471df84513c521c282b1b3004ba0095d"
}

response = requests.get(url, headers=headers)

#print(response.json())

# Serializing json
json_object = json.dumps(response.json(), indent=4)

# Writing to behaviour_results.json
with open("behaviour_results.json", "w") as outfile:
    outfile.write(json_object)

# Summary_behaviour

url = f"https://www.virustotal.com/api/v3/files/{hash_file}/behaviour_summary"
headers = {
    "accept": "application/json",
    "x-apikey": "f18862dd85b0ec074530c0931faab8b9471df84513c521c282b1b3004ba0095d"
}

response = requests.get(url, headers=headers)

# Serializing json
json_object = json.dumps(response.json(), indent=4)

# Writing to behaviour_summary_results.json
with open("behaviour_summary_results.json", "w") as outfile:
    outfile.write(json_object)

"""
if response.status_code == 200:
    report = response.json()
else:
    print('Error getting behavior report: ', response.status_code)
    report = None

# Shw the ScreenShots
if report and 'data' in report:
    for behavior in report['data']:
        if 'screenshots' in behavior:
            for screenshot in behavior['screenshots']:
                screenshot_url = screenshot['url']
                print('Screenshot URL: ', screenshot_url)

response = requests.get(screenshot_url, stream=True)
with open('screenshot.png', 'wb') as f:
    response.raw.decode_content = True
    shutil.copyfileobj(response.raw, f)
"""