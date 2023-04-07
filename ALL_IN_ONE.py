import requests, json, time, shutil
import os
import json
import hashlib

def Initial_Connection(hash_file):
    url = "https://www.virustotal.com/api/v3/files"

    files = {'file': (open(r"C:\Users\cherif\Documents\pestudio.exe", 'rb'))}

    headers = {'x-apikey': 'f18862dd85b0ec074530c0931faab8b9471df84513c521c282b1b3004ba0095d'}

    response = requests.post(url, headers=headers, files=files)
    #print(response.json())
    analysis_id = str(response.json()['data']['id'])


    ### Summary of behaviour analysis
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


def is_md4(_hash):
    return hashlib.new('md4').hexdigest() == _hash

def check_for_lockbit_behaviors(json_file):
    
    # Read the file json
    with open(json_file) as f:
        report_data = f.read()
    dictionary = json.loads(report_data)

    # List of common file extensions encrypted by LockBit
    LOCKBIT_EXTENSIONS = [".lockbit", ".abcd", ".sddm", ".lock"]
    

    # List of common registry keys modified by LockBit
    LOCKBIT_REGISTRY_KEYS = [
        r"HKEY_CURRENT_USER\SOFTWARE\LockBit",
        r"HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
        r"HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        r"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
        r"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\*",
        r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\*\ChannelAccess",
        r"HKLM\SOFTWARE\Policies\Microsoft\Windows\System",
        r"HKLM\SOFTWARE\Policies\Microsoft\Windows Defender",
        r"HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection",
        r"HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet",
        r"HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet",
        r"HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile",
        r"HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\StandardProfile",
        "<HKLM>\\Software\\Classes\\.lockbit",
        "<HKLM>\\Software\\Classes\\.lockbit\\DefaultIcon",
        r"HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows NT\CurrentVersion\RunOnce",
        r"HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Run",
        r"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\RunOnce",
        r"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Run",
        r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\WINEVT\Channels",
        r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\WINEVT\Channels\*\ChannelAccess",
        r"HKLM\SOFTWARE\Policies\Microsoft\Windows NT\System",
        r"HKLM\SOFTWARE\Policies\Microsoft\Windows NT Defender",
        r"HKLM\SOFTWARE\Policies\Microsoft\Windows NT Defender\Real-Time Protection",
        r"HKLM\SOFTWARE\Policies\Microsoft\Windows NT Defender\Spynet",
        r"HKLM\SOFTWARE\Policies\Microsoft\Windows NT Defender\Spynet",
        'HKCR\\.lockbit', '\\.lockbit\\DefaultIcon', 'HKCR\\.lockbit\\DefaultIcon',
        r'HKCU\Control Panel\Desktop\WallPaper', r'C:\ProgramData\.lockbit.bmp', r'SOFTWARE\Policies\Microsoft\Windows\OOBE', r'CurrentVersion\Winlogon',

    ]
    
    # Check for suspicious process names associated with LockBit
    SUSPICIOUS_PROCESS_NAMES = ['lockbit.exe', 'chocolatey', 'filezilla', 'Impacket', 'mega', 'procdump', 'lsass.exe', 'psexec', 'mimikatz', 'putty', 'rclone', 'splashtop', 'winscp','dllhost.exe', "svchost"]
    
    PATH_RANSOMWARE = [r"root\Local Settings\Temp", r"Administrator\Local Settings\Temp"]
    power_shell = "powershell Get-ADComputer -filter * -Searchbase '%s' | Foreach-Object { Invoke-GPUpdate -computer $_.name -force -RandomDelayInMinutes 0}"
    SERVICES_KILLED = ["sql", "memtas", "sophos", "svc$","mepocs", "msexchange", "veeam", "backup", "GxVss", "GxBlr", "GxFWD", "GxCVD", "GxCIMgr"]
    PROCESSES_KILLED = ["sql", "oracle", "ocssd","dbsnmp", "synctime", "agntsvc", "isqlplussvc", "xfssvccon", "mydesktopservice", "ocautoupds", "encsvc", "firefox","tbirdconfig", "mydesktopqos", "ocomm","dbeng50", "sqbcoreservice" ",excel","infopath", "msaccess", "mspu","onenote", "outlook", "powerpnt","steam", "thebat", "thunderbird","visio", "winword", "wordpad","notepad"]

    # Check for suspicious files in startup directories
    STARTUP_DIRECTORIES = [
        os.path.join(os.environ["APPDATA"], "Microsoft", "Windows", "Start Menu", "Programs", "Startup"),
        os.path.join(os.environ["USERPROFILE"], "Start Menu", "Programs", "Startup"),
        os.path.join(os.environ["ALLUSERSPROFILE"], "Microsoft", "Windows", "Start Menu", "Programs", "Startup"),
    ]
    
    URLS_SUSPECTS = ["http://lockbit","https://bigblog.at","https://decoding.at","https://www.premiumize.com","https://anonfiles.com","https://www.sendspace.com","https://fex.net","https://transfer.sh","https://send.exploit.in","https://aka.ms/","http://www2.hursley.ibm.com/"]
    NT_DETECTED = ["Restore-My-Files.txt -> ","readme"]
    # Evaluation 
    total = 0


    # Registry Key of file :
    try :
        
        for i in dictionary["data"]["registry_keys_opened"] :
            for j in LOCKBIT_REGISTRY_KEYS:
                if j in i:
                    total += 1
        #print("Total est : "+str(len(dictionary["data"]["registry_keys_opened"]))+"/"+str(total))
    except KeyError:
        total += 0

    # processes terminated
    try:
        for i in dictionary["data"]["processes_terminated"] :
            for j in PROCESSES_KILLED:
                if j in i:
                    total += 1
            for j in SUSPICIOUS_PROCESS_NAMES:
                if j in i:
                    total += 1
        #print("Total est : "+str(len(dictionary["data"]["processes_terminated"]))+"/"+str(total))
    except KeyError:
        total += 0

    # files deleted
    try:
        for i in dictionary["data"]["files_deleted"]:
            for j in LOCKBIT_EXTENSIONS:
                if j in i:
                    total += 1
            for j in PATH_RANSOMWARE:
                if j in i:
                    if ".exe" in i:
                        total += 1
        #print("Total est : "+str(len(dictionary["data"]["files_deleted"]))+"/"+str(total))
    except KeyError:
        total += 0

    # signature matches
    try:
        for i in dictionary["data"]["signature_matches"]:
            for j in i:
                if j == "match_data":
                    for k in i[j]:
                        for l in LOCKBIT_EXTENSIONS:
                            if l.lower() in k.lower():
                                total += 1
                        for l in PATH_RANSOMWARE:
                            if l.lower() in k.lower():
                                if ".exe" in i:
                                    total += 1
                        for l in PROCESSES_KILLED:
                            if l.lower() in k.lower():
                                total += 1
                        for l in SUSPICIOUS_PROCESS_NAMES:
                            if l.lower() in k.lower():
                                total += 1
                        for l in LOCKBIT_REGISTRY_KEYS:
                            if l.lower() in k.lower():
                                total += 1
                        for l in NT_DETECTED:
                            if l.lower() in k.lower():
                                total += 1
                        for l in URLS_SUSPECTS:
                            if l.lower() in k.lower():
                                total += 1
                        for l in STARTUP_DIRECTORIES:
                            if l.lower() in k.lower():
                                total += 1
                        for l in SERVICES_KILLED:
                            if l.lower() in k.lower():
                                total += 1
        #print("Total est : "+str(len(dictionary["data"]["signature_matches"]))+"/"+str(total))
    except KeyError :
        total += 0

    # mutexes created
    try:
        for i in dictionary["data"]["mutexes_created"]:
            if "Global\\" in i:
                #print(i.split("\\")[-1])
                if is_md4(i.split("\\")[-1]) :
                    total += 1
        #print("Total est : "+str(len(dictionary["data"]["mutexes_created"]))+"/"+str(total))
    except KeyError :
        total += 0

    # files_opened
    try:
        for i in dictionary["data"]["files_opened"]:
            for j in LOCKBIT_EXTENSIONS:
                if j in i:
                    total += 1
            for j in PATH_RANSOMWARE:
                if j in i:
                    if ".exe" in i:
                        total += 1
            for j in PROCESSES_KILLED:
                if j in i:
                    total += 1
            for j in SUSPICIOUS_PROCESS_NAMES:
                if j in i:
                    total += 1
            for j in STARTUP_DIRECTORIES:
                if j in i:
                    total += 1
        #print("Total est : "+str(len(dictionary["data"]["files_opened"]))+"/"+str(total))
    except KeyError:
        total += 0

    # registry_keys_set
    try:
        for i in dictionary["data"]["registry_keys_set"]:
            cpt = 0
            for j in i:
                if j in "key" and i[j] in r"HKLM\SOFTWARE\Policies\Microsoft\Windows\System":
                    cpt = 1
                if (cpt == 1 and j in "value") and ("GroupPolicyRefreshTimeDC" in i[j] or "GroupPolicyRefreshTimeOffsetDC" in i[j]  or "GroupPolicyRefreshTime" in i[j] or "GroupPolicyRefreshTimeOffset" in i[j] or "EnableSmartScreen" in i[j] or "**del.ShellSmartScreenLevel" in i[j]):
                    total += 1
                
                if j in "key" and i[j] in r"HKLM\SOFTWARE\Policies\Microsoft\Windows Defender":
                    cpt = 1
                if (cpt == 1 and j in "value") and ("DisableAntiSpyware" in i[j] or "DisableRoutinelyTakingAction" in i[j] ):
                    total += 1

                if j in "key" and i[j] in r"HKLM\SOFTWARE\Policies\Microsoft\Windows  Defender\Real-Time Protection":
                    cpt = 1
                if (cpt == 1 and j in "value") and ("DisableRealtimeMonitoring" in i[j] or "DisableBehaviorMonitoring" in i[j] ):
                    total += 1
                
                if j in "key" and i[j] in r"HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet":
                    cpt = 1
                if (cpt == 1 and j in "value") and ("SubmitSamplesConsent" in i[j] or "SpynetReporting" in i[j] ):
                    total += 1

                if j in "key" and i[j] in r"HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile":
                    cpt = 1
                if (cpt == 1 and j in "value") and ("EnableFirewall"):
                    total += 1
                
                if j in "key" and i[j] in r"HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\StandardProfile":
                    cpt = 1
                if (cpt == 1 and j in "value") and ("EnableFirewall"):
                    total += 1
        
        #print("Total est : "+str(len(dictionary["data"]["registry_keys_set"]))+"/"+str(total))
    except KeyError :
        total += 0

    # processes_created
    try:
        for i in dictionary["data"]["processes_created"]:
            for j in LOCKBIT_EXTENSIONS:
                if j in i:
                    total += 1
            for j in PATH_RANSOMWARE:
                if j in i:
                    if ".exe" in i:
                        total += 1
            for j in PROCESSES_KILLED:
                if j in i:
                    total += 1
            for j in SUSPICIOUS_PROCESS_NAMES:
                if j in i:
                    total += 1
            for j in STARTUP_DIRECTORIES:
                if j in i:
                    total += 1
        #print("Total est : "+str(len(dictionary["data"]["processes_created"]))+"/"+str(total))
    except KeyError:
        total += 0

    # attack_techniques
    try :
        mitre_techniques = ["T1078","T1133","T1189","T1190","T1566","TA0002","T1072","T1547","TA0004","T1027","T1070.004","T1480.001","T1003.001","T1046","T1082","T1614.001","T1021.001","T1071.002","T1572","TA0010","T1567","T1567.002","T1485","T1486","T1489","T1490","T1491.001"]
        total += 0
        for i in dictionary["data"]["attack_techniques"]:
            for j in mitre_techniques:
                if j in i:
                    total += 1
        #print("Total est : "+str(len(dictionary["data"]["mitre_attack_techniques"]))+"/"+str(total))
    except KeyError:
        total += 0

    # ip_traffic
    """for i in dictionary["data"]["ip_traffic"]:
        print(i)"""
    
    # files_copied
    try:
        for i in dictionary["data"]["files_copied"]:
            for j in LOCKBIT_EXTENSIONS:
                if j in i["destination"]:
                    total += 1
        #print("Total est : "+str(4 * len(dictionary["data"]["files_copied"]))+"/"+str(total))
    except KeyError:
        total += 0

    # files_written
    try:
        for i in dictionary["data"]["files_written"]:
            for j in LOCKBIT_EXTENSIONS:
                if j in i:
                    total += 1
            for j in SUSPICIOUS_PROCESS_NAMES:
                if j in i:
                    total += 1
            for j in STARTUP_DIRECTORIES:
                if j in i:
                    total += 1
        #print("Total est : "+str(len(dictionary["data"]["files_written"]))+"/"+str(total))
    except KeyError:
        total += 0

    # files_dropped
    try:
        for i in dictionary["data"]["files_dropped"]:
            for j in LOCKBIT_EXTENSIONS:
                if j in i["path"]:
                    total += 1
            for j in SUSPICIOUS_PROCESS_NAMES:
                if j in i["path"]:
                    total += 1
            for j in STARTUP_DIRECTORIES:
                if j in i["path"]:
                    total += 1
        #print("Total est : "+str(len(dictionary["data"]["files_dropped"]))+"/"+str(total))
    except KeyError:
        total += 0

    # command_executions
    try:
        for i in dictionary["data"]["command_executions"]:
            if power_shell in i:
                total += 1

        #print("Total est : "+str(2*len(dictionary["data"]["files_dropped"]))+"/"+str(total))
    except KeyError:
        total += 0

    # services_opened
    try:
        for i in dictionary["data"]["services_opened"]:
            for j in SUSPICIOUS_PROCESS_NAMES:
                if j in i:
                    total += 1
            for j in SERVICES_KILLED:
                if j in i:
                    total += 1
        #print("Total est : "+str(len(dictionary["data"]["services_opened"]))+"/"+str(total))
    except KeyError:
        total += 0

    # memory_pattern_urls
    try:
        for i in dictionary["data"]["memory_pattern_urls"]:
            for j in URLS_SUSPECTS:
                if j in i:
                    total += 1
            
        #print("Total est : "+str(len(dictionary["data"]["memory_pattern_urls"]))+"/"+str(total))
    except KeyError:
        total += 0

    # Calculate the probs
    print("[Lockbit] ~ La somme de tout est : "+str(total))
    return total

def check_for_wannacry_behaviors(json_file):
    total = 0
    # Read the file json
    with open(json_file) as f:
        report_data = f.read()
    dictionary = json.loads(report_data)

    # List of common file extensions encrypted by WANNACRY
    WANNACRY_EXTENSIONS = [".wnry",".wncryt"]
    

    # List of common registry keys modified by WANNACRY
    WANNACRY_REGISTRY_KEYS = [
        r"HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\mssecsvc2.0",
        r"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\tasksche.exe",
        r"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\@WanaDecryptor@.exe",
        r"HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Cryptography\Defaults\Provider Types\Type 001",
        r"HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Cryptography\Defaults\Provider Types\Type 024",
        r"HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Cryptography\Defaults\Provider\Microsoft Enhanced RSA and AES Cryptographic Provider",
        r"HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Cryptography\Defaults\Provider\Microsoft Strong Cryptographic Provider",
        r"HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Internet Explorer\Security",
        r"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters",
        r"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        r"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\msseces.exe",
        r"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\msmpeng.exe",
        r"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile",
        r"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\mssecsvc2.0",
        "HKEY_LOCAL_MACHINE\\SOFTWARE\\WOW6432Node\\WanaCrypt0r\\wd",
        r"HKLM\SOFTWARE\Wow6432Node\WanaCrypt0r\wd",
        "HKEY_LOCAL_MACHINE\\SOFTWARE\\WOW6432Node\\Microsoft\\Cryptography\\Defaults\\Provider\\Microsoft Enhanced RSA and AES Cryptographic Provider",
        "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Tracing\\"
    ]
    # RASAPI32 - RASMANCS
    # Check for suspicious process names associated with WANNACRY
    SUSPICIOUS_PROCESS_NAMES = ["CRYPT32.dll.mui","bcryptPrimitives.dll","bcrypt.dll","CRYPTSP.dll","CRYPTBASE.dll","readme.dll","svchost.exe","C:\\Windows\\mssecsvr.exe","f.wnry","b.wnry","c.wnry", "svchost","@WanaDecryptor@.exe","r.wnry","s.wnry","t.wnry","taskdl.exe","taskse.exe","u.wnry","wmic","vssadmin","bcdedit","rpcrtremote.dll","bcryptprimitives.dll","crypt32.dll","cryptsp.dll","cryptbase.dll"]
    PATH_RANSOMWARE = ["C:\\ProgramData\\Microsoft\\Crypto\\RSA","C:\\Windows\\system32\\rsaenh.dll","C:\\Users\\All Users\\Microsoft\\Crypto\\RSA\\"]
    power_shell_cmd = ["%windir%\\System32\\svchost.exe -k WerSvcGroup","%WinDir%\tasksche.exe","cmd.exe /c vssadmin delete shadows /all /quiet", 
    "wmic shadowcopy delete", "bcdedit /set {default} bootstatuspolicy ignoreallfailures","bcdedit /set {default} recoveryenabled no",
    "wbadmin delete catalog \–quiet"]

    # Check for suspicious network connections associated with WANNACRY
    suspicious_network_port = [22,135,443,445,1433,1434,3389,4343,5000,5985,5355]
    suspicious_network_ips = ["68.183.20.194","83.97.20.160","159.89.140.116","192.99.178.145","23.106.160.174","162.244.80.235","85.93.88.165","185.141.63.120","82.118.21.1","1.177.172.158","104.244.76.44","122.51.149.86","176.9.1.211","176.9.98.228","18.27.197.252","185.130.44.108","185.220.103.4","2.82.175.32","217.160.251.63","218.92.0.211","45.153.160.134","46.101.236.25","49.234.143.71","51.75.171.136","54.36.108.162","6.11.76.81","61.177.172.158","64.113.32.29","66.211.197.38"]
    # Positive Technologies says you should also be looking for connections to the Tor network on ports 9001 and 9003.
    # SMBv1 ports TCP 445 and 139, as well as DNS queries for the kill switch domain.

    
    URLS_SUSPECTS = ["http://www.iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com",
                    "iuqerfsodp9ifjaposdfjhgosurijfaewrwergwff.com",
                    "gx7ekbenv2riucmf.onion",
                    "cwwnhwhlz52maqm7.onion",
                    "57g7spgrzlojinas.onion", 
                    "https://www.kryptoslogic.com",
                    "xxlvbrloxvriy2c5.onion",
                    "76jdd2ir2embyv47.onion"]
    
    NT_DETECTED = ["@Please_Read_Me@.txt"]
    # http_conversations
    try:
        for i in dictionary["data"]["http_conversations"] :
            for j in URLS_SUSPECTS:
                if j in i["url"]:
                    total += 1
    except KeyError:
        total += 0
    # Registry Key of file :
    try:
        for i in dictionary["data"]["registry_keys_opened"] :
            for j in WANNACRY_REGISTRY_KEYS:
                if j in i and j in "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Tracing\\":
                    if "RASAPI32" in i or "RASMANCS" in i:
                        total += 1
                if j in i:
                    total += 1
        #print("Total registry_keys_opened est : "+str(len(dictionary["data"]["registry_keys_opened"]))+"/"+str(total))
    except KeyError:
        total += 0

    # processes terminated
    try:
        for i in dictionary["data"]["processes_terminated"] :
            for j in SUSPICIOUS_PROCESS_NAMES:
                if j in i:
                    total += 1
            for j in power_shell_cmd:
                if j in i:
                    total += 1
        #print("Total processes_terminated est : "+str(len(dictionary["data"]["processes_terminated"]))+"/"+str(total))
    except KeyError:
        total += 0

    # files deleted
    try:
        for i in dictionary["data"]["files_deleted"]:
            for j in WANNACRY_EXTENSIONS:
                if j in i:
                    total += 1
            for j in PATH_RANSOMWARE:
                if j in i:
                    total += 1
            for j in SUSPICIOUS_PROCESS_NAMES:
                if j in i:
                    total += 1
        #print("Total files_deleted est : "+str(len(dictionary["data"]["files_deleted"]))+"/"+str(total))
    except KeyError:
        total += 0

    # signature matches
    try:
        for i in dictionary["data"]["signature_matches"]:
            for j in i:
                if j == "match_data":
                    for k in i[j]:
                        for l in WANNACRY_EXTENSIONS:
                            if l.lower() in k.lower():
                                total += 1
                        for l in PATH_RANSOMWARE:
                            if l.lower() in k.lower():
                                if ".exe" in i:
                                    total += 1
                        for l in SUSPICIOUS_PROCESS_NAMES:
                            if l.lower() in k.lower():
                                total += 1
                        for l in WANNACRY_REGISTRY_KEYS:
                            if l.lower() in k.lower():
                                total += 1
                        for l in NT_DETECTED:
                            if l.lower() in k.lower():
                                total += 1
                        for l in URLS_SUSPECTS:
                            if l.lower() in k.lower():
                                total += 1
        #print("Total signature matches est : "+str(len(dictionary["data"]["signature_matches"]))+"/"+str(total))
    except KeyError :
        total += 0
    # modules_loaded
    try :
        cpt_modules_loaded = 0
        for i in dictionary["data"]["modules_loaded"]:
            for j in WANNACRY_EXTENSIONS:
                if j.lower() in i.lower():
                    cpt_modules_loaded += 1
            for j in SUSPICIOUS_PROCESS_NAMES:
                if j.lower() in i.lower():
                    cpt_modules_loaded += 1
            for j in PATH_RANSOMWARE:
                if j.lower() in i.lower():
                    cpt_modules_loaded += 1
        #print("Total modules_loaded est : "+str(len(dictionary["data"]["modules_loaded"]))+"/"+str(cpt_modules_loaded))
    except KeyError :
        total += 0

    # memory_pattern_domains
    try :
        for i in dictionary["data"]["memory_pattern_domains"]:
            for j in URLS_SUSPECTS:
                if j in i:
                    total += 1
        #print("Total  memory_pattern_domains est : "+str(len(dictionary["data"]["memory_pattern_domains"]))+"/"+str(total))
    except KeyError :
        total += 0

    # mutexes created
    try:
        for i in dictionary["data"]["mutexes_created"]:
            if "Global\\MsWinZonesCacheCounterMutexA0" in i:
                total += 1
        #print("Total mutexes created est : "+str(len(dictionary["data"]["mutexes_created"]))+"/"+str(total))
    except KeyError :
        total += 0

    # text_decoded
    try :
        cpt_text_decoded = 0
        for i in dictionary["data"]["text_decoded"]:
            if "WANACRY" in i:
                cpt_text_decoded += 1
        #print("Total cpt_text_decoded est : "+str(len(dictionary["data"]["text_decoded"]))+"/"+str(cpt_text_decoded))
    except KeyError :
        cpt_text_decoded = 0

    # files_opened
    try:
        for i in dictionary["data"]["files_opened"]:
            for j in WANNACRY_EXTENSIONS:
                if j.lower() in i.lower():
                    total += 1
            for j in PATH_RANSOMWARE:
                if j.lower() in i.lower():
                    if ".exe" in i:
                        total += 1
            for j in SUSPICIOUS_PROCESS_NAMES:
                if j.lower() in i.lower():
                    total += 1

        #print("Total files_opened est : "+str(len(dictionary["data"]["files_opened"]))+"/"+str(total))
    except KeyError:
        total += 0

    #registry_keys_set
    try:
        for i in dictionary["data"]["registry_keys_set"]:
            for j in i:
                if j in "key":
                    for k in WANNACRY_REGISTRY_KEYS:
                        if k in i[j]:
                            total +=1
        
        #print("Total registry_keys_set est : "+str(len(dictionary["data"]["registry_keys_set"]))+"/"+str(total))
    except KeyError :
        total += 0
        
    # registry_keys_deleted
    try :
        totalistry_keys_deleted = 0
        for i in dictionary["data"]["registry_keys_deleted"]:
            for j in WANNACRY_REGISTRY_KEYS:
                if j in i:
                    totalistry_keys_deleted +=1
        
        #print("Total registry_keys_deleted est : "+str(len(dictionary["data"]["registry_keys_deleted"]))+"/"+str(totalistry_keys_deleted))
    except KeyError :
        total += 0

    # processes_created
    try:
        for i in dictionary["data"]["processes_created"]:
            for j in WANNACRY_EXTENSIONS:
                if j in i:
                    total += 1
            for j in PATH_RANSOMWARE:
                if j in i:
                    if ".exe" in i:
                        total += 1
            for j in SUSPICIOUS_PROCESS_NAMES:
                if j in i:
                    total += 1
            for j in power_shell_cmd:
                if j in i:
                    total += 1
        #print("Total processes_created est : "+str(len(dictionary["data"]["processes_created"]))+"/"+str(total))
    except KeyError:
        total += 0

    # attack_techniques
    try :
        mitre_techniques = ["T1543.003","T1486","T1573.002","T1210","T1083","T1222.001","T1564.001","T1490","T1570","T1120","T1090.003","T1563.002","T1018","T1489","T1016","T1047","T0866","T0867"]
        total += 0
        for i in dictionary["data"]["attack_techniques"]:
            for j in mitre_techniques:
                if j in i:
                    total += 1
        #print("Total total est : "+str(len(dictionary["data"]["mitre_attack_techniques"]))+"/"+str(total))
    except KeyError:
        total += 0

    # ip_traffic

    try :
        for i in dictionary["data"]["ip_traffic"]:
            for j in i:
                if j in "destination_port":
                    for k in suspicious_network_port:
                        if k == i[j]:
                            total += 1
                if j in "destination_ip":
                    for k in suspicious_network_ips:
                        if k in i[j]:
                            total += 1
        #print("Total ip_traffic est : "+str(len(dictionary["data"]["ip_traffic"]))+"/"+str(total))
    except KeyError:
        total += 0
    
    # files_copied
    try:
        for i in dictionary["data"]["files_copied"]:
            for j in SUSPICIOUS_PROCESS_NAMES:
                if j in i["destination"]:
                    total += 1
        #print("Total files_copied est : "+str(4 * len(dictionary["data"]["files_copied"]))+"/"+str(total))
    except KeyError:
        total += 0

    # files_written
    try:
        for i in dictionary["data"]["files_written"]:
            for j in WANNACRY_EXTENSIONS:
                if j in i:
                    total += 1
            for j in SUSPICIOUS_PROCESS_NAMES:
                if j in i:
                    total += 1
            for j in PATH_RANSOMWARE:
                if j in i:
                    total += 1
            
        #print("Total files_written est : "+str(len(dictionary["data"]["files_written"]))+"/"+str(total))
    except KeyError:
        total += 0

    # files_dropped
    try:
        for i in dictionary["data"]["files_dropped"]:
            for j in i:
                if "path" in j:
                    for k in WANNACRY_EXTENSIONS:
                        if k in i[j]:
                            total += 1
                    for k in SUSPICIOUS_PROCESS_NAMES:
                        if k in i[j]:
                            total += 1
                    for k in PATH_RANSOMWARE:
                        if k in i[j]:
                            total += 1
                    for k in NT_DETECTED:
                        if k in i[j]:
                            total += 1
            
        #print("Total files_dropped est : "+str(len(dictionary["data"]["files_dropped"]))+"/"+str(total))
    except KeyError:
        total += 0

    # command_executions
    try:
        for i in dictionary["data"]["command_executions"]:
            for j in power_shell_cmd :
                if j in i:
                    total += 1
        #print("Total command_executions est : "+str(2*len(dictionary["data"]["files_dropped"]))+"/"+str(total))
    except KeyError:
        total += 0

    
    # memory_pattern_urls
    try:
        for i in dictionary["data"]["memory_pattern_urls"]:
            for j in URLS_SUSPECTS:
                if j in i:
                    total += 1
            
        #print("Total memory_pattern_urls est : "+str(len(dictionary["data"]["memory_pattern_urls"]))+"/"+str(total))
    except KeyError:
        total += 0
    # processes_tree
    try :
        
        for i in dictionary["data"]["processes_tree"]:
            for j in WANNACRY_EXTENSIONS:
                if j.lower() in i["name"].lower():
                    total += 1
            for j in PATH_RANSOMWARE:
                if j.lower() in i["name"]:
                    total += 1
            for j in SUSPICIOUS_PROCESS_NAMES:
                if j.lower() in i["name"]:
                    total += 1
            for j in power_shell_cmd:
                if j in i:
                    total += 1
        #print("Total processes_tree est : "+str(len(dictionary["data"]["processes_tree"]))+"/"+str(total))
    except KeyError:
        total += 0

    # Calculate the probs
    print("[WANNACRY] ~ La somme de tout est : "+str(total))

def check_for_conti_behaviors(json_file):
    # Somme total 
    total = 0

    # Read the file json
    with open(json_file) as f:
        report_data = f.read()
    dictionary = json.loads(report_data)

    # List of common file extensions encrypted by CONTI
    CONTI_EXTENSIONS = [".conti",".enc",".CIop",".gefsera"]
    
    # List of common registry keys modified by CONTI
    CONTI_REGISTRY_KEYS = [
        "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Cryptography\\Defaults\\Provider\\Microsoft Enhanced RSA and AES Cryptographic Provider",
        "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\AppCompatFlags\\Custom\\net.exe",
        r"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\Conti",
        r"HKEY_CURRENT_USER\Software\Conti",
        r"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Conti",
        r"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Hidden",
        r"HKEY_CURRENT_USER\Control Panel\Desktop\Wallpaper",
        "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Policies\\Microsoft\\Cryptography\\Configuration",
        "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Cryptography\\Defaults\\Provider\\Microsoft Strong Cryptographic Provider",
        "HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Rpc\\Extensions",
        "HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows NT\\Rpc",
        r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
        r"HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce",
        r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
        r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunServices",
        r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Zones",
        r"HKLM\SYSTEM\CurrentControlSet\Services",
        r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options",
        r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell",
        r"HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run",
        r"HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\System",
        r"HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced",
        r"HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\BootExecute",
        r"HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\DisableAntiSpyware",
        r"HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Monitoring\DisableRealtimeMonitoring",
        r"HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Monitoring\DisableBehaviorMonitoring",
        r"HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Monitoring\DisableIntrusionPreventionSystem",
        r"HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection"
    ]

    # Check for suspicious process names associated with CONTI
    SUSPICIOUS_PROCESS_NAMES = ["readme.dll","srv.txt","wm_start.bat","copy_files_srv.bat","rclone.exe","README.txt","ShellExperienceHost.exe","net.exe","conti_readme.txt", "taskdl.exe", "cobaltstrike.exe", "powershell.exe", "rundll32.exe", "wscript.exe", "lsass.exe", "svchost.exe", "explorer.exe", "spoolsv.exe","crypt32.dll","bcrypt.dll","ncrypt.dll","CRYPTBASE.dll","CRYPTSP.dll"]
    PATH_RANSOMWARE = [r"c:\windows\192145.dll,StartW",r"C:\Windows\System32\dllhost.exe 	",r"C:\Users\USER\AppData\Local\Temp\icju1.exe 	",r"C:\Windows\System32\dllhost.exe","%CONHOST%","C:\\ProgramData\\Microsoft\\Crypto\\RSA","C:\\Windows\\system32\\rsaenh.dll","C:\\Users\\All Users\\Microsoft\\Crypto\\RSA\\","c:\\programdata\\microsoft\\crypto\\rsa\\","C:\\Documents and Settings\\All Users\\Microsoft\\Crypto\\RSA\\"]
    power_shell_cmd = ["cmd.exe /C portscan","cmd.exe /C wmic /node:","C:\Programdata\sys.dll entryPoint",
                        "cmd.exe /C nltest /dclist:","cmd.exe /C net group “domain Admins” /domain",
                        "cmd.exe /C nltest /DOMAIN_TRUSTS","cmd.exe /C adft.bat","cmd.exe /C type shares.txt",
                        "cmd.exe /c %windir%\\System32\\wbem\\WMIC.exe shadowcopy where","%windir%\\System32\\wbem\\WMIC.exe  shadowcopy where"]

    # Check for suspicious network connections associated with CONTI
    SUSPICIOUS_NETWORK_IPS = ["68.183.20.194","83.97.20.160","159.89.140.116","192.99.178.145","23.106.160.174","162.244.80.235","85.93.88.165","185.141.63.120","82.118.21.1","1.177.172.158","104.244.76.44","122.51.149.86","176.9.1.211","176.9.98.228","18.27.197.252","185.130.44.108","185.220.103.4","2.82.175.32","217.160.251.63","218.92.0.211","45.153.160.134","46.101.236.25","49.234.143.71","51.75.171.136","54.36.108.162","6.11.76.81","61.177.172.158","64.113.32.29","66.211.197.38"]
    SUSPICIOUS_NETWORK_PORT = [22,135,443,445,1433,1434,3389,4343,5000,5985,5355]
    URLS_SUSPECTS = ["dimentos.com","thulleultinn.club","dictorecovery.cyou","expertulthima.club","vaclicinni.xyz","oxythuler.cyou","docns.com/OrderEntryService.asmx/AddOrderLine","Docns.com/us/ky/louisville/312-s-fourth-st.html",'badiwaw.com', 'balacif.com', 'barovur.com', 'basisem.com', 'bimafu.com', 'bujoke.com', 'buloxo.com', 'bumoyez.com', 'bupula.com', 'fipoleb.com', 'fofudir.com', 'fulujam.com', 'ganobaz.com', 'gerepa.com', 'gucunug.com', 'guvafe.com', 'hakakor.com', 'hejalij.com', 'kipitep.com', 'kirute.com', 'kogasiv.com', 'kozoheh.com', 'kuxizi.com', 'kuyeguh.com', 'lipozi.com', 'lujecuk.com', 'masaxoc.com', 'pihafi.com', 'pilagop.com', 'pipipub.com', 'pofifa.com', 'radezig.com', 'raferif.com', 'ragojel.com', 'rexagi.com', 'rimurik.com', 'tiyuzub.com', 'tubaho.com', 'vafici.com', 'vegubu.com', 'vigave.com', 'vipeced.com', 'vizosi.com', 'vojefe.com', 'vonavu.com', 'cajeti.com', 'cilomum.com', 'codasal.com', 'comecal.com', 'dawasab.com', 'derotin.com', 'dihata.com', 'dirupun.com', 'dohigu.com', 'dubacaj.com', 'fecotis.com', 'hepide.com', 'hesovaw.com', 'hewecas.com', 'hidusi.com', 'hireja.com', 'hoguyum.com', 'jecubat.com', 'jegufe.com', 'joxinu.com', 'kelowuh.com', 'kidukes.com', 'mebonux.com', 'mihojip.com', 'modasum.com', 'moduwoj.com', 'movufa.com', 'nagahox.com', 'nawusem.com', 'nerapo.com', 'newiro.com', 'paxobuy.com', 'pazovet.com', 'rinutov.com', 'rusoti.com', 'sazoya.com', 'sidevot.com', 'solobiv.com', 'sufebul.com', 'suhuhow.com', 'sujaxa.com', 'tafobi.com', 'tepiwo.com', 'tifiru.com', 'wezeriw.com', 'wideri.com', 'wudepen.com', 'wuluxo.com', 'wuvehus.com', 'wuvici.com', 'wuvidi.com', 'xegogiv.com', 'xekezix.com']
    NT_DETECTED = ["locked","decrypt","encrypted by conti","Need restore files?"]
    # Registry Key of file :
    try :
        for i in dictionary["data"]["registry_keys_opened"] :
            for j in CONTI_REGISTRY_KEYS:
                if j in i:
                    total += 1
        #print("Total registry_keys_opened est : "+str(len(dictionary["data"]["registry_keys_opened"]))+"/"+str(total))
    except KeyError:
        total += 0

    # processes terminated
    try :
        
        for i in dictionary["data"]["processes_terminated"] :
            for j in SUSPICIOUS_PROCESS_NAMES:
                if j.lower() in i.lower():
                    total += 1
            for j in power_shell_cmd:
                if j in i:
                    total += 1
            for j in PATH_RANSOMWARE:
                if j in i:
                    total += 1
        #print("Total processes_terminated est : "+str(len(dictionary["data"]["processes_terminated"]))+"/"+str(total))
    except KeyError:
        total += 0

    # files deleted
    try :
        
        for i in dictionary["data"]["files_deleted"]:
            for j in CONTI_EXTENSIONS:
                if j.lower() in i.lower():
                    total += 1
            for j in PATH_RANSOMWARE:
                if j.lower() in i.lower():
                    total += 1
            for j in SUSPICIOUS_PROCESS_NAMES:
                if j.lower() in i.lower():
                    total += 1
        #print("Total files_deleted est : "+str(len(dictionary["data"]["files_deleted"]))+"/"+str(total))
    except KeyError:
        total += 0
    # processes_tree
    try :
        
        for i in dictionary["data"]["processes_tree"]:
            for j in CONTI_EXTENSIONS:
                if j.lower() in i["name"].lower():
                    total += 1
            for j in PATH_RANSOMWARE:
                if j.lower() in i["name"]:
                    total += 1
            for j in SUSPICIOUS_PROCESS_NAMES:
                if j.lower() in i["name"]:
                    total += 1
            for j in power_shell_cmd:
                if j in i:
                    total += 1
        #print("Total processes_tree est : "+str(len(dictionary["data"]["processes_tree"]))+"/"+str(total))
    except KeyError:
        total += 0

    # signature matches
    try :
        
        for i in dictionary["data"]["signature_matches"]:
            for j in i:
                if j == "match_data":
                    for k in i[j]:
                        for l in CONTI_EXTENSIONS:
                            if l.lower() in k.lower():
                                total += 1
                        for l in PATH_RANSOMWARE:
                            if l.lower() in k.lower():
                                total += 1
                        for l in SUSPICIOUS_PROCESS_NAMES:
                            if l.lower() in k.lower():
                                total += 1
                        for l in CONTI_REGISTRY_KEYS:
                            if l.lower() in k.lower():
                                total += 1
                        for l in NT_DETECTED:
                            if l.lower() in k.lower():
                                total += 1
                        for l in URLS_SUSPECTS:
                            if l.lower() in k.lower():
                                total += 1
        #print("Total signature matches est : "+str(len(dictionary["data"]["signature_matches"]))+"/"+str(total))
    except KeyError :
        total += 0
    # modules_loaded
    try :
        
        for i in dictionary["data"]["modules_loaded"]:
            for j in CONTI_EXTENSIONS:
                if j.lower() in i.lower():
                    total += 1
            for j in SUSPICIOUS_PROCESS_NAMES:
                if j.lower() in i.lower():
                    total += 1
            for j in PATH_RANSOMWARE:
                if j.lower() in i.lower():
                    total += 1
        #print("Total modules_loaded est : "+str(len(dictionary["data"]["modules_loaded"]))+"/"+str(total))
    except KeyError :
        total += 0

    # memory_pattern_domains
    try :
        
        for i in dictionary["data"]["memory_pattern_domains"]:
            for j in URLS_SUSPECTS:
                if j.lower() in i.lower() :
                    total += 1
        #print("Total  memory_pattern_domains est : "+str(len(dictionary["data"]["memory_pattern_domains"]))+"/"+str(total))
    except KeyError :
        total += 0

    # mutexes created
    try :
        
        for i in dictionary["data"]["mutexes_created"]:
            if "_CONTI_" in i or "\\Sessions\\1\\BaseNamedObjects\\_CONTI_" in i:
                total += 1
        for i in dictionary["data"]["mutexes_opened"]:
            if "_CONTI_" in i or "\\Sessions\\1\\BaseNamedObjects\\_CONTI_" in i:
                total += 1
        #print("Total mutexes created and opened est : "+str(len(dictionary["data"]["mutexes_created"]))+"/"+str(total))
    except KeyError :
        total += 0

    # text_decoded
    try :
        
        for i in dictionary["data"]["text_decoded"]:
            if "CONTI" in i:
                total += 1
            for j in NT_DETECTED:
                if j in i:
                    total += 1
        #print("Total total est : "+str(len(dictionary["data"]["text_decoded"]))+"/"+str(total))
    except KeyError :
        total += 0

    # files_opened
    try :
        
        for i in dictionary["data"]["files_opened"]:
            for j in CONTI_EXTENSIONS:
                if j.lower() in i.lower():
                    total += 1
            for j in PATH_RANSOMWARE:
                if j.lower() in i.lower():
                    total += 1
            for j in SUSPICIOUS_PROCESS_NAMES:
                if j.lower() in i.lower():
                    total += 1

        #print("Total files_opened est : "+str(len(dictionary["data"]["files_opened"]))+"/"+str(total))
    except KeyError:
        total += 0

    #registry_keys_set
    try :
        
        for i in dictionary["data"]["registry_keys_set"]:
            for j in i:
                if j in "key":
                    for k in CONTI_REGISTRY_KEYS:
                        if k in i[j]:
                            total +=1
        
        #print("Total registry_keys_set est : "+str(len(dictionary["data"]["registry_keys_set"]))+"/"+str(total))
    except KeyError :
        total += 0
        
    # registry_keys_deleted
    try :
        
        for i in dictionary["data"]["registry_keys_deleted"]:
            for j in CONTI_REGISTRY_KEYS:
                if j in i:
                    total +=1
        
        #print("Total registry_keys_deleted est : "+str(len(dictionary["data"]["registry_keys_deleted"]))+"/"+str(total))
    except KeyError :
        total += 0

    # processes_created
    try :
        
        for i in dictionary["data"]["processes_created"]:
            for j in CONTI_EXTENSIONS:
                if j.lower() in i.lower():
                    total += 1
            for j in PATH_RANSOMWARE:
                if j.lower() in i.lower():
                    total += 1
            for j in SUSPICIOUS_PROCESS_NAMES:
                if j.lower() in i.lower():
                    total += 1
            for j in power_shell_cmd:
                if j in i:
                    total += 1
        #print("Total processes_created est : "+str(len(dictionary["data"]["processes_created"]))+"/"+str(total))
    except KeyError:
        total += 0

    # attack_techniques
    try :
        mitre_techniques = ["TA0004","TA0006","TA0007","TA0011","TA0010","T1016","T1018","T1021.002","T1027","T1049","T1055.001","T1057","T1059","T1059.003","T1078","T1080","T1083","T1106","T1110","T1133","T1135","T1140","T1190","T1486"
                            "T1489","T1490","T1558.003","T1566.001","T1566.002","T1567"]
        
        for i in dictionary["data"]["attack_techniques"]:
            for j in mitre_techniques:
                if j in i:
                    total += 1
        #print("Total total est : "+str(len(dictionary["data"]["mitre_attack_techniques"]))+"/"+str(total))
    except KeyError:
        total += 0

    # ip_traffic
    
    try :
        for i in dictionary["data"]["ip_traffic"]:
            for j in i:
                if j in "destination_ip":
                    for k in SUSPICIOUS_NETWORK_IPS:
                        if k in i[j]:
                            total += 1
                if j in "destination_port":
                    for k in SUSPICIOUS_NETWORK_PORT:
                        if k == i[j]:
                            total += 1
        #print("Total ip_traffic est : "+str(5*len(dictionary["data"]["ip_traffic"]))+"/"+str(total))
    except KeyError:
        total += 0
    
    # files_copied
    try :
        
        for i in dictionary["data"]["files_copied"]:
            for j in SUSPICIOUS_PROCESS_NAMES:
                if j.lower() in i["destination"].lower():
                    total += 1
        #print("Total files_copied est : "+str(4 * len(dictionary["data"]["files_copied"]))+"/"+str(total))
    except KeyError:
        total += 0

    # files_written
    try :
        
        for i in dictionary["data"]["files_written"]:
            for j in CONTI_EXTENSIONS:
                if j.lower() in i.lower():
                    total += 1
            for j in SUSPICIOUS_PROCESS_NAMES:
                if j.lower() in i.lower():
                    total += 1
            for j in PATH_RANSOMWARE:
                if j.lower() in i.lower():
                    total += 1
            
        #print("Total files_written est : "+str(len(dictionary["data"]["files_written"]))+"/"+str(total))
    except KeyError:
        total += 0

    # files_dropped
    try :
        
        for i in dictionary["data"]["files_dropped"]:
            for j in i:
                if "path" in j:
                    for k in CONTI_EXTENSIONS:
                        if k.lower() in i[j].lower():
                            total += 1
                    for k in SUSPICIOUS_PROCESS_NAMES:
                        if k.lower() in i[j].lower():
                            total += 1
                    for k in PATH_RANSOMWARE:
                        if k.lower() in i[j].lower():
                            total += 1
                    for k in NT_DETECTED:
                        if k in i[j]:
                            total += 1
            
        #print("Total files_dropped est : "+str(len(dictionary["data"]["files_dropped"]))+"/"+str(total))
    except KeyError:
        total += 0

    # command_executions
    try :
        
        for i in dictionary["data"]["command_executions"]:
            for j in power_shell_cmd :
                if j in i:
                    total += 1
        #print("Total command_executions est : "+str(2*len(dictionary["data"]["files_dropped"]))+"/"+str(total))
    except KeyError:
        total += 0

    
    # memory_pattern_urls
    try :
        
        for i in dictionary["data"]["memory_pattern_urls"]:
            for j in URLS_SUSPECTS:
                if j in i:
                    total += 1
            
        #print("Total memory_pattern_urls est : "+str(len(dictionary["data"]["memory_pattern_urls"]))+"/"+str(total))
    except KeyError:
        total += 0

    # Calculate the probs
    print("[Conti] ~ La somme de tout est : "+str(total))
    return total

def check_for_maze_behaviors(json_file):
    # Somme total 
    total = 0

    # Read the file json
    with open(json_file) as f:
        report_data = f.read()
    dictionary = json.loads(report_data)

    # List of common file extensions encrypted by MAZE
    MAZE_EXTENSIONS = [".maze",".ILnnD"]
    
    # List of common registry keys modified by MAZE
    MAZE_REGISTRY_KEYS = [
        "HKLM\\SOFTWARE\\WOW6432NODE\\MICROSOFT\\TRACING\\0036407552_RASAPI32",
        "HKLM\\Software\\Microsoft\\Tracing\\ESET32_RASAPI32",
        "HKLM\\Software\\Microsoft\\Tracing\\ESET32_RASMANCS",
        "\\REGISTRY\\MACHINE\\Software\\Wow6432Node\\Microsoft\\Tracing\\RASAPI32",
        "\\REGISTRY\\MACHINE\\Software\\Wow6432Node\\Microsoft\\Tracing\\RASMANCS",
        r"HKEY_CURRENT_USER\Software[random_name]",
        r"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run",
        r"HKEY_CURRENT_USER\Control Panel\Desktop\Wallpaper",
        r"HKEY_CURRENT_USER\Control Panel\Desktop\WallpaperStyle",
        r"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Hidden",
        "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\",
        r"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\exe.docx\UserChoice\Progid",
        r"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\exe.docx\OpenWithList",
        r"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\exe.docx\OpenWithProgids",
        "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Cryptography\\Defaults\\Provider\\Microsoft Enhanced RSA and AES Cryptographic Provider",
        "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Cryptography\\Defaults\\Provider\\Microsoft Strong Cryptographic Provider",
        r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options",
        r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell",
        r"HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run",
        r"HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\System",
        r"HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced",
        r"HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\BootExecute",
        r"HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\DisableAntiSpyware",
        r"HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Monitoring\DisableRealtimeMonitoring",
        r"HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Monitoring\DisableBehaviorMonitoring",
        r"HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Monitoring\DisableIntrusionPreventionSystem",
        r"HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection",
        "HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Rpc\\Extensions",
        "HKEY_LOCAL_MACHINE\\Software\\WOW6432Node\\Microsoft\\Rpc",
        "HKEY_LOCAL_MACHINE\\Software\\WOW6432Node\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options",
        "HKEY_LOCAL_MACHINE\\Software\\WOW6432Node\\Policies\\Microsoft\\Windows NT\\Rpc",
        r"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA",
        r"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces",
        "HKLM\\System\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces",
        r"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SafeBoot\Minimal",
        "HKLM\\Software\\Microsoft\\Cryptography",
        "HKLM\\Software\\Policies\\Microsoft\\Cryptography",
        "HKLM\\SOFTWARE\\Microsoft\\Cryptography\\Defaults\\Provider\\Microsoft Strong Cryptographic Provider",
        "HKLM\\Software\\Microsoft\\Cryptography\\Offload",
        "HKLM\\SYSTEM\\CurrentControlSet\\Services\\Winsock\\Setup Migration\\Providers\\Tcpip6"
    ]
    
    TERMES = ["top secret","Important confidential","Important equipment","Interior Pictures","Legal Affairs"]

    # Check for suspicious process names associated with MAZE
    SUSPICIOUS_PROCESS_NAMES = ["m.exe","Taschost.exe","u0441host.exe","int32.dll","psexec.exe","Invoice_29557473.exe","windef.exe","win163.65.tmp",
                                "winupd.tmp","officeupd.tmp","mswordupd.tmp","dospizdos.tmp","wordupd.tmp","wordupd_3.0.1.tmp","srv.txt",
                                "wm_start.bat","copy_files_srv.bat","rclone.exe","README.txt","ShellExperienceHost.exe","net.exe",
                                "MAZE_readme.txt", "taskdl.exe", "cobaltstrike.exe", "powershell.exe","cmd.exe", "rundll32.exe", "wscript.exe", 
                                "lsass.exe", "svchost.exe", "explorer.exe", "spoolsv.exe","crypt32.dll","bcrypt.dll","ncrypt.dll","CRYPTBASE.dll",
                                "wuapihost.exe","WMIC.exe","conhost.exe","CRYPTSP.dll","rpcrt4.dll","Maze.exe","sc.exe","svc.exe","winlogon.exe",
                                "wermgr.exe","rdpclip.exe","wininit.exe","regsvr32.exe","explorer.exe","wininet.dll","userinit.dll","wuauclt.exe",
                                "winrm.vbs","spoolsv.exe","logonui.exe","backup.exe","msvcrt.dll","RpcRtRemote.dll","rasapi32.dll","rasman.dll",
                                "DECRYPT-FILES.txt","wmiprvse.exe","decrypt-files.html"]
    PATH_RANSOMWARE = [r"%APPDATA%\teamviewers\msi.dll",r"c:\windows\192145.dll,StartW",r"C:\Windows\System32\dllhost.exe",
                    r"C:\Users\USER\AppData\Local\Temp\icju1.exe",r"C:\Windows\System32\dllhost.exe","%CONHOST%"
                    "C:\\ProgramData\\Microsoft\\Crypto\\RSA","C:\\Windows\\system32\\rsaenh.dll",
                    "C:\\Users\\All Users\\Microsoft\\Crypto\\RSA\\","c:\\programdata\\microsoft\\crypto\\rsa\\",
                    "C:\\Documents and Settings\\All Users\\Microsoft\\Crypto\\RSA\\",
                    "${SamplePath}\\"]
    power_shell_cmd = ["cmd.exe /c schtasks /create /sc minute /mo 1 /tn shadowdev /tr",
                    "cmd.exe /c echo TjsfoRdwOe=9931 & reg add HKCU\SOFTWARE\WIlumYjNSyHob /v xFCbJrNfgBNqRy /t REG_DWORD /d 3045 & exit",
                    "cmd.exe /c echo ucQhymDRSRvq=1236 & reg add HKCU\\SOFTWARE\\YkUJvbgwtylk /v KYIaIoYxqwO /t REG_DWORD /d 9633 & exit",
                    "WMIC.exe  SHADOWCOPY /nointeractive","wbadmin DELETE SYSTEMSTATEBACKUP","wbadmin DELETE SYSTEMSTATEBACKUP - deleteOldest",
                    "bcdedit /set {default} recoveryenabled No","bcdedit /set {default} bootstatuspolicy ignoreallfailures","vssadmin.exe Delete Shadows /All /Quiet"
                    ]
    # UNC2198
    # Check for suspicious network connections associated with MAZE
    SUSPICIOUS_NETWORK_IPS = ["5.149.253.199","23.227.193.167","195.123.240.219","193.34.167.34","149.28.201.253","79.141.166.158","45.141.84.223","45.141.84.212","5.199.167.188","37.252.7.142","37.1.213.9","193.36.237.173","173.209.43.61","91.218.114.11","91.218.114.25","91.218.114.26","91.218.114.31","91.218.114.32","91.218.114.37","91.218.114.38","91.218.114.4","91.218.114.77","91.218.114.79","92.63.11.151","92.63.15.6","92.63.15.8","92.63.17.245","92.63.194.20","92.63.194.3","92.63.29.137","92.63.32.2","92.63.32.52","92.63.32.55","92.63.32.57","92.63.37.100","92.63.8.47"]
    SUSPICIOUS_NETWORK_PORT = [21,22,135,443,445,1433,1434,3389,4343,5000,5985,5355,8079,25055,4132,4124,4114]
    URLS_SUSPECTS = ["airmail.cc","lilith.com","U.Awf.Aw","june85.cyou","golddisco.top","colosssueded.top","colombosuede.club","att-customer.com","att-information.com","att-newsroom.com","att-plans.com","bezahlen-1und1.icu","bzst-info.icu","bzst-inform.icu","bzstinfo.icu",
                    "bzstinform.icu","canada-post.icu","canadapost-delivery.icu","canadapost-tracking.icu","hilfe-center-1und1.icu","hilfe-center-internetag.icu","trackweb-canadapost.icu",
                    "updates.updatecenter.icu","thesawmeinrew.net","plaintsotherest.net","drivers.updatecenter.icu","checksoffice.me","aoacugmutagkwctu.onion","mazedecrypt.top","mazenews.top","newsmaze.top","http://104.168.174.32/wordupd_3.0.1.tmp","http://104.168.198.208/wordupd.tmp","http://104.168.198.208/dospizdos.tmp","http://104.168.201.47/wordupd.tmp",
                    "http://104.168.215.54/wordupd.tmp","http://149.56.245.196/wordupd.tmp","http://192.119.106.235/mswordupd.tmp","http://192.119.106.235/officeupd.tmp","http://192.99.172.143/winupd.tmp","http://54.39.233.188/win163.65.tmp","http://91.208.184.174/windef.exe",
                    "http://agenziainformazioni.icu/wordupd.tmp","http://www.download-invoice.site/Invoice_29557473.exe"]
    NT_DETECTED = ["locked","decrypt","encrypted by MAZE","Need restore files?"]
    # Registry Key of file :
    try :
        for i in dictionary["data"]["registry_keys_opened"] :
            for j in MAZE_REGISTRY_KEYS:
                if j in i:
                    if j in "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\":
                        if ".exe" in j:
                            total += 1
                        else:
                            total += 0
                    else:
                        total += 1
        #print("Total registry_keys_opened est : "+str(len(dictionary["data"]["registry_keys_opened"]))+"/"+str(total))
    except KeyError:
        total += 0
    

    # processes terminated
    try :
        
        for i in dictionary["data"]["processes_terminated"] :
            for j in SUSPICIOUS_PROCESS_NAMES:
                if j.lower() in i.lower():
                    total += 1
            for j in power_shell_cmd:
                if j in i:
                    total += 1
            for j in PATH_RANSOMWARE:
                if j in i:
                    total += 1
        #print("Total processes_terminated est : "+str(len(dictionary["data"]["processes_terminated"]))+"/"+str(total))
    except KeyError:
        total += 0

    # files deleted
    try :
        
        for i in dictionary["data"]["files_deleted"]:
            for j in MAZE_EXTENSIONS:
                if j.lower() in i.lower():
                    total += 1
            for j in PATH_RANSOMWARE:
                if j.lower() in i.lower():
                    total += 1
            for j in SUSPICIOUS_PROCESS_NAMES:
                if j.lower() in i.lower():
                    total += 1
        #print("Total files_deleted est : "+str(len(dictionary["data"]["files_deleted"]))+"/"+str(total))
    except KeyError:
        total += 0
    # processes_tree
    try :
        
        for i in dictionary["data"]["processes_tree"]:
            for j in MAZE_EXTENSIONS:
                if j.lower() in i["name"].lower():
                    total += 1
            for j in PATH_RANSOMWARE:
                if j.lower() in i["name"]:
                    total += 1
            for j in SUSPICIOUS_PROCESS_NAMES:
                if j.lower() in i["name"]:
                    total += 1
            for j in power_shell_cmd:
                if j in i:
                    total += 1
        #print("Total processes_tree est : "+str(len(dictionary["data"]["processes_tree"]))+"/"+str(total))
    except KeyError:
        total += 0

    # signature matches
    try :
        
        for i in dictionary["data"]["signature_matches"]:
            for j in i:
                if j == "match_data":
                    for k in i[j]:
                        for l in MAZE_EXTENSIONS:
                            if l.lower() in k.lower():
                                total += 1
                        for l in PATH_RANSOMWARE:
                            if l.lower() in k.lower():
                                total += 1
                        for l in SUSPICIOUS_PROCESS_NAMES:
                            if l.lower() in k.lower():
                                total += 1
                        for l in MAZE_REGISTRY_KEYS:
                            if l in k:
                                total += 1
                        for l in NT_DETECTED:
                            if l in k:
                                total += 1
                        for l in URLS_SUSPECTS:
                            if l in k:
                                total += 1
        #print("Total signature matches est : "+str(len(dictionary["data"]["signature_matches"]))+"/"+str(total))
    except KeyError :
        total += 0
    # modules_loaded
    try :
        for i in dictionary["data"]["modules_loaded"]:
            for j in MAZE_EXTENSIONS:
                if j.lower() in i.lower():
                    total += 1
            for j in SUSPICIOUS_PROCESS_NAMES:
                if j.lower() in i.lower():
                    total += 1
            for j in PATH_RANSOMWARE:
                if j.lower() in i.lower():
                    total += 1
        #print("Total modules_loaded est : "+str(len(dictionary["data"]["modules_loaded"]))+"/"+str(total))
    except KeyError :
        total += 0

    # memory_pattern_domains
    try :
        
        for i in dictionary["data"]["memory_pattern_domains"]:
            for j in URLS_SUSPECTS:
                if j.lower() in i.lower() :
                    total += 1
        #print("Total  memory_pattern_domains est : "+str(len(dictionary["data"]["memory_pattern_domains"]))+"/"+str(total))
    except KeyError :
        total += 0
    # memory_pattern_ips
    try :
        for i in dictionary["data"]["memory_pattern_ips"]:
            for j in SUSPICIOUS_NETWORK_IPS:
                if j.lower() in i.lower() :
                    total += 1
        #print("Total  memory_pattern_domains est : "+str(len(dictionary["data"]["memory_pattern_domains"]))+"/"+str(total))
    except KeyError :
        total += 0
    # mutexes created
    mutex = [r"Global\MsWinZonesCacheCounterMutexA",r"Global\MsWinZonesCacheCounterMutexB",r"Global\RPCSS_ServiceMutex",
            r"Global\csrss.exe",r"Global\Device_Udp_Writer_Lock","Global\\","Local\\"]
    try :
        for i in dictionary["data"]["mutexes_created"]:
            for j in mutex:
                if j in i:
                    total += 1
        #print("Total mutexes created and opened est : "+str(len(dictionary["data"]["mutexes_created"]))+"/"+str(total))
    except KeyError :
        total += 0

    # text_decoded
    try :
        
        for i in dictionary["data"]["text_decoded"]:
            if "MAZE" in i:
                total += 1
            for j in NT_DETECTED:
                if j in i:
                    total += 1
    except KeyError :
        total += 0

    # files_opened
    try :
        
        for i in dictionary["data"]["files_opened"]:
            for j in MAZE_EXTENSIONS:
                if j.lower() in i.lower():
                    total += 1
            for j in PATH_RANSOMWARE:
                if j.lower() in i.lower():
                    total += 1
            for j in SUSPICIOUS_PROCESS_NAMES:
                if j.lower() in i.lower():
                    total += 1
            for j in TERMES:
                if j.lower() in i.lower():
                    total += 1
    except KeyError:
        total += 0

    #registry_keys_set
    try :
        
        for i in dictionary["data"]["registry_keys_set"]:
            for j in i:
                if j in "key":
                    for k in MAZE_REGISTRY_KEYS:
                        if k in i[j]:
                            total +=1
        
        #print("Total registry_keys_set est : "+str(len(dictionary["data"]["registry_keys_set"]))+"/"+str(total))
    except KeyError :
        total += 0
        
    # registry_keys_deleted
    try :
        
        for i in dictionary["data"]["registry_keys_deleted"]:
            for j in MAZE_REGISTRY_KEYS:
                if j in i:
                    total +=1
        
        #print("Total registry_keys_deleted est : "+str(len(dictionary["data"]["registry_keys_deleted"]))+"/"+str(total))
    except KeyError :
        total += 0

    # processes_created
    try :
        
        for i in dictionary["data"]["processes_created"]:
            for j in MAZE_EXTENSIONS:
                if j.lower() in i.lower():
                    total += 1
            for j in PATH_RANSOMWARE:
                if j.lower() in i.lower():
                    total += 1
            for j in SUSPICIOUS_PROCESS_NAMES:
                if j.lower() in i.lower():
                    total += 1
            for j in power_shell_cmd:
                if j in i:
                    total += 1
        #print("Total processes_created est : "+str(len(dictionary["data"]["processes_created"]))+"/"+str(total))
    except KeyError:
        total += 0

    # attack_techniques
    try :
        mitre_techniques = ["T1133","T1078","T1059","T1086","T1064","T1035","T1050","T1036","T1027","T1110","T1003","T1087","T1482","T1032"
                            "T1083","T1135","T1069","T1016","T1018","T1076","T1105","T1005","T1043","T1071","T1002","T1048","T1486","T1020"
                            "T1489","T1193","T1085","T1204","T1028","T1136","T1140","T1107","T1081","T1171","T1033","T1074","T1039","T1219",
                            "T1031","T1055","T1116","T1089","T1202","T1112","T1108","T1097","T1077","T1490","T1583","T1583.003","T1587","T1587.003",
                            "T1588","T1588.003","T1588.004","T1566","T1566.001","T1090.003","T1090","T1573","T1573.002","T1071.001","T1041","T1560",
                            "T1074.001","T1053.005","T1082","T1057","T1059.001"]
        
        for i in dictionary["data"]["attack_techniques"]:
            for j in mitre_techniques:
                if j in i:
                    total += 1
        #print("Total total est : "+str(len(dictionary["data"]["mitre_attack_techniques"]))+"/"+str(total))
    except KeyError:
        total += 0

    # ip_traffic
    
    try :
        for i in dictionary["data"]["ip_traffic"]:
            for j in i:
                if j in "destination_ip":
                    for k in SUSPICIOUS_NETWORK_IPS:
                        if k in i[j]:
                            total += 1
                if j in "destination_port":
                    for k in SUSPICIOUS_NETWORK_PORT:
                        if k == i[j]:
                            total += 1
        #print("Total ip_traffic est : "+str(5*len(dictionary["data"]["ip_traffic"]))+"/"+str(total))
    except KeyError:
        total += 0
    
    # files_copied
    
    try :
        for i in dictionary["data"]["files_copied"]:
            for j in SUSPICIOUS_PROCESS_NAMES:
                if j.lower() in i["destination"].lower():
                    total += 1
            for j in TERMES:
                if j.lower() in i["destination"].lower():
                    total += 1
        #print("Total files_copied est : "+str(4 * len(dictionary["data"]["files_copied"]))+"/"+str(total))
    except KeyError:
        total += 0

    # files_written
    try :
        
        for i in dictionary["data"]["files_written"]:
            for j in MAZE_EXTENSIONS:
                if j.lower() in i.lower():
                    total += 1
            for j in SUSPICIOUS_PROCESS_NAMES:
                if j.lower() in i.lower():
                    total += 1
            for j in PATH_RANSOMWARE:
                if j.lower() in i.lower():
                    total += 1
            for j in TERMES:
                if j.lower() in i.lower():
                    total += 1
            
        #print("Total files_written est : "+str(len(dictionary["data"]["files_written"]))+"/"+str(total))
    except KeyError:
        total += 0

    # files_dropped
    try :
        
        for i in dictionary["data"]["files_dropped"]:
            for j in i:
                if "path" in j:
                    for k in MAZE_EXTENSIONS:
                        if k.lower() in i[j].lower():
                            total += 1
                    for k in SUSPICIOUS_PROCESS_NAMES:
                        if k.lower() in i[j].lower():
                            total += 1
                    for k in PATH_RANSOMWARE:
                        if k.lower() in i[j].lower():
                            total += 1
                    for k in TERMES:
                        if k in i[j]:
                            total += 1
            
        #print("Total files_dropped est : "+str(len(dictionary["data"]["files_dropped"]))+"/"+str(total))
    except KeyError:
        total += 0

    # command_executions
    try :
        
        for i in dictionary["data"]["command_executions"]:
            for j in power_shell_cmd :
                if j in i:
                    total += 1
        #print("Total command_executions est : "+str(2*len(dictionary["data"]["files_dropped"]))+"/"+str(total))
    except KeyError:
        total += 0

    
    # memory_pattern_urls
    try :
        
        for i in dictionary["data"]["memory_pattern_urls"]:
            for j in URLS_SUSPECTS:
                if j in i:
                    total += 1
            for j in SUSPICIOUS_NETWORK_IPS:
                if j in i:
                    total += 1
            
        #print("Total memory_pattern_urls est : "+str(len(dictionary["data"]["memory_pattern_urls"]))+"/"+str(total))
    except KeyError:
        total += 0
    # http_conversations
    try :
        for i in dictionary["data"]["http_conversations"]:
            for j in URLS_SUSPECTS:
                if j in i["url"]:
                    total += 1
            for j in SUSPICIOUS_NETWORK_IPS:
                if j in i["url"]:
                    total += 1
            
        #print("Total http_conversations est : "+str(len(dictionary["data"]["http_conversations"]))+"/"+str(total))
    except KeyError:
        total += 0
    # Calculate the probs
    print("[MAZE] ~ La somme de tout est : "+str(total))
    return total

#Initial_Connection("6a22220c0fe5f578da11ce22945b63d93172b75452996defdc2ff48756bde6af")
check_for_lockbit_behaviors(r"C:\Users\cherif\Documents\behaviour detections\behaviour_summary_results.json")
check_for_wannacry_behaviors(r"C:\Users\cherif\Documents\behaviour detections\behaviour_summary_results.json")
check_for_conti_behaviors(r"C:\Users\cherif\Documents\behaviour detections\behaviour_summary_results.json")
check_for_maze_behaviors(r"C:\Users\cherif\Documents\behaviour detections\behaviour_summary_results.json")