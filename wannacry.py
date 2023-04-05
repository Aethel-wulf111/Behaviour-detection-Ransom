import os
import json
import hashlib

def is_md4(_hash):
    return hashlib.new('md4').hexdigest() == _hash

def check_for_WANNACRY_behaviors(json_file):
    
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
    SUSPICIOUS_PROCESS_NAMES = ["f.wnry","b.wnry","c.wnry", "svchost","@WanaDecryptor@.exe","r.wnry","s.wnry","t.wnry","taskdl.exe","taskse.exe","u.wnry","wmic","vssadmin","bcdedit","rpcrtremote.dll","bcryptprimitives.dll","crypt32.dll","cryptsp.dll","cryptbase.dll"]
    PATH_RANSOMWARE = ["C:\\ProgramData\\Microsoft\\Crypto\\RSA","C:\\Windows\\system32\\rsaenh.dll","C:\\Users\\All Users\\Microsoft\\Crypto\\RSA\\"]
    power_shell_cmd = ["%windir%\\System32\\svchost.exe -k WerSvcGroup","%WinDir%\tasksche.exe","cmd.exe /c vssadmin delete shadows /all /quiet", 
    "wmic shadowcopy delete", "bcdedit /set {default} bootstatuspolicy ignoreallfailures","bcdedit /set {default} recoveryenabled no",
    "wbadmin delete catalog \–quiet"]

    # Check for suspicious network connections associated with WANNACRY
    suspicious_network_ips = [445,139,9001,9003]

    # Positive Technologies says you should also be looking for connections to the Tor network on ports 9001 and 9003.
    # SMBv1 ports TCP 445 and 139, as well as DNS queries for the kill switch domain.

    
    URLS_SUSPECTS = ["http://www.iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com","gx7ekbenv2riucmf.onion","cwwnhwhlz52maqm7.onion",
            "57g7spgrzlojinas.onion", "https://www.kryptoslogic.com","xxlvbrloxvriy2c5.onion","76jdd2ir2embyv47.onion"]
    NT_DETECTED = ["@Please_Read_Me@.txt"]
    # Registry Key of file :
    try :
        cpt_reg = 0
        for i in dictionary["data"]["registry_keys_opened"] :
            for j in WANNACRY_REGISTRY_KEYS:
                if j in i and j in "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Tracing\\":
                    if "RASAPI32" in i or "RASMANCS" in i:
                        cpt_reg += 1
                if j in i:
                    cpt_reg += 1
        print("Total registry_keys_opened est : "+str(len(dictionary["data"]["registry_keys_opened"]))+"/"+str(cpt_reg))
    except KeyError:
        cpt_reg = 0

    # processes terminated
    try :
        cpt_proc_ter = 0
        for i in dictionary["data"]["processes_terminated"] :
            for j in SUSPICIOUS_PROCESS_NAMES:
                if j in i:
                    cpt_proc_ter += 1
            for j in power_shell_cmd:
                if j in i:
                    cpt_proc_ter += 1
        print("Total processes_terminated est : "+str(len(dictionary["data"]["processes_terminated"]))+"/"+str(cpt_proc_ter))
    except KeyError:
        cpt_proc_ter = 0

    # files deleted
    try :
        cpt_files_deleted = 0
        for i in dictionary["data"]["files_deleted"]:
            for j in WANNACRY_EXTENSIONS:
                if j in i:
                    cpt_files_deleted += 1
            for j in PATH_RANSOMWARE:
                if j in i:
                    cpt_files_deleted += 1
            for j in SUSPICIOUS_PROCESS_NAMES:
                if j in i:
                    cpt_files_deleted += 1
        print("Total files_deleted est : "+str(len(dictionary["data"]["files_deleted"]))+"/"+str(cpt_files_deleted))
    except KeyError:
        cpt_files_deleted = 0

    # signature matches
    try :
        cpt_signature_matches = 0
        for i in dictionary["data"]["signature_matches"]:
            for j in i:
                if j == "match_data":
                    for k in i[j]:
                        for l in WANNACRY_EXTENSIONS:
                            if l in k:
                                cpt_signature_matches += 1
                        for l in PATH_RANSOMWARE:
                            if l in k:
                                if ".exe" in i:
                                    cpt_files_deleted += 1
                        for l in SUSPICIOUS_PROCESS_NAMES:
                            if l in k:
                                cpt_signature_matches += 1
                        for l in WANNACRY_REGISTRY_KEYS:
                            if l in k:
                                cpt_signature_matches += 1
                        for l in NT_DETECTED:
                            if l in k:
                                cpt_signature_matches += 1
                        for l in URLS_SUSPECTS:
                            if l in k:
                                cpt_signature_matches += 1
        print("Total signature matches est : "+str(len(dictionary["data"]["signature_matches"]))+"/"+str(cpt_signature_matches))
    except KeyError :
        cpt_signature_matches = 0
    # modules_loaded
    try :
        cpt_modules_loaded = 0
        for i in dictionary["data"]["modules_loaded"]:
            for j in WANNACRY_EXTENSIONS:
                if j in i:
                    cpt_modules_loaded += 1
            for j in SUSPICIOUS_PROCESS_NAMES:
                if j in i:
                    cpt_modules_loaded += 1
            for j in PATH_RANSOMWARE:
                if j in i:
                    cpt_modules_loaded += 1
        print("Total modules_loaded est : "+str(len(dictionary["data"]["modules_loaded"]))+"/"+str(cpt_modules_loaded))
    except KeyError :
        cpt_memory_pattern_domains = 0

    # memory_pattern_domains
    try :
        cpt_memory_pattern_domains = 0
        for i in dictionary["data"]["memory_pattern_domains"]:
            for j in URLS_SUSPECTS:
                if j in i:
                    cpt_memory_pattern_domains += 1
        print("Total  memory_pattern_domains est : "+str(len(dictionary["data"]["memory_pattern_domains"]))+"/"+str(cpt_memory_pattern_domains))
    except KeyError :
        cpt_memory_pattern_domains = 0

    # mutexes created
    try :
        cpt_mutexes_created = 0
        for i in dictionary["data"]["mutexes_created"]:
            if "Global\\MsWinZonesCacheCounterMutexA0" in i:
                cpt_mutexes_created += 1
        print("Total mutexes created est : "+str(len(dictionary["data"]["mutexes_created"]))+"/"+str(cpt_mutexes_created))
    except KeyError :
        cpt_mutexes_created = 0

    # text_decoded
    try :
        cpt_text_decoded = 0
        for i in dictionary["data"]["text_decoded"]:
            if "WANACRY" in i:
                cpt_text_decoded += 1
        print("Total cpt_text_decoded est : "+str(len(dictionary["data"]["text_decoded"]))+"/"+str(cpt_text_decoded))
    except KeyError :
        cpt_text_decoded = 0

    # files_opened
    try :
        cpt_files_opened = 0
        for i in dictionary["data"]["files_opened"]:
            for j in WANNACRY_EXTENSIONS:
                if j in i:
                    cpt_files_opened += 1
            for j in PATH_RANSOMWARE:
                if j in i:
                    if ".exe" in i:
                        cpt_files_opened += 1
            for j in SUSPICIOUS_PROCESS_NAMES:
                if j in i:
                    cpt_files_opened += 1

        print("Total files_opened est : "+str(len(dictionary["data"]["files_opened"]))+"/"+str(cpt_files_opened))
    except KeyError:
        cpt_files_opened = 0

    #registry_keys_set
    try :
        cpt_registry_keys_set = 0
        for i in dictionary["data"]["registry_keys_set"]:
            for j in i:
                if j in "key":
                    for k in WANNACRY_REGISTRY_KEYS:
                        if k in i[j]:
                            cpt_registry_keys_set +=1
        
        print("Total registry_keys_set est : "+str(len(dictionary["data"]["registry_keys_set"]))+"/"+str(cpt_registry_keys_set))
    except KeyError :
        cpt_registry_keys_set = 0
        
    # registry_keys_deleted
    try :
        cpt_registry_keys_deleted = 0
        for i in dictionary["data"]["registry_keys_deleted"]:
            for j in WANNACRY_REGISTRY_KEYS:
                if j in i:
                    cpt_registry_keys_deleted +=1
        
        print("Total registry_keys_deleted est : "+str(len(dictionary["data"]["registry_keys_deleted"]))+"/"+str(cpt_registry_keys_deleted))
    except KeyError :
        cpt_registry_keys_set = 0

    # processes_created
    try :
        cpt_processes_created = 0
        for i in dictionary["data"]["processes_created"]:
            for j in WANNACRY_EXTENSIONS:
                if j in i:
                    cpt_processes_created += 1
            for j in PATH_RANSOMWARE:
                if j in i:
                    if ".exe" in i:
                        cpt_processes_created += 1
            for j in SUSPICIOUS_PROCESS_NAMES:
                if j in i:
                    cpt_processes_created += 1
            for j in power_shell_cmd:
                if j in i:
                    cpt_processes_created += 1
        print("Total processes_created est : "+str(len(dictionary["data"]["processes_created"]))+"/"+str(cpt_processes_created))
    except KeyError:
        cpt_processes_created = 0

    # attack_techniques
    try :
        mitre_techniques = ["T1543.003","T1486","T1573.002","T1210","T1083","T1222.001","T1564.001","T1490","T1570","T1120","T1090.003","T1563.002","T1018","T1489","T1016","T1047","T0866","T0867"]
        cpt_mitre_attack_techniques = 0
        for i in dictionary["data"]["attack_techniques"]:
            for j in mitre_techniques:
                if j in i:
                    cpt_mitre_attack_techniques += 1
        print("Total cpt_mitre_attack_techniques est : "+str(len(dictionary["data"]["mitre_attack_techniques"]))+"/"+str(cpt_mitre_attack_techniques))
    except KeyError:
        cpt_mitre_attack_techniques = 0

    # ip_traffic
    cpt_ip_traffic = 0
    try :
        for i in dictionary["data"]["ip_traffic"]:
            for j in i:
                if j in "destination_port":
                    for k in suspicious_network_ips:
                        if k == i[j]:
                            cpt_ip_traffic += 1
        print("Total ip_traffic est : "+str(len(dictionary["data"]["ip_traffic"]))+"/"+str(cpt_ip_traffic))
    except KeyError:
        cpt_ip_traffic = 0
    
    # files_copied
    try :
        cpt_files_copied = 0
        for i in dictionary["data"]["files_copied"]:
            for j in SUSPICIOUS_PROCESS_NAMES:
                if j in i["destination"]:
                    cpt_files_copied += 1
        print("Total files_copied est : "+str(4 * len(dictionary["data"]["files_copied"]))+"/"+str(cpt_files_copied))
    except KeyError:
        cpt_files_copied = 0

    # files_written
    try :
        cpt_files_written = 0
        for i in dictionary["data"]["files_written"]:
            for j in WANNACRY_EXTENSIONS:
                if j in i:
                    cpt_files_written += 1
            for j in SUSPICIOUS_PROCESS_NAMES:
                if j in i:
                    cpt_files_written += 1
            for j in PATH_RANSOMWARE:
                if j in i:
                    cpt_files_written += 1
            
        print("Total files_written est : "+str(len(dictionary["data"]["files_written"]))+"/"+str(cpt_files_written))
    except KeyError:
        cpt_files_written = 0

    # files_dropped
    try :
        cpt_files_dropped = 0
        for i in dictionary["data"]["files_dropped"]:
            for j in i:
                if "path" in j:
                    for k in WANNACRY_EXTENSIONS:
                        if k in i[j]:
                            cpt_files_dropped += 1
                    for k in SUSPICIOUS_PROCESS_NAMES:
                        if k in i[j]:
                            cpt_files_dropped += 1
                    for k in PATH_RANSOMWARE:
                        if k in i[j]:
                            cpt_files_dropped += 1
                    for k in NT_DETECTED:
                        if k in i[j]:
                            cpt_files_dropped += 1
            
        print("Total files_dropped est : "+str(len(dictionary["data"]["files_dropped"]))+"/"+str(cpt_files_dropped))
    except KeyError:
        cpt_files_dropped = 0

    # command_executions
    try :
        cpt_command_executions = 0
        for i in dictionary["data"]["command_executions"]:
            for j in power_shell_cmd :
                if j in i:
                    cpt_command_executions += 1
        print("Total command_executions est : "+str(2*len(dictionary["data"]["files_dropped"]))+"/"+str(cpt_command_executions))
    except KeyError:
        cpt_command_executions = 0

    
    # memory_pattern_urls
    try :
        cpt_URLS_SUSPECTS = 0
        for i in dictionary["data"]["memory_pattern_urls"]:
            for j in URLS_SUSPECTS:
                if j in i:
                    cpt_URLS_SUSPECTS += 1
            
        print("Total memory_pattern_urls est : "+str(len(dictionary["data"]["memory_pattern_urls"]))+"/"+str(cpt_URLS_SUSPECTS))
    except KeyError:
        cpt_URLS_SUSPECTS = 0

    # Calculate the probs
    total = cpt_memory_pattern_domains + cpt_URLS_SUSPECTS + cpt_command_executions + cpt_files_dropped + cpt_files_written + cpt_files_copied + cpt_mitre_attack_techniques + cpt_processes_created + cpt_registry_keys_set + cpt_files_opened + cpt_mutexes_created + cpt_signature_matches + cpt_files_deleted + cpt_proc_ter + cpt_reg
    print("La somme de tout est : "+str(total))

check_for_WANNACRY_behaviors(r"C:\Users\cherif\Documents\behaviour detections\behaviour_summary_results.json")
