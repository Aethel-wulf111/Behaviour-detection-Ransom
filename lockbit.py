import os
import json
import hashlib

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

    # Check for suspicious network connections associated with LockBit
    suspicious_network_ips = ['192.168.56.101']

    # Check for suspicious files in startup directories
    STARTUP_DIRECTORIES = [
        os.path.join(os.environ["APPDATA"], "Microsoft", "Windows", "Start Menu", "Programs", "Startup"),
        os.path.join(os.environ["USERPROFILE"], "Start Menu", "Programs", "Startup"),
        os.path.join(os.environ["ALLUSERSPROFILE"], "Microsoft", "Windows", "Start Menu", "Programs", "Startup"),
    ]
    
    URLS_SUSPECTS = ["http://lockbit","https://bigblog.at","https://decoding.at","https://www.premiumize.com","https://anonfiles.com","https://www.sendspace.com","https://fex.net","https://transfer.sh","https://send.exploit.in","https://aka.ms/","http://www2.hursley.ibm.com/"]
    NT_DETECTED = ["Restore-My-Files.txt -> ","readme"]
    # Evaluation 

    # Registry Key of file :
    try :
        cpt_reg = 0
        for i in dictionary["data"]["registry_keys_opened"] :
            for j in LOCKBIT_REGISTRY_KEYS:
                if j in i:
                    cpt_reg += 1
        print("Total est : "+str(len(dictionary["data"]["registry_keys_opened"]))+"/"+str(cpt_reg))
    except KeyError:
        cpt_reg = 0

    # processes terminated
    try :
        cpt_proc_ter = 0
        for i in dictionary["data"]["processes_terminated"] :
            for j in PROCESSES_KILLED:
                if j in i:
                    cpt_proc_ter += 1
            for j in SUSPICIOUS_PROCESS_NAMES:
                if j in i:
                    cpt_proc_ter += 1
        print("Total est : "+str(len(dictionary["data"]["processes_terminated"]))+"/"+str(cpt_proc_ter))
    except KeyError:
        cpt_proc_ter = 0

    # files deleted
    try :
        cpt_files_deleted = 0
        for i in dictionary["data"]["files_deleted"]:
            for j in LOCKBIT_EXTENSIONS:
                if j in i:
                    cpt_files_deleted += 1
            for j in PATH_RANSOMWARE:
                if j in i:
                    if ".exe" in i:
                        cpt_files_deleted += 1
        print("Total est : "+str(len(dictionary["data"]["files_deleted"]))+"/"+str(cpt_files_deleted))
    except KeyError:
        cpt_files_deleted = 0

    # signature matches
    try :
        cpt_signature_matches = 0
        for i in dictionary["data"]["signature_matches"]:
            for j in i:
                if j == "match_data":
                    for k in i[j]:
                        for l in LOCKBIT_EXTENSIONS:
                            if l in k:
                                cpt_signature_matches += 1
                        for l in PATH_RANSOMWARE:
                            if l in k:
                                if ".exe" in i:
                                    cpt_files_deleted += 1
                        for l in PROCESSES_KILLED:
                            if l in k:
                                cpt_signature_matches += 1
                        for l in SUSPICIOUS_PROCESS_NAMES:
                            if l in k:
                                cpt_signature_matches += 1
                        for l in LOCKBIT_REGISTRY_KEYS:
                            if l in k:
                                cpt_signature_matches += 1
                        for l in NT_DETECTED:
                            if l in k:
                                cpt_signature_matches += 1
                        for l in URLS_SUSPECTS:
                            if l in k:
                                cpt_signature_matches += 1
                        for l in STARTUP_DIRECTORIES:
                            if l in k:
                                cpt_signature_matches += 1
                        for l in SERVICES_KILLED:
                            if l in k:
                                cpt_signature_matches += 1
        print("Total est : "+str(len(dictionary["data"]["signature_matches"]))+"/"+str(cpt_signature_matches))
    except KeyError :
        cpt_signature_matches = 0

    # mutexes created
    try :
        cpt_mutexes_created = 0
        for i in dictionary["data"]["mutexes_created"]:
            if "Global\\" in i:
                #print(i.split("\\")[-1])
                if is_md4(i.split("\\")[-1]) :
                    cpt_mutexes_created += 1
        print("Total est : "+str(len(dictionary["data"]["mutexes_created"]))+"/"+str(cpt_mutexes_created))
    except KeyError :
        cpt_mutexes_created = 0

    # files_opened
    try :
        cpt_files_opened = 0
        for i in dictionary["data"]["files_opened"]:
            for j in LOCKBIT_EXTENSIONS:
                if j in i:
                    cpt_files_opened += 1
            for j in PATH_RANSOMWARE:
                if j in i:
                    if ".exe" in i:
                        cpt_files_opened += 1
            for j in PROCESSES_KILLED:
                if j in i:
                    cpt_files_opened += 1
            for j in SUSPICIOUS_PROCESS_NAMES:
                if j in i:
                    cpt_files_opened += 1
            for l in STARTUP_DIRECTORIES:
                if l in k:
                    cpt_files_opened += 1
        print("Total est : "+str(len(dictionary["data"]["files_opened"]))+"/"+str(cpt_files_opened))
    except KeyError:
        cpt_files_opened = 0

    #registry_keys_set
    try :
        cpt_registry_keys_set = 0
        for i in dictionary["data"]["registry_keys_set"]:
            cpt = 0
            for j in i:
                if j in "key" and i[j] in r"HKLM\SOFTWARE\Policies\Microsoft\Windows\System":
                    cpt = 1
                if (cpt == 1 and j in "value") and ("GroupPolicyRefreshTimeDC" in i[j] or "GroupPolicyRefreshTimeOffsetDC" in i[j]  or "GroupPolicyRefreshTime" in i[j] or "GroupPolicyRefreshTimeOffset" in i[j] or "EnableSmartScreen" in i[j] or "**del.ShellSmartScreenLevel" in i[j]):
                    cpt_registry_keys_set += 1
                
                if j in "key" and i[j] in r"HKLM\SOFTWARE\Policies\Microsoft\Windows Defender":
                    cpt = 1
                if (cpt == 1 and j in "value") and ("DisableAntiSpyware" in i[j] or "DisableRoutinelyTakingAction" in i[j] ):
                    cpt_registry_keys_set += 1

                if j in "key" and i[j] in r"HKLM\SOFTWARE\Policies\Microsoft\Windows  Defender\Real-Time Protection":
                    cpt = 1
                if (cpt == 1 and j in "value") and ("DisableRealtimeMonitoring" in i[j] or "DisableBehaviorMonitoring" in i[j] ):
                    cpt_registry_keys_set += 1
                
                if j in "key" and i[j] in r"HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet":
                    cpt = 1
                if (cpt == 1 and j in "value") and ("SubmitSamplesConsent" in i[j] or "SpynetReporting" in i[j] ):
                    cpt_registry_keys_set += 1

                if j in "key" and i[j] in r"HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile":
                    cpt = 1
                if (cpt == 1 and j in "value") and ("EnableFirewall"):
                    cpt_registry_keys_set += 1
                
                if j in "key" and i[j] in r"HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\StandardProfile":
                    cpt = 1
                if (cpt == 1 and j in "value") and ("EnableFirewall"):
                    cpt_registry_keys_set += 1
        
        print("Total est : "+str(len(dictionary["data"]["registry_keys_set"]))+"/"+str(cpt_registry_keys_set))
    except KeyError :
        cpt_registry_keys_set = 0

    # processes_created
    try :
        cpt_processes_created = 0
        for i in dictionary["data"]["processes_created"]:
            for j in LOCKBIT_EXTENSIONS:
                if j in i:
                    cpt_processes_created += 1
            for j in PATH_RANSOMWARE:
                if j in i:
                    if ".exe" in i:
                        cpt_processes_created += 1
            for j in PROCESSES_KILLED:
                if j in i:
                    cpt_processes_created += 1
            for j in SUSPICIOUS_PROCESS_NAMES:
                if j in i:
                    cpt_processes_created += 1
            for l in STARTUP_DIRECTORIES:
                if l in k:
                    cpt_processes_created += 1
        print("Total est : "+str(len(dictionary["data"]["processes_created"]))+"/"+str(cpt_processes_created))
    except KeyError:
        cpt_processes_created = 0

    # attack_techniques
    try :
        mitre_techniques = ["T1078","T1133","T1189","T1190","T1566","TA0002","T1072","T1547","TA0004","T1027","T1070.004","T1480.001","T1003.001","T1046","T1082","T1614.001","T1021.001","T1071.002","T1572","TA0010","T1567","T1567.002","T1485","T1486","T1489","T1490","T1491.001"]
        cpt_mitre_attack_techniques = 0
        for i in dictionary["data"]["attack_techniques"]:
            for j in mitre_techniques:
                if j in i:
                    cpt_mitre_attack_techniques += 1
        print("Total est : "+str(len(dictionary["data"]["mitre_attack_techniques"]))+"/"+str(cpt_mitre_attack_techniques))
    except KeyError:
        cpt_mitre_attack_techniques = 0

    # ip_traffic
    """for i in dictionary["data"]["ip_traffic"]:
        print(i)"""
    
    # files_copied
    try :
        cpt_files_copied = 0
        for i in dictionary["data"]["files_copied"]:
            for j in LOCKBIT_EXTENSIONS:
                if j in i["destination"]:
                    cpt_files_copied += 1
        print("Total est : "+str(4 * len(dictionary["data"]["files_copied"]))+"/"+str(cpt_files_copied))
    except KeyError:
        cpt_files_copied = 0

    # files_written
    try :
        cpt_files_written = 0
        for i in dictionary["data"]["files_written"]:
            for j in LOCKBIT_EXTENSIONS:
                if j in i:
                    cpt_files_written += 1
            for j in SUSPICIOUS_PROCESS_NAMES:
                if j in i:
                    cpt_files_written += 1
            for j in STARTUP_DIRECTORIES:
                if j in i:
                    cpt_files_written += 1
        print("Total est : "+str(len(dictionary["data"]["files_written"]))+"/"+str(cpt_files_written))
    except KeyError:
        cpt_files_written = 0

    # files_dropped
    try :
        cpt_files_dropped = 0
        for i in dictionary["data"]["files_dropped"]:
            for j in LOCKBIT_EXTENSIONS:
                if j in i["path"]:
                    cpt_files_dropped += 1
            for j in SUSPICIOUS_PROCESS_NAMES:
                if j in i["path"]:
                    cpt_files_dropped += 1
            for j in STARTUP_DIRECTORIES:
                if j in i["path"]:
                    cpt_files_dropped += 1
        print("Total est : "+str(len(dictionary["data"]["files_dropped"]))+"/"+str(cpt_files_dropped))
    except KeyError:
        cpt_files_dropped = 0

    # command_executions
    try :
        cpt_command_executions = 0
        for i in dictionary["data"]["command_executions"]:
            if power_shell in i:
                cpt_command_executions += 1

        print("Total est : "+str(2*len(dictionary["data"]["files_dropped"]))+"/"+str(cpt_command_executions))
    except KeyError:
        cpt_command_executions = 0

    # services_opened
    try :
        cpt_services_opened = 0
        for i in dictionary["data"]["services_opened"]:
            for j in SUSPICIOUS_PROCESS_NAMES:
                if j in i:
                    cpt_services_opened += 1
            for j in SERVICES_KILLED:
                if j in i:
                    cpt_services_opened += 1
        print("Total est : "+str(len(dictionary["data"]["services_opened"]))+"/"+str(cpt_services_opened))
    except KeyError:
        cpt_services_opened = 0

    # memory_pattern_urls
    try :
        cpt_URLS_SUSPECTS = 0
        for i in dictionary["data"]["memory_pattern_urls"]:
            for j in URLS_SUSPECTS:
                if j in i:
                    cpt_URLS_SUSPECTS += 1
            
        print("Total est : "+str(len(dictionary["data"]["memory_pattern_urls"]))+"/"+str(cpt_URLS_SUSPECTS))
    except KeyError:
        cpt_URLS_SUSPECTS = 0

    # Calculate the probs
    total = cpt_URLS_SUSPECTS + cpt_services_opened + cpt_command_executions + cpt_files_dropped + cpt_files_written + cpt_files_copied + cpt_mitre_attack_techniques + cpt_processes_created + cpt_registry_keys_set + cpt_files_opened + cpt_mutexes_created + cpt_signature_matches + cpt_files_deleted + cpt_proc_ter + cpt_reg
    print("La somme de tout est : "+str(total))

check_for_lockbit_behaviors(r"C:\Users\cherif\Documents\behaviour detections\behaviour_summary_results.json")
