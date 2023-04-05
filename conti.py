import json

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
    SUSPICIOUS_PROCESS_NAMES = ["srv.txt","wm_start.bat","copy_files_srv.bat","rclone.exe","README.txt","ShellExperienceHost.exe","net.exe","conti_readme.txt", "taskdl.exe", "cobaltstrike.exe", "powershell.exe", "rundll32.exe", "wscript.exe", "lsass.exe", "svchost.exe", "explorer.exe", "spoolsv.exe","crypt32.dll","bcrypt.dll","ncrypt.dll","CRYPTBASE.dll","CRYPTSP.dll"]
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
        print("Total registry_keys_opened est : "+str(len(dictionary["data"]["registry_keys_opened"]))+"/"+str(total))
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
        print("Total processes_terminated est : "+str(len(dictionary["data"]["processes_terminated"]))+"/"+str(total))
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
        print("Total files_deleted est : "+str(len(dictionary["data"]["files_deleted"]))+"/"+str(total))
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
        print("Total processes_tree est : "+str(len(dictionary["data"]["processes_tree"]))+"/"+str(total))
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
                            if l in k:
                                total += 1
                        for l in NT_DETECTED:
                            if l in k:
                                total += 1
                        for l in URLS_SUSPECTS:
                            if l in k:
                                total += 1
        print("Total signature matches est : "+str(len(dictionary["data"]["signature_matches"]))+"/"+str(total))
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
        print("Total modules_loaded est : "+str(len(dictionary["data"]["modules_loaded"]))+"/"+str(total))
    except KeyError :
        total += 0

    # memory_pattern_domains
    try :
        
        for i in dictionary["data"]["memory_pattern_domains"]:
            for j in URLS_SUSPECTS:
                if j.lower() in i.lower() :
                    total += 1
        print("Total  memory_pattern_domains est : "+str(len(dictionary["data"]["memory_pattern_domains"]))+"/"+str(total))
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
        print("Total mutexes created and opened est : "+str(len(dictionary["data"]["mutexes_created"]))+"/"+str(total))
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
        print("Total total est : "+str(len(dictionary["data"]["text_decoded"]))+"/"+str(total))
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

        print("Total files_opened est : "+str(len(dictionary["data"]["files_opened"]))+"/"+str(total))
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
        
        print("Total registry_keys_set est : "+str(len(dictionary["data"]["registry_keys_set"]))+"/"+str(total))
    except KeyError :
        total += 0
        
    # registry_keys_deleted
    try :
        
        for i in dictionary["data"]["registry_keys_deleted"]:
            for j in CONTI_REGISTRY_KEYS:
                if j in i:
                    total +=1
        
        print("Total registry_keys_deleted est : "+str(len(dictionary["data"]["registry_keys_deleted"]))+"/"+str(total))
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
        print("Total processes_created est : "+str(len(dictionary["data"]["processes_created"]))+"/"+str(total))
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
        print("Total total est : "+str(len(dictionary["data"]["mitre_attack_techniques"]))+"/"+str(total))
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
        print("Total ip_traffic est : "+str(5*len(dictionary["data"]["ip_traffic"]))+"/"+str(total))
    except KeyError:
        total += 0
    
    # files_copied
    try :
        
        for i in dictionary["data"]["files_copied"]:
            for j in SUSPICIOUS_PROCESS_NAMES:
                if j.lower() in i["destination"].lower():
                    total += 1
        print("Total files_copied est : "+str(4 * len(dictionary["data"]["files_copied"]))+"/"+str(total))
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
            
        print("Total files_written est : "+str(len(dictionary["data"]["files_written"]))+"/"+str(total))
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
            
        print("Total files_dropped est : "+str(len(dictionary["data"]["files_dropped"]))+"/"+str(total))
    except KeyError:
        total += 0

    # command_executions
    try :
        
        for i in dictionary["data"]["command_executions"]:
            for j in power_shell_cmd :
                if j in i:
                    total += 1
        print("Total command_executions est : "+str(2*len(dictionary["data"]["files_dropped"]))+"/"+str(total))
    except KeyError:
        total += 0

    
    # memory_pattern_urls
    try :
        
        for i in dictionary["data"]["memory_pattern_urls"]:
            for j in URLS_SUSPECTS:
                if j in i:
                    total += 1
            
        print("Total memory_pattern_urls est : "+str(len(dictionary["data"]["memory_pattern_urls"]))+"/"+str(total))
    except KeyError:
        total += 0

    # Calculate the probs
    print("[Conti] ~ La somme de tout est : "+str(total))
    return total

check_for_conti_behaviors(r"C:\Users\cherif\Documents\behaviour detections\behaviour_summary_results.json")
