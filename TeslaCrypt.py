import json

def check_for_TeslaCrypt_behaviors(json_file):
    # Somme total 
    total = 0

    # Read the file json
    with open(json_file) as f:
        report_data = f.read()
    dictionary = json.loads(report_data)

    # List of common file extensions encrypted by petya
    petya_EXTENSIONS = [".micro",".ttt",".xxx",".ecc",".exx",".xyz"]
    
    # List of common registry keys modified by petya
    petya_REGISTRY_KEYS = [
        r"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4",
        r"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS",
        r"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL",
        r"HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services",
        r"HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders\Cookies",
        r"HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders\Cache",
        r"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Folder\Hidden\SHOWALL",
        r"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
        r"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
        r"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        r"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders",
        r"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SafeBoot\Network",
        r"HKEY_CURRENT_USER\Software",
        r"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run",
        r"HKEY_CURRENT_USER\Control Panel\Desktop\Wallpaper",
        r"HKEY_CURRENT_USER\Control Panel\Desktop\WallpaperStyle",
        r"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Hidden",
        "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\",
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
        r"HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Control\SafeBoot\Minimal",
        r"HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Control\SafeBoot\Network",
        r"HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Microsoft\Tracing",
        "HKEY_LOCAL_MACHINE\\Software\\WOW6432Node\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options",
        "HKEY_LOCAL_MACHINE\\Software\\WOW6432Node\\Policies\\Microsoft\\Windows NT\\Rpc",
        r"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA",
        r"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces",
        r"HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Control\Nls\Locale\Alternate Sorts",
        "HKLM\\System\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces",
        r"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SafeBoot\Minimal",
        "HKLM\\Software\\Microsoft\\Cryptography",
        r"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks",
        r"HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\Disk",
        r"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree",
        r"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options",
        "HKLM\\Software\\Policies\\Microsoft\\Cryptography",
        "HKLM\\SOFTWARE\\Microsoft\\Cryptography\\Defaults\\Provider\\Microsoft Strong Cryptographic Provider",
        "HKLM\\Software\\Microsoft\\Cryptography\\Offload",
        "HKLM\\SYSTEM\\CurrentControlSet\\Services\\Winsock\\Setup Migration\\Providers\\Tcpip6",
        "HKLM\\SOFTWARE\\MICROSOFT\\WINDOWS\\CURRENTVERSION\\EXPLORER\\SHELL FOLDERS",
        "\\REGISTRY\\MACHINE\\Software\\Policies\\Microsoft\\Windows NT\\Rpc",
        "\\Registry\\Machine\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\svchost.exe",
        "\\REGISTRY\\MACHINE\\Software\\Policies\\Microsoft\\Cryptography",
        ]
    
    # Check for suspicious process names associated with petya
    SUSPICIOUS_PROCESS_NAMES = ['Howto_Restore_FILES','recover_file_','help_recover_instructions','HELP_TO_SAVE_YOUR_FILES','HELP_TO_DECRYPT_YOUR_FILES','money.doc','fondue.exe','mshearts.exe','Win32.ExPetr.a','CRYPTBASE.dll','blastcln.exe','unlodctr.exe','rsopprov.exe','taskdl.exe', 'taskse.exe', 'psexec.exe', 'cmd.exe', 'wmiprvse.exe', 'Psexec.exe', 'mmc.exe', 'svchost.exe', 'schtasks.exe', 'wscript.exe', 'winword.exe', 'excel.exe', 'powerpnt.exe', 'msaccess.exe', 'outlook.exe', 'onenote.exe', 'steam.exe', 'chrome.exe', 'firefox.exe', 'iexplore.exe', 'opera.exe', 'safari.exe', 'thunderbird.exe', 'acrobat.exe', 'notepad.exe', 'wmic.exe', 'ctfmon.exe', 'msiexec.exe', 'rundll32.exe', 'dllhost.exe', 'taskeng.exe', 'explorer.exe', 'lsass.exe', 'rundll.exe', 'MsMpEng.exe', 'services.exe', 'wininit.exe', 'winlogon.exe', 'csrss.exe', 'smss.exe', 'spoolsv.exe', 'lsaiso.exe', 'vssadmin.exe', 'dispci.exe', 'mssecsvc.exe', 'taskhost.exe', 'dllhst3g.exe', 'conhost.exe', 'kernel32.dll', 'user32.dll', 'wininet.dll', 'winmm.dll', 'ws2_32.dll', 'gdi32.dll', 'comctl32.dll', 'ntdll.dll', 'shell32.dll', 'advapi32.dll', 'ole32.dll', 'shlwapi.dll', 'rpcrt4.dll', 'comdlg32.dll', 'crypt32.dll', 'msvcr71.dll', 'imm32.dll', 'version.dll', 'oleaut32.dll', 'iphlpapi.dll', 'urlmon.dll', 'cryptdll.dll', 'netapi32.dll', 'wintrust.dll', 'msimg32.dll', 'msvcrt.dll', 'secur32.dll', 'dnsapi.dll', 'mss32.dll', 'd3dx9_41.dll', 'rasadhlp.dll', 'sspicli.dll', 'winspool.drv', 'cryptsp.dll', 'rasapi32.dll', 'dwmapi.dll', 'rsaenh.dll', 'api-ms-win-core-libraryloader-l1-2-0.dll', 'api-ms-win-core-processthreads-l1-1-1.dll', 'api-ms-win-core-file-l1-2-1.dll', 'api-ms-win-core-heap-l1-2-0.dll', 'api-ms-win-core-debug-l1-1-1.dll', 'api-ms-win-core-synch-l1-2-0.dll', 'api-ms-win-core-handle-l1-1-0.dll', 'api-ms-win-core-localization-l1-2-0.dll', 'api-ms-win-core-console-l1-1-0.dll', 'api-ms-win-core-io-l1-1-1.dll', 'api-ms-win-core-registry-l1-1-0.dll', 'api-ms-win-core-timezone-l1-1-0.dll', 'api-ms-win-core-processthreads-l1-1-0.dll', 'api-ms-win-core-string-l1-1-0.dll', 'api-ms-win-core-threadpool-l1-2-0.dll', 'api-ms-win-core-xstate-l']
    PATH_RANSOMWARE = [r"%APPDATA%\teamviewers\msi.dll",r"c:\windows\192145.dll,StartW",
                    "C:\\bootmgr","C:\\totalcmd\\","C:\\Far2\\",
                    r"C:\Users\<User>\AppData\Local",
                    "C:\\Users\\user\\Documents\\",
                    "C:\\decrypt",
                    "C:\\DOCUME~1\\Miller\\LOCALS~1\\Temp\\",
                    "C:\\Users\\<USER>\\Downloads\\ransimware.exe",
                    r"C:\Users\USER\AppData\Local\Temp\icju1.exe","%CONHOST%",
                    "C:\\ProgramData\\Microsoft\\Crypto\\RSA","C:\\Windows\\system32\\rsaenh.dll",
                    "C:\\Users\\All Users\\Microsoft\\Crypto\\RSA\\","c:\\programdata\\microsoft\\crypto\\rsa\\",
                    "C:\\Documents and Settings\\All Users\\Microsoft\\Crypto\\RSA\\",
                    "${SamplePath}\\","<PATH_SAMPLE.EXE>","%SAMPLEPATH%",
                    r"C:\Documents and Settings\<User>\Application Data",
                    r"C:\Documents and Settings\<User>\Local Application Data","%Temp%",r"C:\Windows"
                    ]
    power_shell_cmd = ["%WinDir%\system32\vssadmin delete shadows /all"]
    # Check for suspicious network connections associated with petya
    SUSPICIOUS_NETWORK_IPS = ["50.7.138.132",'50.7.138.132', '46.4.20.40', '178.63.9.48', '94.242.216.5', '94.242.216.63']
    SUSPICIOUS_NETWORK_PORT = [1026,1433,1025,135,137,138,139,21,22,135,443,445,1433,1434,3389,4343,5000,5985,5355,8079,25055,4132,4124,4114,53]
    URLS_SUSPECTS = ['Tor2web.org', 'tor2web.fi','blutmagie.de',"h5534bvnrnkj345.maniupulp.com","pot98bza3sgfjr35t.fausttime.com","en.wikipedia.org",
            "bddadmin.desjardins.fr","southinstrument.org","i4sdmjn4fsdsdqfhu12l.orbyscabz.com","h5534bvnrnkj345.maniupulp.com","pot98bza3sgfjr35t.fausttime.com","i4sdmjn4fsdsdqfhu12l.orbyscabz.com","en.wikipedia.org",
            "dpckd2ftmf7lelsa.aenf387awmx28.com",'sshowmethemoney.com', 'jjeyd2u37an30.com', '63ghdye17.com', '42k2bu15.com', '42k2b14.net', '42kjb11.net', '2kjb9.net', '2kjb8.net', '2kjb7.net', '7hwr34n18.com', 'wh47f2as19.com', '63ghdye17.com', 'aw49f4j3n26.com', '79fhdm16.com', 'dfj3d8w3n27.com', '4lpwzo5ptsv6a2y5.onion', '34r6hq26q2h4jkzj.onion', 'qcuikaiye577q3p2.onion', '7tno4hib47vlep5o.onion', '3kxwjihmkgibht2s.onion', 'epmhyca5ol6plmx3.onion', 'tkj3higtqlvohs7z.onion']
    
    NT_DETECTED = ["What happened to your files ?"]
    # Registry Key of file :
    try :
        for i in dictionary["data"]["registry_keys_opened"] :
            for j in petya_REGISTRY_KEYS:
                if j in i:
                    if j in "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\":
                        if ".exe" in j or ".dll" in j:
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
                    if "%SAMPLEPATH%" in i or "${SamplePath}" in j or j in r"C:\Users\<User>\AppData\Local" or j in "C:\\DOCUME~1\\Miller\\LOCALS~1\\Temp\\":
                        if ".exe" in i or ".dll" in i:
                            total += 1
                        else :
                            total += 0
                    else:
                        total += 1
        #print("Total processes_terminated est : "+str(len(dictionary["data"]["processes_terminated"]))+"/"+str(total))
    except KeyError:
        total += 0

    # files deleted
    try :
        
        for i in dictionary["data"]["files_deleted"]:
            for j in petya_EXTENSIONS:
                if j.lower() in i.lower():
                    total += 1
            for j in PATH_RANSOMWARE:
                if j in i:
                    if "%SAMPLEPATH%" in i or "${SamplePath}" in j or r"C:\Users\<User>\AppData\Local":
                        if ".exe" in i or ".dll" in i:
                            total += 1
                        else :
                            total += 0
                    else:
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
            for j in petya_EXTENSIONS:
                if j.lower() in i["name"].lower():
                    total += 1
            for j in PATH_RANSOMWARE:
                if j in i:
                    if "%SAMPLEPATH%" in i["name"] or "${SamplePath}" in j or r"C:\Users\<User>\AppData\Local":
                        if ".exe" in i["name"] or ".dll" in i["name"]:
                            total += 1
                        else :
                            total += 0
                    else:
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
                        for l in petya_EXTENSIONS:
                            if l.lower() in k.lower():
                                total += 1
                        for l in PATH_RANSOMWARE:
                            if l.lower() in k.lower():
                                total += 1
                        for l in SUSPICIOUS_PROCESS_NAMES:
                            if l.lower() in k.lower():
                                total += 1
                        for l in petya_REGISTRY_KEYS:
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
            for j in petya_EXTENSIONS:
                if j.lower() in i.lower():
                    total += 1
            for j in SUSPICIOUS_PROCESS_NAMES:
                if j.lower() in i.lower():
                    total += 1
            for j in PATH_RANSOMWARE:
                if "%SAMPLEPATH%" in i or "${SamplePath}" in j or r"C:\Users\<User>\AppData\Local":
                        if ".exe" in i or ".dll" in i:
                            total += 1
                        else :
                            total += 0
        #print("Total modules_loaded est : "+str(len(dictionary["data"]["modules_loaded"]))+"/"+str(total))
    except KeyError :
        total += 0
    #dns_lookups
    try :
        for i in dictionary["data"]["dns_lookups"]:
            for j in URLS_SUSPECTS:
                if j in i["hostname"]:
                    total += 1
            for j in SUSPICIOUS_NETWORK_IPS:
                if j in i["resolved_ips"]:
                    total += 1
            
        #print("Total dns_lookups est : "+str(len(dictionary["data"]["dns_lookups"]))+"/"+str(total))
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
    mutex = ["Global\\","_!MSFTHISTORY!_","System1230123","dslhufdks3","uyfgdvcghuasd",r"\Sessions\1\BaseNamedObjects"]
    try :
        for i in dictionary["data"]["mutexes_created"]:
            for j in mutex:
                if j in i:
                    total += 1
        for i in dictionary["data"]["mutexes_opened"]:
            for j in mutex:
                if j in i:
                    total += 1
        #print("Total mutexes created and opened est : "+str(len(dictionary["data"]["mutexes_created"]))+"/"+str(total))
    except KeyError :
        total += 0

    # text_decoded
    try :
        
        for i in dictionary["data"]["text_decoded"]:
            if "petya" in i:
                total += 1
            for j in NT_DETECTED:
                if j in i:
                    total += 1
    except KeyError :
        total += 0

    # files_opened
    try :
        
        for i in dictionary["data"]["files_opened"]:
            for j in petya_EXTENSIONS:
                if j.lower() in i.lower():
                    total += 1
            for j in PATH_RANSOMWARE:
                if "%SAMPLEPATH%" in i or "${SamplePath}" in j or r"C:\Users\<User>\AppData\Local":
                        if ".exe" in i or ".dll" in i:
                            total += 1
                        else :
                            total += 0
            for j in SUSPICIOUS_PROCESS_NAMES:
                if j.lower() in i.lower():
                    total += 1
    except KeyError:
        total += 0

    #registry_keys_set
    try :
        
        for i in dictionary["data"]["registry_keys_set"]:
            for j in i:
                if j in "key":
                    for k in petya_REGISTRY_KEYS:
                        if k in i[j]:
                            total +=1
        
        #print("Total registry_keys_set est : "+str(len(dictionary["data"]["registry_keys_set"]))+"/"+str(total))
    except KeyError :
        total += 0
        
    # registry_keys_deleted
    try :
        
        for i in dictionary["data"]["registry_keys_deleted"]:
            for j in petya_REGISTRY_KEYS:
                if j in i:
                    total +=1
        
        #print("Total registry_keys_deleted est : "+str(len(dictionary["data"]["registry_keys_deleted"]))+"/"+str(total))
    except KeyError :
        total += 0

    # processes_created
    try :
        
        for i in dictionary["data"]["processes_created"]:
            for j in petya_EXTENSIONS:
                if j.lower() in i.lower():
                    total += 1
            for j in PATH_RANSOMWARE:
                if "%SAMPLEPATH%" in i or "${SamplePath}" in j or r"C:\Users\<User>\AppData\Local":
                        if ".exe" in i or ".dll" in i:
                            total += 1
                        else :
                            total += 0
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
        mitre_techniques = ["T1486","T1105","T1102","T1104","T1003","T1049","T1048","T1057","T1055","T1053","T1059","T1007","T1012","T1018","T1027",
                            "T1033","T1035","T1043","T1082","T1096","T1099","T1100","T1134","T1140","T1143","T1172","T1193","T1195","T1204","T1210",
                            "T1560","T1096","T1095","T1173","T1192","T1203","T1218","T1220","T1070","T1021","T1024","T1056","T1058","T1064","T1065",
                            "T1090","T1114","T1132","T1145"]
        
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
            for j in PATH_RANSOMWARE:
                if "%SAMPLEPATH%" in i["destination"] or "${SamplePath}" in j or r"C:\Users\<User>\AppData\Local":
                        if ".exe" in i["destination"] or ".dll" in i["destination"]:
                            total += 1
                        else :
                            total += 0
        #print("Total files_copied est : "+str(4 * len(dictionary["data"]["files_copied"]))+"/"+str(total))
    except KeyError:
        total += 0

    # files_written
    try :
        
        for i in dictionary["data"]["files_written"]:
            for j in petya_EXTENSIONS:
                if j.lower() in i.lower():
                    total += 1
            for j in SUSPICIOUS_PROCESS_NAMES:
                if j.lower() in i.lower():
                    total += 1
            for j in PATH_RANSOMWARE:
                if "%SAMPLEPATH%" in i or "${SamplePath}" in j or r"C:\Users\<User>\AppData\Local":
                        if ".exe" in i or ".dll" in i:
                            total += 1
                        else :
                            total += 0
            
        #print("Total files_written est : "+str(len(dictionary["data"]["files_written"]))+"/"+str(total))
    except KeyError:
        total += 0

    # files_dropped
    try :
        
        for i in dictionary["data"]["files_dropped"]:
            for j in i:
                if "path" in j:
                    for k in petya_EXTENSIONS:
                        if k.lower() in i[j].lower():
                            total += 1
                    for k in SUSPICIOUS_PROCESS_NAMES:
                        if k.lower() in i[j].lower():
                            total += 1
                    for k in PATH_RANSOMWARE:
                        if "%SAMPLEPATH%" in i or "${SamplePath}" in j or r"C:\Users\<User>\AppData\Local":
                            if ".exe" in i or ".dll" in i:
                                total += 1
                            else :
                                total += 0
            
        #print("Total files_dropped est : "+str(len(dictionary["data"]["files_dropped"]))+"/"+str(total))
    except KeyError:
        total += 0

    # command_executions
    try :
        
        for i in dictionary["data"]["command_executions"]:
            for j in power_shell_cmd :
                if j in i:
                    total += 1
            for j in SUSPICIOUS_PROCESS_NAMES:
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
    print("[TeslaCrypt] ~ La somme de tout est : "+str(total))
    return total

check_for_TeslaCrypt_behaviors(r"C:\Users\cherif\Documents\behaviour detections\behaviour_summary_results.json")
