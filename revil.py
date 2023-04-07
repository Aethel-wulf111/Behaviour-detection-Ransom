import json

def check_for_revil_behaviors(json_file):
    # Somme total 
    total = 0

    # Read the file json
    with open(json_file) as f:
        report_data = f.read()
    dictionary = json.loads(report_data)

    # List of common file extensions encrypted by revil
    revil_EXTENSIONS = [".revil",".veds",".klflf",".sodinokibi"]
    
    # List of common registry keys modified by revil
    revil_REGISTRY_KEYS = [
        r"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4",
        r"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS",
        r"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL",
        r"HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services",
        r"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Folder\Hidden\SHOWALL",
        r"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
        r"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
        r"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        r"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders",
        r"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SafeBoot\Network",
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
        "HKLM\\SYSTEM\\CurrentControlSet\\Services\\Winsock\\Setup Migration\\Providers\\Tcpip6",
        r"\REGISTRY\MACHINE\SOFTWARE\Wow6432Node\LFF9miD",
        "<HKLM>\\SOFTWARE\\Wow6432Node\\LFF9miD",
        "HKLM\\Software\\SBB CFF FFS AG\\Ransimware\\1.0.0.0"
    ]
    
    TERMES = ["top secret","Important confidential","Important equipment","Interior Pictures","Legal Affairs"]

    # Check for suspicious process names associated with revil
    SUSPICIOUS_PROCESS_NAMES = ["user32.dll","HOW-TO-DECRYPT.txt","dontsleep.exe","msmpeng.exe","netscan.exe","m.exe","Taschost.exe","u0441host.exe","int32.dll","psexec.exe","Invoice_29557473.exe","windef.exe","win163.65.tmp",
                                "winupd.tmp","officeupd.tmp","mswordupd.tmp","dospizdos.tmp","wordupd.tmp","wordupd_3.0.1.tmp","srv.txt",
                                "wm_start.bat","copy_files_srv.bat","rclone.exe","README.txt","ShellExperienceHost.exe","net.exe",
                                "revil_readme.txt", "taskdl.exe", "cobaltstrike.exe", "powershell.exe","cmd.exe", "rundll32.exe", "wscript.exe", 
                                "lsass.exe", "svchost.exe", "explorer.exe", "spoolsv.exe","crypt32.dll","bcrypt.dll","ncrypt.dll","CRYPTBASE.dll",
                                "wuapihost.exe","WMIC.exe","conhost.exe","CRYPTSP.dll","rpcrt4.dll","revil.exe","sc.exe","svc.exe","winlogon.exe",
                                "wermgr.exe","rdpclip.exe","wininit.exe","regsvr32.exe","wininet.dll","userinit.dll","wuauclt.exe",
                                "winrm.vbs","logonui.exe","backup.exe","msvcrt.dll","RpcRtRemote.dll","rasapi32.dll","rasman.dll",
                                "DECRYPT-FILES.txt","wmiprvse.exe","decrypt-files.html","unsecapp.exe","PXxGl2m5n3.exe","dllhost.exe","services.exe"
                                , "winlogon.exe","taskhost.exe","csrss.exe","ctfmon.exe","dwm.exe","mshta.exe","mstsc.exe","notepad.exe","netsh.exe",
                                "mmc.exe","calc.exe","chkdsk.exe","winword.exe","excel.exe","lsm.exe","osk.exe","msconfig.exe","winrm.exe","sethc.exe",
                                "cscript.exe","snippingtool.exe","schtasks.exe","Decryptor.exe"]
    PATH_RANSOMWARE = [r"%APPDATA%\teamviewers\msi.dll",r"c:\windows\192145.dll,StartW",
                    "C:\\bootmgr","C:\\totalcmd\\","C:\\Far2\\",
                    "C:\\Users\\user\\Documents\\",
                    "C:\\decrypt",
                    "C:\\Users\\<USER>\\Downloads\\ransimware.exe",
                    r"C:\Users\USER\AppData\Local\Temp\icju1.exe","%CONHOST%","C:\\Far2\\Plugins\\"
                    "C:\\ProgramData\\Microsoft\\Crypto\\RSA","C:\\Windows\\system32\\rsaenh.dll",
                    "C:\\Users\\All Users\\Microsoft\\Crypto\\RSA\\","c:\\programdata\\microsoft\\crypto\\rsa\\",
                    "C:\\Documents and Settings\\All Users\\Microsoft\\Crypto\\RSA\\",
                    "${SamplePath}\\","<PATH_SAMPLE.EXE>","%SAMPLEPATH%"]
    power_shell_cmd = ["cmd.exe /c vssadmin.exe Delete Shadows /All /Quiet & bcdedit /set {default}",
                    "recoveryenabled No & bcdedit /set {default} bootstatuspolicy ignoreallfailures"]
    # UNC2198
    # Check for suspicious network connections associated with revil
    SUSPICIOUS_NETWORK_IPS = [
        "54.39.233.132","45.67.14.162","185.193.141.248","185.234.218.9"
    ]
    SUSPICIOUS_NETWORK_PORT = [137,138,21,22,135,443,445,1433,1434,3389,4343,5000,5985,5355,8079,25055,4132,4124,4114,53]
    URLS_SUSPECTS = ['Anmcousa.xyz','Blaerck.xyz','cklinosleeve.icu','fcamylleibrahim.top','.onion','hcp://system','res://ieframe.dll','localhost','101gowrie.com', '123vrachi.ru', '12starhd.online', '1kbk.com.ua', '1team.es', '2ekeus.nl', '321play.com.hk', '35-40konkatsu.net', '365questions.org', '4net.guru', '4youbeautysalon.com', '8449nohate.org', 'DupontSellsHomes.com', 'aakritpatel.com', 'aarvorg.com', 'abitur-undwieweiter.de', 'abl1.net', 'abogadoengijon.es', 'abogados-en-alicante.es', 'abogadosaccidentetraficosevilla.es', 'abogadosadomicilio.es', 'abuelos.com', 'accountancywijchen.nl', 'aco-media.nl', 'acomprarseguidores.com', 'actecfoundation.org', 'admos-gleitlager.de', 'adoptioperheet.fi', 'adultgamezone.com', 'advizewealth.com', 'advokathuset.dk', 'agence-chocolat-noir.com', 'agence-referencement-naturel-geneve.net', 'aglend.com.au', 'ahouseforlease.com', 'ai-spt.jp', 'airconditioning-waalwijk.nl', 'alfa-stroy72.com', 'alhashem.net', 'all-turtles.com', 'allamatberedare.se', 'allentownpapershow.com', 'allfortheloveofyou.com', 'allure-cosmetics.at', 'almosthomedogrescue.dog', 'alsace-first.com', 'alten-mebel63.ru', 'alvinschwartz.wordpress.com', 'alysonhoward.com', 'americafirstcommittee.org', 'amerikansktgodis.se', 'aminaboutique247.com', 'ampisolabergeggi.it', 'amylendscrestview.com', 'analiticapublica.es', 'andersongilmour.co.uk', 'aniblinova.wordpress.com', 'answerstest.ru', 'antenanavi.com', 'anteniti.com', 'anthonystreetrimming.com', 'antiaginghealthbenefits.com', 'antonmack.de', 'anybookreader.de', 'aodaichandung.com', 'apolomarcas.com', 'apprendrelaudit.com', 'appsformacpc.com', 'aprepol.com', 'architecturalfiberglass.org', 'architekturbuero-wagner.net', 'argenblogs.com.ar', 'argos.wityu.fund', 'art2gointerieurprojecten.nl', 'artallnightdc.com', 'arteservicefabbro.com', 'artige.com', 'artotelamsterdam.com', 'aselbermachen.com', 'asgestion.com', 'asiluxury.com', 'associacioesportivapolitg.cat', 'associationanalytics.com', 'assurancesalextrespaille.fr', 'asteriag.com', 'atalent.fi', 'ateliergamila.com', 'atmos-show.com', 'atozdistribution.co.uk', 'augenta.com', 'aunexis.ch', 'aurum-juweliere.de', 'ausair.com.au', 'ausbeverage.com.au', 'austinlchurch.com', 'autodemontagenijmegen.nl', 'autodujos.lt', 'autofolierung-lu.de', 'autopfand24.de', 'babcockchurch.org', 'backstreetpub.com', 'bafuncs.org', 'balticdentists.com', 'balticdermatology.lt', 'baptisttabernacle.com', 'bargningavesta.se', 'bargningharnosand.se', 'baronloan.org', 'basisschooldezonnewijzer.nl', 'bastutunnan.se', 'bauertree.com', 'baumkuchenexpo.jp', 'baustb.de', 'baylegacy.com', 'bayoga.co.uk', 'bbsmobler.se', 'beaconhealthsystem.org', 'beautychance.se', 'behavioralmedicinespecialists.com', 'berlin-bamboo-bikes.org', 'berliner-versicherungsvergleich.de', 'bestbet.com', 'besttechie.com', 'better.town', 'beyondmarcomdotcom.wordpress.com', 'bhwlawfirm.com', 'biapi-coaching.fr', 'bierensgebakkramen.nl', 'bigasgrup.com', 'bigbaguettes.eu', 'bigler-hrconsulting.ch', 'bildungsunderlebnis.haus', 'bimnapratica.com', 'binder-buerotechnik.at', 'bingonearme.org', 'biortaggivaldelsa.com', 'birnam-wood.com', 'blacksirius.de', 'blewback.com', 'blgr.be', 'blog.solutionsarchitect.guru', 'blogdecachorros.com', 'bloggyboulga.net', 'blood-sports.net', 'blossombeyond50.com', 'blumenhof-wegleitner.at', 'bockamp.com', 'body-armour.online', 'body-guards.it', 'bodyforwife.com', 'bodyfulls.com', 'bogdanpeptine.ro', 'boisehosting.net', 'boldcitydowntown.com', 'bookspeopleplaces.com', 'boompinoy.com', 'boosthybrid.com.au', 'bordercollie-nim.nl', 'botanicinnovations.com', 'bouldercafe-wuppertal.de', 'boulderwelt-muenchen-west.de', 'bouncingbonanza.com', 'bouquet-de-roses.com', 'bowengroup.com.au', 'bptdmaluku.com', 'bradynursery.com', 'braffinjurylawfirm.com', 'brandl-blumen.de', 'brawnmediany.com', 'brevitempore.net', 'bricotienda.com', 'bridgeloanslenders.com', 'brigitte-erler.com', 'bristolaeroclub.co.uk', 'broseller.com', 'bsaship.com', 'bunburyfreightservices.com.au', 'bundabergeyeclinic.com.au', 'burkert-ideenreich.de', 'buroludo.nl', 'buymedical.biz', 'bxdf.info', 'c-a.co.in', 'c2e-poitiers.com', 'cactusthebrand.com', 'cafemattmeera.com', 'caffeinternet.it', 'calabasasdigest.com', 'calxplus.eu', 'campus2day.de', 'campusoutreach.org', 'camsadviser.com', 'candyhouseusa.com', 
                    'caribbeansunpoker.com', 'caribdoctor.org', 'carlosja.com', 'carolinepenn.com', 'carriagehousesalonvt.com', 'carrybrands.nl', 'castillobalduz.es', 'catholicmusicfest.com', 'ccpbroadband.com', 'ceid.info.tr', 'celeclub.org', 'celularity.com', 'centromarysalud.com', 'centrospgolega.com', 'centuryrs.com', 'cerebralforce.net', 'ceres.org.au', 'chandlerpd.com', 'chaotrang.com', 'charlesreger.com', 'charlottepoudroux-photographie.fr', 'chatizel-paysage.fr', 'chavesdoareeiro.com', 'chefdays.de', 'cheminpsy.fr', 'chrissieperry.com', 'christ-michael.net', 'christinarebuffetcourses.com', 'cimanchesterescorts.co.uk', 'cirugiauretra.es', 'cite4me.org', 'citymax-cr.com', 'cityorchardhtx.com', 'classycurtainsltd.co.uk', 'cleliaekiko.online', 'clos-galant.com', 'cnoia.org', 'coastalbridgeadvisors.com', 'coding-machine.com', 'coding-marking.com', 'coffreo.biz', 'collaborativeclassroom.org', 'colorofhorses.com', 'comarenterprises.com', 'commercialboatbuilding.com', 'commonground-stories.com', 'comparatif-lave-linge.fr', 'completeweddingkansas.com', 'compliancesolutionsstrategies.com', 'conasmanagement.de', 'conexa4papers.trade', 'connectedace.com', 'consultaractadenacimiento.com', 'controldekk.com', 'copystar.co.uk', 'corelifenutrition.com', 'corendonhotels.com', 'corola.es', 
                    'corona-handles.com', 'cortec-neuro.com', 'coursio.com', 'courteney-cox.net', 'craftleathermnl.com', 'craigmccabe.fun', 'craigvalentineacademy.com', 'cranleighscoutgroup.org', 'creamery201.com', 'creative-waves.co.uk', 'crediacces.com', 'croftprecision.co.uk', 'crosspointefellowship.church', 'crowd-patch.co.uk', 'csgospeltips.se', 'ctrler.cn', 'cuppacap.com', 'cursoporcelanatoliquido.online', 'cursosgratuitosnainternet.com', 'cuspdental.com', 'cwsitservices.co.uk', 'cyntox.com', 'd1franchise.com', 'd2marketing.co.uk', 'daklesa.de', 'danholzmann.com', 'daniel-akermann-architektur-und-planung.ch', 'danielblum.info', 'danskretursystem.dk', 'danubecloud.com', 'dareckleyministries.com', 'darnallwellbeing.org.uk', 'darrenkeslerministries.com', 'datacenters-in-europe.com', 'deepsouthclothingcompany.com', 'degroenetunnel.com', 'dekkinngay.com', 'deko4you.at', 'delchacay.com.ar', 'deltacleta.cat', 'denifl-consulting.at', 'denovofoodsgroup.com', 'deoudedorpskernnoordwijk.nl', 'deprobatehelp.com', 'deschl.net', 'desert-trails.com', 'despedidascostablanca.es', 'destinationclients.fr', 'devlaur.com', 'devok.info', 'devstyle.org', 'dezatec.es', 'digi-talents.com', 'digivod.de', 'dinslips.se', 'directwindowco.com', 'dirittosanitario.biz', 'ditog.fr', 'div-vertriebsforschung.de', 'diversiapsicologia.es', 'dlc.berlin', 'dnepr-beskid.com.ua', 'dontpassthepepper.com', 'dpo-as-a-service.com', 'dr-pipi.de', 'dr-seleznev.com', 'dr-tremel-rednitzhembach.de', 'dramagickcom.wordpress.com', 'drfoyle.com', 'drinkseed.com', 'drnice.de', 'drugdevice.org', 'dsl-ip.de', 'dublikator.com', 'dubnew.com', 'dubscollective.com', 'durganews.com', 'dushka.ua', 'dutchbrewingcoffee.com', 'dutchcoder.nl', 'dw-css.de', 'eadsmurraypugh.com', 'eaglemeetstiger.de', 'easytrans.com.au', 'echtveilig.nl', 'eco-southafrica.com', 'ecoledansemulhouse.fr', 'ecopro-kanto.com', 'ecpmedia.vn', 'edelman.jp', 'edgewoodestates.org', 'edrcreditservices.nl', 'educar.org', 'edv-live.de', 'effortlesspromo.com', 'eglectonk.online', 'elimchan.com', 'elpa.se', 'em-gmbh.ch', 'embracinghiscall.com', 'employeesurveys.com', 'enovos.de', 'entopic.com', 'epwritescom.wordpress.com', 'eraorastudio.com', 'erstatningsadvokaterne.dk', 'esope-formation.fr', 'euro-trend.pl', 'evangelische-pfarrgemeinde-tuniberg.de', 'evergreen-fishing.com', 'evologic-technologies.com', 'executiveairllc.com', 'exenberger.at', 'expandet.dk', 'extensionmaison.info', 'extraordinaryoutdoors.com', 'facettenreich27.de', 'fairfriends18.de', 'faizanullah.com', 'falcou.fr', 'familypark40.com', 'fannmedias.com', 'farhaani.com', 'faroairporttransfers.net', 'fatfreezingmachines.com', 'fax-payday-loans.com', 'fayrecreations.com', 'femxarxa.cat', 'fensterbau-ziegler.de', 'fibrofolliculoma.info', 'figura.team', 'filmstreamingvfcomplet.be', 'filmvideoweb.com', 'financescorecard.com', 'finde-deine-marke.de', 'finediningweek.pl', 'first-2-aid-u.com', 'firstpaymentservices.com', 'fiscalsort.com', 'fitnessbazaar.com', 'fitnessingbyjessica.com', 'fitovitaforum.com', 'fizzl.ru', 'flexicloud.hk', 'forestlakeuca.org.au', 'foretprivee.ca', 'forskolorna.org', 'foryourhealth.live', 'fotoideaymedia.es', 'fotoscondron.com', 'fransespiegels.nl', 'freie-baugutachterpraxis.de', 'freie-gewerkschaften.de', 'friendsandbrgrs.com', 'frontierweldingllc.com', 'ftf.or.at', 'ftlc.es', 'fundaciongregal.org', 'funjose.org.gt', 'gadgetedges.com', 'gaiam.nl', 'galleryartfair.com', 'galserwis.pl', 'gamesboard.info', 'gantungankunciakrilikbandung.com', 'garage-lecompte-rouen.fr', 'gasbarre.com', 'gasolspecialisten.se', 'gastsicht.de', 'geekwork.pl', 'geisterradler.de', 'gemeentehetkompas.nl', 'geoffreymeuli.com', 'girlillamarketing.com', 'glennroberts.co.nz', 'global-kids.info', 'globedivers.wordpress.com', 'gmto.fr', 'gonzalezfornes.es', 'goodgirlrecovery.com', 'gopackapp.com', 'gporf.fr', 'gratispresent.se', 'greenfieldoptimaldentalcare.com', 'greenko.pl', 'greenpark.ch', 'grelot-home.com', 'groupe-cets.com', 'groupe-frayssinet.fr', 'grupocarvalhoerodrigues.com.br', 
                    'gw2guilds.org', 'gymnasedumanagement.com', 'haar-spange.com', 'hairnetty.wordpress.com', 'hairstylesnow.site', 'handi-jack-llc.com', 'hannah-fink.de', 'happyeasterimages.org', 'hardinggroup.com', 'haremnick.com', 'harpershologram.wordpress.com', 'harveybp.com', 'hashkasolutindo.com', 'hatech.io', 'havecamerawilltravel2017.wordpress.com', 'healthyyworkout.com', 'hebkft.hu', 'heidelbergartstudio.gallery', 'helenekowalsky.com', 'helikoptervluchtnewyork.nl', 'heliomotion.com', 'hellohope.com', 'henricekupper.com', 'herbayupro.com', 'herbstfeststaefa.ch', 'heurigen-bauer.at', 'hexcreatives.co', 'hhcourier.com', 'hiddencitysecrets.com.au', 'higadograsoweb.com', 'highimpactoutdoors.net', 'highlinesouthasc.com', 'hihaho.com', 'hkr-reise.de', 'hmsdanmark.dk', 'hokagestore.com', 'homecomingstudio.com', 'homesdollar.com', 'homng.net', 'hoteledenpadova.it', 'hotelsolbh.com.br', 'hotelzentral.at', 'houseofplus.com', 'hrabritelefon.hr', 'htchorst.nl', 'huehnerauge-entfernen.de', 'huesges-gruppe.de', 'hugoversichert.de', 'huissier-creteil.com', 'humanityplus.org', 'hushavefritid.dk', 'hvccfloorcare.com', 'hypozentrum.com', 'i-arslan.de', 'i-trust.dk', 'ianaswanson.com', 'icpcnj.org', 'id-et-d.fr', 'id-vet.com', 'idemblogs.com', 'igfap.com', 'igorbarbosa.com', 'igrealestate.com', 'ihr-news.jp', 'ikads.org', 'ilcdover.com', 'ilive.lt', 'ilso.net', 'imadarchid.com', 'imaginado.de', 'imperfectstore.com', 'importardechina.info', 'innote.fi', 'ino-professional.ru', 'insidegarage.pl', 'insigniapmg.com', 'insp.bi', 'instatron.net', 'intecwi.com', 'interactcenter.org', 'international-sound-awards.com', 'iphoneszervizbudapest.hu', 'iqbalscientific.com', 'irinaverwer.com', 'irishmachineryauctions.com', 'itelagen.com', 'ivfminiua.com', 'iviaggisonciliegie.it', 'ivivo.es', 'iwelt.de', 'iwr.nl', 'iyahayki.nl', 'iyengaryogacharlotte.com', 'izzi360.com', 'jacquin-maquettes.com', 'jadwalbolanet.info', 'jakekozmor.com', 'jameskibbie.com', 'jandaonline.com', 'jbbjw.com', 'jeanlouissibomana.com', 'jenniferandersonwriter.com', 'jerling.de', 'jiloc.com', 'jobcenterkenya.com', 'jobmap.at', 'johnsonfamilyfarmblog.wordpress.com', 'jolly-events.com', 'jorgobe.at', 'joseconstela.com', 'journeybacktolife.com', 'joyeriaorindia.com', 'jsfg.com', 'judithjansen.com', 'julis-lsa.de', 'juneauopioidworkgroup.org', 'jusibe.com', 'justinvieira.com', 'jvanvlietdichter.nl', 'jyzdesign.com', 'kadesignandbuild.co.uk', 'kafu.ch', 'kaliber.co.jp', 'kalkulator-oszczednosci.pl', 'kamahouse.net', 'kamienny-dywan24.pl', 'kaminscy.com', 'kampotpepper.gives', 'kao.at', 'kaotikkustomz.com', 'karacaoglu.nl', 'kariokids.com', 'kath-kirche-gera.de', 'katiekerr.co.uk', 'kedak.de', 'kenhnoithatgo.com', 'kevinjodea.com', 'ki-lowroermond.nl', 'kidbucketlist.com.au', 'kikedeoliveira.com', 'kindersitze-vergleich.de', 'kingfamily.construction', 'kirkepartner.dk', 'kisplanning.com.au', 'kissit.ca', 'klimt2012.info', 'klusbeter.nl', 'kmbshipping.co.uk', 'knowledgemuseumbd.com', 'kojima-shihou.com', 'kojinsaisei.info', 'koken-voor-baby.nl', 'koko-nora.dk', 'kostenlose-webcams.com', 'kosterra.com', 'krcove-zily.eu', 'krlosdavid.com', 'kuntokeskusrok.fi', 'kunze-immobilien.de', 'labobit.it', 'lachofikschiet.nl', 'ladelirante.fr', 'lange.host', 'lapinlviasennus.fi', 'lapinvihreat.fi', 'lapmangfpt.info.vn', 'lascuola.nl', 'latestmodsapks.com', 'latribuessentielle.com', 'launchhubl.com', 'layrshift.eu', 'lbcframingelectrical.com', 'leather-factory.co.jp', 'lebellevue.fr', 'lecantou-coworking.com', 'leda-ukraine.com.ua', 'ledmes.ru', 'leeuwardenstudentcity.nl', 'lefumetdesdombes.com', 'lenreactiv-shop.ru', 'leoben.at', 'lescomtesdemean.be', 'levdittliv.se', 'levihotelspa.fi', 'lichencafe.com', 
                    'licor43.de', 'lightair.com', 'ligiercenter-sachsen.de', 'liikelataamo.fi', 'liliesandbeauties.org', 'lillegrandpalais.com', 'limassoldriving.com', 'lionware.de', 'littlebird.salon', 'live-con-arte.de', 'live-your-life.jp', 'liveottelut.com', 'lmtprovisions.com', 'logopaedie-blomberg.de', 'longislandelderlaw.com', 'loprus.pl', 'lorenacarnero.com', 'love30-chanko.com', 'lubetkinmediacompanies.com', 'lucidinvestbank.com', 'luckypatcher-apkz.com', 'lukeshepley.wordpress.com', 'lusak.at', 'luxurytv.jp', 'lykkeliv.net', 'lynsayshepherd.co.uk', 'maasreusel.nl', 'macabaneaupaysflechois.com', 'madinblack.com', 'maineemploymentlawyerblog.com', 'makeflowers.ru', 'makeitcount.at', 'makeurvoiceheard.com', 'malychanieruchomoscipremium.com', 'manifestinglab.com', 'manijaipur.com', 'mank.de', 'manutouchmassage.com', 'mapawood.com', 'marathonerpaolo.com', 'maratonaclubedeportugal.com', 'marchand-sloboda.com', 'marcuswhitten.site', 'mardenherefordshire-pc.gov.uk', 'marietteaernoudts.nl', 'mariposapropaneaz.com', 'markelbroch.com', 'marketingsulweb.com', 'maryloutaylor.com', 'mastertechengineering.com', 'maureenbreezedancetheater.org', 'maxadams.london', 'mbxvii.com', 'mdacares.com', 'mdk-mediadesign.de', 'mediaacademy-iraq.org', 'mediaclan.info', 'mediaplayertest.net', 'memaag.com', 'mepavex.nl', 'mercantedifiori.com', 'merzi.info', 'meusharklinithome.wordpress.com', 'mezhdu-delom.ru', 'micahkoleoso.de', 'michaelsmeriglioracing.com', 'micro-automation.de', 'microcirc.net', 'midmohandyman.com', 'mikeramirezcpa.com', 'milanonotai.it', 'milestoneshows.com', 'milltimber.aberdeen.sch.uk', 'milsing.hr', 'minipara.com', 'mir-na-iznanku.com', 'miraclediet.fun', 'miriamgrimm.de', 'mirjamholleman.nl', 'mirjamholleman.nl', 'mirkoreisser.de', 'mmgdouai.fr', 'modamilyon.com', 'modelmaking.nl', 'modestmanagement.com', 'monark.com', 'mooglee.com', 'mooreslawngarden.com', 'mooshine.com', 'morawe-krueger.de', 'mountaintoptinyhomes.com', 'mountsoul.de', 'mousepad-direkt.de', 'moveonnews.com', 'mrsfieldskc.com', 'mrsplans.net', 'mrtour.site', 'mrxermon.de', 'muamuadolls.com', 'musictreehouse.net', 'myhealth.net.au', 'myhostcloud.com', 'mylolis.com', 'mylovelybluesky.com', 'mymoneyforex.com', 'myteamgenius.com', 'mytechnoway.com', 'myzk.site', 'n1-headache.com', 'nachhilfe-unterricht.com', 'nacktfalter.de', 'nakupunafoundation.org', 'nancy-informatique.fr', 'nandistribution.nl', 'narcert.com', 
                    'naswrrg.org', 'nataschawessels.com', 'nativeformulas.com', 'naturalrapids.com', 'naturstein-hotte.de', 'ncid.bc.ca', 'ncs-graphic-studio.com', 'ncuccr.org', 'nestor-swiss.ch', 'neuschelectrical.co.za', 'new.devon.gov.uk', 'newstap.com.ng', 'newyou.at', 'nhadatcanho247.com', 'nicoleaeschbachorg.wordpress.com', 'nijaplay.com', 'nmiec.com', 'no-plans.com', 'noesis.tech', 'noixdecocom.fr', 'nokesvilledentistry.com', 'norovirus-ratgeber.de', 'norpol-yachting.com', 'noskierrenteria.com', 'nosuchthingasgovernment.com', 'notmissingout.com', 'notsilentmd.org', 'nsec.se', 'nurturingwisdom.com', 'nuzech.com', 'nvwoodwerks.com', 'oceanastudios.com', 'oemands.dk', 'officehymy.com', 'offroadbeasts.com', 'ogdenvision.com', 'ohidesign.com', 'oldschoolfun.net', 'olejack.ru', 'oncarrot.com', 'oneheartwarriors.at', 'oneplusresource.org', 'onlybacklink.com', 'onlyresultsmarketing.com', 'ontrailsandboulevards.com', 'opatrovanie-ako.sk', 'operaslovakia.sk', 'ora-it.de', 'oslomf.no', 'osterberg.fi', 'ostheimer.at', 'otsu-bon.com', 'otto-bollmann.de', 'ouryoungminds.wordpress.com', 'outcomeisincome.com', 'panelsandwichmadrid.es', 'paradicepacks.com', 'parebrise-tla.fr', 'parkcf.nl', 'parking.netgateway.eu', 'parks-nuernberg.de', 'parkstreetauto.net', 'partnertaxi.sk', 'pasivect.co.uk', 'pasvenska.se', 'patrickfoundation.net', 'paulisdogshop.de', 'pawsuppetlovers.com', 'pay4essays.net', 'paymybill.guru', 'pcp-nc.com', 'pcprofessor.com', 'pelorus.group', 'penco.ie', 'people-biz.com', 'perbudget.com', 'personalenhancementcenter.com', 'peterstrobos.com', 'petnest.ir', 'pferdebiester.de', 'phantastyk.com', 'philippedebroca.com', 'physiofischer.de', 'piajeppesen.dk', 'pickanose.com', 'pier40forall.org', 'pierrehale.com', 'pinkexcel.com', 'pivoineetc.fr', 'pixelarttees.com', 'planchaavapor.net', 'plantag.de', 'plastidip.com.ar', 'platformier.com', 'plotlinecreative.com', 'plv.media', 'pmc-services.de', 'pmcimpact.com', 'pocket-opera.de', 'podsosnami.ru', 'pogypneu.sk', 'pointos.com', 'polychromelabs.com', 'polymedia.dk', 'polzine.net', 'pomodori-pizzeria.de', 'porno-gringo.com', 'portoesdofarrobo.com', 'poultrypartners.nl', 'praxis-foerderdiagnostik.de', 'praxis-management-plus.de', 'precisionbevel.com', 'presseclub-magdeburg.de', 'pridoxmaterieel.nl', 'prochain-voyage.net', 'profectis.de', 'projetlyonturin.fr', 'promalaga.es', 'promesapuertorico.com', 'proudground.org', 'psa-sec.de', 'psc.de', 'psnacademy.in', 'pt-arnold.de', 'pubweb.carnet.hr', 'puertamatic.es', 'punchbaby.com', 'purposeadvisorsolutions.com', 'pv-design.de', 'qlog.de', 'qualitaetstag.de', 'qualitus.com', 'quemargrasa.net', 'quickyfunds.com', 'quizzingbee.com', 'ra-staudte.de', 'radaradvies.nl', 'rafaut.com', 'ralister.co.uk', 'raschlosser.de', 'ravensnesthomegoods.com', 'readberserk.com', 'real-estate-experts.com', 'rebeccarisher.com', 'reddysbakery.com', 'refluxreducer.com', 'rehabilitationcentersinhouston.net', 'remcakram.com', 'renergysolution.com', 'rerekatu.com', 'resortmtn.com', 'restaurantesszimmer.de', 'retroearthstudio.com', 'revezlimage.com', 'rhinosfootballacademy.com', 'richard-felix.co.uk', 'rieed.de', 'rimborsobancario.net', 'rksbusiness.com', 'roadwarrior.app', 'rocketccw.com', 'rollingrockcolumbia.com', 'romeguidedvisit.com', 'rosavalamedahr.com', 'rostoncastings.co.uk', 'rota-installations.co.uk', 'roygolden.com', 'rozemondcoaching.nl', 'rumahminangberdaya.com', 'run4study.com', 'ruralarcoiris.com', 'rushhourappliances.com', 'saarland-thermen-resort.com', 'sabel-bf.com', 'sachnendoc.com', 'sagadc.com', 'sahalstore.com', 'sairaku.net', 'saka.gr', 'samnewbyjax.com', 'sanaia.com', 'sandd.nl', 'sanyue119.com', 'sarbatkhalsafoundation.org', 'satyayoga.de', 'sauschneider.info', 'saxtec.com', 'scenepublique.net', 'schlafsack-test.net', 'schmalhorst.de', 'schmalhorst.de', 'schoellhammer.com', 'schoolofpassivewealth.com', 
                    'schraven.de', 'schutting-info.nl', 'seagatesthreecharters.com', 'securityfmm.com', 'seevilla-dr-sturm.at', 'seitzdruck.com', 'selfoutlet.com', 'seminoc.com', 'senson.fi', 'seproc.hn', 'serce.info.pl', 'servicegsm.net', 'sevenadvertising.com', 'sexandfessenjoon.wordpress.com', 'shadebarandgrillorlando.com', 'shhealthlaw.com', 'shiftinspiration.com', 'shiresresidential.com', 'shonacox.com', 'shsthepapercut.com', 'siliconbeach-realestate.com', 'siluet-decor.ru', 'simoneblum.de', 'simpkinsedwards.co.uk', 'simpliza.com', 'simplyblessedbykeepingitreal.com', 'simulatebrain.com', 'sinal.org', 'sipstroysochi.ru', 'skanah.com', 'skiltogprint.no', 'sla-paris.com', 'slashdb.com', 'slimani.net', 'slimidealherbal.com', 'sloverse.com', 'slupetzky.at', 'slwgs.org', 'smale-opticiens.nl', 'smalltownideamill.wordpress.com', 'smart-light.co.uk', 'smartypractice.com', 'smejump.co.th', 'smessier.com', 'smhydro.com.pl', 'smithmediastrategies.com', 'smogathon.com', 'smokeysstoves.com', 'sobreholanda.com', 'socialonemedia.com', 'socstrp.org', 'sofavietxinh.com', 'softsproductkey.com', 'sojamindbody.com', 'solerluethi-allart.ch', 'solhaug.tk', 'solinegraphic.com', 'songunceliptv.com', 'sotsioloogia.ee', 'southeasternacademyofprosthodontics.org', 'space.ua', 'spacecitysisters.org', 'spargel-kochen.de', 'spd-ehningen.de', 'spectrmash.ru', 'spinheal.ru', 'sporthamper.com', 'sportiomsportfondsen.nl', 'sportsmassoren.com', 'sportverein-tambach.de', 'spsshomeworkhelp.com', 'spylista.com', 'stacyloeb.com', 'stallbyggen.se', 'stampagrafica.es', 'starsarecircular.org', 'steampluscarpetandfloors.com', 'stefanpasch.me', 'stemenstilte.nl', 'stemplusacademy.com', 'sterlingessay.com', 'stingraybeach.com', 'stoeberstuuv.de', 'stoeferlehalle.de', 'stoneys.ch', 'stopilhan.com', 'stormwall.se', 'strandcampingdoonbeg.com', 'strategicstatements.com', 'streamerzradio1.site', 'stupbratt.no', 'summitmarketingstrategies.com', 'suncrestcabinets.ca', 'supportsumba.nl', 'surespark.org.uk', 'sw1m.ru', 'sweering.fr', 'symphonyenvironmental.com', 'syndikat-asphaltfieber.de', 'synlab.lt', 'systemate.dk', 'takeflat.com', 'talentwunder.com', 'tampaallen.com', 'tanciu.com', 'tandartspraktijkhartjegroningen.nl', 'tandartspraktijkheesch.nl', 'tanzprojekt.com', 
                    'tanzschule-kieber.de', 'tarotdeseidel.com', 'tastewilliamsburg.com', 'team-montage.dk', 'tecnojobsnet.com', 'teczowadolina.bytom.pl', 'teknoz.net', 'tenacitytenfold.com', 'tennisclubetten.nl', 'teresianmedia.org', 'testcoreprohealthuk.com', 'testzandbakmetmening.online', 'tetinfo.in', 'thailandholic.com', 'thaysa.com', 'the-domain-trader.com', 'the-virtualizer.com', 'theadventureedge.com', 'theapifactory.com', 'theclubms.com', 'thedad.com', 'thedresserie.com', 'theduke.de', 
                    'thee.network', 'thefixhut.com', 'theletter.company', 'themadbotter.com', 'thenewrejuveme.com', 'theshungiteexperience.com.au', 'thewellnessmimi.com', 'thomas-hospital.de', 'thomasvicino.com', 'tigsltd.com', 'tinkoff-mobayl.ru', 'tinyagency.com', 'tips.technology', 'todocaracoles.com', 'tomaso.gr', 'tomoiyuma.com', 'tonelektro.nl', 'tongdaifpthaiphong.net', 'tophumanservicescourses.com', 'toponlinecasinosuk.co.uk', 'toreria.es', 'torgbodenbollnas.se', 'trackyourconstruction.com', 'tradiematepro.com.au', 'transliminaltribe.wordpress.com', 'transportesycementoshidalgo.es', 'trapiantofue.it', 'travelffeine.com', 'triactis.com', 'triggi.de', 'troegs.com', 'truenyc.co', 'trulynolen.co.uk', 'trystana.com', 'tsklogistik.eu', 'tstaffing.nl', 'tulsawaterheaterinstallation.com', 'turkcaparbariatrics.com', 'tuuliautio.fi', 'tux-espacios.com', 'twohourswithlena.wordpress.com', 'uimaan.fi', 'ulyssemarketing.com', 'unetica.fr', 'ungsvenskarna.se', 'unim.su', 'upmrkt.co', 'upplandsspar.se', 'uranus.nl', 'urclan.net', 'urist-bogatyr.ru', 'urmasiimariiuniri.ro', 'ussmontanacommittee.us', 'vancouver-print.ca', 'vannesteconstruct.be', 'vanswigchemdesign.com', 'vdberg-autoimport.nl', 'ventti.com.ar', 'verbisonline.com', 'verifort-capital.de', 'vermoote.de', 'verytycs.com', 'vesinhnha.com.vn', 'vetapharma.fr', 'veybachcenter.de', 'vibehouse.rw', 'vibethink.net', 'vickiegrayimages.com', 'victoriousfestival.co.uk', 'videomarketing.pro', 'vietlawconsultancy.com', 'vihannesporssi.fi', 'villa-marrakesch.de', 'visiativ-industry.fr', 'vitalyscenter.es', 'vitavia.lt', 'vloeren-nu.nl', 'vorotauu.ru', 'vox-surveys.com', 'vyhino-zhulebino-24.ru', 'wacochamber.com', 'waermetauscher-berechnen.de', 'walkingdeadnj.com', 'walter-lemm.de', 'wari.com.pe', 'wasmachtmeinfonds.at', 'waveneyrivercentre.co.uk', 'waynela.com', 'waywithwords.net', 'web.ion.ag', 'webcodingstudio.com', 'webmaster-peloton.com', 'wellplast.se', 'werkkring.nl', 'westdeptfordbuyrite.com', 'whittier5k.com', 'whyinterestingly.ru', 'wien-mitte.co.at', 'winrace.no', 'withahmed.com', 'wmiadmin.com', 'wolf-glas-und-kunst.de', 'woodleyacademy.org', 'woodworkersolution.com', 'work2live.de', 'worldhealthbasicinfo.com', 'wraithco.com', 'wsoil.com.sg', 'wurmpower.at', 'www1.proresult.no', 'wychowanieprzedszkolne.pl', 'x-ray.ca', 'xlarge.at', 'xltyu.com', 'xn--fn-kka.no', 'xn--fnsterputssollentuna-39b.se', 'xn--logopdie-leverkusen-kwb.de', 'xn--rumung-bua.online', 'xn--singlebrsen-vergleich-nec.com', 'xn--thucmctc-13a1357egba.com', 'xn--vrftet-pua.biz', 'xoabigail.com', 'xtptrack.com', 'y-archive.com', 'yamalevents.com', 'yassir.pro', 'ymca-cw.org.uk', 'you-bysia.com.au', 'yourobgyn.net', 'yousay.site', 'zenderthelender.com', 'zervicethai.co.th', 'zewatchers.com', 'zflas.com', 'ziegler-praezisionsteile.de', 'zieglerbrothers.de', 'zimmerei-deboer.de', 'zimmerei-fl.de', 'zonamovie21.net', 'zso-mannheim.de', 'zweerscreatives.nl', 'zzyjtsgls.com']
    NT_DETECTED = ["Your files are encrypted"]
    # Registry Key of file :
    try :
        for i in dictionary["data"]["registry_keys_opened"] :
            for j in revil_REGISTRY_KEYS:
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
                    if "%SAMPLEPATH%" in i or "${SamplePath}" in j :
                        if ".exe" in i:
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
            for j in revil_EXTENSIONS:
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
            for j in revil_EXTENSIONS:
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
                        for l in revil_EXTENSIONS:
                            if l.lower() in k.lower():
                                total += 1
                        for l in PATH_RANSOMWARE:
                            if l.lower() in k.lower():
                                total += 1
                        for l in SUSPICIOUS_PROCESS_NAMES:
                            if l.lower() in k.lower():
                                total += 1
                        for l in revil_REGISTRY_KEYS:
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
            for j in revil_EXTENSIONS:
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
    #dns_lookups
    try :
        for i in dictionary["data"]["dns_lookups"]:
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
    mutex = [r"Global\MsWinZonesCacheCounterMutexA",r"Global\UACMutex",r"Global\WindowsUpdateLockMutex",r"Global\RpcEptMapperMutex",
            r"Global\UuidMutex",r"Global\wininetCacheMutex","Global\\","Local\\"]
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
            if "revil" in i:
                total += 1
            for j in NT_DETECTED:
                if j in i:
                    total += 1
    except KeyError :
        total += 0

    # files_opened
    try :
        
        for i in dictionary["data"]["files_opened"]:
            for j in revil_EXTENSIONS:
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
                    for k in revil_REGISTRY_KEYS:
                        if k in i[j]:
                            total +=1
        
        #print("Total registry_keys_set est : "+str(len(dictionary["data"]["registry_keys_set"]))+"/"+str(total))
    except KeyError :
        total += 0
        
    # registry_keys_deleted
    try :
        
        for i in dictionary["data"]["registry_keys_deleted"]:
            for j in revil_REGISTRY_KEYS:
                if j in i:
                    total +=1
        
        #print("Total registry_keys_deleted est : "+str(len(dictionary["data"]["registry_keys_deleted"]))+"/"+str(total))
    except KeyError :
        total += 0

    # processes_created
    try :
        
        for i in dictionary["data"]["processes_created"]:
            for j in revil_EXTENSIONS:
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
        mitre_techniques = ["T1566","T1190","T1189","T1195","T1078","T1204","T1129","T1059","T1106","T1547","T1574","T1134","T1068","T1574","T1027",
                            "T1562","T1574","T1083","T1018","T1057","T1082","T1012","T1063","T1003","T1552","T1570","T1560","T1005","T1071","T1567",
                            "T1048","T1486","T1489","T1490","T1529","T1491","T1518"]
        
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
            for j in PATH_RANSOMWARE:
                if j.lower() in i["destination"].lower():
                    total += 1
        #print("Total files_copied est : "+str(4 * len(dictionary["data"]["files_copied"]))+"/"+str(total))
    except KeyError:
        total += 0

    # files_written
    try :
        
        for i in dictionary["data"]["files_written"]:
            for j in revil_EXTENSIONS:
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
                    for k in revil_EXTENSIONS:
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
    print("[revil] ~ La somme de tout est : "+str(total))
    return total

check_for_revil_behaviors(r"C:\Users\cherif\Documents\behaviour detections\behaviour_summary_results.json")
