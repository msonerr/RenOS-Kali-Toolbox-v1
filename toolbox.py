#!/usr/bin/env python
#_*_ coding: utf-8 _*_
# RenOs Kali Toolkit v1.0 
# Kodlayan : Muhammed SÖNER
# Email : msonerr@yandex.com
# Site : Kali-linuxtr.net

import os
import sys, traceback

print r"""
  _____             ____   _____ 
 |  __ \           / __ \ / ____|
 | |__) |___ _ __ | |  | | (___  
 |  _  // _ \ '_ \| |  | |\___ \ 
 | | \ \  __/ | | | |__| |____) |
 |_|  \_\___|_| |_|\____/|_____/ 
                                 
"""
	
### Bilgi Menüsü
def bilgi():
	print r"""
 RenOs Kali Toolkit v1.0 
 Kodlayan : Muhammed SÖNER
 Email : msonerr@yandex.com
 Site : Kali-linuxtr.net
"""
bilgi()
###Information Gathering
def kategori_1():
	print r"""
	[1] acccheck 			[20] enum4linux			[39] ntop
	[2] ace-voip			[21] enumIAX			[40] p0f
	[3] Amap			[22] exploitdb			[41] Parsero
	[4] Automater  			[23] Fierce			[42] Recon-ng 		 	
	[5] bing-ip2hosts		[24] Firewalk 			[43] SET
	[6] braa 	        	[25] fragroute 			[44] smtp-user-enum
	[7] CaseFile 			[26] fragrouter        		[45] snmpcheck
	[8] CDPSnarf	        	[27] Ghost Phisher              [46] sslcaudit
	[9] cisco-torch 		[28] GoLismero			[47] SSLsplit
	[10] Cookie Cadger 		[29] goofile 			[48] sslstrip
	[11] copy-router-config 	[30] hping3            		[49] SSLyze
	[12] DMitry 			[31] InTrace   			[50] THC-IPV6 
	[13] dnmap			[32] iSMTP			[51] theHarvester
	[14] dnsenum 			[33] lbd			[52] TLSSLed
	[15] dnsmap			[34] Maltego Teeth		[53] twofi
	[16] DNSRecon			[35] masscan			[54] URLCrazy
	[17] dnstracer			[36] Metagoofil			[55] Wireshark
	[18] dnswalk			[37] Miranda			[56] WOL-E 
	[19] DotDotPwn			[38] Nmap			[57] Xplico
	"""
	secenek=raw_input("RenOS > ")
	if secenek=="1":
		s1=os.system("apt-get install acccheck")
	elif secenek=="2":
		s1=os.system("apt-get install ace-voip")
	elif secenek=="3":
		s1=os.system("apt-get install amap")
	elif secenek=="4":
		s1=os.system("apt-get install automater")
	elif secenek=="5":
		s1=os.system("apt-get install bing-ip2hosts ")
	elif secenek=="6":
		s1=os.system("apt-get install braa")
	elif secenek=="7":
		s1=os.system("apt-get install casefile")
	elif secenek=="8":
		s1=os.system("apt-get install cdpsnarf")
	elif secenek=="9":
		s1=os.system("apt-get install cisco-torch")
	elif secenek=="10":
		s1=os.system("apt-get install cookie cadger")
	elif secenek=="11":
		s1=os.system("apt-get install copy-router-config")
	elif secenek=="12":
		s1=os.system("apt-get install dmitry")
	elif secenek=="13":
		s1=os.system("apt-get install dnmap")
	elif secenek=="14":
		s1=os.system("apt-get install dnsenum")
	elif secenek=="15":
		s1=os.system("apt-get install dnsmap")
	elif secenek=="16":
		s1=os.system("apt-get install dnsrecon")
	elif secenek=="17":
		s1=os.system("apt-get install dnstracer")
	elif secenek=="18":
		s1=os.system("apt-get install dnswalk")
	elif secenek=="19":
		s1=os.system("apt-get install dotdotpwn")
	elif secenek=="20":
		s1=os.system("apt-get install enum4linux")
	elif secenek=="21":
		s1=os.system("apt-get install enumiax")
	elif secenek=="22":
		s1=os.system("apt-get install exploitdb")
	elif secenek=="23":
		s1=os.system("apt-get install fierce")
	elif secenek=="24":
		s1=os.system("apt-get install firewalk")
	elif secenek=="25":
		s1=os.system("apt-get install fragroute")
	elif secenek=="26":
		s1=os.system("apt-get install fragrouter")
	elif secenek=="27":
		s1=os.system("apt-get install ghost phisher")
	elif secenek=="29":
		s1=os.system("apt-get install golismero")
	elif secenek=="30":
		s1=os.system("apt-get install goofile")
	elif secenek=="31":
		s1=os.system("apt-get install hping3")
	elif secenek=="32":
		s1=os.system("apt-get install intrace")
	elif secenek=="33":
		s1=os.system("apt-get install lbd")
	elif secenek=="34":
		s1=os.system("apt-get install maltego-teeth")
	elif secenek=="35":
		s1=os.system("apt-get install masscan")
	elif secenek=="36":
		s1=os.system("apt-get install metagoofil")
	elif secenek=="37":
		s1=os.system("apt-get install miranda")
	elif secenek=="38":
		s1=os.system("apt-get install nmap")
	elif secenek=="39":
		s1=os.system("apt-get install ntop")
	elif secenek=="40":
		s1=os.system("apt-get install p0f")
	elif secenek=="41":
		s1=os.system("apt-get install parsero")
	elif secenek=="42":
		s1=os.system("apt-get install recon-ng")
	elif secenek=="43":
		s1=os.system("apt-get install set")
	elif secenek=="44":
		s1=os.system("apt-get install smtp-user-enum")
	elif secenek=="45":
		s1=os.system("apt-get install snmpcheck")
	elif secenek=="46":
		s1=os.system("apt-get install sslcaudit")
	elif secenek=="47":
		s1=os.system("apt-get install sslsplit")
	elif secenek=="48":
		s1=os.system("apt-get install sslstrip")
	elif secenek=="49":
		s1=os.system("apt-get install sslyze")
	elif secenek=="50":
		s1=os.system("apt-get install thc-ipv6 ")
	elif secenek=="51":
		s1=os.system("apt-get install theharvester")
	elif secenek=="52":
		s1=os.system("apt-get install tlssled")
	elif secenek=="53":
		s1=os.system("apt-get install twofi")
	elif secenek=="54":
		s1=os.system("apt-get install urlcrazy")
	elif secenek=="55":
		s1=os.system("apt-get install Wireshark")
	elif secenek=="56":
		s1=os.system("apt-get install WOL-E ")
	elif secenek=="57":
		s1=os.system("apt-get install xplico")
	else:
		print "Hatalı Giriş"	
###Vulnerability Analysis
def kategori_2():
	print r"""
	[1] BBQSQL				[13] HexorBase 			[25] sfuzz
	[2] BED					[14] Inguma			[26] SidGuesser
	[3] cisco-auditing-tool 		[15] jSQL			[27] SIPArmyKnife
	[4] cisco-global-exploiter 		[16] Lynis			[28] sqlmap
	[5] cisco-ocs 				[17] Nmap			[29] Sqlninja
	[6] cisco-torch 	  		[18] ohrwurm 			[30] sqlsus
	[7] copy-router-config 			[19] openvas-administrator 	[31] THC-IPV6 	
	[8] DBPwAudit				[20] openvas-cli 		[32] tnscmd10g
	[9] Doona				[21] openvas-manager 		[33] unix-privesc-check 
	[10] DotDotPwn				[22] openvas-scanner 		[34] Yersinia
	[11] Greenbone Security Assistant 	[23] openvas-scanner 		
	[12] GSD				[24] Powerfuzzer
	""" 
	secenek=raw_input("RenOS > ")
	if secenek=="1":
		s1=os.system("apt-get install BBQSQL")
	elif secenek=="2":
		s1=os.system("apt-get install BED")
	elif secenek=="3":
		s1=os.system("apt-get install cisco-auditing-tool")
	elif secenek=="4":
		s1=os.system("apt-get install cisco-global-exploiter")
	elif secenek=="5":
		s1=os.system("apt-get install cisco-ocs")
	elif secenek=="6":
		s1=os.system("apt-get install cisco-torch")
	elif secenek=="7":
		s1=os.system("apt-get install copy-router-config")
	elif secenek=="8":
		s1=os.system("apt-get install dBPwAudit")
	elif secenek=="9":
		s1=os.system("apt-get install doona")
	elif secenek=="10":
		s1=os.system("apt-get install dotDotPwn")
	elif secenek=="11":
		s1=os.system("apt-get install greenbone Security Assistant")
	elif secenek=="12":
		s1=os.system("apt-get install GSD")
	elif secenek=="13":
		s1=os.system("apt-get install hexorBase")
	elif secenek=="14":
		s1=os.system("apt-get install inguma")
	elif secenek=="15":
		s1=os.system("apt-get install jSQL")
	elif secenek=="16":
		s1=os.system("apt-get install lynis")
	elif secenek=="17":
		s1=os.system("apt-get install nmap")
	elif secenek=="18":
		s1=os.system("apt-get install ohrwurm")
	elif secenek=="19":
		s1=os.system("apt-get install openvas-administrator")
	elif secenek=="20":
		s1=os.system("apt-get install openvas-cli")
	elif secenek=="21":
		s1=os.system("apt-get install openvas-manager")
	elif secenek=="22":
		s1=os.system("apt-get install openvas-scanner")
	elif secenek=="23":
		s1=os.system("apt-get install oscanner")
	elif secenek=="24":
		s1=os.system("apt-get install powerfuzzer")
	elif secenek=="25":
		s1=os.system("apt-get install sfuzz")
	elif secenek=="26":
		s1=os.system("apt-get install sidGuesser")
	elif secenek=="27":
		s1=os.system("apt-get install siPArmyKnife")
	elif secenek=="28":
		s1=os.system("apt-get install sqlmap")
	elif secenek=="29":
		s1=os.system("apt-get install sqlninja")
	elif secenek=="30":
		s1=os.system("apt-get install sqlsus")
	elif secenek=="31":
		s1=os.system("apt-get install tHC-IPV6 ")
	elif secenek=="32":
		s1=os.system("apt-get install tnscmd10g")
	elif secenek=="33":
		s1=os.system("apt-get install unix-privesc-check ")
	elif secenek=="34":
		s1=os.system("apt-get install yersinia")
	else:
		print "Hatalı Giriş..."	
###Web Applications
def kategori_3():
	print r"""
    	[1] apache-users 		[15] joomscan			[29] ua-tester 
	[2] Arachni			[16] jSQL			[30] Uniscan
	[3] BBQSQL			[17] Maltego Teeth 		[31] Vega
	[4] BlindElephant		[18] PadBuster			[32] w3af
	[5] Burp Suite 			[19] Paros 			[33] WebScarab
	[6] CutyCapt  			[20] Parsero			[34] Webshag
	[7] DAVTest			[21] plecost	        	[35] WebSlayer
	[8] deblaze			[22] Powerfuzzer		[36] WebSploit
	[9] DIRB			[23] ProxyStrike		[37] Wfuzz
	[10] DirBuster			[24] Recon-ng 			[38] WPScan
	[11] fimap			[25] Skipfish 		    	[39] XSSer
	[12] FunkLoad			[26] sqlmap   			[40] zaproxy
	[13] Grabber			[27] Sqlninja
	[14] jboss-autopwn 		[28] sqlsus 	
	"""
	secenek=raw_input("RenOS > ")
	if secenek=="1":
		s1=os.system("apt-get install apache-users")
	elif secenek=="2":
		s1=os.system("apt-get install arachni")
	elif secenek=="3":
		s1=os.system("apt-get install BBQSQL")
	elif secenek=="4":
		s1=os.system("apt-get install blindElephant")
	elif secenek=="5":
		s1=os.system("apt-get install burp Suite")
	elif secenek=="6":
		s1=os.system("apt-get install cutyCapt")
	elif secenek=="7":
		s1=os.system("apt-get install dAVTest")
	elif secenek=="8":
		s1=os.system("apt-get install deblaze")
	elif secenek=="9":
		s1=os.system("apt-get install dirb")
	elif secenek=="10":
		s1=os.system("apt-get install dirBuster")
	elif secenek=="11":
		s1=os.system("apt-get install fimap")
	elif secenek=="12":
		s1=os.system("apt-get install funkLoad")
	elif secenek=="13":
		s1=os.system("apt-get install grabber")
	elif secenek=="14":
		s1=os.system("apt-get install jboss-autopwn")
	elif secenek=="15":
		s1=os.system("apt-get install joomscan")
	elif secenek=="16":
		s1=os.system("apt-get install jSQL")
	elif secenek=="17":
		s1=os.system("apt-get install maltego Teeth")
	elif secenek=="18":
		s1=os.system("apt-get install padBuster")
	elif secenek=="19":
		s1=os.system("apt-get install paros")
	elif secenek=="20":
		s1=os.system("apt-get install Parsero")
	elif secenek=="21":
		s1=os.system("apt-get install plecost")
	elif secenek=="22":
		s1=os.system("apt-get install Powerfuzzer")
	elif secenek=="23":
		s1=os.system("apt-get install ProxyStrike")
	elif secenek=="24":
		s1=os.system("apt-get install recon-ng")
	elif secenek=="25":
		s1=os.system("apt-get install skipfish")
	elif secenek=="26":
		s1=os.system("apt-get install sqlmap")
	elif secenek=="27":
		s1=os.system("apt-get install sqlninja")
	elif secenek=="28":
		s1=os.system("apt-get install sqlsus")
	elif secenek=="29":
		s1=os.system("apt-get install ua-tester")
	elif secenek=="30":
		s1=os.system("apt-get install uniscan")
	elif secenek=="31":
		s1=os.system("apt-get install vega")
	elif secenek=="32":
		s1=os.system("apt-get install w3af")
	elif secenek=="33":
		s1=os.system("apt-get install webScarab")
	elif secenek=="34":
		s1=os.system("apt-get install webshag")
	elif secenek=="35":
		s1=os.system("apt-get install webSlayer")
	elif secenek=="36":
		s1=os.system("apt-get install webSploit")
	elif secenek=="37":
		s1=os.system("apt-get install wfuzz")
	elif secenek=="38":
		s1=os.system("apt-get install wPScan")
	elif secenek=="39":
		s1=os.system("apt-get install xSSer")
	elif secenek=="40":
		s1=os.system("apt-get install zaproxy")
	else:
		print "Hatalı Giriş..."	
###Wireless Attacks
def kategori_4():
	print r"""
 	[1] Aircrack-ng 		[13] Ghost Phisher 		[25] PixieWPS
	[2] Asleap  			[14] GISKismet			[26] Reaver
	[3] Bluelog			[15] Gqrx			[27] redfang
	[4] BlueMaho			[16] gr-scan 			[28] RTLSDR Scanner 
	[5] Bluepot			[17] kalibrate-rtl 		[29] Spooftooph
	[6] BlueRanger 			[18] KillerBee    		[30] Wifi Honey 
	[7] Bluesnarfer			[19] Kismet	        	[31] Wifitap
	[8] Bully			[20] mdk3 			[32] Wifite
	[9] coWPAtty			[21] mfcuk
	[10] crackle			[22] mfoc
	[11] eapmd5pass			[23] mfterm		
	[12] Fern Wifi Cracker 		[24] Multimon-NG 
	"""
	secenek=raw_input("RenOS > ")
	if secenek=="1":
		s1=os.system("apt-get install aircrack-ng")
	elif secenek=="2":
		s1=os.system("apt-get install asleap")
	elif secenek=="3":
		s1=os.system("apt-get install bluelog")
	elif secenek=="4":
		s1=os.system("apt-get install blueMaho")
	elif secenek=="5":
		s1=os.system("apt-get install bluepot")
	elif secenek=="6":
		s1=os.system("apt-get install blueRanger")
	elif secenek=="7":
		s1=os.system("apt-get install bluesnarfer")
	elif secenek=="8":
		s1=os.system("apt-get install bully")
	elif secenek=="9":
		s1=os.system("apt-get install coWPAtty")
	elif secenek=="10":
		s1=os.system("apt-get install crackle")
	elif secenek=="11":
		s1=os.system("apt-get install eapmd5pass")
	elif secenek=="12":
		s1=os.system("apt-get install fern Wifi Cracker")
	elif secenek=="13":
		s1=os.system("apt-get install ghost Phisher")
	elif secenek=="14":
		s1=os.system("apt-get install giSKismet")
	elif secenek=="15":
		s1=os.system("apt-get install gqrx")
	elif secenek=="16":
		s1=os.system("apt-get install gr-scan")
	elif secenek=="17":
		s1=os.system("apt-get install kalibrate-rtl")
	elif secenek=="18":
		s1=os.system("apt-get install killerBee")
	elif secenek=="19":
		s1=os.system("apt-get install Kismet")
	elif secenek=="20":
		s1=os.system("apt-get install mdk3")
	elif secenek=="21":
		s1=os.system("apt-get install mfcuk")
	elif secenek=="22":
		s1=os.system("apt-get install mfoc")
	elif secenek=="23":
		s1=os.system("apt-get install mfterm")
	elif secenek=="24":
		s1=os.system("apt-get install multimon-NG")
	elif secenek=="25":
		s1=os.system("apt-get install pixieWPS")
	elif secenek=="26":
		s1=os.system("apt-get install reaver")
	elif secenek=="27":
		s1=os.system("apt-get install redfang")
	elif secenek=="28":
		s1=os.system("apt-get install rTLSDR Scanner")
	elif secenek=="29":
		s1=os.system("apt-get install spooftooph")
	elif secenek=="30":
		s1=os.system("apt-get install Wifi Honey")
	elif secenek=="31":
		s1=os.system("apt-get install Wifitap")
	elif secenek=="32":
		s1=os.system("apt-get install Wifite")
	else:
		print "Hatalı Giriş..."	
###Exploitation Tools
def kategori_5():
	print r"""
	[1] Armitage			[10] jboss-autopwn 
	[2] Backdoor Factory		[11] Linux Exploit Suggester
	[3] BeEF			[12] Maltego Teeth
	[4] cisco-auditing-tool		[13] SET
	[5] cisco-global-exploiter	[14] ShellNoob
	[6] cisco-ocs  			[15] sqlmap
	[7] cisco-torch			[16] THC-IPV6
	[8] Commix			[17] Yersinia
	[9] crackle
	"""
	secenek=raw_input("RenOS > ")
	if secenek=="1":
		s1=os.system("apt-get install armitage")
	elif secenek=="2":
		s1=os.system("apt-get install backdoor Factory")
	elif secenek=="3":
		s1=os.system("apt-get install beEF")
	elif secenek=="4":
		s1=os.system("apt-get install cisco-auditing-tool")
	elif secenek=="5":
		s1=os.system("apt-get install cisco-global-exploiter")
	elif secenek=="6":
		s1=os.system("apt-get install cisco-ocs")
	elif secenek=="7":
		s1=os.system("apt-get install cisco-torch")
	elif secenek=="8":
		s1=os.system("apt-get install commix")
	elif secenek=="9":
		s1=os.system("apt-get install crackle")
	elif secenek=="10":
		s1=os.system("apt-get install jboss-autopwn")
	elif secenek=="11":
		s1=os.system("apt-get install linux Exploit Suggester")
	elif secenek=="12":
		s1=os.system("apt-get install maltego Teeth")
	elif secenek=="13":
		s1=os.system("apt-get install SET")
	elif secenek=="14":
		s1=os.system("apt-get install shellNoob")
	elif secenek=="15":
		s1=os.system("apt-get install sqlmap")
	elif secenek=="16":
		s1=os.system("apt-get install tHC-iPV6")
	elif secenek=="17":
		s1=os.system("apt-get install yersinia")
	else:
		print "Hatalı Giriş..."
###Forensics Tools
def kategori_6():
	print r"""
	[1] Binwalk 			[13] Galleta
	[2] bulk-extractor		[14] Guymager
	[3] Capstone			[15] iPhone Backup Analyzer
	[4] chntpw			[16] p0f
	[5] Cuckoo			[17] pdf-parser
	[6] dc3dd  			[18] pdfid
	[7] ddrescue			[19] pdgmail
	[8] DFF				[20] peepdf
	[9] diStorm3			[21] RegRipper 
	[10] Dumpzilla			[22] Volatility
	[11] extundelete		[23] Xplico
	[12] Foremost			
	"""
	secenek=raw_input("RenOS > ")
	if secenek=="1":
		s1=os.system("apt-get install binwalk")
	elif secenek=="2":
		s1=os.system("apt-get install bulk-extractor")
	elif secenek=="3":
		s1=os.system("apt-get install capstone")
	elif secenek=="4":
		s1=os.system("apt-get install chntpw")
	elif secenek=="5":
		s1=os.system("apt-get install cuckoo")
	elif secenek=="6":
		s1=os.system("apt-get install dc3dd")
	elif secenek=="7":
		s1=os.system("apt-get install ddrescue")
	elif secenek=="8":
		s1=os.system("apt-get install DFF")
	elif secenek=="9":
		s1=os.system("apt-get install diStorm3")
	elif secenek=="10":
		s1=os.system("apt-get install dumpzilla")
	elif secenek=="11":
		s1=os.system("apt-get install extundelete")
	elif secenek=="12":
		s1=os.system("apt-get install foremost")
	elif secenek=="13":
		s1=os.system("apt-get install galleta")
	elif secenek=="14":
		s1=os.system("apt-get install guymager")
	elif secenek=="15":
		s1=os.system("apt-get install iPhone Backup Analyzer")
	elif secenek=="16":
		s1=os.system("apt-get install p0f")
	elif secenek=="17":
		s1=os.system("apt-get install pdf-parser")
	elif secenek=="18":
		s1=os.system("apt-get install pdfid")
	elif secenek=="19":
		s1=os.system("apt-get install pdgmail")
	elif secenek=="20":
		s1=os.system("apt-get install peepdf")
	elif secenek=="21":
		s1=os.system("apt-get install regRipper")
	elif secenek=="22":
		s1=os.system("apt-get install volatility")
	elif secenek=="23":
		s1=os.system("apt-get install xplico")
	else:
		print "Hatalı Giriş..."	
###Stress Testing
def kategori_7():
	print r"""
	[1] DHCPig
	[2] FunkLoad
	[3] iaxflood
	[4] Inundator
	[5] inviteflood
	[6] ipv6-toolkit
	[7] mdk3
	[8] Reaver
	[9] rtpflood
	[10] SlowHTTPTest
	[11] t50
	[12] Termineter 
	[13] THC-IPV6
	[14] THC-SSL-DOS
	"""
	secenek=raw_input("RenOS > ")
	if secenek=="1":
		s1=os.system("apt-get install dHCPig")
	elif secenek=="2":
		s1=os.system("apt-get install funkLoad")
	elif secenek=="3":
		s1=os.system("apt-get install iaxflood")
	elif secenek=="4":
		s1=os.system("apt-get install inundator")
	elif secenek=="5":
		s1=os.system("apt-get install inviteflood")
	elif secenek=="6":
		s1=os.system("apt-get install ipv6-toolkit")
	elif secenek=="7":
		s1=os.system("apt-get install mdk3")
	elif secenek=="8":
		s1=os.system("apt-get install reaver")
	elif secenek=="9":
		s1=os.system("apt-get install rtpflood")
	elif secenek=="10":
		s1=os.system("apt-get install slowHTTPTest")
	elif secenek=="11":
		s1=os.system("apt-get install t50")
	elif secenek=="12":
		s1=os.system("apt-get install termineter")
	elif secenek=="13":
		s1=os.system("apt-get install tHC-IPV6")
	elif secenek=="14":
		s1=os.system("apt-get install tHC-SSL-DOS")
	else:
		print "Hatalı Giriş..."
###Sniffing & Spoofing
def kategori_8():
	print r"""
	[1] Burp Suite			[13] rebind 			[25] THC-IPV6
	[2] DNSChef			[14] responder			[26] VoIPHopper
	[3] fiked			[15] rtpbreak			[27] WebScarab
	[4] hamster-sidejack		[16] rtpinsertsound		[28] Wifi Honey
	[5] HexInject			[17] rtpmixsound		[29] Wireshark
	[6] iaxflood  			[18] sctpscan			[30] xspy
	[7] inviteflood			[19] SIPArmyKnife	        [31] Yersinia
	[8] iSMTP			[20] SIPp			[32] zaproxy
	[9] isr-evilgrade		[21] SIPVicious
	[10] mitmproxy			[22] SniffJoke
	[11] ohrwurm			[23] SSLsplit		
	[12] protos-sip			[24] sslstrip
	"""
	secenek=raw_input("RenOS > ")
	if secenek=="1":
		s1=os.system("apt-get install burp Suite")
	elif secenek=="2":
		s1=os.system("apt-get install dNSChef")
	elif secenek=="3":
		s1=os.system("apt-get install fiked")
	elif secenek=="4":
		s1=os.system("apt-get install hamster-sidejack")
	elif secenek=="5":
		s1=os.system("apt-get install hexInject")
	elif secenek=="6":
		s1=os.system("apt-get install iaxflood")
	elif secenek=="7":
		s1=os.system("apt-get install inviteflood")
	elif secenek=="8":
		s1=os.system("apt-get install iSMTP")
	elif secenek=="9":
		s1=os.system("apt-get install isr-evilgrade")
	elif secenek=="10":
		s1=os.system("apt-get install mitmproxy")
	elif secenek=="11":
		s1=os.system("apt-get install ohrwurm")
	elif secenek=="12":
		s1=os.system("apt-get install protos-sip")
	elif secenek=="13":
		s1=os.system("apt-get install rebind")
	elif secenek=="14":
		s1=os.system("apt-get install responder")
	elif secenek=="15":
		s1=os.system("apt-get install rtpbreak")
	elif secenek=="16":
		s1=os.system("apt-get install rtpinsertsound")
	elif secenek=="17":
		s1=os.system("apt-get install rtpmixsound")
	elif secenek=="18":
		s1=os.system("apt-get install sctpscan")
	elif secenek=="19":
		s1=os.system("apt-get install siPArmyKnife")
	elif secenek=="20":
		s1=os.system("apt-get install siPp")
	elif secenek=="21":
		s1=os.system("apt-get install siPpPVicious")
	elif secenek=="22":
		s1=os.system("apt-get install sniffJoke")
	elif secenek=="23":
		s1=os.system("apt-get install ssLsplit")
	elif secenek=="24":
		s1=os.system("apt-get install sslstrip")
	elif secenek=="25":
		s1=os.system("apt-get install thC-IPV6")
	elif secenek=="26":
		s1=os.system("apt-get install voIPHopper")
	elif secenek=="27":
		s1=os.system("apt-get install webScarab")
	elif secenek=="28":
		s1=os.system("apt-get install wifi Honey")
	elif secenek=="29":
		s1=os.system("apt-get install wireshark")
	elif secenek=="30":
		s1=os.system("apt-get install xspy")
	elif secenek=="31":
		s1=os.system("apt-get install yersinia")
	elif secenek=="32":
		s1=os.system("apt-get install zaproxy")                                               
	else:                                                                                     
		print "Hatalı Giriş..."
###Password Attacks
def kategori_9():
	print r"""
	[1] acccheck			[13] HexorBase 			[25] phrasendrescher
	[2] Burp Suite			[14] THC-Hydra			[26] polenum
	[3] CeWL			[15] John the Ripper		[27] RainbowCrack
	[4] chntpw			[16] Johnny			[28] rcracki-mt
	[5] cisco-auditing-tool		[17] keimpx			[29] RSMangler
	[6] CmosPwd  			[18] Maltego Teeth		[30] SQLdict
	[7] creddump			[19] Maskprocessor	        [31] Statsprocessor
	[8] crunch			[20] multiforcer		[32] THC-pptp-bruter
	[9] DBPwAudit			[21] Ncrack			[33] TrueCrack
	[10] Findmyhash			[22] oclgausscrack		[34] WebScarab
	[11] Gpp-decrypt		[23] PACK			[35] wordlists
	[12] hash-identifier		[24] patator			[36] zaproxy
	"""
	secenek=raw_input("RenOS > ")
	if secenek=="1":
		s1=os.system("apt-get install acccheck")
	elif secenek=="2":
		s2=os.system("apt-get install burpsuite")
	elif secenek=="3":
		s3=os.system("apt-get install cewl")
	elif secenek=="4":
		s4=os.system("apt-get install chntpw")
	elif secenek=="5":
		s5=os.system("apt-get install cisco-auditing-tool")
	elif secenek=="6":
		s6=os.system("apt-get install cmospwd")
	elif secenek=="7":
		s7=os.system("apt-get install creddump")
	elif secenek=="8":
		s8=os.system("apt-get install crunch")
	elif secenek=="9":
		s9=os.system("apt-get install dbpwaudit")
	elif secenek=="10":
		s10=os.system("apt-get install findmyhash")
	elif secenek=="11":
		s11=os.system("apt-get install gpp-decrypt")
	elif secenek=="12":
		s12=os.system("apt-get install hash-identifier")
	elif secenek=="13":
		s13=os.system("apt-get install haxorbase")
	elif secenek=="14":
		s14=os.system("apt-get install thc-hydra")
	elif secenek=="15":
		s15=os.system("apt-get install john-the-ripper")
	elif secenek=="16":
		s16=os.system("apt-get install jhonny")
	elif secenek=="17":
		s17=os.system("apt-get install keimpx")
	elif secenek=="18":
		s18=os.system("apt-get install maltego-teeth")
	elif secenek=="19":
		s19=os.system("apt-get install maskprocessor")
	elif secenek=="20":
		s10=os.system("apt-get install multiforcer")
	elif secenek=="21":
		s21=os.system("apt-get install ncrack")
	elif secenek=="22":
		s22=os.system("apt-get install oclgausscrack")
	elif secenek=="23":
		s23=os.system("apt-get install pack")
	elif secenek=="24":
		s24=os.system("apt-get install patator")
	elif secenek=="25":
		s25=os.system("apt-get install phrasendrescher")
	elif secenek=="26":
		s26=os.system("apt-get install polenum")
	elif secenek=="27":
		s27=os.system("apt-get install rainbowcrack")
	elif secenek=="28":
		s28=os.system("apt-get install rcracki-mt ")	
	elif secenek=="29":
		s29=os.system("apt-get install RSMangler")
	elif secenek=="30":
		s30=os.system("apt-get install SQLdict")
	elif secenek=="31":
		s31=os.system("apt-get install statsprocessor")
	elif secenek=="32":
		s32=os.system("apt-get install THC-pptp-bruter ")
	elif secenek=="33":
		s33=os.system("apt-get install truecrack")
	elif secenek=="34":
		s34=os.system("apt-get install webscarab ")
	elif secenek=="35":
		s35=os.system("apt-get install wordlists")
	elif secenek=="36":
		s36=os.system("apt-get install zaproxy")
	else:
		print "Hatalı Giriş..."
###Maintaining Access
def kategori_10():
	print r"""
	[1] CryptCat			
	[2] Cymothoa
	[3] Dbd					
	[3] dns2tcp			
	[4] http-tunnel			
	[5] HTTPTunnel			
	[6] Intersect  	
	[7] Nishang			
	[7] polenum			
	[8] PowerSploit			
	[9] pwnat	
	[10] RidEnum
	[11] sbd
	[12] U3-Pwn
	[13] Webshells
	[14] Winexe
	[15] Weevely
	"""
	secenek=raw_input("RenOS > ")
	if secenek=="1":
		s1=os.system("apt-get install cryptcat")
	elif secenek=="2":
		s2=os.system("apt-get install cymothoa")
	elif secenek=="3":
		s3=os.system("apt-get install dbd")
	elif secenek=="4":
		s4=os.system("apt-get install dns2tcp")
	elif secenek=="5":
		s5=os.system("apt-get install http-tunnel")
	elif secenek=="6":
		s6=os.system("apt-get install httptunnel")
	elif secenek=="7":
		s7=os.system("apt-get install intersect")
	elif secenek=="8":
		s8=os.system("apt-get install nishang")
	elif secenek=="9":
		s9=os.system("apt-get install polenum")
	elif secenek=="10":
		s10=os.system("apt-get install powersploit")
	elif secenek=="11":
		s11=os.system("apt-get install pwnat")
	elif secenek=="12":
		s12=os.system("apt-get install ridenum")
	elif secenek=="13":
		s13=os.system("apt-get install sbd")
	elif secenek=="14":
		s14=os.system("apt-get install u3-pwn")
	elif secenek=="15":
		s15=os.system("apt-get install webshells")
	elif secenek=="16":
		s16=os.system("apt-get install winexe")
	elif secenek=="17":
		s17=os.system("apt-get install veevely")
	else:
		print "Hatalı Giriş..."
###Reverse Engineering
def kategori_11():
	print r"""
	[1] Apktool
	[2] Dex2jar
	[3] DiStorm3
	[4] Edb-debugger
	[5] Jad
	[6] Javasnoop
	[7] JD-GUI
	[8] OllyDbg
	[9] Smali
	[10] Valgrind
	[11] YARA
	"""
	secenek=raw_input("RenOS > ")
	if secenek=="1":
		s1=os.system("apt-get install apktool")
	elif secenek=="2":
		s2=os.system("apt-get install dex2jar")
	elif secenek=="3":
		s3=os.system("apt-get install distorm3")
	elif secenek=="4":
		s4=os.system("apt-get install edb-debugger")
	elif secenek=="5":
		s5=os.system("apt-get install jad")
	elif secenek=="6":
		s6=os.system("apt-get install javasnoop")
	elif secenek=="7":
		s7=os.system("apt-get install jd-gui")
	elif secenek=="8":
		s8=os.system("apt-get install OllyDbg")
	elif secenek=="9":
		s9=os.system("apt-get install smali")
	elif secenek=="10":
		s10=os.system("apt-get install valgrind")
	elif secenek=="11":
		s11=os.system("apt-get install yara")
	else:
		print "Hatalı Giriş..."
###Reporting Tools
def kategori_12():
	print r"""
	[1] CaseFile
	[2] CutyCapt
	[3] Dos2Unix
	[4] Dradis
	[5] KeepNote
	[6] MagicTree
	[7] Metagoofil
	[8] Nipper-ng
	[9] Pipal
	"""
	secenek=raw_input("RenOS > ")
	if secenek=="1":
		s1=os.system("apt-get install casefile")
	elif secenek=="2":
		s2=os.system("apt-get install cutycapt")
	elif secenek=="3":
		s3=os.system("apt-get install dos2unix")
	elif secenek=="4":
		s4=os.system("apt-get install dradis")
	elif secenek=="5":
		s5=os.system("apt-get install keepnote")
	elif secenek=="6":
		s6=os.system("apt-get install magictree")
	elif secenek=="7":
		s7=os.system("apt-get install metagoofil")
	elif secenek=="8":
		s8=os.system("apt-get install nipper-ng")
	elif secenek=="9":
		s9=os.system("apt-get install pipal")
	else:
		print "Hatalı Giriş..."
###Hardware Hacking
def kategori_13():
	print r"""
	[1] Android-sdk
	[2] Apktool
	[3] Ardunio
	[4] Dex2jar
	[5] Sakis3G
	[6] Smali
	"""
	secenek=raw_input("RenOS > ")
	if secenek=="1":
		s1=os.system("apt-get install android-sdk")
	elif secenek=="2":
		s2=os.system("apt-get install apktool")
	elif secenek=="3":
		s3=os.system("apt-get install ardunio")
	elif secenek=="4":
		s4=os.system("apt-get install dex2jar")
	elif secenek=="5":
		s5=os.system("apt-get install sakis3g")
	elif secenek=="6":
		s6=os.system("apt-get install smali")
	else:
		print "Hatalı Giriş.."	

###Kategori Listele
def k_listele():
	print r"""
	[1] Information Gathering
	[2] Vulnerability Analysis
	[3] Web Applications
	[4] Wireless Attacks
	[5] Exploitation Tools
	[6] Forensics Tools
	[7] Stress Testing
	[8] Sniffing & Spoofing
	[9] Password Attacks
	[10] Maintaining Access
	[11] Reverse Engineering
	[12] Hardware Hacking
	[13] Reporting Tools
	"""
	secenek = raw_input("RenOS > ")
	if secenek=="1":
		kategori_1()
	elif secenek=="2":
		kategori_2()
	elif secenek=="3":
		kategori_3()
	elif secenek=="4":
		kategori_4()
	elif secenek=="5":
		kategori_5()
	elif secenek=="6":
		kategori_6()
	elif secenek=="7":
		kategori_7()
	elif secenek=="8":
		kategori_8()
	elif secenek=="9":
		kategori_9()
	elif secenek=="10":
		kategori_10()
	elif secenek=="11":
		kategori_11()
	elif secenek=="12":
		kategori_12()
	elif secenek=="13":
		kategori_13()
	elif secenek=="0":
		print "Eklenecektir.."
	else:
		print "Hatalı Giriş..."

###Depoları Ekle
def d_ekle():
	r_ekle1=os.system("apt-key adv --keyserver pgp.mit.edu --recv-keys ED444FF07D8D0BF6")
	r_ekle2=os.system("echo '# Kali LinuxTR\ndeb http://http.kali.org/kali kali-rolling main contrib non-free\ndeb http://repo.kali.org/kali kali-bleeding-edge main' >> /etc/apt/sources.list")
	print "Depolar Eklenmiştir..."
###Depoları Güncelle
def depog():
	gdepo=os.system("apt-get update")
	print "Depolar Güncellenmiştir..."
###Yardım Menüsü
def yardim():
	print "Sistemizi araçları kullanabilmeniz için ilk önce depoları ekleyip daha sonra seçtiğiniz aracı kurabilirsiniz.."

###Ana İşlevler
while True:
	print r"""
		[1] Depoları Ekle
		[2] Depoları Güncelle
		[3] Araçlar
		[4] Yardım
		[5] Çıkış
		"""	
	secenek = raw_input("RenOS > ")
	if secenek=="1":
		d_ekle()
		secenek = raw_input("RenOS > ")
	elif secenek=="2":
		depog()
		secenek = raw_input("RenOS > ")
	elif secenek=="3":
		k_listele()
		secenek = raw_input("RenOS > ")
	elif secenek=="4":
		yardim()
		secenek = raw_input("RenOS > ")
	elif secenek=="5":
		break			
	else:
		print "Hatalı Giriş..."
		break


