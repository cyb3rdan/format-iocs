import requests
import json
import time
import re
import sys
import csv

'''
Carbon Black SHA256 hash - sample csv format
/*** SHA256 Hash ***/
BLACK_LIST,SHA256,dcab890006eccd887c26a1bd2bcb344e2ce1a80c2e6fc8621ed04489dc1631c8,DPC Alert
BLACK_LIST,SHA256,5348cfde0024b9557e57f099e1f3c3e20f389e7822dda376ad06009e43dd700a,DPC Alert
'''
# Add your virustotal.com API key here
vt_apikey = ""

#f = open('covid-19-iocs.csv','r')
f = open(sys.argv[1], 'r')
 
def extract_ips():
	print ("config firewall address")
	ip_addr_list = []
	for line in f:
		row = line.split(',')[1].replace('\xa0','').replace('[','').replace(']','')
		ip = re.findall( r'[0-9]+(?:\.[0-9]+){3}', row)
		for iplist in ip:
			ip_addr_list.append(iplist)
	ip_addr_list = list(dict.fromkeys(ip_addr_list))
	for ip_addr in ip_addr_list:
			print ("edit blockip-" + ip_addr)
			print ("set subnet " + ip_addr + " 255.255.255.255")
			print ("next")
	print ("end")

def extract_sha256():
	#print ("[*] Carbon Black Cb-Defense csv format")
	sha256_list=[]
	for line in f:
		row = line.split(',')[1].replace('\xa0','').replace('[','').replace(']','')
		sha256 = re.findall(r'(?i)(?<![a-z0-9])[a-f0-9]{64}(?![a-z0-9])', row)
		for sha256list in sha256:
			sha256_list.append(sha256list)
	for sha256_items in sha256_list:
		#print ("BLACK_LIST,SHA256," + sha256_items + ",DPC Alert")
		with open('sha256.csv', 'a') as csv_file:
			writer = csv.writer(csv_file, dialect=csv.excel)
			writer.writerow(['BLACK_LIST', 'SHA256', sha256_items, 'DPC Alert'])
	print ("[*] ./sha256.csv file has been successfully written.")
    	

def extract_urls():
	print ("config firewall address")
	url_list=[]
	for line in f:
		row = line.split(',')[1].replace('\xa0','').replace('[','').replace(']','')
		url = re.findall('http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', row)
		for urllist in url:
			url_list.append(urllist.split('/')[2])
	url_list = list(dict.fromkeys(url_list))
	regex = re.compile('[0-9]+(?:\.[0-9]+){3}')
	fqdn_list = [x for x in url_list if not regex.match(x)]
	for fqdn in fqdn_list:
		print ("edit blockfqdn-" + fqdn)
		print ("set type fqdn")
		print ("fqdn " + fqdn)
		print ("next")
	print ("end")

def extract_md5():
	print ("[*] Extracting MD5 hashes and converting them to SHA256 using virustotal API.")
	print ("[*] This might take a while - we can only make 4 requests per minute...")
	sha256_list=[]
	for line in f:
		row = line.split(',')[1].replace('\xa0','').replace('[','').replace(']','')
		md5 = re.findall(r'(?i)(?<![a-z0-9])[a-f0-9]{32}(?![a-z0-9])', row)
		for md5list in md5:
			url = 'https://www.virustotal.com/vtapi/v2/file/report'
			params = {'apikey': vt_apikey, 'resource': md5list}
			r = requests.get(url, params=params)
			vt_response = json.loads(r.text)
			#print ("BLACK_LIST,SHA256," + vt_response["sha256"] + ",DPC Alert") 
			time.sleep(15)
			sha256_list.append(vt_response["sha256"])
			sys.stdout.write("#")
    		sys.stdout.flush()
	for sha256_items in sha256_list:
		#print ("BLACK_LIST,SHA256," + sha256_items + ",DPC Alert")
		with open('sha256.csv', 'a') as csv_file:
			writer = csv.writer(csv_file, dialect=csv.excel)
			writer.writerow(['BLACK_LIST', 'SHA256', sha256_items, 'DPC Alert'])
	print ("")
	print ("[*] ./sha256.csv file has been successfully written.")
	
if sys.argv[2] == 'ip':
	extract_ips()

elif sys.argv[2] == 'sha256':
	extract_sha256()

elif sys.argv[2] == 'url':
	extract_urls()

elif sys.argv[2] == 'md5':
	extract_md5()

else:
	print("Argument 1 needs to be the file containing the IOCs and argument 2 is for the output type.")
	print("Output options are:")
	print(" [*] ip")
	print(" [*] sha256")
	print(" [*] url")
	print(" [*] md5")
