# crossdomain
Checking for CORS misconfiguration
1. Scanning for list domains
* python corser.py -list_domain ~/aquatone/target.com/urls.txt -origin attacker.com

>the file is a list subdomains that's result from aquatone tool

Inline-style: 
![alt text](https://ibb.co/fhdVby "Logo Title Text 1")

2. Bruteforce endpoints and then checking for cors
* python corser.py -u https://target.com/ -list_endpoint ~/Desktop/listendpoint.txt -origin attacker.com

3. Trying to bypass origin when we encounter filter
* python corser.py -u https://target.com -origin attacker.com -fuzz true

4. Gen Poc
* python corser.py -poc GET
* python corser.py -poc POST

additional options

-t : set number of threads

-header : custom your request if website requires authenticated cookie

ex: python corser.py -u https://target.com -header "Cookie:sessid=123456;role=user, Authorization: zxbdGDH7438"
