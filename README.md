# crossdomain
Checking for CORS misconfiguration
1. Scanning for list domains
* python corser.py -list_domain ~/aquatone/target.com/urls.txt -origin attacker.com

>the file is a list subdomains that's result from aquatone tool
 
2. Bruteforce endpoints and then checking for cors
* python corser.py -u https://target.com/ -list_endpoint ~/Desktop/listendpoint.txt -origin attacker.com

![alt text](https://image.ibb.co/dXCqby/endpoint.png "Fig2")

3. Trying to bypass origin when we encounter filter
* python corser.py -u https://target.com -origin attacker.com -fuzz true

![alt text](https://image.ibb.co/jv01Gy/fuzz.png "Fig3")
4. Gen Poc
* python corser.py -poc GET
* python corser.py -poc POST

![alt text](https://image.ibb.co/hiv1Gy/Screenshot_from_2018_07_16_01_46_14.png "Fig4")
additional options

-t : set number of threads

-header : custom your request if website requires authenticated cookie

ex: python corser.py -u https://target.com -header "Cookie:sessid=123456;role=user, Authorization: zxbdGDH7438"
