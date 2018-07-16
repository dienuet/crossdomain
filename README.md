# crossdomain
Checking for CORS misconfiguration

Usage: python corser.py -h

1. Scanning for list domains
* python corser.py -list_domain ~/aquatone/target.com/urls.txt -origin attacker.com

>the file is a list subdomains that's result from aquatone tool

![alt text](https://image.ibb.co/d0Mx6y/Screenshot_from_2018_07_16_02_31_24.png "Fig2")
 
2. Bruteforce endpoints and then checking for cors
* python corser.py -u https://target.com/ -list_endpoint ~/Desktop/listendpoint.txt -origin attacker.com

![alt text](https://image.ibb.co/dXCqby/endpoint.png "Fig2")

3. Trying to bypass origin when we encounter filter

simple filter

```php
<?php
if(isset($_SERVER['HTTP_ORIGIN'])){
	if(preg_match('/^http:\/\/dienpv\.com/', $_SERVER['HTTP_ORIGIN'])){
		header("Access-Control-Allow-Origin: ".$_SERVER['HTTP_ORIGIN']);
		header("Access-Control-Allow-Credentials: True");
	}
	else{
		header("Access-Control-Allow-Origin: "."http://dienpv.com");
		header("Access-Control-Allow-Credentials: True");
	}
}

echo "your code: hacker1337";
?>
```

* python corser.py -u https://target.com -origin attacker.com -fuzz true

![alt text](https://image.ibb.co/bNsgYd/Screenshot_from_2018_07_16_02_24_28.png "Fig3")

4. Gen Poc
* python corser.py -poc GET
* python corser.py -poc POST

![alt text](https://image.ibb.co/hiv1Gy/Screenshot_from_2018_07_16_01_46_14.png "Fig4")
---
additional options

-t : set number of threads

-header : custom your request if website requires authenticated cookie

ex: python corser.py -u https://target.com -header "Cookie:sessid=123456;role=user, Authorization: zxbdGDH7438"
