# XmlValidator - XXE Vulnerability Writeup from EPFL Ctf

**Challenge Type**: Web Security / XXE (XML External Entity Injection)  
**Difficulty**: Medium  

## Sorry for This undetailed Writeup.

## Step 1 : Get payload of xxe from payloadforallthings

![getpayload](./imgs/getpayload.png)

## Step 2 : Edit Payload by changing element from foo to title :

and i try to get

```
file:///etc/passwd 
```

and this is result :
![getetcpasswd](./imgs/get_etc:passwd.png)

## Step3 : Now Get Flag :

![getetcpasswd](./imgs/flag.png)

## The End .