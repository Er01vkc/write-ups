# BuckeyeCTF 2025 : Awklet (web challenge)

## The Website Code:
![Alt text](./pic's/awklet_code.png)

#### When I first saw the website, I assumed it was a SQLi vulnerability.
### But it turns out it wasn’t SQLi at all — it was actually an LFI.

##### Here is the vulnerable part:
![Alt text](./pic's/awklet_vulnerable.png)

---

# I knew the flag was stored in the Docker environment file, so I tried loading it through the vulnerable parameter:
``` /cgi-bin/awklet.awk?name=x&font=../../../proc/self/environ ```


![Alt text](./pic's/awklet_first_try.png)

#### As you can see, it works — but where is the flag?
#### Like I noticed, the vulnerable code concatenates what we input with `.txt`:
``` ../../../proc/self/environ.txt ```

---

# So we need to break the path apart from the automatic `.txt` extension.  
Using a null-byte bypass does exactly that:
``` /cgi-bin/awklet.awk?name=x&font=../../../proc/self/environ%00 ```

![Alt text](./pic's/awklet_second_try.png)

# Wow, flag! hehe heckkkerr.  
Thanks for reading.
