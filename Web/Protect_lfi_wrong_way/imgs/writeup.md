# image Gallery Challenge From (i forget ctf name) 2025

## Challenge Overview

**Challenge Name:** imagegallery 
**Vulnerability Type:** LFI / Bad param parsing
**Difficulty:** easy 

# Local File Inclusion (LFI) Vulnerability: Why Removing "../" Is Insufficient

![challenge_card](./imgs/challengecard.png)

## Analyzing: figure out the vulner param:

![history](./imgs/analysis_http_history.png)

## Attack Vectors: How To Bypass Simple Filtering

### 1. **Double URL Encoding**

The simplest bypass. If the server applies filtering but doesn't decode input properly:

```
Input: ....//....//....//etc/passwd
After filter removes ../: ....//....//etc/passwd
Result after path normalization: ../../etc/passwd ✓ WORKS
```

![firsttest](./imgs/first_test.png)

## I try found /etc/passwd just to make sure is lfi :

```
....//....//....//etc/passwd
```

![etc/passwd_found](./imgs/the_:etc:passwd.png)

## Now , I Fuzzing randomly, and i found it :

![etc/passwd_found](./imgs/get_flag.png)


## The End .