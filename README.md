# Introduction

Check Vulnerable Version of BBB using: 


```bash
✗ python3 check_bbb.py -h
```

```bash
usage: check_bbb.py [-h] [-c9 C9PORT] [-Ni NISYSSERVER_PORT] target

positional arguments:
  target                Set the address of target BBB host

optional arguments:
  -h, --help            show this help message and exit
  -c9 C9PORT, --cloud9-port C9PORT
                        Set the address cloud9 of port
  -Ni NISYSSERVER_PORT, -nisysserver-port NISYSSERVER_PORT
                        Set the address NiSysServer.py port
```

![Animation](image.gif)

Exploit the BBB's Labview Service by restarting it using:

```bash
✗ python3 exploit.py -h
```
```bash
usage: exploit.py [-h] [-c  COUNT] [-p PORT] [-d DURATION] target

positional arguments:
  target                Set the address of target BBB host

optional arguments:
  -h, --help            show this help message and exit
  -c  COUNT, --count COUNT
                        Number of Requests you want to send to DOS
  -p PORT, --port PORT  Set the address of port
  -d DURATION, --duration DURATION
                        The duration for which the exploit should persist
```




