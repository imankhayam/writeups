import pyAesCrypt
import sys
from threading import Thread
from queue import Queue

bufferSize = 64 * 1024  # 64KB buffer
q = Queue()

input_file = "web_20250806_120723.zip.aes"
output_file = "web_20250806_120723.zip"
password = ""
password_found = False
counter = 0
wordlist_len = 0


def worker():
    global password_found
    global password
    global q

    while not password_found:
        pwd = q.get()
        try:
            pyAesCrypt.decryptFile(input_file, "tmp", pwd, bufferSize)
            password = pwd
            password_found = True
        except ValueError:
            print(f"Tried: {pwd}")

        q.task_done()


# load rockyou.txt
with open("/usr/share/wordlists/rockyou.txt", "r", errors="ignore") as wordlist:
    print("\rLoading wordlist...", end="")
    for password in wordlist:
        q.put(password.strip())

    print("\r", end=" " * 20)
    print("\rDone")

# using multi thread to speed up the process
threads = []
for _ in range(50):
    wrk = Thread(target=worker, daemon=True)
    threads.append(wrk)
    wrk.start()

for w in threads:
    w.join()

print("\npassword:", password)
pyAesCrypt.decryptFile(input_file, output_file, password, bufferSize)
