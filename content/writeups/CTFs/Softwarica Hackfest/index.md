---
title: "SOFTWARICA HACKFEST 2025"
description: Writeups of SOFTWARICA HACKFEST 2025
draft: false
date: 2025-01-28
tags:
- CTF
- 2025
---

# SOFTWARICA HACKFEST 2025 Jan 03 Writeup by Team TkNB@Nepal

# Challenge name: Happy Holi!

## Category: Misc

This challenge provided an image file which had various color combination.

![Green_Organic_Scrap_Collage_Desktop_Wallpaper.png](SOFTWARICA%20HACKFEST%202025%20Jan%2003%20Writeup%20by%20Team%20Tk%20170b62881f0980a795f1eb7fd344efb0/Green_Organic_Scrap_Collage_Desktop_Wallpaper.png)

In [dcode.fr](http://dcode.fr) we have a tool called cipher identifier. There is a graphical section which contains `gravity falls color code` . The colors on top left represented it. So, I matched the colors and got a text when decoded.

![image.png](SOFTWARICA%20HACKFEST%202025%20Jan%2003%20Writeup%20by%20Team%20Tk%20170b62881f0980a795f1eb7fd344efb0/image.png)

This gave me the contents of the flag. But, I had to modify this a bit and submitted the flag.

Final flag: `softwarica{hacker_love_black_color}`

# Challenge name: Math genius!

## Category: Misc

This challenge was provided through a docker container which could be accessed using nc command. This challenge was based on math problems. So, we wrote a script which extracts the math expression, evaluates it and returns the answer and automatically inputs it to the challenge. Running this script ran the program for sometime and gave us a flag.

Python script used:

```python
import socket
import re

def solve_question(question):
    # Extract the math expression using regex
    match = re.search(r"Solve\s+(.*)\s+:", question)
    if match:
        expression = match.group(1)
        try:
            # Evaluate the math expression
            return str(eval(expression))
        except Exception as e:
            print(f"Error evaluating expression: {expression}")
            return None
    return None

def main():
    host = "172.100.100.23"
    port = 1603

    # Connect to the server
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((host, port))
        print("Connected to the server...")

        while True:
            # Receive data from the server
            data = s.recv(1024).decode()
            if not data:
                print("Disconnected from the server.")
                break

            print(f"Server: {data}")

            # Check if the data contains a question
            if "Solve" in data:
                answer = solve_question(data)
                if answer:
                    print(f"Answer: {answer}")
                    s.sendall(answer.encode() + b'\n')
                else:
                    print("Failed to solve the question.")
                    break
            elif "Free Flag" in data or "Good luck" in data:
                continue
            else:
                print("Unexpected server response. Exiting.")
                break

if __name__ == "__main__":
    main()

```

# Challenge name: E*VAL services

## Category: Misc

This challenge also provided a nc command connecting to a docker. It was a pyjail challenge.

This was quite an easy challenge. Looking through its source we found that providing a character we could get the flag. But, when entered correct character it just returned correct but no flag. So, we printed the character ( print(x) ). Though it said wrong, we got a flag.

![Screenshot_2025-01-03_13_59_22.png](SOFTWARICA%20HACKFEST%202025%20Jan%2003%20Writeup%20by%20Team%20Tk%20170b62881f0980a795f1eb7fd344efb0/Screenshot_2025-01-03_13_59_22.png)

