---
title: "VishwaCTF 2025"
description: "Writeups of VishwaCTF 2025"
draft: false
date: 2025-03-11
tags:
- CTF
- VishwaCTF
- 2025
---


![image.png](VishwaCTF-2025%20Writeups%201acb62881f0980cf8ee8d6ceb9fd15a8/image.png)

Due to some teams being disqualified, we were later ranked 11th.

# Web Exploitation

## Challenge: Flames

### Flag: VishwaCTF{SQL_1nj3ct10n_C4n_Qu3ry_Your_He4rt}

This challenge must be done by spawning the instance.

We got stuck in a rabbit hole, it gave us results of XSS so we tried fetching it through our webhook with no avail.

Then we stumbled across a new endpoint. /db.php

![image.png](VishwaCTF-2025%20Writeups%201acb62881f0980cf8ee8d6ceb9fd15a8/image%201.png)

This error made us think there is sqli again, as our previous attempts failed. Then we tried  union sqli with syntax `'UNION SELECT 1,2,3;-- -`. 

![image.png](VishwaCTF-2025%20Writeups%201acb62881f0980cf8ee8d6ceb9fd15a8/image%202.png)

Then we saw some outputs we didn’t saw before. AND the link we get gives us access to famous love stories and our flag.

![image.png](VishwaCTF-2025%20Writeups%201acb62881f0980cf8ee8d6ceb9fd15a8/image%203.png)

![image.png](VishwaCTF-2025%20Writeups%201acb62881f0980cf8ee8d6ceb9fd15a8/image%204.png)

## Challenge: **scan-it-to-stay-safe**

### Flag: VishwaCTF{Y0u_7R4c30lI7_3000_4rK}

After starting the instance we get to see a url scanner.

![image.png](VishwaCTF-2025%20Writeups%201acb62881f0980cf8ee8d6ceb9fd15a8/image%205.png)

So, why not try [http://localhost/flag](http://localhost/flag), right? It didn’t work and also said max tries reached for it.

But this challenge was also very guessy. We tried web hook. IT WORKED. When we check the url of the Web hook, and checked the web hook site we got our flag in one of the headers called flag.

 

![image.png](VishwaCTF-2025%20Writeups%201acb62881f0980cf8ee8d6ceb9fd15a8/image%206.png)

## Challenge: Are We Up?

### Flag: VishwaCTF{Y0r4_lo7al_b4bby_A4k18aw2}

This was quite a hard challenge though it was rated as medium.

After gaining the domain for this challenge we also found the availability checker of uptimer so we tried to bypass [localhost:8080](http://localhost:8080) while submitting the url using ngrok server. 

![image.png](VishwaCTF-2025%20Writeups%201acb62881f0980cf8ee8d6ceb9fd15a8/image%207.png)

![image.png](VishwaCTF-2025%20Writeups%201acb62881f0980cf8ee8d6ceb9fd15a8/image%208.png)

![image.png](VishwaCTF-2025%20Writeups%201acb62881f0980cf8ee8d6ceb9fd15a8/image%209.png)

Then when we tried redirecting 127.0.0.1:8080/flag instead of using [localhost:8008](http://localhost:8008) we succeed in retriving the flag.

![image.png](VishwaCTF-2025%20Writeups%201acb62881f0980cf8ee8d6ceb9fd15a8/image%2010.png)

![image.png](VishwaCTF-2025%20Writeups%201acb62881f0980cf8ee8d6ceb9fd15a8/image%2011.png)

## Challenge: Forgot-h1-login

### Flag: VishwaCTF{y0u_4r3_7h3_h4ck3r_numb3r_0n3_2688658}

First we try to send the reset request and redirect it to our email hook site using burpsuite.

![image.png](VishwaCTF-2025%20Writeups%201acb62881f0980cf8ee8d6ceb9fd15a8/image%2012.png)

![image.png](VishwaCTF-2025%20Writeups%201acb62881f0980cf8ee8d6ceb9fd15a8/image%2013.png)

In response we get otp and also the flag in x-ctf-secrets header

![image.png](VishwaCTF-2025%20Writeups%201acb62881f0980cf8ee8d6ceb9fd15a8/image%2014.png)

# Cryptography

## Challenge: Rythmic Cipher

### Flag: VishwaCTF{CIPHERED_DANCE}

This challenge provided us with 2 gifs.

![image.png](VishwaCTF-2025%20Writeups%201acb62881f0980cf8ee8d6ceb9fd15a8/image%2015.png)

These gifs had dancing men so we thought of dancing man cipher. So we used a gif decompiler to split our gif into frames.

![image.png](VishwaCTF-2025%20Writeups%201acb62881f0980cf8ee8d6ceb9fd15a8/image%2016.png)

![image.png](VishwaCTF-2025%20Writeups%201acb62881f0980cf8ee8d6ceb9fd15a8/image%2017.png)

Then we went to [dcode.fr](http://dcode.fr) to decode this using dancing man cipher

![image.png](VishwaCTF-2025%20Writeups%201acb62881f0980cf8ee8d6ceb9fd15a8/image%2018.png)

This is the contents of the flag, the flag format was `VishwaCTF{word1_word2}`

## Challenge: Aira of the Lost Code

### Flag: VishwaCTF{H4v3_y0u_7ri3d_Ar_70n3l1c0}

This challenged provided us with one .png file which contained different symbols.

![image.png](VishwaCTF-2025%20Writeups%201acb62881f0980cf8ee8d6ceb9fd15a8/image%2019.png)

![image.png](VishwaCTF-2025%20Writeups%201acb62881f0980cf8ee8d6ceb9fd15a8/image%2020.png)

Comparing these symbols in [dcode.fr](http://dcode.fr) symbol cipher list we saw a cipher called hymnos cipher.

![image.png](VishwaCTF-2025%20Writeups%201acb62881f0980cf8ee8d6ceb9fd15a8/image%2021.png)

And decoding this gave us the contents of the flag.

![image.png](VishwaCTF-2025%20Writeups%201acb62881f0980cf8ee8d6ceb9fd15a8/image%2022.png)

**Fun Fact:** Ar Tonelico is a game that uses this cipher.

## Challenge: Chaos

### Flag: VishwaCTF{CrYpt0_cRyPT0_1g_It_1s_sOm3_7hiNg_t0_D0}

Challenge.py:

![image.png](VishwaCTF-2025%20Writeups%201acb62881f0980cf8ee8d6ceb9fd15a8/image%2023.png)

output.txt

![image.png](VishwaCTF-2025%20Writeups%201acb62881f0980cf8ee8d6ceb9fd15a8/image%2024.png)

solve.py:

![image.png](VishwaCTF-2025%20Writeups%201acb62881f0980cf8ee8d6ceb9fd15a8/image%2025.png)

Output:

![image.png](VishwaCTF-2025%20Writeups%201acb62881f0980cf8ee8d6ceb9fd15a8/image%2026.png)

## Challenge: Forgotten Cipher

### Flag: VishwaCTF{VIC_Decoded_113510}

![image.png](VishwaCTF-2025%20Writeups%201acb62881f0980cf8ee8d6ceb9fd15a8/image%2027.png)

![image.png](VishwaCTF-2025%20Writeups%201acb62881f0980cf8ee8d6ceb9fd15a8/image%2028.png)

Along with these we were given 1 file called info.txt which contained the following:

```
Encrypted Message :- 0d4ac648a2f0bee7bccf0231c35e13ba7bc93a2d8f7d9498885e3f4998

Key Evolution Formula :- K(n) = [ K(n−1) × 3 + index ] mod 25
```

After the hint was given we gave the description, hint and contents of the info.txt file to chat gpt which then provided us with a script which actually worked.

Solution:

```python
def rotate_right(val, r_bits, max_bits=8):
    """Performs a right rotation on an integer value."""
    return ((val >> r_bits) | (val << (max_bits - r_bits))) & ((1 << max_bits) - 1)

def rotate_left(val, r_bits, max_bits=8):
    """Performs a left rotation on an integer value."""
    return ((val << r_bits) | (val >> (max_bits - r_bits))) & ((1 << max_bits) - 1)

def decrypt_vic_cipher(ciphertext_hex, initial_key):
    """
    Decrypts a given ciphertext using the VIC cipher.
    ciphertext_hex: The hexadecimal string representing the ciphertext.
    initial_key: The starting key for the cipher decryption.
    """
    # Convert the hexadecimal string to bytes
    ciphertext = bytes.fromhex(ciphertext_hex)
    plaintext = bytearray(len(ciphertext))
    key = initial_key

    for i, c in enumerate(ciphertext):
        # Update the key based on the current index
        key = (key * 3 + i) % 256
        
        # Reverse the rotation based on the index
        if i % 2 == 0:
            # If index is even, reverse a left rotation with a right rotation
            temp = rotate_right(c, 2)
        else:
            # If index is odd, reverse a right rotation with a left rotation
            temp = rotate_left(c, 2)
        
        # Reverse XOR with the key to get the original plaintext byte
        plaintext[i] = temp ^ key

    # Decode the plaintext to a UTF-8 string
    return plaintext.decode('utf-8', errors='replace')

# Example usage
ciphertext_hex = "0d4ac648a2f0bee7bccf0231c35e13ba7bc93a2d8f7d9498885e3f4998"
initial_key = 7
result = decrypt_vic_cipher(ciphertext_hex, initial_key)

print("Decrypted Flag:", result)

```

# Reverse Engineering

## Challenge: Safe Box

### Flag: VishwaCTF{h3r3_y0u_@r3}

This challenge gave us a .zip file which contained

![image.png](VishwaCTF-2025%20Writeups%201acb62881f0980cf8ee8d6ceb9fd15a8/image%2029.png)

Contents of the zip file:

![image.png](VishwaCTF-2025%20Writeups%201acb62881f0980cf8ee8d6ceb9fd15a8/image%2030.png)

Then, the files were transferred to our windows vm.

We need melon loader, unity explorer for this challenge. 

![image.png](VishwaCTF-2025%20Writeups%201acb62881f0980cf8ee8d6ceb9fd15a8/image%2031.png)

After it is fully loaded we get this UI:

![image.png](VishwaCTF-2025%20Writeups%201acb62881f0980cf8ee8d6ceb9fd15a8/image%2032.png)

We were stuck here for while trying to reverse the executable. After  messing around we got the flag by opening the object explorer extending the container in the list and unchecking game object which removed the front layer, revealing the flag.

![image.png](VishwaCTF-2025%20Writeups%201acb62881f0980cf8ee8d6ceb9fd15a8/image%2033.png)

![image.png](VishwaCTF-2025%20Writeups%201acb62881f0980cf8ee8d6ceb9fd15a8/image%2034.png)

## Challenge: Hungry Friend

### Flag: VishwaCTF{th3r3_4r3_5n4k35_all_4r0und}

This challenge gave us a .exe file.

![image.png](VishwaCTF-2025%20Writeups%201acb62881f0980cf8ee8d6ceb9fd15a8/image%2035.png)

I used a vm for this. Initially it wasn’t running due to missing libraries of GCC. So I installed MinGW.

![image.png](VishwaCTF-2025%20Writeups%201acb62881f0980cf8ee8d6ceb9fd15a8/image%2036.png)

As for patching the binary, we used ghidra. Only patching it needed was change the comparing number.

![image.png](VishwaCTF-2025%20Writeups%201acb62881f0980cf8ee8d6ceb9fd15a8/image%2037.png)

It checked the score of the user, if it was 9999 which then called the function called SHOW_FLAG.

![image.png](VishwaCTF-2025%20Writeups%201acb62881f0980cf8ee8d6ceb9fd15a8/image%2038.png)

So, to patch this we change the comparing value to one.

![image.png](VishwaCTF-2025%20Writeups%201acb62881f0980cf8ee8d6ceb9fd15a8/image%2039.png)

Now, when we run it, it should gove us the flag when our score is 1.

![image.png](VishwaCTF-2025%20Writeups%201acb62881f0980cf8ee8d6ceb9fd15a8/image%2040.png)

## Challenge: Phantom Rollcall

### Flag:VishwaCTF{ReV_EngIn33ring_Is_Crezy}

First intercepted the network traffic saw a firebase api calls, we checked if it was open then began searching.

![image.png](VishwaCTF-2025%20Writeups%201acb62881f0980cf8ee8d6ceb9fd15a8/image%2041.png)

![image.png](VishwaCTF-2025%20Writeups%201acb62881f0980cf8ee8d6ceb9fd15a8/image%2042.png)

Then, tried if we can run other queries in the firebase.  Then we guessed so hard asf that we stumbled upon this glorious yet unknown secret.

![image.png](VishwaCTF-2025%20Writeups%201acb62881f0980cf8ee8d6ceb9fd15a8/image%2043.png)

After that we used that key in this dumb enter attendance code once that’s done.

![image.png](VishwaCTF-2025%20Writeups%201acb62881f0980cf8ee8d6ceb9fd15a8/image%2044.png)

Here you go the flag:

![image.png](VishwaCTF-2025%20Writeups%201acb62881f0980cf8ee8d6ceb9fd15a8/image%2045.png)

# Steganography

## Challenge: Quadrant

### Flag: VishwaCTF{aG9lMTIzNDU2c3Bhc3NhZ2U=}

This challenge provided us with a zip file containing 4 pictures named flag1,2,3,4.

These images contained some pieces of qr code.

![image.png](VishwaCTF-2025%20Writeups%201acb62881f0980cf8ee8d6ceb9fd15a8/image%2046.png)

Now we have to combine this so we can get a valid output, so we used Gimp to restore the broken qr.

![image.png](VishwaCTF-2025%20Writeups%201acb62881f0980cf8ee8d6ceb9fd15a8/image%2047.png)

![image.png](VishwaCTF-2025%20Writeups%201acb62881f0980cf8ee8d6ceb9fd15a8/image%2048.png)

Though this was still not complete we gave it to google lens without expecting anything but we got the flag.

![image.png](VishwaCTF-2025%20Writeups%201acb62881f0980cf8ee8d6ceb9fd15a8/image%2049.png)

## Challenge: Spilled Paint Water

### Flag: VishwaCTF{STROKE__N_FILL}

This Challenge gave us a file called canvas.svg which on opening was just blank.

![image.png](VishwaCTF-2025%20Writeups%201acb62881f0980cf8ee8d6ceb9fd15a8/image%2050.png)

Then we opened it in a text editor and changed width and height to 300 but no result was seen.

![image.png](VishwaCTF-2025%20Writeups%201acb62881f0980cf8ee8d6ceb9fd15a8/image%2051.png)

![image.png](VishwaCTF-2025%20Writeups%201acb62881f0980cf8ee8d6ceb9fd15a8/image%2052.png)

This also didn’t give any result so, as last effort we asked chatgpt to fix this and it gave us the fixed version.

![image.png](VishwaCTF-2025%20Writeups%201acb62881f0980cf8ee8d6ceb9fd15a8/image%2053.png)

![image.png](VishwaCTF-2025%20Writeups%201acb62881f0980cf8ee8d6ceb9fd15a8/image%2054.png)

## Challenge: Let’s Race

### Flag: VishwaCTF  {1_l0v3_ C0r5}

This challenge provided us with a zip file and had a note `use winrar` .

We have a avif file and a doc.txt which had a hint.

![image.png](VishwaCTF-2025%20Writeups%201acb62881f0980cf8ee8d6ceb9fd15a8/image%2055.png)

![image.png](VishwaCTF-2025%20Writeups%201acb62881f0980cf8ee8d6ceb9fd15a8/image%2056.png)

We tried many things but no avail. then we changed it to .png and went to extract the data using stegonline. AND while keeping the value of R=1, G=2, B=3 we got the flag.

 

![image.png](VishwaCTF-2025%20Writeups%201acb62881f0980cf8ee8d6ceb9fd15a8/image%2057.png)

## Challenge: Echoes of Unknown

### Flag: VishwaCTF{CR4CK3D_7H3_C0D3}

Uploading the file directly didn’t give anything useful. So we used audacity and we could see the morse code. 

![image.png](VishwaCTF-2025%20Writeups%201acb62881f0980cf8ee8d6ceb9fd15a8/image%2058.png)

When we crack the morse code we get our flag contents.

![image.png](VishwaCTF-2025%20Writeups%201acb62881f0980cf8ee8d6ceb9fd15a8/image%2059.png)

# DIFR

## Challenge: Leaky Stream

### Flag: VishwaCTF{this_is_first_part_this_second_part}

This challenge gave us a pcap file, so just to ttry our luck we simply did strings and grep “VishwaCTF” and guess what?, we got first part of the flag.

![image.png](VishwaCTF-2025%20Writeups%201acb62881f0980cf8ee8d6ceb9fd15a8/image%2060.png)

As this gave us the first part of flag, we tried grepping “}” and scan through the output to get the other half of the flag. AND we got another part of the flag.

![image.png](VishwaCTF-2025%20Writeups%201acb62881f0980cf8ee8d6ceb9fd15a8/image%2061.png)

## Challenge: Persist

### Flag: VishwaCTF{b3l1ef_in_r3g_p0wer}

We used the RegRipper Tool for the HKCU file.
https://github.com/keydet89/RegRipper3.0

![image.png](VishwaCTF-2025%20Writeups%201acb62881f0980cf8ee8d6ceb9fd15a8/image%2062.png)

![image.png](VishwaCTF-2025%20Writeups%201acb62881f0980cf8ee8d6ceb9fd15a8/image%2063.png)

![image.png](VishwaCTF-2025%20Writeups%201acb62881f0980cf8ee8d6ceb9fd15a8/image%2064.png)

![image.png](VishwaCTF-2025%20Writeups%201acb62881f0980cf8ee8d6ceb9fd15a8/image%2065.png)

Closer inspection of report.txt :

![image.png](VishwaCTF-2025%20Writeups%201acb62881f0980cf8ee8d6ceb9fd15a8/image%2066.png)

We got the flag.

# OSINT

## Challenge: The lecture code

### Flag: VishwaCTF{cs5o_qu4ck!}

Linked in enumeration:

 

![image.png](VishwaCTF-2025%20Writeups%201acb62881f0980cf8ee8d6ceb9fd15a8/image%2067.png)

Then checking vishwactf.com/heroes

![image.png](VishwaCTF-2025%20Writeups%201acb62881f0980cf8ee8d6ceb9fd15a8/image%2068.png)

In github:

![image.png](VishwaCTF-2025%20Writeups%201acb62881f0980cf8ee8d6ceb9fd15a8/image%2069.png)

![image.png](VishwaCTF-2025%20Writeups%201acb62881f0980cf8ee8d6ceb9fd15a8/image%2070.png)

modified crack2.py:

```python
def custom_decrypt(encrypted_text):
    shift = 3  # Same shift used for encryption
    reversed_text = "".join(chr(ord(c) - shift) for c in encrypted_text)  # Reverse shift
    original_text = reversed_text[::-1]  # Reverse back to original
    print(original_text)
 
hidden_encrypted_pass = "$nf7xtbr8vf"  
custom_decrypt(hidden_encrypted_pass)
```

## Challenge:  Stadium!!

### Flag: VishwaCTF{Saling_Cricket_Stadium_Ghanche}

Checking given image in google lens:

![image.png](VishwaCTF-2025%20Writeups%201acb62881f0980cf8ee8d6ceb9fd15a8/image%2071.png)

Checking the X account we know the name.

![image.png](VishwaCTF-2025%20Writeups%201acb62881f0980cf8ee8d6ceb9fd15a8/image%2072.png)

## Challenge: Follow For Clues

### Flag:**VishwaCTF{L3t_Th3_hUn7_8Eg1n}**

There was nothing in linked in and twitter so we looked up in instagram. Checking about 10 posts, we got the flag.

![image.png](VishwaCTF-2025%20Writeups%201acb62881f0980cf8ee8d6ceb9fd15a8/image%2073.png)

## Challenge : The Summit

### Flag: VishwaCTF{18.51,73.89_Devendra Fadnavis}

The THeMIS in tank suggest it was event related to military power showcase and the peoples seems to be from India ,and there was date in the watermark of image. so i googled for the military event organized in Jan 5 , 2025 in India and there was event named , “Know your Army”. and it was organized by southern command and also got another article : https://www.punekarnews.in/pune-know-your-army-mela-2025-set-to-showcase-indian-armys-strength-and-innovation-from-january-3-5/

![image.png](VishwaCTF-2025%20Writeups%201acb62881f0980cf8ee8d6ceb9fd15a8/image%2074.png)

![image.png](VishwaCTF-2025%20Writeups%201acb62881f0980cf8ee8d6ceb9fd15a8/image%2075.png)

![image.png](VishwaCTF-2025%20Writeups%201acb62881f0980cf8ee8d6ceb9fd15a8/image%2076.png)

 The event was organized in race course of RWITC whose coordinates was , 18.51, 73.89 and after using Chatgpt for adjusting the coordinates we got the flag: VishwaCTF{18.51,73.89_Devendra Fadnavis}