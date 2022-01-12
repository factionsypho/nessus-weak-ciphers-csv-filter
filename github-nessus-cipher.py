#/usr/env/python3 
import os
import sys
import glob
import pandas as pd
import re

_STRONG_CIPHER_ = ['TLS_AES_128_GCM_SHA256', 'TLS_AES_256_GCM_SHA384', 'TLS_CHACHA20_POLY1305_SHA256', 'ECDHE-ECDSA-AES128-GCM-SHA256','ECDHE-RSA-AES128-GCM-SHA256','ECDHE-ECDSA-AES256-GCM-SHA384','ECDHE-RSA-AES256-GCM-SHA384','ECDHE-ECDSA-CHACHA20-POLY1305','ECDHE-RSA-CHACHA20-POLY1305','DHE-RSA-AES128-GCM-SHA256','DHE-RSA-AES256-GCM-SHA384']

#Change _INPUTDIRECTORY_ value to the folder containing your CSV files 
_INPUTDIRECTORY_ = 'C:\\windows\\temp\\csvfolder\\' # Linux example: /home/user/data/csvfiles/
#Change _OUTPUTCIPHER_ value to the directory and filename you want to output as.
_OUTPUTCIPHER_ = 'C:\\windows\\temp\\csvfolder\\output.csv' # Linux example: /home/user/data/csvfiles/output.csv

def removeStrongCiphers(ciphers):
    for goodcipher in _STRONG_CIPHER_:
        if goodcipher in ciphers: ciphers.remove(goodcipher)
    return ciphers

if __name__ == "__main__":
    frames = []
    for csvfile in csvfiles:
        print("Merging %s" % csvfile)
        data = pd.read_csv(csvfile, usecols=['Plugin ID','Host','Port','Protocol','Plugin Output'])
        frames.append(data)
        df = pd.concat(frames,ignore_index=True)
    df = df[df['Plugin ID'].astype(str).str.contains('21643', regex=False)]

    df['Ciphers'] = ""
    df['Ciphers'] = df['Ciphers'].astype('object')
    df['TLS'] = ""
    df['TLS'] = df['TLS'].astype('object')
    tls_regex = r'TLSv[0-9]+'
    cipher_regex = r'    (.*?).0x'
    
    for row in df.itertuples():
        plugin_output = row[5]

        ciphers = re.findall(cipher_regex, plugin_output)
        ciphers = [cipher.replace(" ","") for cipher in ciphers]
        ciphers = removeStrongCiphers(ciphers)

        df.loc[row.Index, 'Ciphers'] = ''
        df.at[row.Index, 'Ciphers'] = ciphers

        tls = re.findall(tls_regex, plugin_output)
        df.loc[row.Index, 'TLS'] = ''
        df.at[row.Index, 'TLS'] = tls

    df.to_csv(_OUTPUTCIPHER_, columns=['Host','Protocol','Port', 'Ciphers'], index=False)
    print("Sorted File Ouput: %s" % _OUTPUTCIPHER_)