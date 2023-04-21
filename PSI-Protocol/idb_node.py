import socket
import hashlib
import pandas
import os
import binascii
import struct
import rsa
import json
import time

#start = time.time()

# adapt each row by replacing the exact values with the corresponding category to fit the PSI format
def row_adaptation(row):
    if row['RestBP'] < 120:
        row['RestBP'] = 'low'
    elif 120 <= row['RestBP'] < 130:
        row['RestBP'] = 'normal'
    elif 130 <= row['RestBP'] < 140:
        row['RestBP'] = 'high normal'
    elif row['RestBP'] >= 140:
        row['RestBP'] = 'high'

    if row['Chol'] < 100:
        row['Chol'] = 'low'
    elif 100 <= row['Chol'] < 115:
        row['Chol'] = 'normal'
    elif row['Chol'] >= 115:
        row['Chol'] = 'increased'

    if row['Fbs'] == 0:
        row['Fbs'] = 'no'
    elif row['Fbs'] == 1:
        row['Fbs'] = 'yes'

    if row['RestECG'] == 0:
        row['RestECG'] = 'no'
    elif row['RestECG'] == 1:
        row['RestECG'] = 'yes'
    elif row['RestECG'] == 2:
        row['RestECG'] = 'yes'

    if row['MaxHR'] < 100:
        row['MaxHR'] = 'normal'
    elif 100 <= row['MaxHR'] <= 120:
        row['MaxHR'] = 'increased'
    elif row['MaxHR'] > 120:
        row['MaxHR'] = 'highly increased'

    if row['ExAng'] == 0:
        row['ExAng'] = 'no'
    elif row['ExAng'] == 1:
        row['ExAng'] = 'yes'

    if row['Oldpeak'] < 0.5:
        row['Oldpeak'] = 'small'
    elif 0.5 <= row['Oldpeak'] <= 1:
        row['Oldpeak'] = 'noticeable'
    elif row['Oldpeak'] > 1:
        row['Oldpeak'] = 'bad'

    return row

# generate 32 byte random int as a private key
def generate_key():
    private_key = int(binascii.hexlify(os.urandom(32)), base=16)
    #print('Private key:' + str(private_key))
    return private_key

# hash element using SHA256
def hash_element(element):
    element_bytes = hashlib.sha256(element.encode("utf-8")).digest()
    return element_bytes

# calculate Diffie-Hellman public key using the hashed cell as the generator g
def hash_cell(cell):
    return use_key(str(int.from_bytes(hash_element(cell), "big")))

# use private key by calculating g^private_key mod p
def use_key(g):
    return str(pow(int(g), private_key, p))

# send the dataframes to med_node
def sendToMedNote(conn, df_med, private_key, p):
    # call use_key per cell in df_med to calculate the Diffie-Hellman shared keys
    df_med_shared = df_med.applymap(use_key)
    df_med_shared.to_csv("idb_patient_shared.csv", index=False)

    #Content to send
    with open("idb_patient_shared.csv", 'r') as file:
        content = file.read()

    #First step is to send the length of the content
    content_len = len(content)
    conn.sendall(struct.pack('!I', content_len))

    #med_node now knows how many Bytes it should receive
    conn.sendall(content.encode())

    #Same with idb_disease.csv
    with open("idb_disease.csv", 'r') as file:
        disease_content = file.read()

    disease_content_len = len(disease_content)
    conn.sendall(struct.pack('!I', disease_content_len))

    conn.sendall(disease_content.encode())

def listenToConnectionAttempt(df_PSI, private_key, p):
    #print("Listening to MED")
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(('127.0.0.1', 1234))
        s.listen()
        # wait for a connection from the med_node
        conn, addr = s.accept()
        with conn:
            #print('Connected by', addr)

            # per cell: hash elements of the patient dataframe using SHA256 and store them as Diffie-Hellman public keys
            df_idb = df_PSI.applymap(hash_cell)  # call function hash_cell per cell in df_PSI
            df_idb.to_csv('idb_disease.csv', index=False)
            # print('Diseases as DH-public keys:')
            # print(df_idb)

            # Wait for the length of the content the med_node wants to send
            content_len_bytes = conn.recv(4)
            content_len = struct.unpack('!I', content_len_bytes)[0]

            # Receive content
            content = b''
            while len(content) < content_len:
                data = conn.recv(content_len - len(content))
                if not data:
                    break
                content += data

            # Process content
            #print(f'Received {len(content)} bytes of data')

            # Save the received content
            with open('idb_patient.csv', 'wb') as f:
                f.write(content)

            # Read to print
            df_med = pandas.read_csv("idb_patient.csv")

            #print('CSV file written')
            sendToMedNote(conn, df_med, private_key, p)
            conn.close()
            s.close()

# 1-out-of-n oblivious Transfer based on RSA (server)
def OT_idb(array_disease, num, s, first_run, rsa_private_key, array_rdm, array_decrypt, array_message):

    # if is first run of OT: generate RSA key pair and send public key
    if first_run:
        test1 = time.time()
        (rsa_public_key, rsa_private_key) = rsa.newkeys(2048)
        public_key_byte = rsa_public_key.save_pkcs1('DER')
        public_key_byte_len = len(public_key_byte)
        s.sendall(struct.pack('!I', public_key_byte_len))
        s.sendall(public_key_byte)
        first_run = False
        test2 = time.time()
        print(f"Key Zeit in Sekunden: {test2 - test1}")

    # generate num random values, where num equals the number of diseases
    for i in range(num):
        rdm = os.urandom(256)
        rdm_int = int.from_bytes(rdm, "big")
        array_rdm[i] = rdm_int

    # send array_rdm to med
    array_rdm_json = json.dumps(array_rdm)
    array_rdm_bytes = bytes(array_rdm_json, "utf-8")
    array_rdm_len = len(array_rdm_bytes)
    array_rdm_len_byte = bytes(str(array_rdm_len), "utf-8")
    amount_digits = len(array_rdm_len_byte)
    s.send(bytes(str(amount_digits), "utf-8"))
    s.send(array_rdm_len_byte)
    s.send(array_rdm_bytes)

    # receive v
    size = s.recv(3)
    size = int(size.decode("utf-8"))
    v_byte = s.recv(size)
    v = int(v_byte.decode("utf-8"))

    # calculate OT-messaged per disease
    for j in range(num):
        crypt = v - array_rdm[j]
        array_decrypt[j] = pow(crypt, rsa_private_key.d, rsa_private_key.n)
        array_message[j] = int.from_bytes(bytes(array_disease[j], "utf-8")) + array_decrypt[j]

    # send array_message
    array_message_json = json.dumps(array_message)
    array_message_bytes = bytes(array_message_json, "utf-8")
    array_message_len = bytes(str(len(array_message_bytes)), "utf-8")
    amount_digits = len(array_message_len)
    s.send(bytes(str(amount_digits), "utf-8"))
    s.send(array_message_len)
    s.send(array_message_bytes)

    return first_run, rsa_private_key

# large prime from group 14, 2048 bits
p = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF
private_key = generate_key()  # generate private key for idb

# read csv containing all the diseases, drop the name column and adapt the rest to the PSI format
df = pandas.read_csv('disease.csv')
array_disease = df['Name'].tolist()  # save all disease names
df = df.drop(['Name'], axis=1)
df_PSI = df.apply(row_adaptation, axis=1)  # call row_adaptation per row in df
# print('Diseases in PSI format:')
# print(df_PSI)

# wait to receive patient dataframe from med_node, calculate the Diffie-Hellman shared keys and send it back
# send the disease dataframe to med_node
listenToConnectionAttempt(df_PSI, private_key, p)

first_run = True
num = len(array_disease)        # number of diseases
rsa_private_key = rsa.PrivateKey
array_rdm = [0 for x in range(num)]
array_decrypt = [0 for y in range(num)]
array_message = [0 for z in range(num)]
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.bind(('127.0.0.1', 1235))
    s.listen()
    conn, addr = s.accept()
    with conn:
        while True:     # until med closes connection: listen for more OT attempts
            data = conn.recv(1024)
            if not data: break
            first_run, rsa_private_key = OT_idb(array_disease, num, conn, first_run, rsa_private_key, array_rdm, array_decrypt, array_message)  # start new 1-out-of-n OT
        conn.close()
        s.close()
#end = time.time()
#print(f"Zeit in Sekunden: {end-start}")