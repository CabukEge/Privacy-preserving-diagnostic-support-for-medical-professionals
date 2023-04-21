import hashlib
import socket
import pandas
import os
import binascii
import struct
import rsa
import json
import time

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

# determines the most likely diseases per patient
def compare(row):
    global n        # current patient number
    for i in range(1, df_idb_shared.shape[0] + 1):      # iterating over all diseases i.e. rows in the disease dataframe
        for attr in range(df_med_shared.shape[1]):      # iterating over all attributes and counting the number of matches per disease
            if row[attr] == df_idb_shared.loc[i][attr]:
                matches[i] += 1

    max = 0
    temp = []       # save diseases with the same amount of matches
    for i in range(1, len(matches)):        # determine disease with most matches
        if matches[i] > max:        # disease has more matches and is new max
            temp.clear()
            max = matches[i]
            temp.append(i)
        elif matches[i] == max:     # append diseases with same amount of matches to temp
            temp.append(i)
        matches[i] = 0

    for i in range(len(temp)):      # save diseases with most matches per patient
        if i < len(patient[n]):
            patient[n][i] = temp[i]
    n += 1
    temp.clear()
    return row

def StartExchange(Path_to_hashed_df_med):
    #print("Start exchange")
    # Content to send
    with open(Path_to_hashed_df_med, 'r') as file:
        content = file.read()
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect(('127.0.0.1', 1234))
        #print('Connected to server')

        # First step is to send the length of the content
        content_len = len(content)
        s.send(struct.pack('!I', content_len))
        # idb_node now knows how many Bytes it should receive
        s.sendall(content.encode())

        # receive length
        med_shared_csv_len_bytes = s.recv(4)
        #print(f'Received {len(med_shared_csv_len_bytes)} bytes of data')
        med_shared_csv_len = struct.unpack('!I', med_shared_csv_len_bytes)[0]

        # Receive content
        med_shared_csv = b''
        while len(med_shared_csv) < med_shared_csv_len:
            data = s.recv(med_shared_csv_len - len(med_shared_csv))
            if not data:
                break
            med_shared_csv += data

        #Save content
        with open('med_patient_shared.csv', 'wb') as f:
            f.write(med_shared_csv)

        idb_csv_len_bytes = s.recv(4)
        #print(f'Received {len(med_shared_csv_len_bytes)} bytes of data')
        idb_csv_len = struct.unpack('!I', idb_csv_len_bytes)[0]
        # Receive idb_csv
        idb_csv = b''
        while len(idb_csv) < idb_csv_len:
            data = s.recv(idb_csv_len - len(idb_csv))
            if not data:
                break
            idb_csv += data

        # Save content
        with open('med_disease.csv', 'wb') as f:
            f.write(idb_csv)

        s.close()

# 1-out-of-n oblivious Transfer based on RSA (client)
def OT_med(index, s, first_run, rsa_public_key):

    # send initialization message
    s.sendall("Start OT".encode())

    # if is first run of OT: wait to receive RSA public key
    if first_run:
        key_len_byte = s.recv(4)
        key_len = struct.unpack('!I', key_len_byte)[0]
        key_byte = s.recv(key_len)
        rsa_public_key = rsa.PublicKey.load_pkcs1(key_byte, 'DER')
        first_run = False

    # receive array_rdm
    digits = s.recv(1)
    digits = int(digits.decode("utf-8"))
    size = s.recv(digits)
    size = int(size.decode("utf-8"))
    array_rdm_byte = s.recv(size)
    array_rdm_json = array_rdm_byte.decode("utf-8")
    array_rdm = json.loads(array_rdm_json)

    # generate random k and calculate v
    k = os.urandom(250)
    k_int = int.from_bytes(k, "big")
    v = (array_rdm[index] + pow(k_int, rsa_public_key.e, rsa_public_key.n))

    # send v to idb_node
    v_bytes = bytes(str(v), "utf-8")
    v_len = bytes(str(len(v_bytes)), "utf-8")
    s.send(v_len)
    s.send(v_bytes)

    # wait to receive array_message
    digits = s.recv(1)
    digits = int(digits.decode("utf-8"))
    size = int(s.recv(digits).decode())

    # array_message_byte = s.recv(size)
    array_message_byte = b''
    while len(array_message_byte) < size:
        data = s.recv(size - len(array_message_byte))
        if not data:
            break
        array_message_byte += data
    array_message_json = array_message_byte.decode("utf-8")
    array_message = json.loads(array_message_json)

    # determine wanted disease by subtracting k from the wanted message
    disease = array_message[index] - k_int
    disease_len = len(str(disease))
    disease_byte = disease.to_bytes(disease_len, "big")
    disease_str = disease_byte.decode("utf-8").replace('\x00', '')
    return disease_str, first_run, rsa_public_key

# large prime from group 14, 2048 bits
p = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF
private_key = generate_key()        # generate private key for doctor

# adapt each row of the patient files to the PSI format
df = pandas.read_csv('patient.csv')
df_PSI = df.apply(row_adaptation, axis=1)       # call row_adaptation per row in df
#print('Patient data in PSI format:')
#print(df_PSI)

# per cell: hash elements of the patient dataframe using SHA256 and store them as Diffie-Hellman public keys
df_med = df_PSI.applymap(hash_cell)     # call function hash_cell per cell in df_PSI
df_med.to_csv('med_patient.csv', index=False)
#print('Patient data as DH-public keys:')
#print(df_med)

# send the patient dataframe to idb_node and receive the dataframe containing the Diffie-Hellman shared keys
# receive the disease dataframe from idb_node
StartExchange('med_patient.csv')
df_med_shared = pandas.read_csv('med_patient_shared.csv')
df_med_shared.index = df_med_shared.index + 1       # start index at 1 instead of 0
#print('Patient data as DH-shared keys:')
#print(df_med_shared)

# per cell: call use_key to calculate the Diffie-Hellman shared keys for all cells in the disease dataframe
df_idb = pandas.read_csv('med_disease.csv')
df_idb_shared = df_idb.applymap(use_key)        # call use_key per cell in df_idb
df_idb_shared.index = df_idb_shared.index + 1       # start index at 1 instead of 0
#print('Diseases as DH-shared keys:')
#print(df_idb_shared)

# compare the shared keys in the patient and disease dataframes to determine the disease with the most matches per patient
col = 3     # max number of collisions that are recorded
patient = [[0 for x in range(col)] for y in range(df_med_shared.shape[0])]      # array to save the most likely disease per patient (starts at 0)
matches = [0 for z in range(df_idb_shared.shape[0]+1)]      # array to save number of matches per disease, overwritten per patient (starts at 1)
n = 0 # global counter for patient number
df_compare = df_med_shared.apply(compare, axis=1)       # call compare function per patient i.e. each row in patient dataframe

count = 1
first_run = True
rsa_public_key = rsa.PublicKey

#start_ot = time.time()

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect(('127.0.0.1', 1235))
    print('Starting OT', end='\n\n')
    for row in patient:     # iterate through array saving the most likely disease per patient
        print('Patient ' + str(count), end=' '),
        count += 1
        first_element = True
        for element in row:     # iterate through collisions
            if element != 0:
                disease, first_run, rsa_public_key = OT_med(element - 1, s, first_run, rsa_public_key)  # retrieve corresponding disease using 1-out-of-n OT
                if first_element:
                    print('has ' + disease, end=' '),
                    first_element = False
                else:
                    print('or ' + disease, end=' '),
                    continue

        print(' ', end='\n\n')
    s.close()

#end_ot = time.time()
#print(f"OT Zeit: {end_ot-start_ot}")

