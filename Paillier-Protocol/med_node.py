import socket
from threading import Thread
from threading import Event
import csv
import phe.paillier
import json
import os
import rsa
import time

start_time = time.time()


# serialize cypher to byte using phe recommended serialization
def enc_to_byte(encrypted_number_list):
    enc_with_one_pub_key = {}
    enc_with_one_pub_key['public_key'] = {'g': public_key.g, 'n': public_key.n}
    enc_with_one_pub_key['values'] = [(str(x.ciphertext()), x.exponent) for x in encrypted_number_list]
    serialised = json.dumps(enc_with_one_pub_key)
    to_byte = bytes(serialised, "utf-8")
    return to_byte


# Take an int/float and mutate it into an int/float between 0 and its corresponding x-value.
def mutate(mut_var, x_var, min, max):
    y = mut_var-min
    var_scaled = (y/(max-min))*int(x_var)
    return var_scaled


precision_grade = 2        # Amount of numbers after comma, that should not be not rounded.


# Multiply a value by 10^f, whereby f stands for the wanted precision provided above (precision_grade).
def scale_up_once(scale_var):
    scale_var = pow(10, precision_grade)*scale_var
    return int(scale_var)


# Multiply a value by (10^f)^2.
def scale_up_twice(scale_var):
    for x in range(2):
        scale_var = pow(10, precision_grade)*scale_var
    return int(scale_var)


def server(s_host, s_port):
    host = s_host
    port = s_port
    first_run = True

    # open port for connection with hdb
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as receiver:
        receiver.bind((host, port))
        receiver.listen()
        new_sock, addr = receiver.accept()
        with new_sock:
            # print(f"Verbunden mit {addr}")
            global public_key

            event_patient.wait()
            for y in range(len(patientList)):
                new_sock.send(b"1")

                # receive length of key
                if first_run:
                    length_byte = new_sock.recv(3)
                    length_string = length_byte.decode("utf-8")
                    length_int = int(length_string)

                    # receive public key
                    public_key_serial = new_sock.recv(length_int)
                    public_key_string = public_key_serial.decode("utf-8")
                    n = int(public_key_string)
                    public_key = phe.paillier.PaillierPublicKey(n=n)

                    event_key.set()     # signal public key availible

                    first_run = False

                # receive index of minimal disease
                global res
                res = new_sock.recv(4)
                global res_int
                res_int = int.from_bytes(res, "big")

                event.set()     # start transmission of disease index

                calc_end = time.time()
                print(f"Calc in Sekunden: {calc_end - calc_start}")


            new_sock.send(b'0')
            new_sock.close()


def client(c_host, c_port):
    host = c_host
    port = c_port
    # time.sleep(5)
    first_run = True

    # connect to idb as client
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sender:
        sender.connect((host, port))
        # print(f"Verbunden mit {host}")

        event_patient.wait()
        for y in range(len(patientList)):

            send_start = time.time()

            sender.send(b"1")

            # transform data to byte
            encrypted_schema_serial_byte = enc_to_byte(encrypted_schemaList[y])
            encrypted_patientdata_serial_byte = enc_to_byte(encrypted_patientdataList[y])

            # send length of patientdata
            encrypted_patientdata_serial_length_bytes = bytes(str(len(encrypted_patientdata_serial_byte)), "utf-8")
            digits = len(encrypted_patientdata_serial_length_bytes)
            sender.send(bytes(str(digits), "utf-8"))
            sender.send(encrypted_patientdata_serial_length_bytes)

            # send length of schema
            encrypted_schema_serial_length_bytes = bytes(str(len(encrypted_schema_serial_byte)), "utf-8")
            digits = len(encrypted_schema_serial_length_bytes)
            sender.send(bytes(str(digits), "utf-8"))
            sender.send(encrypted_schema_serial_length_bytes)

            # send schema and patientdata
            sender.send(encrypted_patientdata_serial_byte)
            sender.send(encrypted_schema_serial_byte)

            # send min/max_val to idb to transform diseases
            if first_run:
                min_val_json = json.dumps(min_val)
                min_val_byte = bytes(min_val_json, "utf-8")
                min_val_len = len(min_val_byte)
                digits = len(str(min_val_len))
                sender.send(bytes(str(digits), "utf-8"))
                sender.send(bytes(str(min_val_len), "utf-8"))
                sender.send(min_val_byte)

                max_val_json = json.dumps(max_val)
                max_val_byte = bytes(max_val_json, "utf-8")
                max_val_len = len(max_val_byte)
                digits = len(str(max_val_len))
                sender.send(bytes(str(digits), "utf-8"))
                sender.send(bytes(str(max_val_len), "utf-8"))
                sender.send(max_val_byte)

            send_end = time.time()
            print(f"Send in Sekunden: {send_end - send_start}")

            global calc_start
            calc_start = time.time()

            event.wait()
            event.clear()

            ot_start = time.time()

            # begin OT
            sender.send(b"1")

            # recv the public rsa key
            if first_run:
                key_size_byte = sender.recv(4)
                key_size = int(key_size_byte.decode("utf-8"))
                public_rsa_key_byte = sender.recv(key_size)
                public_rsa_key = rsa.PublicKey.load_pkcs1(public_rsa_key_byte, "DER")

            first_run = False

            # recv array of rdm numbers
            digits = sender.recv(1)
            digits = int(digits.decode("utf-8"))
            size = sender.recv(digits)
            size = int(size.decode("utf-8"))
            array_rdm_byte = sender.recv(size)
            array_rdm_json = array_rdm_byte.decode("utf-8")
            array_rdm = json.loads(array_rdm_json)

            # create rdm number to blind v
            k = os.urandom(250)
            k_int = int.from_bytes(k, "big")

            v = (array_rdm[res_int] + pow(k_int, public_rsa_key.e, public_rsa_key.n))           # calculate v with secret index and rdm array

            # send v to idb
            v_bytes = bytes(str(v), "utf-8")
            v_len = bytes(str(len(v_bytes)), "utf-8")
            sender.send(v_len)
            sender.send(v_bytes)

            # receive array with the encoded diseases
            digits = sender.recv(1)
            digits = int(digits.decode("utf-8"))
            size = int(sender.recv(digits).decode())
            array_message_byte = sender.recv(size)
            array_message_json = array_message_byte.decode("utf-8")
            array_message = json.loads(array_message_json)

            # find index with disease passed over in v and print result
            disease = array_message[res_int] - k_int
            print(disease)
            disease_len = len(str(disease))
            disease_byte = disease.to_bytes(disease_len, "big")
            disease_str = disease_byte.decode("utf-8").replace('\x00', '')
            # print(disease_str)

            ot_end = time.time()
            print(f"OT in Sekunden: {ot_end-ot_start}")

        # end connection
        sender.send(b'0')
        sender.close()


# create events
event = Event()
event_key = Event()
event_patient = Event()

# start thread to accept connection
receiver_thread = Thread(target=server, args=("127.0.0.1", 8080))
receiver_thread.start()

transform_start = time.time()

# Dictionary to map ChestPain values to integers
chest_pain_map = {
        "typical": 1,
        "asymptomatic": 2,
        "nonanginal": 3,
        "nontypical": 4
}

# Get x values for attributes
with open("Schema9.csv", "r") as file2:      # Read the .csv file containing the x-values to transform the patientdata.
    reader = csv.reader(file2)
    header = next(reader)
    schemaList = []         # Create a list meant to contain the x-values needed for transformation of patientdata.
    for row in reader:
        schemaList.append(row)       # Save the  x-values for each patient.

with open("MinMax9.csv", "r") as file2:      # Read the .csv file containing min-max values to transform the patientdata.
    reader = csv.reader(file2)
    header = next(reader)
    min_val = next(reader)      # min values for the attributes
    max_val = next(reader)      # max values for the attributes

# Work with patientdata
with open("Patienten1.csv", "r") as file:        # Read the .csv file containing the patientdata.
    reader = csv.reader(file)
    header = next(reader)

    patientList = []        # List which is meant to hold list with info for each patient.
    # Loop through the rows of the file
    i = 0       # Iterator for SchemaLists
    for row in reader:
        row[0] = chest_pain_map[row[0]]     # Use maps before for loop.

        # Mutate all variables to an int between 0 and x and multiply by (10^f)^2
        z = 0       # Iterator for variables
        while z in range(len(row)):
            if (row[z] == "Yes") | (row[z] == "No"):        # if boolean
                row[z] = scale_up_twice(                                                         # Multiply by (10^f)^2
                    mutate(int((row[z] == "Yes")), schemaList[i][z], int(min_val[z]), int(max_val[z])))     # Mutate to value between 0 and x
            else:       # if float/int
                row[z] = scale_up_twice(                                                         # Multiply by (10^f)^2
                    mutate(float(row[z]), schemaList[i][z], float(min_val[z]), float(max_val[z])))          # Mutate to value between 0 and x
            z += 1
        patientList.append(row)      # Append mutated patientdata to patientList.

event_patient.set()
event_key.wait()

# Encrypt mutated patientdata
encrypted_patientdataList = []      # Create an empty list, meant to hold a list for each patient with their respective encrypted data.
for list in patientList:
    encrypted_patientdata = [public_key.encrypt(value) for value in list]       # Encrypt all values of a patient
    encrypted_patientdataList.append(encrypted_patientdata)     # Append encrypted values to the list for all patients

# Encrypt the x-values for each patient after applying the given precision_grade. This allows working with this sensitive information.
encrypted_schema = [None]*len(schemaList[0])        # Temporary list, to hold encrypted x-values.
encrypted_schemaList = []       # List meant to contain a list of encrypted x-values for each patient.
for list in schemaList:
    for x in range(len(list)):
        encrypted_schema[x] = int(scale_up_once(int(list[x]))/100)     # Apply given precision grade.
        encrypted_schema[x] = public_key.encrypt(encrypted_schema[x])       # encrypt value.
    encrypted_schemaList.append(encrypted_schema)

transform_end = time.time()
print(f"Transform in Sekunden: {transform_end-transform_start}")

# start thread to begin a connection
sender_thread = Thread(target=client, args=("127.0.0.1", 8081))
sender_thread.start()

# wait for both threads
receiver_thread.join()
sender_thread.join()

end_time = time.time()
exec_time = end_time - start_time
print(f"Laufzeit in Sekunden: {exec_time}")
# exec_time_min = divmod(exec_time, 60)
# print(f"Laufzeit in Minuten: {exec_time_min}")
