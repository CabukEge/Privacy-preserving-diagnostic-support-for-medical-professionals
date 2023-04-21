import socket
import threading
import os
import csv
from threading import Event
from phe import paillier
import json
import Crypto.Random.random
import rsa


# define amount of diseases to test and their attributes

# Dictionary to map ChestPain values to integers
chest_pain_map = {
    "typical": 1,
    "asymptomatic": 2,
    "nonanginal": 3,
    "nontypical": 4
}


# serialize cypher to byte using phe recommended serialization
def enc_to_byte(encrypted_number_list):
    enc_with_one_pub_key = {}
    enc_with_one_pub_key['public_key'] = {'g': public_key.g, 'n': public_key.n}
    enc_with_one_pub_key['values'] = [(str(x.ciphertext()), x.exponent) for x in encrypted_number_list]
    serialised = json.dumps(enc_with_one_pub_key)
    to_byte = bytes(serialised, "utf-8")
    return to_byte


# deserialize byte to cypher list using phe recommended serialization
def byte_to_enc_list(to_byte):
    serialised = to_byte.decode("utf-8")
    received_dict = json.loads(serialised)
    pk = received_dict['public_key']
    public_key_rec = paillier.PaillierPublicKey(n=int(pk['n']))
    enc_nums_rec = [paillier.EncryptedNumber(public_key_rec, int(x[0]), int(x[1])) for x in received_dict['values']]
    return enc_nums_rec


# Take an int/float and mutate it into an int/float between 0 and its corresponding x-value.
def mutate(mut_var, x_var, min, max):
    y = mut_var - min
    var_scaled = (y / (max - min)) * int(x_var)         # The mutated value is in the same correlation to 0 and x, as the original value was to min and max.
    return var_scaled


precision_grade = 2        # Amount of numbers after comma, that should not be not rounded. (Maybe be able to receive from doctor?)


# Multiply a value by 10^f, whereby f stands for the wanted precision provided above (precision_grade).
def scale_up_once(scale_var):
    scale_var = pow(10, precision_grade) * scale_var
    return int(scale_var)


def server(s_host, s_port):
    host = s_host
    port = s_port
    first_run = True

    # open port to receive connection from med
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as receiver:
        receiver.bind((host, port))
        receiver.listen()
        new_sock, addr = receiver.accept()
        with new_sock:
            # print(f"Verbunden mit {addr}")
            while new_sock.recv(1) == b'1':

                if not first_run:
                    syn_semaphore.release()

                # get length of patientdata
                digits = new_sock.recv(1)
                digits = int(digits.decode())
                encrypted_patientdata_serial_length_byte = new_sock.recv(digits)
                encrypted_patientdata_serial_length_string = encrypted_patientdata_serial_length_byte.decode("utf-8")
                encrypted_patientdata_serial_length_int = int(encrypted_patientdata_serial_length_string)

                # get lenght of schema
                digits = new_sock.recv(1)
                digits = int(digits.decode())
                encrypted_schema_serial_length_byte = new_sock.recv(digits)
                encrypted_schema_serial_length_string = encrypted_schema_serial_length_byte.decode("utf-8")
                encrypted_schema_serial_length_int = int(encrypted_schema_serial_length_string)

                # get schema and patientdata
                encrypted_patientdata_serial = new_sock.recv(encrypted_patientdata_serial_length_int)
                encrypted_schema_serial = new_sock.recv(encrypted_schema_serial_length_int)

                # get min_val from med
                if first_run:
                    global min_val
                    digits = new_sock.recv(1)
                    digits = int(digits.decode())
                    min_val_len = new_sock.recv(digits)
                    min_val_byte = new_sock.recv(int(str(min_val_len, "utf-8")))
                    min_val_json = min_val_byte.decode("utf-8")
                    min_val = json.loads(min_val_json)

                    # get max_val from med
                    global max_val
                    digits = new_sock.recv(1)
                    digits = int(digits.decode())
                    max_val_len = new_sock.recv(digits)
                    max_val_byte = new_sock.recv(int(str(max_val_len, "utf-8")))
                    max_val_json = max_val_byte.decode("utf-8")
                    max_val = json.loads(max_val_json)

                # transform patientdata and schema
                global encrypted_schema
                global encrypted_patientdata
                encrypted_schema = byte_to_enc_list(encrypted_schema_serial)
                encrypted_patientdata = byte_to_enc_list(encrypted_patientdata_serial)

                event_data.set()        # set event for received data

                syn_semaphore.acquire()
                event_list.wait()  # wait for shuffled list
                event_list.clear()

                # begin OT
                new_sock.recv(1)

                # initialize arrays for later use
                if first_run:
                    array_rdm = [0] * len(list_krankheiten)
                    array_decrypt = [0] * len(list_krankheiten)
                    array_message = [0] * len(list_krankheiten)
                    array_disease = ["a"] * len(list_krankheiten)

                # entry the disease names into array_disease
                x = 0
                while x < len(list_krankheiten):
                    array_disease[x] = list_krankheiten[x][0]
                    x += 1

                if first_run:
                    # create and send public rsa key
                    (public_rsa_key, private_key) = rsa.newkeys(2048)
                    public_rsa_key_byte = public_rsa_key.save_pkcs1("DER")
                    length = len(public_rsa_key_byte)
                    length = bytes(str(length), "utf-8")
                    new_sock.send(length)
                    new_sock.send(public_rsa_key_byte)

                    first_run = False

                # create random int array
                for i in range(len(list_krankheiten)):
                    rdm = os.urandom(256)
                    rdm_int = int.from_bytes(rdm, "big")
                    array_rdm[i] = rdm_int

                # send random array to med to  calculate v
                array_rdm_json = json.dumps(array_rdm)
                array_rdm_bytes = bytes(array_rdm_json, "utf-8")
                array_rdm_len = len(array_rdm_bytes)
                array_rdm_len_byte = bytes(str(array_rdm_len), "utf-8")
                amount_digits = len(array_rdm_len_byte)
                new_sock.send(bytes(str(amount_digits), "utf-8"))
                new_sock.send(array_rdm_len_byte)
                new_sock.send(array_rdm_bytes)

                # receive v from med
                size = new_sock.recv(3)
                size = int(size.decode("utf-8"))
                v_byte = new_sock.recv(size)
                v = int(v_byte.decode("utf-8"))

                # use v to create array_message with disease names
                for j in range(len(list_krankheiten)):
                    crypt = v - array_rdm[j]
                    array_decrypt[j] = pow(crypt, private_key.d, private_key.n)
                    array_message[j] = int.from_bytes(bytes(array_disease[j], "utf-8"), "big") + array_decrypt[j]

                # send array with disease names to med to retrieve the right disease
                array_message_json = json.dumps(array_message)
                array_message_bytes = bytes(array_message_json, "utf-8")
                array_message_len = bytes(str(len(array_message_bytes)), "utf-8")
                amount_digits = len(array_message_len)
                new_sock.send(bytes(str(amount_digits), "utf-8"))
                new_sock.send(array_message_len)
                new_sock.send(array_message_bytes)

            new_sock.close()
            event_end.set()
            syn_semaphore.release()


def client(c_host, c_port):
    host = c_host
    port = c_port
    # time.sleep(5)
    first_run = True

    # start connection with hdb
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sender:
        sender.connect((host, port))
        # print(f"Verbunden mit {host}")

        while True:

            syn_semaphore.acquire()
            if event_end.is_set():
                sender.send(b'0')
                sender.close()  # close the socket
                break
            syn_semaphore.release()

            sender.send(b'1')
            # receive length of key
            if first_run:
                length_byte = sender.recv(3)
                length_string = length_byte.decode("utf-8")
                length_int = int(length_string)

            # receive public key
                public_key_serial = sender.recv(length_int)
                public_key_string = public_key_serial.decode("utf-8")
                n = int(public_key_string)
                global public_key
                public_key = paillier.PaillierPublicKey(n=n)
                # print(public_key.n)

            event_data.wait()       # wait for received patientdata and schema
            event_data.clear()

            global list_krankheiten
            with open("Krankheiten10.csv", "r") as file:      # Read the .csv file containing the sicknesses that we want to compare.
                reader = csv.reader(file)
                header = next(reader)

                list_krankheiten = []       # Create an emtpy list, meant to contain a list for each sickness.

                # Loop through the rows of the .csv file and create a list for each sickness, with its attributes formatted to an int between 0 and their corresponding x-value
                for row in reader:
                    sickness_mutated = [None] * len(row)        # Create a list with the length corresponding to the amount of attributes the provided sickness has.
                    sickness_mutated[0] = row[0]         # Name of sickness
                    row[1] = chest_pain_map[row[1]]  # Use maps before for loop.

                    # Mutate all variables to an int between 0 and x and multiply by 10^f
                    z = 1
                    while z < len(row):
                        if (row[z] == "Yes") | (row[z] == "No"):    # if boolean
                            sickness_mutated[z] = scale_up_once(
                                mutate(int((row[z] == "Yes")), 100, int(min_val[z-1]), int(max_val[z-1])))
                        else:   # if float/int
                            sickness_mutated[z] = scale_up_once(
                                mutate(float(row[z]), 100, float(min_val[z-1]), float(max_val[z-1])))
                        z += 1

                    list_krankheiten.append(sickness_mutated)       # Append the filled in list, to list_krankheiten.

            # Multiply the attribute values from the sicknesses, with their respective encrypted x-values. ((10^f)^2)
            x = 0
            while x < len(list_krankheiten):        # For every sickness
                y = 1
                while y < len(list_krankheiten[x]):         # For every attribute per sickness

                    list_krankheiten[x][y] = list_krankheiten[x][y] * encrypted_schema[y - 1]       # (x*10^f)*(var_mutated*10^f)
                    y += 1
                x += 1

            Crypto.Random.random.shuffle(list_krankheiten)      # randomize order of diseases
            event_list.set()

            # transmit values for the loops
            if first_run:
                amount_disease = bytes(str(len(list_krankheiten)), "utf-8")
                amount_symptome = bytes(str(len(list_krankheiten[0])), "utf-8")
                sender.send(amount_disease)
                sender.send(amount_symptome)
                first_run = False

            # generate rdm, calculate invers binom and sum+rdm
            x = 0
            sum_array = [0] * (len(list_krankheiten))
            while x < len(list_krankheiten):
                y = 1
                invers_array = [0] * (len(list_krankheiten[x]) - 1)
                num_array = [0] * (len(list_krankheiten[x]) - 1)
                while y < len(list_krankheiten[x]):
                    rdm_int = int.from_bytes(os.urandom(150), "big")
                    invers_array[y - 1] = 2 * (encrypted_patientdata[y - 1] - list_krankheiten[x][y]) * rdm_int + rdm_int ** 2
                    # print(rdm_int ** 2)
                    num_array[y - 1] = encrypted_patientdata[y - 1] - list_krankheiten[x][y] + rdm_int
                    y += 1

                # send sum+rdm to recv quad
                num_array = enc_to_byte(num_array)
                sender.send(bytes(str(len(num_array)), "utf-8"))
                sender.send(num_array)

                # recv quad of sum+rdm
                length_int = int(sender.recv(5).decode("utf-8"))
                quad_array = byte_to_enc_list(sender.recv(length_int))

                # sum up the quads for one disease
                y = 1
                while y < len(list_krankheiten[x]):
                    sum_array[x] = sum_array[x] + quad_array[y - 1] - invers_array[y - 1]
                    y += 1
                x += 1

            # send array with all summed up diseases
            sum_array = enc_to_byte(sum_array)
            sender.send(bytes(str(len(sum_array)), "utf-8"))
            sender.send(sum_array)


# create events
event_data = Event()
event_list = Event()
event_end = Event()
syn_semaphore = threading.Semaphore()

receiver_thread = threading.Thread(target=server, args=("127.0.0.1", 8081))
receiver_thread.start()
sender_thread = threading.Thread(target=client, args=("127.0.0.1", 8082))
sender_thread.start()

# wait for the threads
receiver_thread.join()
sender_thread.join()
