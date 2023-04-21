import socket
from threading import Thread
from threading import Event
from phe import paillier
import json


# serialize cypher to byte using phe recommended serialization
def enc_to_byte(encrypted_number_list):
    enc_with_one_pub_key = {}
    enc_with_one_pub_key['public_key'] = {'g': public_key.g, 'n': public_key.n}
    enc_with_one_pub_key['values'] = [(str(x.ciphertext()), x.exponent) for x in encrypted_number_list]
    serialised = json.dumps(enc_with_one_pub_key)
    to_byte = bytes(serialised, "utf-8")
    return to_byte


# deserialize byte to cypher list using phe recommended serialization
def byte_to_enc(to_byte):
    serialised = to_byte.decode("utf-8")
    received_dict = json.loads(serialised)
    pk = received_dict['public_key']
    public_key_rec = paillier.PaillierPublicKey(n=int(pk['n']))
    enc_nums_rec = [paillier.EncryptedNumber(public_key_rec, int(x[0]), int(x[1])) for x in received_dict['values']]
    return enc_nums_rec


def server(s_host, s_port):
    host = s_host
    port = s_port
    first_run = True

    # open port to receive connection from idb
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as receiver:
        receiver.bind((host, port))
        receiver.listen()
        new_sock, addr = receiver.accept()
        with new_sock:
            # print(f"Verbunden mit {addr}")

            while new_sock.recv(1) == b'1':

                # send size of key to idb
                if first_run:
                    length = len(public_key_byte)
                    length_string = str(length)
                    length_bytes = bytes(length_string, "utf-8")
                    new_sock.send(length_bytes)

                    # send public paillier key
                    new_sock.send(public_key_byte)
                    first_run = False

                    # recv values for the loops and arrays
                    amount_disease = new_sock.recv(4)
                    amount_symptome = new_sock.recv(4)
                    global diseases
                    global symptomes
                    diseases = int(amount_disease.decode("utf-8"))
                    symptomes = int(amount_symptome.decode("utf-8"))-1

                # recv and decrypt all sums
                x = 0
                while x < diseases:
                    array_length = int(new_sock.recv(5).decode("utf-8"))
                    num_array = byte_to_enc(new_sock.recv(array_length))
                    num_array = [private_key.decrypt(z) for z in num_array]

                    # calculate quad of all sums, encrypt and send to idb
                    y = 0
                    while y < symptomes:
                        num_array[y] = num_array[y] ** 2
                        y += 1
                    num_array = [public_key.encrypt(z) for z in num_array]
                    num_array = enc_to_byte(num_array)
                    new_sock.send(bytes(str(len(num_array)), "utf-8"))
                    new_sock.send(num_array)
                    x += 1

                # recv and decrypt all summed up diseases
                array_length = int(new_sock.recv(5).decode("utf-8"))
                sum_array = byte_to_enc(new_sock.recv(array_length))
                sum_array = [private_key.decrypt(z) for z in sum_array]

                # find smallest entry - means smallest deviation
                global min_index
                min_index = 0
                counter = 1
                min_value = sum_array[0]
                while counter < diseases:
                    if sum_array[counter] < min_value:
                        min_index = counter
                        min_value = sum_array[counter]

                    counter += 1

                event.set()     # signal client to send max_index to med

            new_sock.close()


def client(c_host, c_port):
    host = c_host
    port = c_port
    # time.sleep(5)
    first_run = True

    # start connection to med
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sender:
        sender.connect((host, port))
        # print(f"Verbunden mit {host}")
        while sender.recv(1) == b'1':

            # calculate size of public key
            if first_run:
                length = len(public_key_byte)
                length_string = str(length)
                length_bytes = bytes(length_string, "utf-8")
                sender.send(length_bytes)

                # send public paillier key to med
                sender.send(public_key_byte)
                first_run = False

            event.wait()    # wait for receiver thread to find minimal entry
            event.clear()

            # send minimal sum to med
            min_index_byte = min_index.to_bytes(4, "big")
            sender.send(min_index_byte)

        # end connection, server recv 0 byte
        sender.close()


# Generate keypair and calculate size of public key

public_key, private_key = paillier.generate_paillier_keypair()
public_key_str = str(public_key.n)
public_key_byte = bytes(public_key_str, "utf-8")


# create event
event = Event()

receiver_thread = Thread(target=server, args=("127.0.0.1", 8082))
receiver_thread.start()
sender_thread = Thread(target=client, args=("127.0.0.1", 8080))
sender_thread.start()

# wait for the threads to join
receiver_thread.join()
sender_thread.join()
