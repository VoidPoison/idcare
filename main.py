import os.path
from os import urandom
from tkinter import filedialog as fd
from unittest import case
from customtkinter import *
import gostcrypto
from gostcrypto.gostrandom import *
from gostcrypto.gostrandom import R132356510062017
import falcon
import fft

# from datetime import datetime, timedelta
# import ipaddress
# from cryptography import x509
# from cryptography.x509.oid import NameOID
# from cryptography.hazmat.primitives import hashes
# from cryptography.hazmat.backends import default_backend
# from cryptography.hazmat.primitives import serialization
# from cryptography.hazmat.primitives.asymmetric import rsa

app = CTk()
app.geometry("900x640")
app.title("IDC")
set_appearance_mode("dark")
app.resizable(False, False)


def new(rand_size: int, **kwargs) -> 'R132356510062017':
    rand_k = kwargs.get('rand_k', bytearray(b''))
    size_s = kwargs.get('size_s', SIZE_S_384)
    return R132356510062017(rand_size, rand_k, size_s)


def click_handler_1():
    # Вычисление ХЭШ сообщения
    filename = fd.askopenfilename();
    buffer_size = 128
    hash_obj = gostcrypto.gosthash.new(cmb_hash.get())
    with open(filename, 'rb') as file:
        buffer = file.read(buffer_size)
        while len(buffer) > 0:
            hash_obj.update(buffer)
            buffer = file.read(buffer_size)
    hash_result = hash_obj.hexdigest()
    label_1.configure(text=f"hash: {hash_result}")


def click_handler_2():
    # Выбор файла для вычисления хеш значения
    filename = fd.askopenfilename();
    buffer_size = 128
    hash_obj = gostcrypto.gosthash.new(cmb_hash.get())
    with open(filename, 'rb') as file:
        buffer = file.read(buffer_size)
        while len(buffer) > 0:
            hash_obj.update(buffer)
            buffer = file.read(buffer_size)

    hash_result = hash_obj.hexdigest()
    digest = bytearray.fromhex(hash_result)

    match cmb_hash.get():
        case "streebog256":
         sign_obj = gostcrypto.gostsignature.new(gostcrypto.gostsignature.MODE_256,
                                            gostcrypto.gostsignature.CURVES_R_1323565_1_024_2019[
                                                cmb_ecp.get()])
         secretkey_gost_raw = new(32)
         secretkey_gost = secretkey_gost_raw.random()
         secretkey_gost_256 = ''.join(format(x, '02x') for x in secretkey_gost)
         secretkey_gost = bytearray.fromhex(secretkey_gost_256)
         publickey_gost = sign_obj.public_key_generate(secretkey_gost)
         signature_gost = sign_obj.sign(secretkey_gost, digest)




        case "streebog512":
         sign_obj =gostcrypto.gostsignature.new(gostcrypto.gostsignature.MODE_512,
                                            gostcrypto.gostsignature.CURVES_R_1323565_1_024_2019[
                                                cmb_ecp.get()])
         secretkey_gost_raw1 = new(32)
         secretkey_gost_raw2 = new(32)
         secretkey_gost_1 = secretkey_gost_raw1.random()
         secretkey_gost_2 = secretkey_gost_raw2.random()
         secretkey_gost_3 = secretkey_gost_1+secretkey_gost_2
         secretkey_gost_512 = ''.join(format(x, '02x') for x in secretkey_gost_3)
         secretkey_gost = bytearray.fromhex(secretkey_gost_512)
         publickey_gost = sign_obj.public_key_generate(secretkey_gost)
         signature_gost = sign_obj.sign(secretkey_gost, digest)


    match cmb_falcon.get():
        case "256bits":
               secretkey_falcon = falcon.SecretKey(256)
               publickey_falcon = falcon.PublicKey(secretkey_falcon)
               with open(filename, 'rb') as file:
                    message = file.read()
               signature_falcon = falcon.SecretKey.sign(secretkey_falcon, message)

        case "512bits":
               secretkey_falcon = falcon.SecretKey(512)
               publickey_falcon = falcon.PublicKey(secretkey_falcon)
               with open(filename, 'rb') as file:
                    message = file.read()
               signature_falcon = falcon.SecretKey.sign(secretkey_falcon, message)

    label_2.configure(text=f"finished")

    # Сохранение файла открытого ключа
    openkey_gost = ''.join(format(x, '02x') for x in publickey_gost)
    openkey_falcon = publickey_falcon
    #openkey_falcon = ''.join(format(x, '02x') for x in publickey_falcon)
    #label_4.configure(text=f"public key: {str(openkey_gost)+openkey_falcon}")
    filepath = filedialog.asksaveasfilename()
    file = open(filepath, "w", encoding="utf-8")
    file.write(openkey_gost+falcon.PublicKey.__repr__(openkey_falcon))
    file.close()



    # Сохранение файла ЦП
    final_gost_signature = ''.join(format(x, '02x') for x in signature_gost)
    final_falcon_signature = ''.join(format(x, '02x') for x in signature_falcon)
    filepath = filedialog.asksaveasfilename()
    file = open(filepath, "w", encoding="utf-8")
    file.write(str(final_gost_signature+final_falcon_signature))
    file.close()



def click_handler_3():

    #    Выбор файла для вычисления ХЭШа
    hash_filename = fd.askopenfilename();
    buffer_size = 128
    hash_obj = gostcrypto.gosthash.new(cmb_hash.get())
    with open(hash_filename, 'rb') as file:
        buffer = file.read(buffer_size)
        while len(buffer) > 0:
            hash_obj.update(buffer)
            buffer = file.read(buffer_size)

    with open(hash_filename, 'rb') as file:
         message = file.read()

    hash_result = hash_obj.hexdigest()
    digest = bytearray.fromhex(hash_result)

    #   Выбор файла с открытым ключом
    publickey_filename = fd.askopenfilename()
    with open(publickey_filename, 'rt') as file:
        publickey_all = file.read()
        print(len(publickey_all))
        match len(publickey_all):
            case 1716:
                falcon.PublicKey.__init__(publickey_all)
                publickey_gost_raw = publickey_all[0:128]
                print(publickey_gost_raw)
                publickey_falcon_raw = publickey_all[128:1716]
                print(publickey_falcon_raw)
                publickey_gost = bytearray.fromhex(publickey_gost_raw)
                print(publickey_gost)
                publickey_falcon = publickey_falcon_raw
                print(publickey_falcon)
                signature_filename = fd.askopenfilename()
                with open(signature_filename, 'rt') as file:
                    signature_all = file.read()
                    match len(signature_all):
                        case 840:
                            signature_gost_raw = signature_all[0:128]
                            print(signature_gost_raw)
                            signature_falcon_raw = signature_all[128:840]
                            print(signature_falcon_raw)
                            sign_obj = gostcrypto.gostsignature.new(gostcrypto.gostsignature.MODE_256,
                                                                    gostcrypto.gostsignature.CURVES_R_1323565_1_024_2019[
                                                                        'id-tc26-gost-3410-2012-256-paramSetA'])
                            signature_gost = bytearray.fromhex(signature_gost_raw)
                            print(signature_gost)
                            signature_falcon = bytearray.fromhex(signature_falcon_raw)
                            print(signature_falcon)
                            if (sign_obj.verify(publickey_gost, digest, signature_gost)) and (
                                    falcon.SecretKey.verify(publickey_falcon, message, signature_falcon)):
                                label_3.configure(text=f"Signature is correct")
                            else:
                                label_3.configure(text=f"Signature is not correct")

                        case 1460:
                            signature_all = file.read()
                            signature_gost_raw = publickey_all[:128]
                            signature_falcon_raw = publickey_all[128:]
                            sign_obj = gostcrypto.gostsignature.new(gostcrypto.gostsignature.MODE_256,
                                                                    gostcrypto.gostsignature.CURVES_R_1323565_1_024_2019[
                                                                        "streebog256"])
                            signature_gost = bytearray.fromhex(signature_gost_raw)
                            signature_falcon = bytearray.fromhex(signature_falcon_raw)
                            if (sign_obj.verify(publickey_gost, digest, signature_gost)) and (
                                    falcon.SecretKey.verify(publickey_falcon, message, signature_falcon)):
                                label_3.configure(text=f"Signature is correct")
                            else:
                                label_3.configure(text=f"Signature is not correct")

                        case 968:
                            signature_all = file.read()
                            signature_gost_raw = publickey_all[:256]
                            signature_falcon_raw = publickey_all[256:]
                            sign_obj = gostcrypto.gostsignature.new(gostcrypto.gostsignature.MODE_512,
                                                                    gostcrypto.gostsignature.CURVES_R_1323565_1_024_2019[
                                                                        "streebog512"])
                            signature_gost = bytearray.fromhex(signature_gost_raw)
                            signature_falcon = bytearray.fromhex(signature_falcon_raw)
                            if (sign_obj.verify(publickey_gost, digest, signature_gost)) and (
                                    falcon.SecretKey.verify(publickey_falcon, message, signature_falcon)):
                                label_3.configure(text=f"Signature is correct")
                            else:
                                label_3.configure(text=f"Signature is not correct")

                        case 1588:
                            signature_all = file.read()
                            signature_gost_raw = publickey_all[:256]
                            signature_falcon_raw = publickey_all[256:]
                            sign_obj = gostcrypto.gostsignature.new(gostcrypto.gostsignature.MODE_512,
                                                                    gostcrypto.gostsignature.CURVES_R_1323565_1_024_2019[
                                                                        "streebog512"])
                            signature_gost = bytearray.fromhex(signature_gost_raw)
                            signature_falcon = bytearray.fromhex(signature_falcon_raw)
                            if (sign_obj.verify(publickey_gost, digest, signature_gost)) and (
                                    falcon.SecretKey.verify()):
                                label_3.configure(text=f"Signature is correct")
                            else:
                                label_3.configure(text=f"Signature is not correct")

            case 3271:
                publickey_all =file.read()
                publickey_gost_raw = publickey_all[:128]
                publickey_falcon_raw = publickey_all[128:]
                publickey_gost = bytearray.fromhex(publickey_gost_raw)
                publickey_falcon = publickey_falcon_raw

            case 1837:
                publickey_all =file.read()
                publickey_gost_raw = publickey_all[:256]
                publickey_falcon_raw = publickey_all[256:]
                publickey_gost = bytearray.fromhex(publickey_gost_raw)
                publickey_falcon = publickey_falcon_raw

            case 3391:
                publickey_all =file.read()
                publickey_gost_raw = publickey_all[:256]
                publickey_falcon_raw = publickey_all[256:]
                publickey_gost = bytearray.fromhex(publickey_gost_raw)
                publickey_falcon = publickey_falcon_raw











def click_handler_check():
       signature_filename = fd.askopenfilename()
       with open(signature_filename, 'rt') as file:
           size = file.read()
           print(len(size))
           key = size[0:128]
           print(key)






hash_opt = ["streebog256", "streebog512"]
hash_opt_base = StringVar(value=hash_opt[0])
cmb_hash = CTkComboBox(master=app,variable=hash_opt_base,values= hash_opt, justify="center", border_width=2, width=300)
cmb_hash.place(relx=0.06, rely=0.12)



ECP = ["id-tc26-gost-3410-2012-256-paramSetA","id-tc26-gost-3410-2012-256-paramSetB", "id-tc26-gost-3410-2012-256-paramSetC", "id-tc26-gost-3410-2012-256-paramSetD",
       "id-tc26-gost-3410-12-512-paramSetA", "id-tc26-gost-3410-12-512-paramSetB", "id-tc26-gost-3410-2012-512-paramSetC"]
ECP_base = StringVar(value=ECP[0])
cmb_ecp = CTkComboBox(master=app,variable=ECP_base,values= ECP, justify="center", border_width=2, width=300)
cmb_ecp.place(relx=0.06, rely=0.19)

falcon_opt = ["256bits", "512bits"]
falcon_opt_base = StringVar(value=falcon_opt[0])
cmb_falcon = CTkComboBox(master=app,variable=falcon_opt_base,values= falcon_opt, justify="center", border_width=2, width=100)
cmb_falcon.place(relx=0.4, rely=0.12)



btn_1 = CTkButton(master=app, text="Hash", corner_radius=32, fg_color="transparent",
                  hover_color="#00BFFF", border_color="#FFCC70", border_width=2, command=click_handler_1)
btn_1.place(relx=0.2, rely=0.3, anchor="center")
btn_2 = CTkButton(master=app, text="sign", corner_radius=32, fg_color="transparent",
                  hover_color="#00BFFF", border_color="#FFCC70", border_width=2, command=click_handler_2)
btn_2.place(relx=0.5, rely=0.3, anchor="center")
btn_3 = CTkButton(master=app, text="check", corner_radius=32, fg_color="transparent",
                  hover_color="#00BFFF", border_color="#FFCC70", border_width=2, command=click_handler_3)
btn_3.place(relx=0.8, rely=0.3, anchor="center")

btn_check = CTkButton(master=app, text="certif", corner_radius=32, fg_color="transparent",
                hover_color="#00BFFF", border_color="#FFCC70", border_width=2, command=click_handler_check)
btn_check.place(relx=1.0, rely=0.5, anchor="center")

label_1 = CTkLabel(master=app, text="", font=("Arial", 20), text_color="#D2691E")
label_1.place(relx=0.5, rely=0.4, anchor="center")
label_4 = CTkLabel(master=app, text="", font=("Arial", 20), text_color="#D2691E")
label_4.place(relx=0.5, rely=0.5, anchor="center")
label_2 = CTkLabel(master=app, text="", font=("Arial", 20), text_color="#D2691E")
label_2.place(relx=0.5, rely=0.6, anchor="center")
label_3 = CTkLabel(master=app, text="", font=("Arial", 20), text_color="#D2691E")
label_3.place(relx=0.5, rely=0.7, anchor="center")

app.mainloop()
