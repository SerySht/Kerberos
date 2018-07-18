from kerberos import*
from datetime import datetime

client_id = "Sergey"
client_key = "qwerty"

kerberos_server = KeyDistributionCenter()
sserver = SServer()

#1.C->AS: {c}.
returned_package = kerberos_server.find_by_id(client_id)
print("Client: Received package:")
print(returned_package)

#3.C->TGS: {TGT}KAS_TGS, {Aut1} KC_TGS, {ID}
tgt = returned_package[0]
tgt = [decrypt(t, client_key) for t in tgt]
client_tgs_key = decrypt(returned_package[1], client_key)

print("Client: Decrypted client-tgs key: {}".format(client_tgs_key))

Aut1 = [encrypt(client_id, client_tgs_key), encrypt(str(datetime.now().minute), client_tgs_key)]
ID = "7"
package = [tgt, Aut1, ID]

returned_package = kerberos_server.send_to_tgs(package)


print("Client: Received packeg: {}".format(returned_package))
ticket = returned_package[0]
ticket = [decrypt(t, client_tgs_key)for t in ticket]

client_ss_key =  decrypt(returned_package[1], client_tgs_key)

print("Client: Decrypted client-ss key: {}".format(client_ss_key))


#5.C->SS: {TGS}KTGS_SS, {Aut2} KC_SS"

t4 = str(datetime.now().minute)
Aut2 = [encrypt(client_id, client_ss_key), encrypt(t4, client_ss_key)]


res = sserver.send_request([ticket, Aut2])

print("Returned from SServer package {}".format(res))
res = decrypt(res, client_ss_key).replace("\x00", "")

print("Decrypted package {}".format(res))

if int(t4) + 1 == int(res):
    print("---Connection established---")
else:
    print("ERROR!!!")

