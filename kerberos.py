from datetime import datetime
from des import decrypt, encrypt


class AuthenticationServer():
    def __init__(self):
        self.as_tgs_key = "lollipop"
        self.client_tgs_key = "abcdef"
        self.tgs_id = "7"
        self.p1 = "10"

    def __is_user_in_db(self, id):
        with open("db.txt", "r") as file:
            for line in file.readlines():
                if line.split()[0] == id:
                    return line.split()[1]
        return False


    def find_by_id(self, client_id):
        #2. AS->C: {{TGT}KAS_TGS, KC_TGS}KC
        client_key = self.__is_user_in_db(client_id)
        if client_key:
            tgt = [encrypt(client_id, self.as_tgs_key),
                    encrypt(self.tgs_id,self.as_tgs_key),
                    encrypt(str(datetime.now().minute), self.as_tgs_key),
                    encrypt(self.p1,self.as_tgs_key),
                    encrypt(self.client_tgs_key, self.as_tgs_key),
            ]
            package = [[encrypt(t, client_key)for t in tgt], encrypt(self.client_tgs_key, client_key)]
            return  package
        else:
            return False


class TicketGrantingServer:
    def __init__(self):
        self.as_tgs_key = "lollipop"
        self.tgs_ss_key = "popup"
        self.client_ss_key ="johnf"

    def check_package(self, package):
        ticket, Aut1, ID = package[0], package[1], package[2]
        ticket = [decrypt(t, self.as_tgs_key) for t in ticket]
        ticket = [t.replace("\x00", "") for t in ticket]

        print("TGS: Decrypted ticket - {}".format(ticket))

        client_id = ticket[0]
        tgs_id = ticket[1],
        t1  = ticket[2]
        p1 = ticket[3]
        client_tgs_key = ticket[4]

        Aut1 = [decrypt(A, client_tgs_key) for A in Aut1]
        Aut1 = [A.replace("\x00", "") for A in Aut1]
        print("TGS: Decrypted Aut1 - {}".format(Aut1))

        if  (Aut1[0] != client_id) or (int(t1) + int(p1) < int(Aut1[1])):
            print("Error: not valid ticket")
            return None

        #4. TGS->C: {{TGS}KTGS_SS,KC_SS}KC_TGS
        ss_id = "8"
        p2 = "10"

        tgs = [
            encrypt(client_id, self.tgs_ss_key),
            encrypt(ss_id, self.tgs_ss_key),
            encrypt(str(datetime.now().minute), self.tgs_ss_key),
            encrypt(p2, self.tgs_ss_key),
            encrypt(self.client_ss_key, self.tgs_ss_key),
        ]

        package = [[encrypt(t, client_tgs_key) for t in tgs], encrypt(self.client_ss_key, client_tgs_key)]
        return package


class KeyDistributionCenter():
    def __init__(self):
        self.authentication_server = AuthenticationServer()
        self.ticket_granting_message = TicketGrantingServer()

    def find_by_id(self, id):
        return self.authentication_server.find_by_id(id)

    def send_to_tgs(self, package):
        return self.ticket_granting_message.check_package(package)


class SServer():
    def __init__(self):
        self.tgs_ss_key = "popup"

    def send_request(self, package):
        ticket, Aut2 = package[0], package[1]

        ticket = [decrypt(t, self.tgs_ss_key) for t in ticket]
        ticket = [t.replace("\x00", "") for t in ticket]
        print("SServer: Decrypted ticket - {}".format(ticket))

        client_id = ticket[0]
        ss_id = ticket[1],
        t1 = ticket[2]
        p1 = ticket[3]
        client_ss_key = ticket[4]

        Aut2 = [decrypt(A, client_ss_key) for A in Aut2]
        Aut2 = [A.replace("\x00", "") for A in Aut2]
        print("SServer: Decrypted Aut2 {}".format(Aut2))


        if (Aut2[0] != client_id) or (int(t1) + int(p1) < int(Aut2[1])):
            print("Error: not valid ticket")
            return None

        #6. SS->C: {t4+1}KC_SS
        return(encrypt(str(int(t1) + 1), client_ss_key))
