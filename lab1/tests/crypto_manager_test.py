import sys
import os
sys.path.insert(0, os.path.abspath('..'))
import unittest
from connectors.crap_xjm.crypto_manager import *

# folder                    = "test_keyfile/"
keyfile_folder            = "keyfiles/"
folder = keyfile_folder
team2_cert_pem_path       = keyfile_folder + "team2_cert.pem"
team2_56_78_key_pem_path  = keyfile_folder + "team2_56_78_key.pem"
team2_56_78_cert_pem_path = keyfile_folder + "team2_56_78_cert.pem"
root_pubk_pem_path        = keyfile_folder + "20194_root_pubk.pem"
root_cert_pem_path        = keyfile_folder + "20194_root_cert.pem"

class Test_croppto_manager(unittest.TestCase):
    def setUp(self):
        self.man            = Crypto_manager()
        self.issuer_key     = self.man.generate_RSA_key()
        self.client_RSA_key = self.man.generate_RSA_key()
        self.server_RSA_key = self.man.generate_RSA_key()
        self.client_subject = self.man.generate_subject("test_client_subject")
        self.issuer_subject = self.man.generate_subject("test_issuer_subject")
        self.client_cert    = self.man.generate_cert(self.client_subject, self.issuer_subject,self.client_RSA_key.public_key(), self.issuer_key)
        self.client_EC_key  = self.man.generate_EC_key()
        self.server_EC_key  = self.man.generate_EC_key()
        self.data           = b"test sig data"
    def test_team2_56_78_cert(self):
        with open("keyfiles/team2_56_78_cert.pem", "rb") as f:
            team2_56_78_cert = self.man.unpemfy_cert(f.read())
        with open("keyfiles/team2_cert1.pem", "rb") as f:
            team2_cert = self.man.unpemfy_cert(f.read())

        self.man.verify_cert(self.man.get_public_key_from_cert(team2_cert), team2_56_78_cert)

    def test_rule1(self):
        keyfile_folder  = "lab3_keyfiles/rule1/"
        domain = "20194.2.57.98"
        # get cert and generate signature
        with open(keyfile_folder + domain + "_key.pem", "rb") as f: 
            domain_key_pem = f.read()
            domain_key = self.man.unpemfy_private_key(domain_key_pem)
        with open(keyfile_folder + domain + "_cert.pem", "rb") as f: 
            domain_cert_pem = f.read()
            domain_cert     = self.man.unpemfy_cert(domain_cert_pem)
        with open(keyfile_folder + "team2_cert.pem", "rb") as f:
            team2_cert_pem = f.read()
            team2_cert    = self.man.unpemfy_cert(team2_cert_pem)
        with open(keyfile_folder + "root_cert.pem", "rb") as f:
            root_cert_pem = f.read()
            root_cert     = self.man.unpemfy_cert(root_cert_pem)

        self.assertEqual("20194.", self.man.get_issuer_common_name_from_cert(team2_cert))
        self.assertEqual("20194.2.", self.man.get_subject_common_name_from_cert(team2_cert))
        self.assertEqual("20194.2.", self.man.get_issuer_common_name_from_cert(domain_cert))
        self.assertEqual(domain, self.man.get_subject_common_name_from_cert(domain_cert))

        self.man.verify_cert(self.man.get_public_key_from_cert(root_cert), team2_cert)
        self.man.verify_cert(self.man.get_public_key_from_cert(team2_cert), domain_cert)

    def test_rule2(self):
        keyfile_folder = "lab3_keyfiles/rule2/"
        domain         = "20194.2.57.98"
        with open(keyfile_folder + domain + "_key.pem", "rb") as f: 
            domain_key_pem = f.read()
            domain_key     = self.man.unpemfy_private_key(domain_key_pem)
        with open(keyfile_folder + domain + "_cert.pem", "rb") as f: 
            domain_cert_pem = f.read()
            domain_cert     = self.man.unpemfy_cert(domain_cert_pem)
        with open(keyfile_folder + "team2_key.pem", "rb") as f:
            team2_key_pem = f.read()
            team2_key     = self.man.unpemfy_private_key(team2_key_pem)

        self.assertEqual("20194.2.", self.man.get_issuer_common_name_from_cert(domain_cert))
        self.assertEqual(domain, self.man.get_subject_common_name_from_cert(domain_cert))

        self.man.verify_cert(team2_key.public_key(), domain_cert)
    
    def test_rule4(self):
        keyfile_folder  = "lab3_keyfiles/rule4/"
        domain = "20194.2.57.98"
        # cert
        with open(keyfile_folder + domain + "_key.pem", "rb") as f: 
            domain_key_pem = f.read()
            domain_key = self.man.unpemfy_private_key(domain_key_pem)
        with open(keyfile_folder + domain + "_cert.pem", "rb") as f: 
            domain_cert_pem = f.read()
            domain_cert     = self.man.unpemfy_cert(domain_cert_pem)
            # NOTE: here is team4
        with open(keyfile_folder + "team4_cert.pem", "rb") as f:
            team4_cert_pem = f.read()
            team4_cert    = self.man.unpemfy_cert(team4_cert_pem)
        with open("keyfiles/root_cert.pem", "rb") as f:
            root_cert_pem = f.read()
            root_cert     = self.man.unpemfy_cert(root_cert_pem)

        self.assertEqual("20194.", self.man.get_issuer_common_name_from_cert(team4_cert))
        self.assertEqual("20194.4.", self.man.get_subject_common_name_from_cert(team4_cert))
        self.assertEqual("20194.4.", self.man.get_issuer_common_name_from_cert(domain_cert))
        self.assertEqual(domain, self.man.get_subject_common_name_from_cert(domain_cert))

        self.man.verify_cert(self.man.get_public_key_from_cert(root_cert), team4_cert)
        self.man.verify_cert(self.man.get_public_key_from_cert(team4_cert), domain_cert)

    def test_cert_chain(self):
        domain = "20194.2.56.98"
        # get cert and generate signature
        with open(keyfile_folder + domain + "_key.pem", "rb") as f: 
            domain_key_pem = f.read()
            domain_key = self.man.unpemfy_private_key(domain_key_pem)
        with open(keyfile_folder + domain + "_cert.pem", "rb") as f: 
            domain_cert_pem = f.read()
            domain_cert     = self.man.unpemfy_cert(domain_cert_pem)
        with open("keyfiles/team2_cert.pem", "rb") as f:
            team2_cert_pem = f.read()
            team2_cert    = self.man.unpemfy_cert(team2_cert_pem)
        with open("keyfiles/20194_root_cert.pem", "rb") as f:
            root_cert_pem = f.read()
            root_cert    = self.man.unpemfy_cert(root_cert_pem)

        self.assertEqual("20194.", self.man.get_issuer_common_name_from_cert(team2_cert))
        self.assertEqual("20194.2.", self.man.get_subject_common_name_from_cert(team2_cert))
        self.assertEqual("20194.2.", self.man.get_issuer_common_name_from_cert(domain_cert))
        self.assertEqual(domain, self.man.get_subject_common_name_from_cert(domain_cert))

        self.man.verify_cert(self.man.get_public_key_from_cert(root_cert), team2_cert)
        self.man.verify_cert(self.man.get_public_key_from_cert(team2_cert), domain_cert)

    def test_team2_1_1_cert(self):
        with open("keyfiles/team2_1_1_cert.pem", "rb") as f:
            team2_1_1_cert = self.man.unpemfy_cert(f.read())
        with open("keyfiles/team2_pubk.pem", "rb") as f:
            team2_pubk = self.man.unpemfy_public_key(f.read())
        self.man.verify_cert(team2_pubk,team2_1_1_cert)

    def test_class_cert(self):
        with open("keyfiles/20194_root_cert.pem","rb") as f:
            root_pubk = self.man.get_public_key_from_cert(self.man.unpemfy_cert(f.read()))
        with open("keyfiles/team2_cert.pem", "rb") as f:
            team2_cert = self.man.unpemfy_cert(f.read())
        self.man.verify_cert(root_pubk, team2_cert)

        self.assertEqual("20194.", self.man.get_issuer_common_name_from_cert(team2_cert))
        self.assertEqual("20194.4.", self.man.get_subject_common_name_from_cert(team2_cert))
        self.man.verify_cert(root_pubk, team2_cert)

    def test_hash(self):
        hash1 = self.man.hash(self.data * 10)
        test = hash1[:11]
        print(self.man.hash(self.data))

    def test_AESGCM(self):
        # aad   = b"authenticated but unencrypted data"
        key   = self.man.generate_AESGCM_key()
        nonce = os.urandom(12)
        ct    = self.man.AESGCM_enc(key, nonce, self.data)
        pt    = self.man.ASEGCM_dec(key, nonce, ct)
        self.assertEqual(pt, self.data)

    def test_key_pemfy(self): 
        key_pem       = self.man.pemfy_private_key(self.client_RSA_key)
        key_pem_again = self.man.pemfy_private_key(self.man.unpemfy_private_key(key_pem))
        self.assertEqual(key_pem, key_pem_again)

        pub_key_pem       = self.man.pemfy_public_key(self.client_RSA_key.public_key())
        pub_key_pem_again = self.man.pemfy_public_key(self.man.unpemfy_public_key(pub_key_pem))
        self.assertEqual(pub_key_pem, pub_key_pem_again)
        
        key_pem       = self.man.pemfy_private_key(self.client_EC_key)
        key_pem_again = self.man.pemfy_private_key(self.man.unpemfy_private_key(key_pem))
        self.assertEqual(key_pem, key_pem_again)

        pub_key_pem       = self.man.pemfy_public_key(self.client_EC_key.public_key())
        pub_key_pem_again = self.man.pemfy_public_key(self.man.unpemfy_public_key(pub_key_pem))
        self.assertEqual(pub_key_pem, pub_key_pem_again)

    def test_cert(self): 
        # test pemfy
        cert_pem            = self.man.pemfy_cert(self.client_cert)
        cert_pem_again = self.man.pemfy_cert(self.man.unpemfy_cert(cert_pem))
        self.assertEqual(cert_pem, cert_pem_again)
        # test verify
        try:
            self.man.verify_cert(self.issuer_key.public_key(), self.client_cert)
        except Exception as e:
            self.fail("fail verify cert")

        self.assertRaises(
            Exception,
            self.man.verify_cert,
            self.server_RSA_key.public_key(),
            self.client_cert
        )

    def test_cert_get_pubk_and_common_name(self):
        derived_pubk = self.man.get_public_key_from_cert(self.client_cert)
        # generate sig
        sig = self.man.generate_RSA_signature(self.client_RSA_key, self.data)
        try:
            self.man.verify_RSA_signature(
                self.client_RSA_key.public_key(), sig, self.data)
        except:
            self.fail("orignal pubk is wrong")

        try:
            self.man.verify_RSA_signature(derived_pubk, sig, self.data)
        except:
            self.fail("pubk from cert is wrong")

    def test_cert_get_common_name(self):
        with open("keyfiles/team2_56_78_cert.pem" , "rb") as f:
            cert         = self.man.unpemfy_cert(f.read())
            subject_name = self.man.get_subject_common_name_from_cert(cert)
            issuer_name  = self.man.get_issuer_common_name_from_cert(cert)
            print(subject_name)
            print(issuer_name)
        with open("keyfiles/team2_cert.pem" , "rb") as f:
            cert         = self.man.unpemfy_cert(f.read())
            subject_name = self.man.get_subject_common_name_from_cert(cert)
            issuer_name  = self.man.get_issuer_common_name_from_cert(cert)
            print(subject_name)
            print(issuer_name)

    def test_EC_derive_key(self):
        server_derived_key = self.man.get_EC_derived_key(
            self.server_EC_key, 
            self.client_EC_key.public_key())
        client_derived_key = self.man.get_EC_derived_key(
            self.client_EC_key, 
            self.server_EC_key.public_key())
        self.assertEqual(server_derived_key, client_derived_key)

    def test_EC_signature(self):
        sig = self.man.generate_EC_signature(self.client_EC_key, self.data)
        try:
            self.man.verify_EC_signature(self.client_EC_key.public_key(), sig, self.data)
        except:
            self.fail("fail verify EC signature")

        self.assertRaises(
            Exception,
            self.man.verify_EC_signature,
            self.client_EC_key.public_key(),
            sig,
            self.data+b'1'
        )

    def test_RSA_signature(self):
        sig = self.man.generate_RSA_signature(self.client_RSA_key, self.data)
        try:
            self.man.verify_RSA_signature(
                self.client_RSA_key.public_key(), 
                sig, 
                self.data)
        except: 
            self.fail("exception when verify true sig")

        self.assertRaises(
            Exception, 
            self.man.verify_EC_signature, 
            self.client_EC_key.public_key(),
            sig, 
            self.data+b"a")

    def test_RSA_signatrue_int(self): 
        sig=self.man.generate_RSA_signature(self.client_RSA_key, 1888)
        try:
            self.man.verify_RSA_signature(
                self.client_RSA_key.public_key(), 
                sig, 
                1888
            )
        except:
            self.fail("RSA sig fail verify")

        self.assertRaises(
            Exception,
            self.man.verify_RSA_signature,
            self.client_RSA_key.public_key(),
            1888+1
        )

if __name__ =="__main__":
    unittest.main()