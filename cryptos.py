
#!/usr/bin/env python
""" Cypher """
""" Utility to create an AES key, and encrypt / decrypt with the key """

import sys
import getopt
from collections import namedtuple
from Crypto.Cipher import AES

class aes_encrypter:

    def __init__(self, secret_key):
        print "secret key: " + secret_key
        Constants = namedtuple('Constants', ['IV_SIZE', 'KEY_SIZE', 'BUFFER_SIZE'])
        self.constants = Constants(16, 16, 1024)

        # self.cipher = cipher.getInstance(['AES', 'CBC', 'PKCS5Padding'])
        self.secret_key = secret_key
        # self.iv_spec = ''
        # self.buf = ''
        # self.iv_bytes = [[None]] * self.constants.IV_SIZE

    def encrypt(self, message):
        print "encrypt: " + message

        obj = AES.new(self.secret_key, AES.MODE_CBC, 16 * '\x00')
        ciphertext = obj.encrypt(message)
        print "ciphertext: " + ciphertext
        
    #     """ create IV and write to output """
    #     self.iv_bytes = self.create_rand_bytes(self.constants.IV_SIZE)
    #     out.writes(self.iv_bytes);
    #     self.ip_spec = new iv_parameter_spec(self.iv_bytes)
    #     self.cipher.init(self.cipher.ENCRYPT_MODE, self.secret_key, self.iv_spec)

    #     """ bytes written to cipher_out will be encrypted """
    #     cipher_out = new cipher_output_stream(out, self.cipher)
    #     num_read = 0
    #     while((num_read = in.read(self.buf)) >= 0):
    #         cipher_out.write(self.buf, 0, num_read)
    #     cipher_out.close()

    def decrypt(self, message):
        print "decrypt: " + message

        obj = AES.new(self.secret_key, AES.MODE_CBC, 16 * '\x00')
        plaintext = obj.decrypt(message)
        print "plaintext: " + plaintext
        
    #     """ read IV first """
    #     in.read(self.iv_bytes)
    #     self.iv_spec = new iv_parameter_spec(self.iv_bytes)

    #     self.cipher.init(self.cipher.DECRYPT_MODE, self.secret_key, self.iv_spec);

    #     // Bytes read from in will be decrypted
    #     CipherInputStream cipherIn = new CipherInputStream(in, cipher);

    #     // Read in the decrypted bytes and write the plaintext to out
    #     int numRead = 0;
    #     while ((numRead = cipherIn.read(buf)) >= 0)
    #         out.write(buf, 0, numRead);
    #     out.close();

    # public static byte [] createRandBytes(int numBytes) 
    # throws NoSuchAlgorithmException {
    # byte [] bytesBuffer = new byte [numBytes];
    # SecureRandom sr = SecureRandom.getInstance("SHA1PRNG");
    # sr.nextBytes(bytesBuffer);
    # return bytesBuffer;
    # }

def usage():
    print "python aes encrypter create_key|encrypt|decrypt <key_file>"
    sys.exit()

def main(argv):
    try:
        opts, args = getopt.getopt(argv, "o:k:", ["operation=", "key_file="])
    except getopt.GetoptError:
        print 'aes.py -o <operation> -k <key_file>'
        sys.exit(2)

    for o, arg in opts:
        if o in ("-o", "--operation"):
            operation = arg
        elif o in ("-k", "--key_file"):
            key_file = arg
        else:
            usage()
            sys.exit()

    if not operation or not key_file:
        usage()

    print "operation: " + operation
    print "key file: " + key_file

    if "create_key" == operation:
        """ write key """
        file = open(key_file, 'w')
        file.write("0123456789abcdef")
        file.close()
    else:
        """ read key """
        file = open(key_file, 'r')
        key = file.read()
        aes = aes_encrypter(key)
        input = ''

        for line in sys.stdin:
            input += line

        if "encrypt" == operation:
            aes.encrypt(input)
        elif "decrypt" == operation:
            aes.decrypt(input)
        else:
            usage()

if __name__ == "__main__":
    main(sys.argv[1:])