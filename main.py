from OpenSSL import crypto
from generate_key import generate_key
from generate_request import generate_request
from create_certificate import create_certificate
from write_file import write_file

def main():
    ca_cert = crypto.load_certificate(crypto.FILETYPE_PEM, open('ca.crt').read())
    ca_key  = crypto.load_privatekey(crypto.FILETYPE_PEM, open('ca.key').read())

    private_key = generate_key(crypto.TYPE_RSA, 2048)
    req = generate_request(private_key)
    cert = create_certificate(req, ca_cert, ca_key)

    key_data = crypto.dump_privatekey(crypto.FILETYPE_PEM, private_key)
    write_file(key_data, 'private.key')

    cert_data = crypto.dump_certificate(crypto.FILETYPE_PEM, cert)
    write_file(cert_data, 'cert.crt')

if __name__ == '__main__':
    main()
