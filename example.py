from OpenSSL import crypto
from generate_key import generate_key
from generate_extensions import generate_extensions
from generate_request import generate_request
from create_certificate import create_certificate
from write_file import write_file

def example1():
    distinguished_name = {
        'country_name': 'CN',
        'state_or_province_name': 'Beijing',
        'locality_name': 'Beijing',
        'organization_name': 'Internet Widgits Pty Ltd',
        'organizational_unit_name': 'Internet Widgits Pty Ltd',
        'common_name': 'mydomain.org'
    }

    # 使用CA签发证书
    ca_cert = crypto.load_certificate(crypto.FILETYPE_PEM, open('ca.crt').read())
    ca_key  = crypto.load_privatekey(crypto.FILETYPE_PEM, open('ca.key').read())

    private_key = generate_key(crypto.TYPE_RSA, 2048)
    req = generate_request(private_key=private_key, **distinguished_name)
    cert = create_certificate(req, ca_cert, ca_key)

    # req_data = crypto.dump_certificate_request(crypto.FILETYPE_PEM, x509_req)
    # write_file(req_data, 'req.csr')

    key_data = crypto.dump_privatekey(crypto.FILETYPE_PEM, private_key)
    write_file(key_data, 'private1.key')

    cert_data = crypto.dump_certificate(crypto.FILETYPE_PEM, cert)
    write_file(cert_data, 'cert1.crt')

def example2():
    # 不需要CA签发证书
    private_key = generate_key(crypto.TYPE_RSA, 2048)
    req = generate_request(private_key)
    cert = create_certificate(req, req, private_key)

    key_data = crypto.dump_privatekey(crypto.FILETYPE_PEM, private_key)
    write_file(key_data, 'private2.key')

    cert_data = crypto.dump_certificate(crypto.FILETYPE_PEM, cert)
    write_file(cert_data, 'cert2.crt')

def example3():
    # 有 X509v3 extensions 的证书
    basic_constraints  = b'CA:false'
    # basic_constraints  = b'critical, CA:true'
    subject_alt_name   = b'IP:127.0.0.1, IP:192.168.1.1, DNS:mydomain.org, DNS:www.mydomain.org'
    key_usage          = b'critical, digitalSignature, keyEncipherment'
    extended_key_usage = b'serverAuth, clientAuth'

    new_basic_constraints  = crypto.X509Extension(b'basicConstraints', False, basic_constraints)
    new_subject_alt_name   = crypto.X509Extension(b'subjectAltName', False, subject_alt_name)
    new_key_usage          = crypto.X509Extension(b'keyUsage', False, key_usage)
    new_extended_key_usage = crypto.X509Extension(b'extendedKeyUsage', False, extended_key_usage)

    ca_cert = crypto.load_certificate(crypto.FILETYPE_PEM, open('ca.crt').read())
    ca_key  = crypto.load_privatekey(crypto.FILETYPE_PEM, open('ca.key').read())

    #
    extensions = generate_extensions(new_basic_constraints, new_subject_alt_name, new_key_usage, new_extended_key_usage)

    private_key = generate_key(crypto.TYPE_RSA, 2048)
    req = generate_request(private_key=private_key, extensions=extensions)
    cert = create_certificate(req, ca_cert, ca_key)

    # req_data = crypto.dump_certificate_request(crypto.FILETYPE_PEM, req)
    # write_file(req_data, 'req3.csr')

    key_data = crypto.dump_privatekey(crypto.FILETYPE_PEM, private_key)
    write_file(key_data, 'private3.key')

    cert_data = crypto.dump_certificate(crypto.FILETYPE_PEM, cert)
    write_file(cert_data, 'cert3.crt')

if __name__ == '__main__':
    example1()
    example2()
    example3()
