from OpenSSL import crypto
from generate_key import generate_key
from generate_extensions import generate_extensions
from generate_request import generate_request
from create_certificate import create_certificate
from write_file import write_file

def example_ca():
    # 创建CA证书
    distinguished_name = {
        'country_name': 'CN',
        'state_or_province_name': 'Beijing',
        'locality_name': 'Beijing',
        'organization_name': 'Internet Widgits Pty Ltd',
        'organizational_unit_name': 'Internet Widgits Pty Ltd',
        'common_name': 'MyCA'
    }

    basic_constraints  = b'critical, CA:true'
    subject_alt_name   = b'DNS:mydomain.org, DNS:www.mydomain.org'
    key_usage          = b'critical, digitalSignature, keyEncipherment'

    new_basic_constraints  = crypto.X509Extension(b'basicConstraints', False, basic_constraints)
    new_subject_alt_name   = crypto.X509Extension(b'subjectAltName', False, subject_alt_name)
    new_key_usage          = crypto.X509Extension(b'keyUsage', False, key_usage)

    extensions = generate_extensions(new_basic_constraints, new_subject_alt_name, new_key_usage)

    key = generate_key(crypto.TYPE_RSA, 2048)
    req = generate_request(key, **distinguished_name, extensions=extensions)
    cert = create_certificate(req, req, key)

    key_data = crypto.dump_privatekey(crypto.FILETYPE_PEM, key)
    write_file(key_data, 'new-ca.key')

    cert_data = crypto.dump_certificate(crypto.FILETYPE_PEM, cert)
    write_file(cert_data, 'new-ca.crt')

if __name__ == '__main__':
    example_ca()
