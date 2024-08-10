from OpenSSL import crypto

def create_certificate(req, ca_cert, ca_key, notafter: int=3650, digest='sha256'):
    # 创建SSL证书
  
    cert = crypto.X509()

    cert.set_subject(req.get_subject())

    cert.set_pubkey(req.get_pubkey())

    cert.add_extensions(req.get_extensions())

    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter(notafter * 24 * 60 * 60)

    cert.set_issuer(ca_cert.get_subject())

    cert.sign(ca_key, digest)

    return cert
