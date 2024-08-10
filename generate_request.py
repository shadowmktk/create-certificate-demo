from OpenSSL import crypto

def generate_request(private_key,
                     country_name: str='CN',
                     state_or_province_name: str='Some-State',
                     locality_name: str=None,
                     organization_name: str='Internet Widgits Pty Ltd',
                     organizational_unit_name: str=None,
                     common_name: str='localhost',
                     extensions=None,
                     digest: str='sha256'):
    # 生成证书签发请求
    
    req = crypto.X509Req()

    if country_name:
        req.get_subject().countryName = country_name

    if state_or_province_name:
        req.get_subject().stateOrProvinceName = state_or_province_name

    if locality_name:
        req.get_subject().localityName = locality_name

    if organization_name:
        req.get_subject().organizationName = organization_name

    if organizational_unit_name:
        req.get_subject().organizationalUnitName = organizational_unit_name

    if common_name:
        req.get_subject().commonName = common_name

    if extensions:
        req.add_extensions(extensions)

    req.set_pubkey(private_key)
    req.sign(private_key, digest)

    return req
