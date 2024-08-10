from OpenSSL import crypto

def generate_key(type_string: str=crypto.TYPE_RSA, bits: int=2048):
    # 生成私有证书
    # type_string: crypto.TYPE_RSA or crypto.TYPE_DSA
  
    private_key = crypto.PKey()
    private_key.generate_key(type_string, bits)

    return private_key
