from OpenSSL import crypto

def generate_extensions(basic_constraints=None, subject_alt_name=None, key_usage=None, extended_key_usage=None):
    # 生成证书扩展 X509v3 extensions
  
    extensions = list()

    if basic_constraints:
        extensions.append(basic_constraints)

    if subject_alt_name:
        extensions.append(subject_alt_name)

    if key_usage:
        extensions.append(key_usage)

    if extended_key_usage:
        extensions.append(extended_key_usage)

    return extensions
