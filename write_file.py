def write_file(data, file_path):
    # 保存证书到本地
    with open(file_path, 'wb') as fp:
       fp.write(data)
