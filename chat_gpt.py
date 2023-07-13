from io import BytesIO

def read_uleb128(value: BytesIO):
    result, offset, byte = 0, 0, 0x80
    while byte & 0x80:
        byte = value.read(1)[0]
        result |= (byte & 0x7f) << offset
        offset += 7
    return result


def language(bin_str: int | bytes):
    data = BytesIO(bin_str)
    while True:
        try:
            length = read_uleb128(data)
            if length:
                print(length, data.read(length+1))
            else:
                break
        except Exception as ex:
            continue



language(b'\r\xb3\x06\xff\x7fT\x06\x06\xe0\x81\xf6\x83\x951\xe9\x0f\xb3\x06\xff\x7fU\x06\x02\x07TIMER01\xb5')
