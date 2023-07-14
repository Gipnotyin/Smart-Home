import sys
import requests
import base64
from functools import reduce
from io import BytesIO


# Функция для вычисления контрольной суммы CRC-8
def crc8(payload):
    crc_lookup = [
        0, 29, 58, 39, 116, 105, 78, 83, 232, 245, 210, 207, 156, 129, 166, 187,
        205, 208, 247, 234, 185, 164, 131, 158, 37, 56, 31, 2, 81, 76, 107, 118,
        135, 154, 189, 160, 243, 238, 201, 212, 111, 114, 85, 72, 27, 6, 33, 60,
        74, 87, 112, 109, 62, 35, 4, 25, 162, 191, 152, 133, 214, 203, 236, 241,
        19, 14, 41, 52, 103, 122, 93, 64, 251, 230, 193, 220, 143, 146, 181, 168,
        222, 195, 228, 249, 170, 183, 144, 141, 54, 43, 12, 17, 66, 95, 120, 101,
        148, 137, 174, 179, 224, 253, 218, 199, 124, 97, 70, 91, 8, 21, 50, 47,
        89, 68, 99, 126, 45, 48, 23, 10, 177, 172, 139, 150, 197, 216, 255, 226,
        38, 59, 28, 1, 82, 79, 104, 117, 206, 211, 244, 233, 186, 167, 128, 157,
        235, 246, 209, 204, 159, 130, 165, 184, 3, 30, 57, 36, 119, 106, 77, 80,
        161, 188, 155, 134, 213, 200, 239, 242, 73, 84, 115, 110, 61, 32, 7, 26,
        108, 113, 86, 75, 24, 5, 34, 63, 132, 153, 190, 163, 240, 237, 202, 215,
        53, 40, 15, 18, 65, 92, 123, 102, 221, 192, 231, 250, 169, 180, 147, 142,
        248, 229, 194, 223, 140, 145, 182, 171, 16, 13, 42, 55, 100, 121, 94, 67,
        178, 175, 136, 149, 198, 219, 252, 225, 90, 71, 96, 125, 46, 51, 20, 9,
        127, 98, 69, 88, 11, 22, 49, 44, 151, 138, 173, 176, 227, 254, 217, 196]
    CRC8 = lambda bytes: reduce(lambda a, x: crc_lookup[a ^ x], bytes, 0)
    return CRC8(payload)


def size_address():
    address = int(sys.argv[2])
    varuint_address = []
    while True:
        byte = address & 0x7F
        address >>= 7
        if address:
            byte |= 0x80
            varuint_address.append(byte)
        if not address:
            break

    varuint_address.reverse()
    print(varuint_address)
    return len(varuint_address)


def decode_base64(data):
    return base64.urlsafe_b64decode(data + '===')


def encode_base64(data):
    return base64.urlsafe_b64encode(data)


def read_uleb128(value: BytesIO):
    result, offset, byte = 0, 0, 0x80
    while byte & 0x80:
        byte = value.read(1)[0]
        result |= (byte & 0x7f) << offset
        offset += 7
    return result


def triggers(stream: BytesIO, byte: int | bytes):
    result = []
    length = read_uleb128(stream)
    for _ in range(length):
        result.append({
            "op": read_uleb128(stream),
            "value": read_uleb128(stream),
            "name": read_string(stream)
        })
    return result


def read_string(stream: BytesIO):
    length = stream.read(1)[0]
    if length < 1:
        exit(99)
    return stream.read(length).decode('ascii')


def cmd_body_parse(dev_type: int | bytes, cmd: int | bytes, stream: BytesIO):
    if (dev_type == 0x01 or dev_type == 0x05) and (cmd == 0x01 or cmd == 0x02): #SmartHub, WHOISHERE (1, 1) | SmartHub, IAMHERE (1, 2) | Socket, WHOISHERE (5, 1) | Socket, IAMHERE (5, 2)
        return {
            "dev_name": read_string(stream)
        }
    elif dev_type == 0x02 and (cmd == 0x01 or cmd == 0x02): #EnvSensor, WHOISHERE (2, 1) | EnvSensor, IAMHERE (2, 2)
        dev_name = read_string(stream)
        sensors = read_uleb128(stream)
        return {
            "dev_name": dev_name,
            "dev_props": {
                "sensors": sensors,
                "triggers": [] if sensors == 0 else triggers(stream, sensors)
            }
        }
    elif (dev_type == 0x02 or dev_type == 0x04 or dev_type == 0x03 or dev_type == 0x05) and cmd == 0x03: #EnvSensor, GETSTATUS  (2, 3) | Switch, GETSTATUS (3, 3) | Lamp, GETSTATUS (4, 3) | Socket, GETSTATUS (5, 3)
        return None
    elif dev_type == 0x02 and cmd == 0x04: #EnvSensor, STATUS  (2, 4)
        length = read_uleb128(stream)
        return {
            "values": [read_uleb128(stream) for _ in range(length)]
        }
    elif dev_type == 0x03 and (cmd == 0x01 or cmd == 0x02): #Switch, WHOISHERE (3, 1) | Switch, IAMHERE (3, 2)
        dev_name = read_string(stream)
        length = read_uleb128(stream)
        return {
            "dev_name": dev_name,
            "dev_props": {
                "dev_names": [read_string(stream) for _ in range(length)]
            }
        }
    elif (dev_type == 0x03 or dev_type == 0x04 or dev_type == 0x05) and cmd == 0x04 \
            or (dev_type == 0x04 or dev_type == 0x05) and cmd == 0x05: #Switch, STATUS (3, 4) | Lamp, STATUS (4, 4) | #Lamp, SETSTATUS (4, 5) | Socket, SETSTATUS (5, 5)
        return {
            "value": read_uleb128(stream)
        }
    elif dev_type == 0x04 and (cmd == 0x01 or cmd == 0x02): #Lamp, WHOISHERE (4, 1) | Lamp, IAMHERE (4, 2)
        return {
            "dev_name": read_string(stream)
        }
    elif dev_type == 0x06 and (cmd == 0x02 or cmd == 0x01):
        return {
            "dev_name": read_string(stream)
        }
    elif dev_type == 0x06 and cmd == 0x06:
        return {
            "timestamp": read_uleb128(stream)
        }
    else:
        exit(99)


def decode_packet(length, data: int | bytes):
    stream = BytesIO(data)
    packet_size = length
    packet_data = stream.read(packet_size+1)
    src8 = packet_data[-1]
    stream.seek(0)
    if crc8(packet_data[:-1]) != src8:
        # Контрольная сумма не совпадает, возвращаем None
        return None

    src = read_uleb128(stream)
    dst = read_uleb128(stream)
    serial = read_uleb128(stream)
    dev_type = read_uleb128(stream)
    cmd = read_uleb128(stream)
    cmd_body = cmd_body_parse(dev_type, cmd, stream)
    # Формируем декодированный пакет
    decoded_packet = {
        'src': src,
        'dst': dst,
        'serial': serial,
        'dev_type': dev_type,
        'cmd': cmd,
        'cmd_body': cmd_body
    }
    if decoded_packet['cmd_body'] is None:
        del decoded_packet['cmd_body']
    return decoded_packet


def string_to_ULEB128(string: str):
    length = len(string.encode())  # вычисляем длину строки в байтах
    len_bytes = []
    while True:
        b = length & 0x7f
        length >>= 7
        if length:
            len_bytes.append(b | 0x80)
        else:
            len_bytes.append(b)
            break
    return bytes(len_bytes) + string.encode()  # кодируем строку в байты


def encode_uleb128(value):
    result = bytearray()
    while True:
        byte = value & 0x7f
        value >>= 7
        if value != 0:
            byte |= 0x80
        result.append(byte)
        if value == 0:
            break
    return bytes(result)


def encode_payload(struct: dict):
    result = []
    for key, val in struct.items():
        if isinstance(val, dict):
            result.extend(encode_payload(val))
        if isinstance(val, list):
            result.extend(encode_uleb128(len(val)))
            for v in val:
                if isinstance(v, dict):
                    result.extend(encode_payload(v))
                if isinstance(v, str):
                    result.extend(string_to_ULEB128(v))
                if isinstance(v, int):
                    result.extend(encode_uleb128(v))
        if isinstance(val, int):
            result.extend(encode_uleb128(val))
        if isinstance(val, str):
            result.extend(string_to_ULEB128(val))
    return result


def encode_packet(packet):
    CRC8_byte = lambda byte, poly=0x1d: reduce(lambda b, _: b << 1 ^ (b & 0x80 and poly), range(8), byte) & 0xff
    CRC8_lookup = list(map(CRC8_byte, range(256)))
    CRC8 = lambda bytes: reduce(lambda c, b: CRC8_lookup[c ^ b], bytes, 0)
    pack = lambda payload: [len(payload), *payload, CRC8(payload)]
    b64encode = lambda payload: base64.urlsafe_b64encode(bytearray(pack(payload))).decode('ascii').rstrip('=')

    payload = encode_payload(packet)

    return b64encode(payload)


def language(bin_str: int | bytes):
    data = BytesIO(bin_str)
    while True:
        try:
            length = read_uleb128(data)
            if length:
                print(decode_packet(length, data.read(length+1)))
            else:
                break
        except Exception:
            break


def main():
    url, address = sys.argv[1:]
    req_url = encode_packet({
        "payload": {
            "src": int(sys.argv[2], 16),
            "dst": 16383,
            "serial": 0,
            "dev_type": 1,
            "cmd": 1,
            "cmd_body":
                {
                    "dev_name": "SMARTHUB01"
                }
        }
    })
    response = requests.post(url, req_url)
    count = 0
    while count < 10:
        if response.status_code == 200:
            if response.text != '':
                decod_str = decode_base64(response.text)
                print(decod_str)
                language(decod_str)
        elif response.status_code == 204:
            print("exit 0")
            exit(0)
        else:
            print('popusk')
            exit(99)
        response = requests.post(url, '')
        count += 1


if __name__ == '__main__':
    main()

