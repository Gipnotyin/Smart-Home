import sys

import requests
import base64
from functools import reduce
from io import BytesIO


class DeviceType:
    SmartHub = 1  # this
    EnvSensor = 2  # датчик
    Switch = 3  # переключатель
    Lamp = 4  # лампа
    Socket = 5  # розетка;
    Clock = 6  # часы


class Command:
    WhoIsHere = 1
    IAmHere = 2
    GetStatus = 3
    Status = 4
    SetStatus = 5
    Tick = 6


# Функция для вычисления контрольной суммы CRC-8
def crc8(payload):
    CRC8_byte = lambda byte, poly=0x1d: reduce(lambda b, _: b << 1 ^ (b & 0x80 and poly), range(8), byte) & 0xff
    CRC8_lookup = list(map(CRC8_byte, range(256)))
    CRC8 = lambda bytes: reduce(lambda c, b: CRC8_lookup[c ^ b], bytes, 0)
    return CRC8(payload)


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
    pack = lambda payload: [len(payload), *payload, crc8(payload)]
    b64encode = lambda payload: base64.urlsafe_b64encode(bytearray(pack(payload))).decode('ascii').rstrip('=')

    payload = encode_payload(packet)

    return b64encode(payload)



class Solution:
    def __init__(self):
        self.BROADCAST = 0x3FFF
        self.url = sys.argv[1]
        self.src = int(sys.argv[2], 16)
        self.dev_name = "SmartHub"
        self.serial = 0
        self.black_list: set = set()
        self.Env_Sensors: dict = dict()
        self.Switches: dict = dict()
        self.Lamps: dict = dict()
        self.Sockets: dict = dict()
        self.Tick: dict = dict()
        self.device_switch: dict = dict()
        self.time: dict = dict()
        self.local_time: int = 0
        self.first_time: int = 0

    def WHO_IS_HERE(self):
        who_is_here = {
            "payload": {
                "src": self.src,
                "dst": self.BROADCAST,
                "serial": self.serial,
                "dev_type": 1,
                "cmd": 1,
                "cmd_body":
                    {
                        "dev_name": self.dev_name
                    }
            }
        }
        response = requests.post(self.url, data=encode_packet(who_is_here))
        if response.status_code == 200:
            self.start_program(decode_base64(response.text))
        elif response.status_code == 204:
            exit(0)
        else:
            exit(99)

    def process(self):
        while True:
            response = requests.post(self.url, "")
            if response.status_code == 200:
                if response.text != '':
                    pack = self.language(decode_base64(response.text))
                    self.request_processing(pack)
            elif response.status_code == 204:
                exit(0)
            else:
                exit(99)

    def language(self, bin_str: int | bytes):
        data = BytesIO(bin_str)
        packets = []
        while True:
            try:
                length = read_uleb128(data)
                if length:
                    packets.append(decode_packet(length, data.read(length + 1)))
                else:
                    break
            except Exception:
                break
        return packets

    def start_program(self, bin_str: int | bytes):
        packets = self.language(bin_str)
        for packet in packets:
            dev_type, cmd = packet['dev_type'], packet['cmd']
            if cmd == Command.Tick:
                self.local_time = packet['cmd_body']['timestamp']
                self.first_time = packet['cmd_body']['timestamp']
            if cmd == Command.IAmHere:
                self.cmd_im_here(packet, dev_type)
            self.serial += 1

    def cmd_im_here(self, packet, dev_type):
        name = packet['cmd_body']['dev_name']
        if dev_type == DeviceType.EnvSensor:
            self.Env_Sensors[packet['src']] = [packet, self.local_time]
        if dev_type == DeviceType.Switch:
            self.Switches[name] = [packet, self.local_time]
            self.device_switch[packet['src']] = packet['cmd_body']['dev_props']['dev_names']
            self.get_status_switch(packet)
        if dev_type == DeviceType.Socket:
            self.Sockets[name] = [packet, self.local_time]
        if dev_type == DeviceType.Lamp:
            self.Lamps[name] = [packet, self.local_time]
        if dev_type == DeviceType.Clock:
            self.Tick = packet

    def request_processing(self, packets):
        for packet in packets:
            self.serial += 1
            dev_type, cmd = packet['dev_type'], packet['cmd']
            if cmd == Command.Tick:
                self.local_time = packet['cmd_body']['timestamp']
            elif cmd == Command.WhoIsHere:
                self.who_is_here_device(packet, dev_type)
            elif cmd == Command.IAmHere:
                if abs(self.first_time - self.local_time) <= 300:
                    self.cmd_im_here(packet, dev_type)
                else:
                    self.black_list.add(packet['src'])
            elif cmd == Command.Status:
                if abs(self.time[packet['src']] - self.local_time) > 300:
                    self.black_list.add(packet['src'])
                    continue
                if dev_type == DeviceType.Switch:
                    self.switch_processing(packet)
                elif dev_type == DeviceType.EnvSensor:
                    self.status_env_sensor(packet)

    def status_env_sensor(self, packet):
        data = self.Env_Sensors[packet['src']]
        sensors = bin(data['cmd_body']['dev_props']['sensors'])[2:]
        values = packet['cmd_body']['values']
        triggers = data['cmd_body']['dev_props']['triggers']
        count = 0
        for sensor in sensors:
            if sensor == '1':
                op = bin(triggers[count]['op'])[2:]
                STATUS = int(op[-1], 2)
                name = triggers[count]['name']
                pac = self.Sockets[name] if name in self.Sockets.keys() else self.Lamps[name]
                if int(op[-2], 2):
                    if values[count] > triggers[count]['value']:
                        self.SET_STATUS(pac, STATUS)
                else:
                    if values[count] > triggers[count]['value']:
                        self.SET_STATUS(pac, STATUS)
                count += 1

    def who_is_here_device(self, packet, dev_type):
        name = packet['cmd_body']['dev_name']
        if packet['src'] in self.black_list:
            self.black_list.discard(packet['src'])
        if dev_type == DeviceType.EnvSensor:
            self.Env_Sensors[packet['src']] = [packet, self.local_time]
        elif dev_type == DeviceType.Switch:
            self.Switches[name] = [packet, self.local_time]
            self.device_switch[packet['src']] = packet['cmd_body']['dev_props']['dev_names']
        elif dev_type == DeviceType.Lamp:
            self.Lamps[name] = [packet, self.local_time]
        elif dev_type == DeviceType.Socket:
            self.Sockets[name] = [packet, self.local_time]
        self.IMHERE(packet)

    def get_status_switch(self, packet: dict):
        get_status = encode_packet({
                "src": self.src,
                "dst": packet['src'],
                "serial": self.serial,
                "dev_type": DeviceType.SmartHub,
                "cmd": Command.GetStatus
            })
        response = requests.post(self.url, data=get_status)
        self.time[packet['src']] = self.local_time
        if response.status_code == 200:
            answer = self.language(decode_base64(response.text))
            for pac in answer:
                if pac['src'] == packet['src'] and pac['cmd'] == Command.Status:
                    self.switch_processing(pac)

    def switch_processing(self, packet):
        STATUS = packet['cmd_body']['value']
        for name in self.device_switch[packet['src']]:
            if name in self.Lamps.keys():
                self.SET_STATUS(self.Lamps[name][0], STATUS)
                self.Lamps[name][1] = self.local_time
            elif name in self.Sockets.keys():
                self.SET_STATUS(self.Sockets[name][0], STATUS)
                self.Sockets[name][1] = self.local_time

    def SET_STATUS(self, packet, STATUS):
        if STATUS == 0:
            self.black_list.add(packet['src'])
        else:
            self.black_list.discard(packet['src'])
        self.time[packet['src']] = self.local_time
        self.serial += 1
        set_status = encode_packet(
            {
                "src": self.src,
                "dst": packet['src'],
                "serial": self.serial,
                "dev_type": DeviceType.SmartHub,
                "cmd": Command.SetStatus,
                "cmd_body": {
                    "value": STATUS
                }
            }
        )
        response = requests.post(self.url, set_status)

    def IMHERE(self, packet):
        i_am_here = encode_packet({
            "src": self.src,
            "dst": self.BROADCAST,
            "serial": self.serial,
            "dev_type": DeviceType.SmartHub,
            "cmd": Command.IAmHere,
            "cmd_body": {
                "dev_name": self.dev_name
            }
        })
        requests.post(self.url, data=i_am_here)


def main():
    try:
        solution = Solution()
        solution.WHO_IS_HERE()
        solution.process()
    except Exception:
        exit(99)


if __name__ == '__main__':
    main()