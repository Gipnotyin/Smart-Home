import sys
from dataclasses import dataclass
from enum import Enum
from typing import Any, Union

import requests
import base64
from functools import reduce

BROADCAST = 0x3FFF


class DeviceType(Enum):
    SmartHub = 0x01  # this
    EnvSensor = 0x02  # датчик
    Switch = 0x03  # переключатель
    Lamp = 0x04  # лампа
    Socket = 0x05  # розетка;
    Clock = 0x06  # часы


class Command(Enum):
    WhoIsHere = 0x01
    IAmHere = 0x02
    GetStatus = 0x03
    Status = 0x04
    SetStatus = 0x05
    Tick = 0x06


@dataclass
class DeviceTypeBody:
    dev_type: DeviceType
    dev_name: str
    dev_props: Union[None, list[str], Any]


@dataclass
class Lamp:
    name: str
    address: int
    status: int


@dataclass
class Switch:
    name: str
    address: int
    status: int
    devices: list[str]


@dataclass
class Payload:
    src: int
    dst: int
    dev_type: DeviceType
    cmd: Command
    cmd_body: Union[None, DeviceTypeBody, bytes]
    serial: int = 0


@dataclass
class Packet:
    length: int
    payload: Payload
    crc8: int


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


def read_string(data: bytes, offset: int):
    length = data[offset]
    offset += 1
    return bytes.decode(data[offset:offset + length]), offset + length


def decode_packet(data) -> list[Payload]:
    data = decode_base64(data)
    offset = 0
    packets = []
    while offset < len(data):
        packet_size, offset = read_uleb128(data, offset)
        packet_offset = offset
        crc = data[offset + packet_size]
        offset += packet_size + 1
        if crc != crc8(data[packet_offset:packet_offset + packet_size]):
            continue

        src, packet_offset = read_uleb128(data, packet_offset)
        dst, packet_offset = read_uleb128(data, packet_offset)
        serial, packet_offset = read_uleb128(data, packet_offset)
        dev_type = DeviceType(data[packet_offset])
        packet_offset += 1
        cmd = Command(data[packet_offset])
        packet_offset += 1
        try:
            cmd_body = cmd_body_parse(dev_type, cmd, data, packet_offset)
        except NotImplementedError as e:
            cmd_body = None

        # Формируем декодированный пакет
        packets.append(Payload(
            src=src,
            dst=dst,
            serial=serial,
            dev_type=dev_type,
            cmd=cmd,
            cmd_body=cmd_body
        ))
    return packets


def cmd_body_parse(dev_type: DeviceType, cmd: Command, data: bytes, offset: int) -> Union[None, DeviceTypeBody, int]:
    if dev_type == DeviceType.Clock:
        if cmd == Command.WhoIsHere:
            return dev_type_body_parse(dev_type, data, offset)
        elif cmd == Command.IAmHere:
            return dev_type_body_parse(dev_type, data, offset)
        elif cmd == Command.Tick:
            return read_uleb128(data, offset)[0]
    elif dev_type == DeviceType.Lamp:
        if cmd == Command.IAmHere:
            return dev_type_body_parse(dev_type, data, offset)
        elif cmd == Command.Status:
            return data[offset]
        else:
            raise NotImplementedError(dev_type, cmd)
    elif dev_type == DeviceType.Switch:
        if cmd == Command.IAmHere:
            return dev_type_body_parse(dev_type, data, offset)
        elif cmd == Command.Status:
            return data[offset]
        else:
            raise NotImplementedError(dev_type, cmd)
    else:
        raise NotImplementedError(dev_type, cmd)


def dev_type_body_parse(dev_type: DeviceType, data: bytes, offset: int):
    if dev_type in [DeviceType.SmartHub, DeviceType.Clock, DeviceType.Lamp]:
        return DeviceTypeBody(dev_type=dev_type, dev_name=read_string(data, offset)[0], dev_props=None)
    elif dev_type == DeviceType.Switch:
        dev_name, offset = read_string(data, offset)
        length = data[offset]
        offset += 1
        dev_props = []
        for _ in range(length):
            name, offset = read_uleb128(data, offset)
            dev_props.append(name)
        return DeviceTypeBody(dev_type=dev_type, dev_name=dev_name, dev_props=dev_props)
    else:
        raise NotImplementedError(dev_type)


def read_uleb128(data: bytes, offset: int):
    result = 0
    shift = 0
    while True:
        result |= (data[offset] & 0x7F) << shift
        if data[offset] & 0x80 == 0:
            break
        offset += 1
        shift += 7
    return result, offset + 1


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


def encode_packet(payload: Payload):
    payload = \
        [
            *encode_uleb128(payload.src),
            *encode_uleb128(payload.dst),
            *encode_uleb128(payload.serial),
            payload.dev_type.value,
            payload.cmd.value,
            *cmd_body_dump(payload.cmd_body),
        ]
    pack = lambda payload: [len(payload), *payload, crc8(payload)]
    b64encode = lambda payload: base64.urlsafe_b64encode(bytearray(pack(payload))).decode('ascii').rstrip('=')

    return b64encode(payload)


def cmd_body_dump(cmd_body: Union[None, DeviceTypeBody, Any]):
    if cmd_body is None:
        return bytes()
    elif type(cmd_body) == bytes:
        return cmd_body
    elif type(cmd_body) in [DeviceTypeBody]:
        return dev_type_body_dump(cmd_body)
    else:
        raise NotImplementedError(type(cmd_body))


def dev_type_body_dump(dev_type_body: DeviceTypeBody):
    if dev_type_body.dev_props is None:
        result = bytearray()
        result.append(len(dev_type_body.dev_name))
        for c in dev_type_body.dev_name:
            result.append(ord(c))
        return bytes(result)


class SmartHub:
    def __init__(self, url, address, name):
        self.url = url
        self.address = int(address, base=16)
        self.name = name
        self.serial = 0
        self.lamps = {}
        self.switches = {}
        self.local_time = 0

    def send(self, payload: Payload) -> list[Payload]:
        self.serial += 1
        payload.serial = self.serial
        r = requests.post(self.url, data=encode_packet(payload))
        if r.status_code not in [200, 204]:
            exit(99)
        if r.status_code == 204:
            exit(0)

        return self.remove_ticks(decode_packet(r.text))

    def remove_ticks(self, payloads):
        cleared = []
        for p in payloads:
            if p.cmd == Command.Tick:
                self.local_time = p.cmd_body
            else:
                cleared.append(p)
        return cleared

    def update(self):
        whoishere = Payload(
            src=self.address,
            dst=BROADCAST,
            dev_type=DeviceType.SmartHub,
            cmd=Command.WhoIsHere,
            cmd_body=DeviceTypeBody(
                dev_type=DeviceType.SmartHub,
                dev_name=self.name,
                dev_props=None
            )
        )
        payloads = self.send(whoishere)
        for p in payloads:
            if p.cmd == Command.IAmHere:
                if p.dev_type == DeviceType.Lamp:
                    self.lamps[p.cmd_body.dev_name] = Lamp(name=p.cmd_body.dev_name, address=p.src, status=0)
                elif p.dev_type == DeviceType.Switch:
                    self.switches[p.cmd_body.dev_name] = Switch(name=p.cmd_body.dev_name, address=p.src, status=0, devices=p.cmd_body.dev_props)
        self.update_devices()

    def update_devices(self):
        for name, switch in self.switches.items():
            getstatus = Payload(
                src=self.address,
                dst=switch.address,
                dev_type=DeviceType.SmartHub,
                cmd=Command.GetStatus,
                cmd_body=None
            )
            response = self.send(getstatus)
            response = self.send(getstatus)
            status = None
            for r in response:
                if r.src == switch.address and r.cmd == Command.Status:
                    status = r.cmd_body
            if status is not None:
                switch.status = status

        for name, lamp in self.lamps.items():
            getstatus = Payload(
                src=self.address,
                dst=lamp.address,
                dev_type=DeviceType.SmartHub,
                cmd=Command.GetStatus,
                cmd_body=None
            )
            response = self.send(getstatus)
            response = self.send(getstatus)
            status = None
            for r in response:
                if r.src == lamp.address and r.cmd == Command.Status:
                    status = r.cmd_body
            if status is not None:
                lamp.status = status

        for switch in self.switches.values():
            for device in switch.devices:
                if device in self.lamps and self.lamps[device].status != switch.status:
                    self.lamps[device].status = switch.status
                    setstatus = Payload(
                        src=self.address,
                        dst=self.lamps[device].address,
                        dev_type=DeviceType.SmartHub,
                        cmd=Command.SetStatus,
                        cmd_body=None
                    )
                    response = self.send(setstatus)
                    response = self.send(setstatus)


def main():
    hub = SmartHub(sys.argv[1], sys.argv[2], 'SmartHub')
    while True:
        hub.update()


if __name__ == '__main__':
    try:
        main()
    except Exception as ex:
        exit(99)

