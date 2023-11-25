# 设置发送数据的时间间隔，单位为秒

INTERVAL_SECONDS = 5

import base64
import json
import os
import random
import re
import socket
import threading
import time

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

from ECCManager import ECCManager
from helper import decode_broadcast_packet, build_broadcast_packet
from sensor import Sensor


class SendData:
    def __init__(self, node_name, port, broadcast_port):
        self.host = '0.0.0.0'
        self.port = port
        self.node_name = node_name
        self.broadcast_port = broadcast_port
        self.ecc_manager = ECCManager()
        self.public_key_pem = self.ecc_manager.get_public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')
        self.shared_secrets = {}
        self.fib = {}
        self.threads = []
        self.running = threading.Event()
        self.running.set()

    def start(self):
        broadcast_thread = threading.Thread(target=self.broadcast_presence)
        discovery_thread = threading.Thread(target=self.listen_for_peer_broadcasts)
        self.threads.extend([broadcast_thread, discovery_thread])
        for t in self.threads:
            t.start()

    def stop(self):
        self.broadcast_offline()
        self.running.clear()
        os._exit(0)

    def broadcast_presence(self):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

            while self.running:
                json_packet = build_broadcast_packet('discovery', 'online', self.node_name, self.port,
                                                     self.public_key_pem, ','.join([]))
                s.sendto(json.dumps(json_packet).encode('utf-8'), ('<broadcast>', self.broadcast_port))
                time.sleep(1)

    def broadcast_offline(self):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            json_packet = build_broadcast_packet('discovery', 'offline', self.node_name, self.port, self.public_key_pem,
                                                 ','.join([]))
            s.sendto(json.dumps(json_packet).encode('utf-8'), ('<broadcast>', self.broadcast_port))
        print('offline')

    def listen_for_peer_broadcasts(self):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
            s.bind((self.host, self.broadcast_port))
            while self.running:
                data, addr = s.recvfrom(1024)
                message = json.loads(data.decode())
                packet_type, status, node_name, peer_port, public_key_pem, sensor_types = decode_broadcast_packet(
                    message)
                if packet_type == 'discovery':
                    if peer_port != self.port:
                        if status == "online":
                            peer = (addr[0], peer_port)
                            if node_name not in self.fib and not node_name.__contains__('phone'):
                                print(f"Discovered peer {node_name}")
                                self.fib[node_name] = peer
                                peer_public_key = serialization.load_pem_public_key(
                                    public_key_pem.encode('utf-8'),
                                    backend=default_backend()
                                )
                                shared_secret = self.ecc_manager.generate_shared_secret(peer_public_key)
                                self.shared_secrets[node_name] = shared_secret
                        elif status == "offline":
                            if node_name in self.fib:
                                del self.fib[node_name]
                                del self.shared_secrets[node_name]
                                for sensor in sensor_types:
                                    print(f'Removed sensor {sensor}')
                                print(f"Peer {node_name} went offline")

    def send_packet(self, peer_node_name, json_packet):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            try:
                peer = self.fib.get(peer_node_name)
                s.connect(peer)
                key = self.shared_secrets[peer_node_name]
                encrypted_data = self.ecc_manager.encrypt_data(key, json_packet['data'].encode('utf-8'))
                # 将加密后的字节串转换为Base64编码的字符串
                json_packet['data'] = base64.b64encode(encrypted_data).decode('utf-8')
                # packet = self.ecc_manager.encrypt_data(key, json.dumps(json_packet).encode('utf-8'))
                packet = json.dumps(json_packet).encode('utf-8')
                s.sendall(packet)
                packet_type = json_packet['type']
                print(f"Sent {packet_type} '{json_packet['name']}' to {json_packet['destination']}")
            except ConnectionRefusedError:
                print(f"Failed to connect to {peer}")

    def send(self):
        # while True:  # 循环发送数据
        devices = [key for key in self.fib.keys()]
        destination_device = random.choice(devices)

        if re.compile(r'device').search(destination_device):
            sensor_type = random.choices(
                ['temperature', 'light', 'humidity', 'radiation', 'co2', 'co', 'motion', 'smoke'])
        else:
            sensor_type = random.choices(
                ['washer', 'lock', 'load', 'electricity_usage', 'water_usage', 'rpm', 'temperature',
                 'duration'])

        sensor_data = str(Sensor.generators.get(sensor_type[0], lambda: None)())

        data = {'type': 'data',
                'version': 'v1',
                'sender': '/house/room/auto_sender',
                'destination': destination_device,
                'time_stamp': time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                'name': f'/house/room/auto_sender/{sensor_type[0]}',
                'data': sensor_data}
        self.send_packet(destination_device, data)
        # time.sleep(10)


def main():
    node_name = '/house/room/auto_sender'
    port = 8003
    broadcast_port = 33000

    node = SendData(node_name, port, broadcast_port)
    node.start()
    time.sleep(10)
    node.send()


if __name__ == "__main__":
    main()
