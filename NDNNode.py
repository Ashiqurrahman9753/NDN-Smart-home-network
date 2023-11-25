import base64
import json
import logging
import os
import re
import socket
import threading
import time

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

import fib
from ECCManager import ECCManager
from helper import build_packet, build_broadcast_packet, decode_command
from sensor import Sensor

API_VERSION = 'v2'


class NDNNode:
    def __init__(self, node_name, port, broadcast_port, sensor_type):

        # Logging verbosity
        logging.basicConfig(format="%(asctime)s.%(msecs)04d [%(levelname)s] %(message)s", level=logging.DEBUG,
                            datefmt="%H:%M:%S:%m")

        self.host = '0.0.0.0'
        self.port = port
        self.node_name = node_name
        self.broadcast_port = broadcast_port
        self.fib = fib.ForwardingInfoBase(self.node_name)  # Forwarding Information Base
        self.pit = {}  # Pending Interest Table
        self.cs = {}
        self.sensor_type = sensor_type

        # Create list of data name as <node_name>/<sensor_name>
        if not node_name.endswith('/'):
            node_name += '/'
        self.data_names = [node_name + s for s in sensor_type]
        logging.info(f"{self.node_name} is the source for: {self.data_names}")

        self.ecc_manager = ECCManager()
        self.public_key_pem = self.ecc_manager.get_public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')
        self.shared_secrets = {}
        self.threads = []
        self.running = threading.Event()
        self.running.set()

    def start(self):
        listener_thread = threading.Thread(target=self.listen_for_connections)
        broadcast_thread = threading.Thread(target=self.broadcast_presence)
        discovery_thread = threading.Thread(target=self.listen_for_peer_broadcasts)
        cs_clear_thread = threading.Thread(target=self.clear_content_store)
        self.threads.extend([listener_thread, broadcast_thread, discovery_thread, cs_clear_thread])
        for t in self.threads:
            t.start()

    def stop(self):
        self.broadcast_offline()
        self.running.clear()
        os._exit(0)

    def listen_for_connections(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind((self.host, self.port))
            s.listen()
            logging.info(f"{self.node_name} is listening for connections on port {self.port}")
            while self.running:
                s.getsockname()
                conn, addr = s.accept()
                threading.Thread(target=self.handle_connection, args=(conn, addr)).start()

    def broadcast_presence(self):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

            while self.running:
                json_packet = build_broadcast_packet(packet_type='discovery',
                                                     name=self.node_name,
                                                     data={'port': self.port,
                                                           'status': 'online',
                                                           'pub_key': self.public_key_pem,
                                                           'sensor_types': ','.join(self.sensor_type)},
                                                     api_version=API_VERSION
                                                     )
                s.sendto(json.dumps(json_packet).encode('utf-8'), ('<broadcast>', self.broadcast_port))
                time.sleep(1)

    def broadcast_offline(self):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            json_packet = build_broadcast_packet(packet_type='discovery',
                                                 name=self.node_name,
                                                 data={'port': self.port,
                                                       'status': 'offline',
                                                       'pub_key': self.public_key_pem,
                                                       'sensor_types': ','.join(self.sensor_type)},
                                                 api_version=API_VERSION
                                                 )
            s.sendto(json.dumps(json_packet).encode('utf-8'), ('<broadcast>', self.broadcast_port))
        logging.info(f"{self.node_name} went offline.")

    def broadcast_distance_vector(self):
        """
        Broadcast when distance vector changes

        """
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            json_packet = build_broadcast_packet(packet_type='routing',
                                                 name=self.node_name,
                                                 data={'port': self.port,
                                                       'vector': self.fib.get_distance_vector()},
                                                 api_version=API_VERSION
                                                 )
            logging.debug(f"{self.node_name} broadcasting distance vector on port {self.broadcast_port}")
            s.sendto(json.dumps(json_packet).encode('utf-8'), ('<broadcast>', self.broadcast_port))

    def listen_for_peer_broadcasts(self):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
            s.bind((self.host, self.broadcast_port))
            logging.info(f"{self.node_name} listening for broadcasts on {self.broadcast_port}")
            while self.running:
                data, addr = s.recvfrom(1024)
                message = json.loads(data.decode())
                packet_type = message['type']
                peer_port = message['data']['port']
                node_name = message['name']
                if peer_port != self.port:
                    if packet_type == 'discovery':
                        status = message['data']['status']

                        if status == "online":
                            if node_name not in self.fib:
                                logging.debug(f"{self.node_name} received broadcast: discovered peer {node_name}")
                                public_key_pem = message['data']['pub_key']
                                peer_addr = (addr[0], peer_port)
                                logging.debug(f"{self.node_name} adding peer {node_name} on {peer_addr} to FIB")
                                self.fib.add_entry(node_name, peer_addr)
                                logging.debug(
                                    f"{self.node_name} updated distance vector: {self.fib.get_distance_vector()}")
                                # Send distance vector updates to neighbours
                                self.broadcast_distance_vector()

                                peer_public_key = serialization.load_pem_public_key(
                                    public_key_pem.encode('utf-8'),
                                    backend=default_backend()
                                )
                                shared_secret = self.ecc_manager.generate_shared_secret(peer_public_key)
                                self.shared_secrets[node_name] = shared_secret

                        elif status == "offline":
                            logging.debug(f"{self.node_name} received broadcast: peer {node_name} went offline")
                            if node_name in self.fib:
                                logging.debug(f"{self.node_name} removing peer {node_name} from FIB")
                                self.fib.remove_entry(node_name)
                                logging.debug(
                                    f"{self.node_name} updated distance vector: {self.fib.get_distance_vector()}")
                                # Send distance vector updates to neighbours
                                self.broadcast_distance_vector()
                                del self.shared_secrets[node_name]

                    elif packet_type == 'routing':
                        logging.debug(f"{self.node_name} received broadcast: peer {node_name} updated distance vector")
                        if node_name in self.fib:
                            peer_vector = message["data"]["vector"]
                            logging.debug(f"{self.node_name} updating peer {node_name} in FIB")
                            dv_changed = self.fib.update_distance_vector(node_name, peer_vector)
                            logging.debug(f"{self.node_name} updated distance vector: {self.fib.get_distance_vector()}")
                            if dv_changed:
                                # Send distance vector updates to neighbours
                                self.broadcast_distance_vector()

    def handle_connection(self, conn, addr):
        with conn:
            try:
                data = conn.recv(1024)
                if data:
                    packet = json.loads(data.decode())
                    sender = packet['sender']
                    if sender in self.shared_secrets:
                        try:
                            # Decrypt data
                            encrypted_data = base64.b64decode(packet['data'])
                            key = self.shared_secrets[sender]
                            decrypted_data = self.ecc_manager.decrypt_data(key, encrypted_data)
                            packet['data'] = decrypted_data.decode('utf-8')
                        except Exception as e:
                            logging.error(f"Error decrypting data: {e}")

                        if packet['type'] == 'interest':
                            logging.debug(f"Received interest packet from {packet['sender']}")
                            self.handle_interest(packet, packet['sender'], addr)
                        elif packet['type'] == 'data':
                            logging.debug(f"Received data packet from {packet['sender']}")
                            self.handle_data(packet)
                        else:
                            logging.warning("Unknown packet type from {sender}. Discarding packet")
                    else:
                        logging.warning("Received packet with unknown encryption.")
            except ConnectionResetError:
                pass

    def handle_interest(self, interest_packet, requester, addr):
        name = interest_packet['name']

        # Check if data name prefix is this node's name
        if name[:name.rindex('/')] == self.node_name:
            if name in self.data_names:
                # Generate data if this is the source
                sensor = name[name.rindex('/') + 1:]
                data = str(Sensor.generators.get(sensor, lambda: None)())
                logging.info(f'Generated {name} for requester {requester}')
                json_packet = build_packet('data', self.node_name, requester, name, data)
                self.send_packet(requester, json_packet)
            else:
                json_packet = build_packet('data', self.node_name, requester, name,
                                           f'No data {name} available')
                self.send_packet(requester, json_packet)

        # Else check Content Store
        elif name in self.cs:
            data = self.cs.get(name)
            json_packet = build_packet('data', self.node_name, requester, name, data)
            self.send_packet(requester, json_packet)

        # Else check if there is an entry in FIB.
        # If so then forward, otherwise send NACK to requester
        else:
            addr_to_try = self.fib.get_routes(name)

            if addr_to_try:
                # Add interest to PIT
                if name not in self.pit:
                    self.pit[name] = set([(requester, addr)])
                else:
                    self.pit[name].add((requester, addr))

                logging.debug(f"{self.node_name} added interest in {name} to PIT")

                success = False
                for destination, dest_addr in addr_to_try:
                    json_packet = build_packet('interest', self.node_name, destination, name, '')
                    success = self.send_packet(destination, json_packet, dest_addr)

                    if success:
                        break

                if not success:
                    json_packet = build_packet('data', self.node_name, requester, name,
                                               f'No data {name} available')
                    self.send_packet(requester, json_packet, addr)

            else:
                json_packet = build_packet('data', self.node_name, requester, name,
                                           f'No data {name} available')
                self.send_packet(requester, json_packet, addr)

    def create_send_intrest_packet(self, data_name, destination):
        # Add interest to PIT
        if data_name not in self.pit:
            self.pit[data_name] = set([(self.node_name, None)])
        else:
            self.pit[data_name].add((self.node_name, None))

        json_packet = build_packet('interest', self.node_name, destination, data_name, '')
        # send interest to node according to fib
        self.send_packet(destination, json_packet)

    def handle_data(self, data_packet):
        name = data_packet['name']
        destination = data_packet['destination']
        data = str(data_packet['data'])
        # logging.debug(f"Recieved packet name: {name}, data: {data}")

        if name in self.pit or destination == self.node_name:

            # If this node is interested in the data or the intended recipient
            # then process the data
            if destination == self.node_name or self.node_name in self.pit[name]:
                if re.compile(r'command').search(data):
                    sensor_type = data_packet['name'].split('/').pop()
                    if sensor_type in self.sensor_type:
                        actuator, command = decode_command(name, data)
                        logging.info(f'{actuator.capitalize()} is turned {command}.')
                elif re.compile(r'alert').search(data):
                    if self.node_name.__contains__('phone'):
                        logging.info(f"Alert {name.split('/')[-1]} is set off.")
                else:
                    logging.info(f"Received data {name}: {data}")

            # If there is pending interest, forward the data and remove entry from PIT
            if name in self.pit:
                for requester, addr in self.pit[name]:
                    if requester != self.node_name:
                        logging.debug(f"Transmitting data packet from {data_packet['sender']} to {requester}")
                        self.send_packet(requester, data_packet, addr)

                # Pending interests satisfied => remove from PIT
                del self.pit[name]

            # Store in content store
            self.cs[name] = data
        logging.info(f"Received stray data packet {data_packet}")

    def send_packet(self, peer_node_name, json_packet, addr=None):
        success = False
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            try:
                if addr == None:
                    addr = self.fib.peer_list[peer_node_name]

                s.connect(addr)
                key = self.shared_secrets[peer_node_name]
                encrypted_data = self.ecc_manager.encrypt_data(key, json_packet['data'].encode('utf-8'))
                # logging.debug(f"Encrypting data {json_packet['data']}")
                # Convert encrypted byte string to Base64 encoded string
                json_packet['data'] = base64.b64encode(encrypted_data).decode('utf-8')
                # packet = self.ecc_manager.encrypt_data(key, json.dumps(json_packet).encode('utf-8'))
                packet = json.dumps(json_packet).encode('utf-8')
                s.sendall(packet)
                logging.debug(f"Sent {json_packet['type']} '{json_packet['name']}' to {json_packet['destination']}")
                success = True
            except Exception as err:
                logging.error(f"Error in send_packet() to {peer_node_name} {type(err).__name__}: {err}")
        return success

    def clear_content_store(self):
        while self.running:
            time.sleep(10)  # Wait for 10 seconds
            self.cs.clear()


def main():
    node_name = os.environ['NODE_NAME']
    port = int(os.environ['PORT'])
    broadcast_port = int(os.environ['BROADCAST_PORT'])
    sensor_type = os.environ['SENSOR_TYPE'].split(',')

    node = NDNNode(node_name, port, broadcast_port, sensor_type)
    node.start()
    try:
        while True:
            command = input(f'Node {node.node_name} - Enter command (interest/data/exit/add_fit): ').strip()
            if command == 'interest':
                destination = input('Enter destination node for interest packet: ').strip()
                sensor_name = input('Enter sensor name: ').strip()
                node.create_send_intrest_packet(f'{destination}/{sensor_name}', destination)
            elif command == 'data':
                destination = input('Enter destination node for data packet: ').strip()
                sensor_name = input('Enter sensor name: ').strip()
                data_content = input('Enter data content: ').strip()
                json_packet = build_packet('data', node.node_name, destination, f'{destination}/{sensor_name}',
                                           data_content)
                # send data to node with the same data name
                logging.debug("call send packet from main loop")
                node.send_packet(destination, json_packet)
            elif command == 'exit':
                node.stop()
            else:
                print('Invalid command. Try again.')
    except KeyboardInterrupt:
        node.stop()


if __name__ == "__main__":
    main()
