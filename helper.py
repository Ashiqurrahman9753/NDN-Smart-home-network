from datetime import datetime, timezone

API_VERSION = 'v2'


def build_packet(packet_type, sender, destination, name, data):
    current_time_utc = datetime.now(timezone.utc)
    time_stamp = current_time_utc.isoformat()
    json_packet = {'type': packet_type,
                   'version': API_VERSION,
                   'sender': sender,
                   'destination': destination,
                   'time_stamp': time_stamp,
                   'name': name,
                   'data': data}
    return json_packet

def build_broadcast_packet(packet_type, name, data, api_version):
    current_time_utc = datetime.now(timezone.utc)
    time_stamp = current_time_utc.isoformat()
    
    json_packet = {'type': packet_type,
                   'version': api_version,
                   #'sender': sender,
                   #'destination': destination,
                   'timestamp': time_stamp,
                   'name': name,
                   'data': data}
    
    return json_packet


#def build_broadcast_packet(packet_type, status, node_name, peer_port, public_key_pem, sensor_type):
#    json_packet = {'type': packet_type,
#                   'version': API_VERSION,
#                   'status': status,
#                   'node_name': node_name,
#                   'peer_port': peer_port,
#                   'public_key_pem': public_key_pem,
#                   'sensor_types': sensor_type
#
#                   }
#    return json_packet


def decode_broadcast_packet(packet):
    return (packet['type'], packet['status'], packet['node_name'],
            int(packet['peer_port']), packet['public_key_pem'], packet['sensor_types'].split(','))


numerical_sensor_list = ['temperature', 'light', 'humidity', 'radiation', 'co2', 'smoke',
                         'rpm', 'duration', 'load', 'electricity_usage', 'water_usage']
binary_sensor_list = ['light_switch', 'motion', 'motor', 'lock']


def get_sensor_type(name):
    return name.split('/')[-1]


def decode_command(name, data):
    actuator = name.split('/')[-1]
    command = data.split('/')[-1]
    return actuator, command


def is_alertable(name, data):
    sensor_type = name.split('/').pop()
    if sensor_type in numerical_sensor_list:
        if int(data) > 10:
            return True
    elif sensor_type in binary_sensor_list:
        if data:
            return True
    else:
        return False
