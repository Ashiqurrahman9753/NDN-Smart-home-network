#!/usr/bin/env python3

import random


class Sensor:
    # Map sensor types to random value generator functions
    generators = {
        'temperature': lambda: random.randint(0, 25),
        'light': lambda: random.randint(0, 25),
        'humidity': lambda: random.randint(0, 25),
        'radiation': lambda: random.randint(0, 25),
        'co2': lambda: random.randint(0, 25),
        'smoke': lambda: random.randint(0, 25),
        'rpm': lambda: random.randint(0, 25),
        'duration': lambda: random.randint(0, 25),
        'load': lambda: random.randint(0, 25),
        'electricity_usage': lambda: random.randint(0, 25),
        'water_usage': lambda: random.randint(0, 25),
        'light_switch': lambda: random.choice([True, False]),
        'motion': lambda: random.choice([True, False]),
        'motor': lambda: random.choice([True, False]),
        'lock': lambda: random.choice([True, False])

    }
