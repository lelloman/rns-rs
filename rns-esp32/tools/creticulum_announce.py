#!/usr/bin/env python3
"""LoRa announce interop between rns-esp32 and creticulum's ESP32 node.

One board runs a console test build of rns-esp32 on creticulum's channel,
announcing on its own:

  ESP_IDF_SDKCONFIG_DEFAULTS="sdkconfig.defaults;sdkconfig.console" \\
  RNS_ESP32_LORA_FREQUENCY=869525000 RNS_ESP32_LORA_SF=7 \\
  RNS_ESP32_LORA_TXPOWER=2 RNS_ESP32_ANNOUNCE_INTERVAL=30 \\
  cargo build --features firmware --target xtensa-esp32s3-espidf --release

the other creticulum's ports/esp-idf/lora-node (869.525 MHz, 125 kHz, SF7,
CR 4/5). This only reads both serial ports, after resetting the boards.

Usage: creticulum_announce.py --rns DEVICE --creticulum DEVICE [--timeout 120]

Passes when rns-esp32 has validated creticulum's announce and creticulum has
verified rns-esp32's. Prints one JSON line per event; exits 0 on success.
"""
import argparse, json, re, sys, threading, time

import serial

a = argparse.ArgumentParser()
a.add_argument('--rns', required=True, help='serial device of the rns-esp32 board')
a.add_argument('--creticulum', required=True, help='serial device of the creticulum board')
a.add_argument('--timeout', type=float, default=120)
o = a.parse_args()
T0 = time.monotonic()
DEADLINE = T0 + o.timeout
ANSI = re.compile(r'\x1b\[[0-9;]*m')

state = {'rns_sent': set(), 'rns_heard': set(), 'ct_dest': None, 'ct_heard': set()}
lock = threading.Lock()


def ev(**kw):
    kw['t'] = round(time.monotonic() - T0, 3)
    print(json.dumps(kw), flush=True)


def reader(device, side, handle):
    s = serial.Serial(device, 115200, timeout=1)
    # Reset into the application, so its first announce is seen.
    s.dtr = False
    s.rts = True
    time.sleep(0.1)
    s.rts = False
    while time.monotonic() < DEADLINE:
        line = ANSI.sub('', s.readline().decode(errors='replace')).strip()
        if line:
            handle(line)


def rns_line(line):
    m = re.search(r'Announce broadcast for dest=([0-9a-f]{32})', line)
    if m:
        ev(side='rns-esp32', event='announced', destination=m.group(1))
        with lock:
            state['rns_sent'].add(m.group(1))
    m = re.search(r'Announce received: dest=([0-9a-f]{32}) hops=(\d+)', line)
    if m:
        ev(side='rns-esp32', event='validated', destination=m.group(1), hops=int(m.group(2)))
        with lock:
            state['rns_heard'].add(m.group(1))


def creticulum_line(line):
    if not line.startswith('CT_'):
        return
    ev(side='creticulum', line=line)
    m = re.match(r'CT_NODE identity=[0-9a-f]{32} destination=([0-9a-f]{32})', line)
    if m:
        with lock:
            state['ct_dest'] = m.group(1)
    m = re.match(r'CT_RX announce destination=([0-9a-f]{32})', line)
    if m:
        with lock:
            state['ct_heard'].add(m.group(1))


for device, side, handle in [(o.rns, 'rns-esp32', rns_line), (o.creticulum, 'creticulum', creticulum_line)]:
    threading.Thread(target=reader, args=(device, side, handle), daemon=True).start()

while time.monotonic() < DEADLINE:
    with lock:
        rns_heard_ct = state['ct_dest'] is not None and state['ct_dest'] in state['rns_heard']
        ct_heard_rns = bool(state['rns_sent'] & state['ct_heard'])
    if rns_heard_ct and ct_heard_rns:
        ev(event='pass')
        sys.exit(0)
    time.sleep(0.5)

with lock:
    ev(event='fail', rns_announced=sorted(state['rns_sent']), rns_validated=sorted(state['rns_heard']),
       creticulum_destination=state['ct_dest'], creticulum_verified=sorted(state['ct_heard']))
sys.exit(1)
