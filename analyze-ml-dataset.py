import os

import numpy as np
import pandas as pd

csv_path = "data/dataset/Edge-IIoTset dataset/Selected dataset for ML and DL/DNN-EdgeIIoT-dataset.csv"
df = pd.read_csv(csv_path, low_memory=False)
used_columns = [
    'arp.opcode', 'arp.hw.size', 'icmp.checksum', 'icmp.seq_le', 'icmp.transmit_timestamp',
    'icmp.unused', 'http.content_length', 'http.response', 'http.tls_port', 'tcp.ack',
    'tcp.ack_raw', 'tcp.checksum', 'tcp.connection.fin', 'tcp.connection.rst',
    'tcp.connection.syn', 'tcp.connection.synack', 'tcp.dstport', 'tcp.flags',
    'tcp.flags.ack', 'tcp.len', 'tcp.seq', 'udp.port', 'udp.stream', 'udp.time_delta',
    'dns.qry.name', 'dns.qry.qu', 'dns.qry.type', 'dns.retransmission',
    'dns.retransmit_request', 'dns.retransmit_request_in', 'mqtt.conflag.cleansess',
    'mqtt.conflags', 'mqtt.hdrflags', 'mqtt.len', 'mqtt.msg_decoded_as', 'mqtt.msgtype',
    'mqtt.proto_len', 'mqtt.topic_len', 'mqtt.ver', 'mbtcp.len', 'mbtcp.trans_id', 'mbtcp.unit_id'
]
print(df[used_columns].describe())

