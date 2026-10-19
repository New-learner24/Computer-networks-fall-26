import argparse
import heapq
import random
import zlib
import time


class TransferSimulation:
    def __init__(self, args):
        self.protocol = args.protocol
        self.packet_count = args.packets
        self.window = args.window
        self.modulus = 2 ** args.bits
        self.loss = args.loss
        self.corruption = args.corruption
        self.delay = args.delay
        self.timeout = args.timeout
        self.seed = args.seed
        self.rng = random.Random(self.seed)
        self.time = 0.0
        self.events = []
        self.event_id = 0
        self.base = 0
        self.next_packet = 0
        self.expected = 0
        self.receive_base = 0
        self.buffer = set()
        self.delivered = set()
        self.acked = set()
        self.outstanding = set()
        self.timer_tokens = {}
        self.gbn_token = 0
        self.transmissions = 0
        self.retransmissions = 0

    def log(self, message):
        print(f"[{self.time:7.3f}] {message}")

    def schedule(self, when, kind, data):
        self.event_id += 1
        heapq.heappush(self.events, (when, self.event_id, kind, data))

    def checksum(self, seq, packet_id):
        return zlib.crc32(f"{seq}:{packet_id}".encode())

    def channel(self, kind, packet_id):
        seq = packet_id % self.modulus
        checksum = self.checksum(seq, packet_id)
        if self.rng.random() < self.loss:
            self.log(f"{kind} {packet_id} lost")
            return
        valid = self.rng.random() >= self.corruption
        if not valid:
            self.log(f"{kind} {packet_id} corrupted (checksum error)")
        extra = self.rng.uniform(0.1, self.timeout * 2) if self.rng.random() < self.delay else 0
        event_kind = "data" if kind == "DATA" else "ack"
        self.schedule(self.time + 0.25 + extra, event_kind, (packet_id, seq, checksum, valid))

    def send_data(self, packet_id, retry=False):
        self.transmissions += 1
        if retry:
            self.retransmissions += 1
            self.log(f"Retransmit pkt {packet_id}")
        else:
            self.log(f"Send pkt {packet_id} (seq {packet_id % self.modulus})")
        self.channel("DATA", packet_id)

    def send_ack(self, packet_id):
        self.log(f"Send ACK {packet_id}")
        self.channel("ACK", packet_id)

    def deliver(self, packet_id):
        if packet_id not in self.delivered:
            self.delivered.add(packet_id)
            self.log(f"Deliver pkt {packet_id}")

    def valid_event(self, data):
        packet_id, seq, checksum, valid = data
        return valid and seq == packet_id % self.modulus and checksum == self.checksum(seq, packet_id)

    def start_gbn_timer(self):
        if self.base < self.next_packet:
            self.gbn_token += 1
            self.schedule(self.time + self.timeout, "gbn_timeout", (self.base, self.gbn_token))

    def start_sr_timer(self, packet_id):
        token = self.timer_tokens.get(packet_id, 0) + 1
        self.timer_tokens[packet_id] = token
        self.schedule(self.time + self.timeout, "sr_timeout", (packet_id, token))

    def handle_data(self, data):
        packet_id, seq, _, _ = data
        if not self.valid_event(data):
            self.log(f"Discard pkt {packet_id}: checksum error")
            return
        self.log(f"Receive pkt {packet_id} (seq {seq})")
        if self.protocol == "gbn":
            if packet_id == self.expected:
                self.deliver(packet_id)
                self.expected += 1
            else:
                self.log(f"Discard pkt {packet_id}; expecting {self.expected}")
            self.send_ack(self.expected - 1)
        elif packet_id < self.receive_base:
            self.send_ack(packet_id)
        elif self.receive_base <= packet_id < self.receive_base + self.window:
            if packet_id not in self.buffer:
                self.buffer.add(packet_id)
                self.log(f"Buffer pkt {packet_id}")
            self.send_ack(packet_id)
            while self.receive_base in self.buffer:
                self.buffer.remove(self.receive_base)
                self.deliver(self.receive_base)
                self.receive_base += 1

    def handle_ack(self, data):
        ack_id, _, _, _ = data
        if not self.valid_event(data):
            self.log(f"Discard ACK {ack_id}: checksum error")
            return
        self.log(f"Receive ACK {ack_id}")
        if self.protocol == "gbn":
            if self.base <= ack_id < self.next_packet:
                self.base = ack_id + 1
                self.start_gbn_timer()
        elif ack_id in self.outstanding:
            self.outstanding.remove(ack_id)
            self.acked.add(ack_id)
            self.timer_tokens[ack_id] = self.timer_tokens.get(ack_id, 0) + 1
            while self.base in self.acked:
                self.acked.remove(self.base)
                self.base += 1

    def run(self):
        start_time = time.perf_counter()
        self.log(f"Start {self.protocol.upper()}: packets={self.packet_count}, window={self.window}, sequence space={self.modulus}, seed={self.seed}")
        while len(self.delivered) < self.packet_count:
            while self.next_packet < self.packet_count and self.next_packet < self.base + self.window:
                packet_id = self.next_packet
                self.next_packet += 1
                if self.protocol == "sr":
                    self.outstanding.add(packet_id)
                self.send_data(packet_id)
                if self.protocol == "gbn" and packet_id == self.base:
                    self.start_gbn_timer()
                elif self.protocol == "sr":
                    self.start_sr_timer(packet_id)

            if not self.events:
                self.log("Simulation stopped: no events remain before delivery completed")
                break
            self.time, _, kind, data = heapq.heappop(self.events)
            if kind == "data":
                self.handle_data(data)
            elif kind == "ack":
                self.handle_ack(data)
            elif kind == "gbn_timeout":
                timed_base, token = data
                if token == self.gbn_token and timed_base == self.base and self.base < self.next_packet:
                    self.log(f"Timeout for pkt {self.base}")
                    for packet_id in range(self.base, self.next_packet):
                        self.send_data(packet_id, retry=True)
                    self.start_gbn_timer()
            elif kind == "sr_timeout":
                packet_id, token = data
                if packet_id in self.outstanding and self.timer_tokens.get(packet_id) == token:
                    self.log(f"Timeout for pkt {packet_id}")
                    self.send_data(packet_id, retry=True)
                    self.start_sr_timer(packet_id)

        print("\nResults")
        print(f"Protocol: {self.protocol.upper()}")
        print(f"Packets delivered: {len(self.delivered)}/{self.packet_count}")
        print(f"Data transmissions: {self.transmissions}")
        print(f"Retransmissions: {self.retransmissions}")
        execution_time = time.perf_counter() - start_time
        print(f"Execution time: {execution_time:.6f} seconds")


def main():
    parser = argparse.ArgumentParser(description="Simulate Go-Back-N and Selective Repeat")
    parser.add_argument("--protocol", choices=["gbn", "sr"], required=True)
    parser.add_argument("--packets", type=int, default=10)
    parser.add_argument("--window", type=int, default=4)
    parser.add_argument("--bits", type=int, default=3)
    parser.add_argument("--loss", type=float, default=0.0)
    parser.add_argument("--corruption", type=float, default=0.0)
    parser.add_argument("--delay", type=float, default=0.0)
    parser.add_argument("--timeout", type=float, default=1.0)
    parser.add_argument("--seed", type=int, required=True)
    args = parser.parse_args()

    if args.packets < 1 or args.window < 1 or args.bits < 1:
        parser.error("packets, window, and bits must be positive")
    if args.timeout <= 0:
        parser.error("timeout must be greater than zero")
    if any(p < 0 or p >= 1 for p in (args.loss, args.corruption, args.delay)):
        parser.error("probabilities must be at least 0 and less than 1")
    sequence_space = 2 ** args.bits
    if args.protocol == "gbn" and args.window >= sequence_space:
        parser.error("GBN window must be smaller than 2^bits")
    if args.protocol == "sr" and args.window > sequence_space // 2:
        parser.error("SR window must be at most half the sequence space")

    TransferSimulation(args).run()


main()
