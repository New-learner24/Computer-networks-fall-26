import socket
import struct
import random

def encode_domain(domain):
    # DNS stores each part of the domain with its length before it
    parts = domain.split('.')
    encoded = b''
    for part in parts:
        encoded += struct.pack('B', len(part))
        encoded += part.encode()
    encoded += b'\x00'
    return encoded

def decode_domain(data, offset):
    # Decode a domain name and handle DNS compression pointers
    labels = []
    original_offset = offset
    jumped = False

    while True:
        if offset >= len(data):
            raise ValueError("Malformed DNS response.")

        length = data[offset]

        if length == 0:
            offset += 1
            break

        # DNS compression pointer starts with two bits set to 1
        if (length & 0xC0) == 0xC0:
            if offset+1 >= len(data):
                raise ValueError("Malformed DNS compression pointer.")
            pointer=((length & 0x3F)<<8) | data[offset+1]
            if pointer >= len(data):
                raise ValueError("Invalid DNS compression pointer.")
            if not jumped:
                original_offset = offset+2
            offset = pointer
            jumped = True
            continue
        offset += 1
        if offset + length > len(data):
            raise ValueError("Malformed domain name.")
        labels.append(data[offset:offset + length].decode())
        offset += length
    if jumped:
        return '.'.join(labels), original_offset
    return '.'.join(labels), offset

def build_query(domain):
    # Generate a random transaction ID so the response can be matched
    transaction_id = random.randint(0, 65535)
    # RD (Recursion Desired) flag is set
    flags = 0x0100
    # One question and no answers in the request
    qdcount = 1
    ancount = 0
    nscount = 0
    arcount = 0
    # DNS header is 12 bytes
    header = struct.pack(
        '!HHHHHH',
        transaction_id,
        flags,
        qdcount,
        ancount,
        nscount,
        arcount
    )
    # Create the question for an A record
    question = encode_domain(domain)
    # QTYPE = 1 means A record
    # QCLASS = 1 means Internet
    question += struct.pack('!HH', 1, 1)
    return header + question, transaction_id
def parse_response(data, expected_transaction_id):
    if len(data) < 12:
        raise ValueError("Malformed DNS response: header is incomplete.")
    # Extract the DNS header
    transaction_id, flags, qdcount, ancount, nscount, arcount = struct.unpack(
        '!HHHHHH',
        data[:12]
    )
    # Make sure the response belongs to our query
    if transaction_id != expected_transaction_id:
        raise ValueError("Transaction ID does not match.")
    # Extract relevant DNS flags
    qr = (flags >> 15) & 1
    aa = (flags >> 10) & 1
    tc = (flags >> 9) & 1
    rd = (flags >> 8) & 1
    ra = (flags >> 7) & 1
    rcode = flags & 0x0F
    status_codes = {
        0: "NOERROR",
        1: "FORMERR",
        2: "SERVFAIL",
        3: "NXDOMAIN",
        4: "NOTIMP",
        5: "REFUSED"
    }
    status = status_codes.get(rcode, f"UNKNOWN ({rcode})")
    print("\nTransaction ID:", transaction_id)
    print("Response:", "Response" if qr else "Query")
    print("Authoritative Answer:", aa)
    print("Truncated:", tc)
    print("Recursion Desired:", rd)
    print("Recursion Available:", ra)
    print("Response Status:", status)
    offset = 12
    # Parse the Question section
    for _ in range(qdcount):
        query_name, offset = decode_domain(data, offset)
        if offset + 4 > len(data):
            raise ValueError("Malformed question section.")
        qtype, qclass = struct.unpack(
            '!HH',
            data[offset:offset + 4]
        )
        offset += 4
        print("\nQuery Name:", query_name)
        print("Query Type:", "A" if qtype == 1 else qtype)
        print("Query Class:", qclass)
    # Parse the Answer section
    answers_found = False
    for i in range(ancount):
        answer_name, offset = decode_domain(data, offset)
        if offset + 10 > len(data):
            raise ValueError("Malformed answer record.")
        # Resource record contains:
        # TYPE (2), CLASS (2), TTL (4), RDLENGTH (2)
        rtype, rclass, ttl, rdlength = struct.unpack(
            '!HHIH',
            data[offset:offset + 10]
        )
        offset += 10
        if offset + rdlength > len(data):
            raise ValueError("Malformed resource record data.")
        rdata = data[offset:offset + rdlength]
        offset += rdlength
        print(f"\nAnswer Record {i + 1}:")
        print("Name:", answer_name)
        print("Type:", "A" if rtype == 1 else rtype)
        print("TTL:", ttl)
        # An A record contains a 4-byte IPv4 address
        if rtype == 1 and rdlength == 4:
            ip_address = socket.inet_ntoa(rdata)
            print("IPv4 Address:", ip_address)
            answers_found = True

    if not answers_found:
        if status == "NXDOMAIN":
            print("\nNo such domain exists.")
        elif status != "NOERROR":
            print("\nDNS query was unsuccessful.")
        else:
            print("\nNo A record was found.")


def dns_lookup(domain, dns_server):
    query, transaction_id = build_query(domain)

    # Create a UDP socket and set a timeout
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(5)

    try:
        print("\nDNS Server:", dns_server)
        print("Domain:", domain)

        # Send the DNS query to port 53
        sock.sendto(query, (dns_server, 53))

        # Receive the raw DNS response
        response, server_address = sock.recvfrom(4096)

        print("Response received from:", server_address[0])

        parse_response(response, transaction_id)

    except socket.timeout:
        print("\nError: DNS request timed out.")

    except ValueError as e:
        print("\nError:", e)

    except OSError as e:
        print("\nNetwork error:", e)

    except Exception as e:
        print("\nUnexpected error:", e)

    finally:
        sock.close()


def main():
    print("***** BASIC DNS QUERY PROGRAM *****")

    dns_server = input("Enter DNS server IP: ").strip()

    while True:
        domain = input(
            "\nEnter domain name or type 'e' to quit!): "
        ).strip()

        if domain.lower() == "e":
            print("\nProgram terminated successfully!")
            break

        if not domain:
            print("Error: Domain name cannot be empty.")
            continue

        dns_lookup(domain, dns_server)


if __name__ == "__main__":
    main()