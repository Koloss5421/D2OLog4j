import socket

try:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("0.0.0.0", 80))

    socket_address =sock.getsockname()
    print("[+] Socket launched on socket: %s" %str(socket_address))
    while True:
        sock.listen(True)
        conn, addr = sock.accept()
        with conn:
            print(f"[!] Host Connected {addr}")
            conn.close()
except KeyboardInterrupt:
    sock.close()
    print("\nKeyboardInterrupt Detected.")
    print("Exiting...")
    exit(0)

