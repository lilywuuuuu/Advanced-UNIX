from pwn import *

url = "ipinfo.io"
r = remote(url, 80)

# Send an HTTP GET request
r.sendline(b"GET /ip HTTP/1.1")
r.sendline(b"Host: " + url.encode())
r.sendline(b"User-Agent: curl/7.88.1")
r.sendline(b"Accept: */*")
r.sendline(b"Connection: close")
r.sendline(b"\r\n")

# Receive the response
response = r.recvall()

# Close the connection
r.close()

# Extract IP address from the response
ip_address = response.decode().strip()
print(ip_address)