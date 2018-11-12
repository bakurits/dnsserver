from struct import pack

def ip_to_string(data: bytes):
    res = ""
    for octet in data:
        res += str(octet) + "."
    return res[: -1]

def get_labels_from_string(data:bytes):
    labels = data.split(b".")
    new_name = bytearray()
    for label in labels:
        new_name += pack("!b", len(label)) + label
    if new_name[-1:][0] != 0:
        new_name += bytes(0)
    return bytes(new_name)

def to_lower(data: bytes):
    return data.decode("ascii").lower().encode("ascii")
