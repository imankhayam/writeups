import struct


def binary_sid_to_string(hex_string):
    # Remove possible b'' and decode hex
    if isinstance(hex_string, bytes):
        data = hex_string
    else:
        data = bytes.fromhex(hex_string)

    # Parse revision and sub-authority count
    revision, subauth_count = data[0], data[1]

    # Identifier authority (6 bytes, big-endian)
    identifier_authority = int.from_bytes(data[2:8], "big")

    # Each sub-authority is 4 bytes, little-endian
    subauths = [
        struct.unpack("<I", data[8 + i * 4 : 12 + i * 4])[0]
        for i in range(subauth_count)
    ]

    # Build SID string
    sid = f"S-{revision}-{identifier_authority}-" + "-".join(str(sa) for sa in subauths)
    return sid


binary_hex = "0105000000000005150000005b7bb0f398aa2245ad4a1ca44f040000"
print(binary_sid_to_string(binary_hex))
