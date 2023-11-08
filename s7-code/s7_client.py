import snap7
from snap7.types import Areas
client = snap7.client.Client()
# client.connect("193.70.114.151", 0, 0, 102)
client.connect("127.0.0.1", 0, 0, 102)

def strip_bytes(data, byte_to_strip):
    start = 0
    end = len(data)

    while start < end and data[start] == byte_to_strip:
        start += 1

    while end > start and data[end - 1] == byte_to_strip:
        end -= 1

    return data[start:end]

def szl_list(client):
    response = client.read_szl_list()
    # Split the response into individual SZL data
    szl_data = response[8:]  # Exclude the first 8 bytes, which are the header

    # Process each SZL and its version
    szl_info = {}
    current_szl = None

    for byte in szl_data:
        if current_szl is None:
            current_szl = byte
        else:
            version = byte
            szl_info[current_szl] = version
            current_szl = None

    # Print the information about SZLs and their versions
    for szl, version in szl_info.items():
        print(f'SZL {szl}: Version {version}')

def szl(client, szl_num, index):
    response = client.read_szl(szl_num,index)
    print(response)
    length_dr = response.Header.LengthDR
    number_dr = response.Header.NDR
    szl_data = bytearray(response.Data)
    print("""
          SZL %s Index %s
          Header Length %s
          Number %s
          Data %s
          """ % (szl_num, index, length_dr, number_dr, strip_bytes(szl_data,0x00)))

print(client.get_connected())
print(client.get_cpu_info())
print(client.get_cpu_state())
# print(client.db_read(0,0,8))
# print(client.read_szl_list())

# szl_list(client)
szl(client,0x0011,0x0000)
szl(client,0x001c,0x0000)

print(client.read_area(Areas.DB, 0, 100, 30))

