import struct
import sys


def calculate_pe_checksum(data, checksum_offset):
    """
    Python implementation of Window's CheckSum
    Reference: https://stackoverflow.com/questions/6429779/can-anyone-define-the-windows-pe-checksum-algorithm

    :param data: bytearray of the PE to calculate the CheckSum of
    :param checksum_offset: the offset of the CheckSum in the PE
    :return: the uint32 CheckSum value
    """

    checksum = 0
    top = 2**32

    for i in range(0, int(len(data)/4)):

        # Don't include the CheckSum of the PE in the calculation
        if i == int(checksum_offset/4):
            continue

        dword = struct.unpack("I", data[i * 4: (i * 4) + 4])[0]
        checksum = (checksum & 0xffffffff) + dword + (checksum >> 32)

        if checksum > top:
            checksum = (checksum & 0xffffffff) + (checksum >> 32)

    checksum = (checksum & 0xffff) + (checksum >> 16)
    checksum = checksum + (checksum >> 16)
    checksum = checksum & 0xffff

    checksum += len(data)
    return checksum


def get_checksum_offset(data):
    """
    Get the offset of the CheckSum in the loaded PE

    PE format reference: https://docs.microsoft.com/en-us/windows/win32/debug/pe-format

    :param data: bytearray of the PE
    :return: uint32 offset of the CheckSum
    """

    # 0x3c in is the PE header offset
    pe_header_offset = struct.unpack("I", data[0x3c : 0x3c + 4])[0]

    # 0x58 offset into the PE header is the CheckSum value
    return pe_header_offset + 0x58


def get_checksum(data, checksum_offset):
    """
    Utility function to retrieve the current PE CheckSum in the loaded PE

    :param data: bytearray of the PE
    :param checksum_offset: offset of the CheckSum in the loaded PE
    :return: uint32 CheckSum of the loaded PE
    """

    return struct.unpack("I", data[checksum_offset : checksum_offset + 4])[0]


if len(sys.argv) != 3:
    print("Usage: python pe_trimmer.py <PE_FILE> <OUTPUT_FILE>")
    sys.exit()

filename = sys.argv[1]
output_filename = sys.argv[2]

with open(filename, "rb") as infile:
    pe_data = bytearray(infile.read())

checksum_offset = get_checksum_offset(pe_data)
true_pe_checksum = get_checksum(pe_data, checksum_offset)

calculated_pe_checksum = calculate_pe_checksum(pe_data, checksum_offset)

print("True PE CheckSum:")
print(hex(true_pe_checksum))
print('')

print("Calculated PE CheckSum:")
print(hex(calculated_pe_checksum))
print('')

if true_pe_checksum == calculated_pe_checksum:
    print("The CheckSum of the input is already correct.")

else:
    print("The CheckSum of the PE does not match the calculated CheckSum.")
    print("Beginning to remove bytes...")
    print('')

    max_steps = len(pe_data) - (checksum_offset + 4)

    for i in range(1, max_steps):
        del(pe_data[-1])

        calculated_pe_checksum = calculate_pe_checksum(pe_data, checksum_offset)

        if true_pe_checksum == calculated_pe_checksum:
            iterations_done = i
            break

        if i == max_steps:
            print("Max iterations reached, CheckSums don't match.")
            sys.exit()

    print("CheckSums match!")
    print("Iterations taken:")
    print(str(i))
    print('')

    with open(output_filename, "wb") as outfile:
        outfile.write(pe_data)

    print('Saved output binary to: ' + output_filename)