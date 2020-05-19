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

def get_pe_header_offset(data):
    # 0x3c in is the PE header offset
    return struct.unpack("I", data[0x3c : 0x3c + 4])[0]

def get_checksum_offset(data):
    """
    Get the offset of the CheckSum in the loaded PE

    PE format reference: https://docs.microsoft.com/en-us/windows/win32/debug/pe-format

    :param data: bytearray of the PE
    :return: uint32 offset of the CheckSum
    """

    pe_header_offset = get_pe_header_offset(data)

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


def get_optional_header_offset(data):
    return get_pe_header_offset(data) + 24

def get_optional_header_size(data):
    pe_header_offset = get_pe_header_offset(data)
    size_of_optional_header_offset = pe_header_offset + 20
    return struct.unpack("H", data[size_of_optional_header_offset : size_of_optional_header_offset + 2])[0]

def get_section_table_offset(data):
    optional_header_offset = get_optional_header_offset(data)
    optional_header_size = get_optional_header_size(data)

    return optional_header_offset + optional_header_size

def get_number_of_sections(data):
    pe_header_offset = get_pe_header_offset(data)
    return data[pe_header_offset + 6]

def get_final_section_table_entry_offset(data):
    section_table_offset = get_section_table_offset(data)
    number_of_sections = get_number_of_sections(data)

    # Each section table entry is 40 bytes
    return section_table_offset + (number_of_sections - 1) * 40

def get_final_section_offset(data):
    final_section_table_entry_offset = get_final_section_table_entry_offset(data)
    return struct.unpack("I", data[final_section_table_entry_offset + 20 : final_section_table_entry_offset + 24])[0]

def get_final_section_raw_size(data):
    final_section_table_entry_offset = get_final_section_table_entry_offset(data)
    return struct.unpack("I", data[final_section_table_entry_offset + 16: final_section_table_entry_offset + 20])[0]

def get_end_of_final_section_offset(data):
    final_section_offset = get_final_section_offset(data)
    final_section_raw_size = get_final_section_raw_size(data)
    return final_section_offset + final_section_raw_size

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
    print('')

    #max_steps = len(pe_data) - (checksum_offset + 4)
    overlay_offset = get_end_of_final_section_offset(pe_data)
    print('Overlay offset:')
    print(hex(overlay_offset))
    print('')

    max_steps = len(pe_data) - overlay_offset

    print('Max iterations to take:')
    print(max_steps)
    print('')

    print("Beginning to remove bytes...")
    print('')

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