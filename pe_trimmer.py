import struct
import sys
import argparse


class ParsedPEHeader:
    pe_header_offset = None
    checksum_offset = None
    pe_checksum = None
    optional_header_offset = None
    optional_header_size = None
    section_table_offset = None
    number_of_sections = None
    final_section_table_entry_offset = None
    final_section_offset = None
    final_section_raw_size = None
    end_of_final_section_offset = None

    def __init__(self, pe_data):
        self.pe_data = pe_data

    def calculate_pe_header_offset(self):
        # 0x3c in is the PE header offset
        self.pe_header_offset = struct.unpack("I", self.pe_data[0x3C : 0x3C + 4])[0]

    def calculate_checksum_offset(self):
        # 0x58 offset into the PE header is the CheckSum value
        self.checksum_offset = self.pe_header_offset + 0x58

    def calculate_checksum(self):
        self.pe_checksum = struct.unpack(
            "I", self.pe_data[self.checksum_offset : self.checksum_offset + 4]
        )[0]

    def calculate_optional_header_offset(self):
        self.optional_header_offset = self.pe_header_offset + 24

    def calculate_optional_header_size(self):
        size_of_optional_header_offset = self.pe_header_offset + 20
        self.optional_header_size = struct.unpack(
            "H",
            self.pe_data[
                size_of_optional_header_offset : size_of_optional_header_offset + 2
            ],
        )[0]

    def calculate_section_table_offset(self):
        self.section_table_offset = (
            self.optional_header_offset + self.optional_header_size
        )

    def calculate_number_of_sections(self):
        self.number_of_sections = self.pe_data[self.pe_header_offset + 6]

    def calculate_final_section_table_entry_offset(self):
        # Each section table entry is 40 bytes
        self.final_section_table_entry_offset = (
            self.section_table_offset + (self.number_of_sections - 1) * 40
        )

    def calculate_final_section_offset(self):
        self.final_section_offset = struct.unpack(
            "I",
            self.pe_data[
                self.final_section_table_entry_offset
                + 20 : self.final_section_table_entry_offset
                + 24
            ],
        )[0]

    def calculate_final_section_raw_size(self):
        self.final_section_raw_size = struct.unpack(
            "I",
            self.pe_data[
                self.final_section_table_entry_offset
                + 16 : self.final_section_table_entry_offset
                + 20
            ],
        )[0]

    def calculate_end_of_final_section_offset(self):
        self.end_of_final_section_offset = (
            self.final_section_offset + self.final_section_raw_size
        )

    def get_checksum_offset(self):
        return self.checksum_offset

    def get_pe_checksum(self):
        return self.pe_checksum

    def get_end_of_final_section_offset(self):
        return self.end_of_final_section_offset

    def parse_headers(self):
        self.calculate_pe_header_offset()
        self.calculate_checksum_offset()
        self.calculate_checksum()
        self.calculate_optional_header_offset()
        self.calculate_optional_header_size()
        self.calculate_section_table_offset()
        self.calculate_number_of_sections()
        self.calculate_final_section_table_entry_offset()
        self.calculate_final_section_offset()
        self.calculate_final_section_raw_size()
        self.calculate_end_of_final_section_offset()


class PETrimmer:
    pe_data = None
    calculated_pe_checksum = None
    true_pe_checksum = None
    overlay_offset = None
    checksum_offset = None

    def calculate_pe_checksum(self):
        """
        Python implementation of Window's CheckSum
        Reference: https://stackoverflow.com/questions/6429779/can-anyone-define-the-windows-pe-checksum-algorithm
        """

        checksum = 0
        top = 2 ** 32

        for i in range(0, int(len(self.pe_data) / 4)):

            # Don't include the CheckSum of the PE in the calculation
            if i == int(self.checksum_offset / 4):
                continue

            dword = struct.unpack("I", self.pe_data[i * 4 : (i * 4) + 4])[0]
            checksum = (checksum & 0xFFFFFFFF) + dword + (checksum >> 32)

            if checksum > top:
                checksum = (checksum & 0xFFFFFFFF) + (checksum >> 32)

        checksum = (checksum & 0xFFFF) + (checksum >> 16)
        checksum = checksum + (checksum >> 16)
        checksum = checksum & 0xFFFF

        checksum += len(self.pe_data)

        self.calculated_pe_checksum = checksum

    def load_pe_data(self, filename):
        with open(filename, "rb") as infile:
            self.pe_data = bytearray(infile.read())

    def parse_pe_header(self):
        parsed_pe_header = ParsedPEHeader(self.pe_data)
        parsed_pe_header.parse_headers()

        self.true_pe_checksum = parsed_pe_header.get_pe_checksum()
        self.overlay_offset = parsed_pe_header.get_end_of_final_section_offset()
        self.checksum_offset = parsed_pe_header.get_checksum_offset()

    def trim_pe_data(self):
        del self.pe_data[-1]

    def get_true_pe_checksum(self):
        return self.true_pe_checksum

    def get_calculated_pe_checksum(self):
        return self.calculated_pe_checksum

    def get_overlay_offset(self):
        return self.overlay_offset

    def get_pe_data(self):
        return self.pe_data


def main():
    if len(sys.argv) != 3:
        print("Usage: python pe_trimmer.py <PE_FILE> <OUTPUT_FILE>")
        sys.exit()

    input_file_path = sys.argv[1]
    output_file_path = sys.argv[2]

    pe_trimmer = PETrimmer()
    pe_trimmer.load_pe_data(input_file_path)
    pe_trimmer.parse_pe_header()
    pe_trimmer.calculate_pe_checksum()

    print("PE CheckSum from header: %s" % (hex(pe_trimmer.get_true_pe_checksum())))
    print(
        "Calculated PE CheckSum: %s\n" % (hex(pe_trimmer.get_calculated_pe_checksum()))
    )

    if pe_trimmer.get_true_pe_checksum() == pe_trimmer.get_calculated_pe_checksum():
        print("The CheckSum of %s is already correct." % input_file_path)

    else:
        print(
            "The CheckSum of %s does not match the calculated CheckSum.\n"
            % input_file_path
        )
        print("Overlay offset: %s" % (hex(pe_trimmer.get_overlay_offset())))

        max_steps = len(pe_trimmer.get_pe_data()) - pe_trimmer.get_overlay_offset()

        print("Max iterations to take: %d\n" % max_steps)
        print("Beginning to remove bytes...\n")

        for i in range(1, max_steps):
            pe_trimmer.trim_pe_data()

            pe_trimmer.calculate_pe_checksum()

            if (
                pe_trimmer.get_true_pe_checksum()
                == pe_trimmer.get_calculated_pe_checksum()
            ):
                iterations_done = i
                break

            if i == max_steps:
                print("Max iterations reached, CheckSums don't match.\n")
                sys.exit()

        print("CheckSums match!")
        print("Iterations taken: %d\n" % i)

        with open(output_file_path, "wb") as outfile:
            outfile.write(pe_trimmer.get_pe_data())

        print("Saved output binary to: %s" % output_file_path)


if __name__ == "__main__":
    main()
