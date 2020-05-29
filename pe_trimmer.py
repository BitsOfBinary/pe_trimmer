import struct
import sys
import argparse
import logging


class ParsedPEHeader:
    def __init__(self, pe_data):
        self.pe_data = pe_data
        self.pe_header_offset = None
        self.checksum_offset = None
        self.pe_checksum = None
        self.optional_header_offset = None
        self.optional_header_size = None
        self.section_table_offset = None
        self.number_of_sections = None
        self.final_section_table_entry_offset = None
        self.final_section_offset = None
        self.final_section_raw_size = None
        self.end_of_final_section_offset = None

    @staticmethod
    def read_dword(data, offset):
        return struct.unpack("I", data[offset : offset + 4])[0]

    @staticmethod
    def read_word(data, offset):
        return struct.unpack("H", data[offset : offset + 2])[0]

    def calculate_pe_header_offset(self):
        # 0x3c in is the PE header offset
        self.pe_header_offset = self.read_dword(self.pe_data, 0x3C)

    def calculate_checksum_offset(self):
        # 0x58 offset into the PE header is the CheckSum value
        self.checksum_offset = self.pe_header_offset + 0x58

    def calculate_checksum(self):
        self.pe_checksum = self.read_dword(self.pe_data, self.checksum_offset)

    def calculate_optional_header_offset(self):
        self.optional_header_offset = self.pe_header_offset + 24

    def calculate_optional_header_size(self):
        size_of_optional_header_offset = self.pe_header_offset + 20
        self.optional_header_size = self.read_word(
            self.pe_data, size_of_optional_header_offset
        )

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
        self.final_section_offset = self.read_dword(
            self.pe_data, self.final_section_table_entry_offset + 20
        )

    def calculate_final_section_raw_size(self):
        self.final_section_raw_size = self.read_dword(
            self.pe_data, self.final_section_table_entry_offset + 16
        )

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

    def __init__(self, input_file_path, output_file_path):
        self.input_file_path = input_file_path
        self.output_file_path = output_file_path

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

    def run(self):
        self.load_pe_data(self.input_file_path)
        self.parse_pe_header()
        self.calculate_pe_checksum()

        logging.info("PE CheckSum from header: %s", (hex(self.get_true_pe_checksum())))
        logging.info(
            "Calculated PE CheckSum: %s\n", (hex(self.get_calculated_pe_checksum()))
        )

        if self.get_true_pe_checksum() == self.get_calculated_pe_checksum():
            logging.info("The CheckSum of %s is already correct.", self.input_file_path)

        else:
            logging.info(
                "The CheckSum of %s does not match the calculated CheckSum.\n",
                self.input_file_path,
            )
            logging.info("Overlay offset: %s", (hex(self.get_overlay_offset())))

            max_steps = len(self.get_pe_data()) - self.get_overlay_offset()

            logging.info("Max iterations to take: %d\n", max_steps)
            logging.info("Beginning to remove bytes...\n")

            for i in range(1, max_steps):
                self.trim_pe_data()

                self.calculate_pe_checksum()

                if self.get_true_pe_checksum() == self.get_calculated_pe_checksum():
                    break

                if i == max_steps:
                    logging.info("Max iterations reached, CheckSums don't match.\n")
                    sys.exit()

            logging.info("CheckSums match!")
            logging.info("Iterations taken: %d\n", i)

            with open(self.output_file_path, "wb") as outfile:
                outfile.write(self.get_pe_data())

            logging.info("Saved output binary to: %s", self.output_file_path)


def main():
    """
    Entry point when called from the command line. Will construct and call the main method of PETrimmer.
    """
    parser = argparse.ArgumentParser(
        description=(
            "Attempt to correct the CheckSum of a PE file by iteratively removing bytes from the overlay."
        )
    )
    parser.add_argument(
        "--debug", help="Enable debug logging", action="store_true", default=False,
    )
    parser.add_argument(
        "-i", "--input", help="Input PE file path", type=str, required=True,
    )
    parser.add_argument(
        "-o", "--output", help="Output (trimmed) PE file path", type=str, required=True,
    )

    args = parser.parse_args()

    if args.debug:
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.INFO, format="%(message)s")

    pe_trimmer = PETrimmer(args.input, args.output)

    pe_trimmer.run()


if __name__ == "__main__":
    main()
