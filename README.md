# PE Trimmer
## Use Case
When dumping a portable executable (PE) from memory, the dumped PE's CheckSum might not be accurate due to extra data being left over. This is inherently an issue, as it usually means the file will still execute properly. However, if you're trying to compare it to a hash of the original image (e.g. comparing an IOC for a known malicious file), the extra data will cause the hashes to mismatch.

To solve this, the PE Trimmer Python 3 script will iterate backwards through the provided PE file, and remove a byte at a time until the CheckSum is correct (or until it runs out of data). This way, you can have more confidence in the dumped file being an accurate representation of the original.

## Usage
```
usage: pe_trimmer.py [-h] [--debug] -i INPUT -o OUTPUT

Attempt to correct the CheckSum of a PE file by iteratively removing bytes from the overlay.

optional arguments:
  -h, --help            show this help message and exit
  --debug               Enable debug logging
  -i INPUT, --input INPUT
                        Input PE file path
  -o OUTPUT, --output OUTPUT
                        Output (trimmed) PE file path
```

## Credit
I couldn't find a Python implementation of Window's PE CheckSum, so I adapated the code from the answer to the following Stack Overflow question:
https://stackoverflow.com/questions/6429779/can-anyone-define-the-windows-pe-checksum-algorithm

## Todo
- Add validation to the input PE file