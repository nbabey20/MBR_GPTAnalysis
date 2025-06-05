import argparse
import hashlib
import struct
import os
import binascii

def calculate_md5(file_path):
    md5_hash = hashlib.md5()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            md5_hash.update(chunk)
    return md5_hash.hexdigest()

def calculate_sha256(file_path):
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            sha256_hash.update(chunk)
    return sha256_hash.hexdigest()

def identify_partition_scheme(file_path):
    #Read the first sector of the disk image and identify the partitioning scheme
    with open(file_path, "rb") as f:
        #Read the first 512 bytes
        data = f.read(512)
        #Check for MBR signature
        #print(data[450:451])
        if data[450:451] == b'\xee':
            return "GPT"
        else:
            return "MBR"

def print_mbr_partition(file_path, i):
    with open(file_path, "rb") as f:
        data = f.read(512)
        #check types
        #get lba of first sector
        start_lba = 512 * int.from_bytes(data[(i+6):(i+10)], byteorder='little')
        part_size = 512 * int.from_bytes(data[(i+10):(i+14)], byteorder='little')
        if data[(i+2):(i+3)] == b'\x07':
            part_type = 'HPFS/NTFS/exFAT'
            print('(07), {}, {}, {}'.format(part_type, start_lba, part_size))
        elif data[(i+2):(i+3)] == b'\x83':
            part_type = 'Linux'
            print('(83), {}, {}, {}'.format(part_type, start_lba, part_size))
        elif data[(i+2):(i+3)] == b'\x06':
            part_type = 'FAT16'
            print('(06), {}, {}, {}'.format(part_type, start_lba, part_size))
        else:
            print('unknown')
        return start_lba

def read_boot_record(file_path, i, lba):
    with open(file_path, "rb") as f:
        f.seek(lba + i)
        byteData = f.read(17)
        hex_data = ''
        ascii_data = ''
        for byte in byteData:
            hex_val = hex(byte)[2:]
            if len(hex_val) == 1:
                hex_val = '0' + hex_val
            hex_data += hex_val

            if byte >= 32 and byte <= 126:
                ascii_data += chr(byte) + ' '
            else:
                ascii_data += '. '
        return hex_data, ascii_data

def read_gpt_partition(file_path, offset):
    with open(file_path, "rb") as f:
        #start at partition entries
        f.seek(1024 + offset)

        #Get type guid
        byteData = f.read(17)
        hex_data = ''
        for byte in byteData:
            hex_val = hex(byte)[2:]
            if len(hex_val) == 1:
                hex_val = '0' + hex_val
            hex_data += hex_val

        #Get Starting and ending LBA addresses in hex
        f.seek(1056 + offset)
        start_lba_data = f.read(8)
        start_lba_dec = int.from_bytes(start_lba_data, byteorder='little')
        reversed_bytes1 = start_lba_data[::-1]
        start_lba_hex = binascii.hexlify(reversed_bytes1).decode('utf-8')
        start_lba_hex = start_lba_hex.lstrip('0x')

        #Get end lba address in hex
        f.seek(1064 + offset)
        end_lba_data = f.read(8)
        end_lba_dec = int.from_bytes(end_lba_data, byteorder='little')
        reversed_bytes2 = end_lba_data[::-1]
        end_lba_hex = binascii.hexlify(reversed_bytes2).decode('utf-8')
        end_lba_hex = end_lba_hex.lstrip('0x')

        #Get the name
        f.seek(1080 + offset)
        name_data = f.read(72)
        name_data = name_data.replace(b'\x00', b'')
        par_name = ''
        for byte in name_data:
            par_name += chr(byte)

        return hex_data, start_lba_hex, end_lba_hex, start_lba_dec, end_lba_dec, par_name
        


def main():
    parser = argparse.ArgumentParser(description="Analyzes MBR and GPT partitions for a disk image.")
    parser.add_argument("-f", "--file", help="The file path", required=True)
    parser.add_argument("-o", "--offsets", nargs="+", type=int, help="MBR offsets", default=[])
    args = parser.parse_args()

    # Calculate hash values
    md5_hash = calculate_md5(args.file)
    sha256_hash = calculate_sha256(args.file)

    ace = "hiii"
    #Write hash values
    with open(f'SHA-256-{os.path.basename(args.file)}.txt', 'w') as f:
        f.write(sha256_hash)

    with open(f'MD5-{os.path.basename(args.file)}.txt', 'w') as f:
        f.write(md5_hash)

    #Identify partition scheme
    partition_scheme = identify_partition_scheme(args.file)

    if partition_scheme == "MBR":
        #Get the lba values and print the partition data
        lba1 = print_mbr_partition(args.file, 448)
        lba2 = print_mbr_partition(args.file, 464)
        lba3 = print_mbr_partition(args.file, 480)
        #read the bytes from the offset in the boot record and convert to ascii
        byteData1, asciiData1 = read_boot_record(args.file, args.offsets[0], lba1)
        byteData2, asciiData2 = read_boot_record(args.file, args.offsets[1], lba2)
        byteData3, asciiData3 = read_boot_record(args.file, args.offsets[2], lba3)

        #print the 16 bytes from the offset and their corresponding ascii values
        print('Partition number: 1')
        print('16 bytes of boot record from offset {}: {}'.format(args.offsets[0], byteData1))
        print('ASCII: {}'.format(asciiData1))

        print('Partition number: 2')
        print('16 bytes of boot record from offset {}: {}'.format(args.offsets[1], byteData2))
        print('ASCII: {}'.format(asciiData2))

        print('Partition number: 3')
        print('16 bytes of boot record from offset {}: {}'.format(args.offsets[2], byteData3))
        print('ASCII: {}'.format(asciiData3))

    elif partition_scheme == "GPT":
        type_guid1, start_lba1_hex, end_lba1_hex, start_lba1_dec, end_lba1_dec, par_name1 = read_gpt_partition(args.file, 0)
        type_guid2, start_lba2_hex, end_lba2_hex, start_lba2_dec, end_lba2_dec, par_name2 = read_gpt_partition(args.file, 128)
        type_guid3, start_lba3_hex, end_lba3_hex, start_lba3_dec, end_lba3_dec, par_name3 = read_gpt_partition(args.file, 256)
        type_guid4, start_lba4_hex, end_lba4_hex, start_lba4_dec, end_lba4_dec, par_name4 = read_gpt_partition(args.file, 384)

        print("Partition number: 1")
        print("Partition Type GUID : {}".format(type_guid1))
        print("Starting LBA address in hex: 0x{}".format(start_lba1_hex))
        print("ending LBA address in hex: 0x{}".format(end_lba1_hex))
        print("starting LBA address in Decimal: {}".format(start_lba1_dec))
        print("ending LBA address in Decimal: {}".format(end_lba1_dec))
        print("Partition name: {}".format(par_name1))

        print("Partition number: 2")
        print("Partition Type GUID : {}".format(type_guid2))
        print("Starting LBA address in hex: 0x{}".format(start_lba2_hex))
        print("ending LBA address in hex: 0x{}".format(end_lba2_hex))
        print("starting LBA address in Decimal: {}".format(start_lba2_dec))
        print("ending LBA address in Decimal: {}".format(end_lba2_dec))
        print("Partition name: {}".format(par_name2))

        print("Partition number: 3")
        print("Partition Type GUID : {}".format(type_guid3))
        print("Starting LBA address in hex: 0x{}".format(start_lba3_hex))
        print("ending LBA address in hex: 0x{}".format(end_lba3_hex))
        print("starting LBA address in Decimal: {}".format(start_lba3_dec))
        print("ending LBA address in Decimal: {}".format(end_lba3_dec))
        print("Partition name: {}".format(par_name3))

        print("Partition number: 4")
        print("Partition Type GUID : {}".format(type_guid4))
        print("Starting LBA address in hex: 0x{}".format(start_lba4_hex))
        print("ending LBA address in hex: 0x{}".format(end_lba4_hex))
        print("starting LBA address in Decimal: {}".format(start_lba4_dec))
        print("ending LBA address in Decimal: {}".format(end_lba4_dec))
        print("Partition name: {}".format(par_name4))

    else:
        print("Unknown partitioning scheme.")

if __name__ == "__main__":
    main()
