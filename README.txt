My program works by setting up a parser to collect the file name in a string and the offset
values in an array. Then, the file is input to calculate both md5 and sha256 hash values. These values
are then written to their corresponding text files that are created in the directory the python script is ran from.
Then the partition scheme is identified with a specific byte in the mbr signature. If it is equal to 'EE' it is GPT, if not
then it is MBR. If the scheme is MBR, then partition information along with lba start address and size are calculated for the first
3 partitions by reading the 16 byte entry in the MBR. Then, for each partition, the offset and starting lba are used to list the 16 requested
bytes of boot record, which are also represented in ASCII. For GPT scheme, the type GUID, starting and ending lba address in both hex and decimal, and
partition name are all calculated by reading the 128 byte partition entry. This requires conversion from byte arrays to hex and ascii. 