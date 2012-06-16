#!/usr/bin/env python

import argparse
import sys


# Magic constants
tag = 0xCAFEBABE
cp_offset = 0x08
cp_class_offset = 0x02
cp_tag_sizes = {
    3: 0x04,
    4: 0x04,
    5: 0x08,
    6: 0x08,
    7: 0x02,
    8: 0x02,
    9: 0x04,
    10: 0x04,
    11: 0x04,
    12: 0x04,
    }


def read_u4(data):  # Read 32-bit unsigned integer
    return (read_u2(data) << 16) | read_u2(data[2:])


def read_u2(data):  # Read 16-bit unsigned integer
    return (read_u1(data) << 8) | read_u1(data[1:])


def read_u1(data):  # Read 8-bit unsigned integer
    return data[0]


def read_utf8(data):  # Read utf8 string
    length = read_u2(data)
    string = data[2: length + 2]
    return string


def str2bytes(string):  # Convert string to binary format
    length = len(string)
    data = bytearray()
    mask8 = (1 << 8) - 1
    data.append((length >> 8) & mask8)
    data.append(length & mask8)
    for c in string:
        data.append(ord(c))
    return data


def get_classname_offset(data):
    # Partically loads constant pool and computes class name offset

    pool_size = read_u2(data[cp_offset:]) - 1  # table is 1-indexed
    raw_offset = cp_offset + 2

    data = data[raw_offset:]
    pool = [None] * (pool_size + 1)

    for i in range(1, pool_size + 1):  # table is 1-indexed
        tag_byte, offset = read_u1(data), 0
        data = data[1:]
        raw_offset += 1

        if tag_byte == 1:
            # Save raw offsets of all strings
            string = read_utf8(data)
            offset = len(string) + 2

            pool[i] = raw_offset
        else:
            offset = cp_tag_sizes[tag_byte]
            if tag_byte == 7:  # Save all class name offsets
                pool[i] = read_u2(data)

        data = data[offset:]
        raw_offset += offset

    self_index = read_u2(data[cp_class_offset:])

    return pool[pool[self_index]]


def get_classname(data):
    offset = get_classname_offset(data)
    return read_utf8(data[offset:]).decode('utf-8')


def set_classname(data, new_name):
    offset = get_classname_offset(data)
    sz = read_u2(data[offset:])
    return data[:offset] + str2bytes(new_name) + data[offset + sz + 2:]


def main():
    parser = argparse.ArgumentParser(prog='javacnch')
    parser.add_argument("FILE", help="Java class file")
    parser.add_argument("-s", "--set_name", help="Set java class name",
            metavar="NAME")
    args = parser.parse_args()

    file_name = args.FILE

    try:
        f = open(file_name, 'rb')
        data = bytearray()
        for c in f.read():
            data.append(c)

        f.close()

        if read_u4(data) != tag:
            sys.stderr.write("Error. File '{}' isn't java class.\n".format(
                file_name))
            sys.exit(1)

        if args.set_name:
            data = set_classname(data, args.set_name)

            try:
                f = open(file_name, 'wb')
                f.write(data)
                f.close()
            except IOError:
                sys.stderr.write("Error. Can't save file.\n")
                sys.exit(1)

        else:
            sys.stdout.write(get_classname(data) + "\n")

    except IOError:
        sys.stderr.write("Error. Can't load file.\n")
        sys.exit(1)

    except Exception:
        sys.stderr.write("Error. Constant pool is corrupted.\n")
        sys.exit(1)


if __name__ == '__main__':
    main()
