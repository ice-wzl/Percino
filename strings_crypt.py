#!/usr/bin/env python3
import argparse
import os
import sys
from typing import Union, List


def get_handle(file_path: str) -> List[str]:
    if not os.path.exists(file_path):
        print(f"[-] {file_path}: no such file or directory", file=sys.stderr)
        sys.exit(1)
    out = []
    with open(file_path, "r", encoding="utf-8") as fp:
        for line in fp:
            s = line.strip()
            if s:
                out.append(s)
    return out


def do_xor(data: Union[str, bytes], key: Union[str, bytes]) -> bytes:
    if isinstance(data, str):
        data = data.encode("utf-8")
    if isinstance(key, str):
        key = key.encode("utf-8")
    if not key:
        raise ValueError("key must not be empty")
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))


def write_output(crypt_bytes: bytes, plain_string: str, output_file: str) -> None:
    # plaintext<TAB>hex(ciphertext)
    line = f"{plain_string}\n{crypt_bytes.hex()}\n\n"
    with open(output_file, "a", encoding="utf-8") as op:
        op.write(line)


if __name__ == '__main__':
    ap = argparse.ArgumentParser(description="XOR each line in a file with a repeating key")
    ap.add_argument("-f", "--file", required=True, help="File with plaintext strings (one per line)")
    ap.add_argument("-k", "--key", required=True, help="XOR key")
    ap.add_argument("-o", "--output", required=True, help="Output file (plaintext<TAB>hex-ciphertext)")
    args = ap.parse_args()

    lines = get_handle(args.file)

    for s in lines:
        c = do_xor(s, args.key)
        write_output(c, s, args.output)
