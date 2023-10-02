#!/usr/bin/env python3

import sys

R = '\033[31m'  # red
G = '\033[32m'  # green
C = '\033[36m'  # cyan
W = '\033[0m'   # white
Y = '\033[33m'  # yellow


def export(output, data):
    if output['format'] != 'txt':
        print(f'{R}[-] {C}Invalid Output Format, Valid Formats : {W}txt')
        sys.exit()

    fname = output['file']
    with open(fname, 'w') as outfile:
        txt_export(data, outfile)


def txt_unpack(outfile, val):
    def write_item(item):
        if isinstance(item, list):
            outfile.write(f'{item[0]}\t{item[1]}\t\t{item[2]}\n')
        else:
            outfile.write(f'{item}\n')

    if isinstance(val, list):
        for item in val:
            write_item(item)

    elif isinstance(val, dict):
        for sub_key, sub_val in val.items():
            if sub_key == 'exported':
                continue
            if isinstance(sub_val, list):
                txt_unpack(outfile, sub_val)
            else:
                outfile.write(f'{sub_key}: {sub_val}\n')


def txt_export(data, outfile):
    for key, val in data.items():
        if key.startswith('module'):
            if not val['exported']:
                txt_unpack(outfile, val)
                val['exported'] = True
        elif key.startswith('Type'):
            outfile.write(f'\n{data[key]}\n')
            outfile.write(f'{"=" * len(data[key])}\n\n')
        else:
            outfile.write(f'{key}: {val}\n')
