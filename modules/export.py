#!/usr/bin/env python3

R = '\033[31m'  # red
G = '\033[32m'  # green
C = '\033[36m'  # cyan
W = '\033[0m'   # white
Y = '\033[33m'  # yellow


def export(output, data):
    if output['format'] != 'txt':
        if output['export'] is True:
            fname = output['file']
            with open(fname, 'w') as outfile:
                if output['format'] != 'txt':
                    print(f'{R}[-] {C}Invalid Output Format, Valid Formats : {W}txt')
                    exit()
        else:
            pass
    elif output['format'] == 'txt':
        fname = output['file']
        with open(fname, 'w') as outfile:
            txt_export(data, outfile)
    else:
        pass


def txt_unpack(outfile, key, val):
    if isinstance(val, list):
        for item in val:
            if isinstance(item, list):
                outfile.write('{}\t{}\t\t{}\n'.format(*item))
            else:
                outfile.write(str(item) + '\n')

    elif isinstance(val, dict):
        for key, val in val.items():
            if key != 'exported':
                if isinstance(val, list):
                    txt_unpack(outfile, key, val)
                else:
                    outfile.write(f'{key}: {val}\n')
    else:
        pass


def txt_export(data, outfile):
    for key, val in data.items():
        if key.startswith('module'):
            if val['exported'] is False:
                txt_unpack(outfile, key, val)
                val['exported'] = True
        elif key.startswith('Type'):
            outfile.write('\n' + data[key] + '\n')
            outfile.write('=' * len(data[key]) + '\n\n')
        else:
            outfile.write(str(key))
            outfile.write(' : ')
            outfile.write(str(val) + '\n')
