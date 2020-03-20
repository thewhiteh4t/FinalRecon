#!/usr/bin/env python3

import os
import csv
import lxml.etree
import xml.etree.ElementTree as ET

R = '\033[31m' # red
G = '\033[32m' # green
C = '\033[36m' # cyan
W = '\033[0m'  # white
Y = '\033[33m' # yellow

root = ''

def export(output, data):
    if output['format'] != 'txt':
        if output['export'] == True:
            fname = output['file']
            with open(fname, 'w') as outfile:
                if output['format'] == 'xml':
                    print(Y + '[!]' + C + ' Exporting to ' + W + fname + '\n')
                    xml_export(output, data, outfile)
                if output['format'] == 'csv':
                    print(Y + '[!]' + C + ' Exporting to ' + W + fname + '\n')
                    csv_export(output, data, outfile)
                if all([output['format'] != 'xml', output['format'] != 'csv']):
                    print(R + '[-]' + C + ' Invalid Output Format, Valid Formats : ' + W + 'txt, xml, csv')
                    exit()
        else:
            pass
    elif output['format'] == 'txt':
        fname = output['file']
        print(Y + '[!]' + C + ' Exporting to ' + W + fname + '\n')
        with open(fname, 'w') as outfile:
            txt_export(data, outfile)
    else:
        pass
    
def txt_unpack(outfile, k, v):
    if isinstance(v, list):
        for item in v:
            if isinstance(item, list):
                outfile.write('{}\t{}\t\t{}\n'.format(*item))
            else:
                outfile.write(str(item) + '\n')
    
    elif isinstance(v, dict):
        for key, val in v.items():
            if isinstance(val, list):
                outfile.write('\n' + str(key) + '\n')
                outfile.write('='*len(key) + '\n\n')
                txt_unpack(outfile, key, val)
            else:
                outfile.write('\n' + str(key))
                outfile.write(' : ')
                outfile.write(str(val) + '\n')
    else:
        pass

def txt_export(data, outfile):
    for k, v in data.items():
        if k.startswith('module'):
            k = k.split('-')
            k = k[1]
            outfile.write('\n' + '#'*len(k) + '\n')
            outfile.write(k)
            outfile.write('\n' + '#'*len(k) + '\n')
            txt_unpack(outfile, k, v)

        elif k.startswith('Type'):
            outfile.write('\n' + data[k] + '\n')
            outfile.write('='*len(data[k]) + '\n\n')
            
        else:
            outfile.write(str(k))
            outfile.write(' : ')
            outfile.write(str(v) + '\n')

def xml_export(output, data, outfile):
    global root
    root = ET.Element('finalrecon')
    modules = ET.Element('modules')

    for k, v in data.items():
        if k.startswith('module'):
            module = k.split('module-')
            module = module[1]
            module_name = ET.Element('moduleName')
            module_name.text = module
            modules.append(module_name)
            if isinstance(v, dict):
                for key, val in v.items():
                    data_pair = ET.Element('dataPair')
                    data_key = ET.Element('dataKey')
                    data_key.text = key
                    data_pair.append(data_key)
                    if isinstance(val, list):
                        for item in val:
                            if isinstance(item, list):
                                data_val = ET.Element('dataVal')
                                data_val.text = '{},{},{}'.format(*item)
                                data_pair.append(data_val)
                            else:
                                data_val = ET.Element('dataVal')
                                data_val.text = str(item)
                                data_pair.append(data_val)
                        module_name.append(data_pair)
                    else:
                        data_val = ET.Element('dataVal')
                        data_val.text = str(val)
                        data_pair.append(data_val)
                        module_name.append(data_pair)

    root.append(modules)
    if output['format'] == 'xml':
        tree = ET.ElementTree(root)
        tree.write(outfile.name,
            encoding='utf8', 
            xml_declaration=True, 
            default_namespace=None, 
            method='xml')
    else:
        pass

def csv_export(output, data, outfile):
    global root
    key_list = []
    val_list = []

    xml_export(output, data, outfile)

    root_str = ET.tostring(root, method='xml').decode()
    xml_data = lxml.etree.fromstring(root_str)
    modules = xml_data.find('modules')
    module_names = modules.findall('moduleName')

    for module_name in module_names:
        module_name_str = module_name.text
        dataPairs = module_name.findall('dataPair')
        
        for dataPair in dataPairs:
            dataKey = dataPair.find('dataKey')
            dataKey = dataKey.text
            key_list.append(dataKey)
            dataVals = dataPair.findall('dataVal')
            if len(dataVals) == 1:
                dataVals = dataVals[0].text
                dataVals = dataVals.replace(',', '/').replace(';', '/')
                val_list.append(dataVals)
            else:
                data_str_list = []
                for item in dataVals:
                    item = item.text
                    item = item.replace(',', '/').replace(';', '/')
                    data_str_list.append(item)
                val_list.append(data_str_list)
        
        with open(outfile.name, 'a') as outfile:
            writer = csv.writer(outfile, delimiter=';')
            key_list.insert(0,'Module')
            writer.writerow(key_list)
            val_list.insert(0, module_name_str)

            val_str_list = []
            
            for item in val_list:
                if isinstance(item, str) == False and isinstance(item, list) == False:
                    item = item.text 
                if isinstance(item, list) == True:
                    item = '\n'.join(item)
                else:
                    pass
                val_str_list.append(item)
            writer.writerow(val_str_list)

            for i in range(1,5):
                writer.writerow([])
            key_list = []
            val_list = []