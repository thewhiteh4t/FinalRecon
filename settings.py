#!/usr/bin/env python3

from os import getenv, path
from json import loads

home = getenv('HOME')
usr_data = f'{home}/.local/share/finalrecon/dumps/'
conf_path = f'{home}/.config/finalrecon'
path_to_script = path.dirname(path.realpath(__file__))
src_conf_path = f'{path_to_script}/conf/'
meta_file_path = f'{path_to_script}/metadata.json'
keys_file_path = f'{conf_path}/keys.json'
conf_file_path = f'{conf_path}/config.json'

if path.exists(conf_path):
	pass
else:
	from shutil import copytree
	copytree(src_conf_path, conf_path, dirs_exist_ok=True)

with open(conf_file_path, 'r') as config_file:
	config_read = config_file.read()
	config_json = loads(config_read)
	timeout = config_json['common']['timeout']

	ssl_port = config_json['ssl_cert']['ssl_port']

	port_scan_th = config_json['port_scan']['threads']

	dir_enum_th = config_json['dir_enum']['threads']
	dir_enum_redirect = config_json['dir_enum']['redirect']
	dir_enum_sslv = config_json['dir_enum']['verify_ssl']
	dir_enum_dns = config_json['dir_enum']['dns_server']
	dir_enum_ext = config_json['dir_enum']['extension']
	dir_enum_wlist = f'{path_to_script}/wordlists/dirb_common.txt'

	export_fmt = config_json['export']['format']
