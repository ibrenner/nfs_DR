#!/usr/bin/python3

from configparser import ConfigParser
import base64, argparse, os
from datetime import datetime
from infinisdk import InfiniBox
import urllib3
urllib3.disable_warnings()


def iboxauth(ibox,user,pw):
        ibox = InfiniBox(ibox, auth=(user,pw))
        ibox.login()
        return ibox


def get_replicas(ibox, role):
    fs_replica=[x for x in  ibox.replicas.get_all().to_list() \
        if x.get_fields()['entity_type'] == 'FILESYSTEM' \
            and x.get_fields()['role'] == '{}'.format(role) ]
    return fs_replica


def export_properties(src_e,replica):
    data={
        'filesystem_id':replica.get_local_entity().id,
        'export_path':src_e['export_path'],
        'inner_path':src_e['inner_path'],
        'anonymous_uid':src_e['anonymous_uid'],
        'anonymous_gid':src_e['anonymous_gid'],
        'transport_protocols':src_e['transport_protocols'],
        'max_read':src_e['max_read'],
        'max_write':src_e['max_write'],
        'pref_read':src_e['pref_read'],
        'pref_write':src_e['pref_write'],
        'pref_readdir':src_e['pref_readdir'],
        'privileged_port':src_e['privileged_port'],
        'make_all_users_anonymous':src_e['make_all_users_anonymous'],
        '32bit_file_id':src_e['32bit_file_id'],
        'enabled':src_e['enabled'],
        'snapdir_visible':src_e['snapdir_visible'],
        'permissions':src_e['permissions']
        }
    return data


def exports_creation(fs_replica, srcibox, dstibox):
    for replica in fs_replica:
        src_exports = srcibox.api.get('exports?filesystem_id={}'.format(replica.get_remote_entity().id))
        for src_e in src_exports.get_result():
            if dstibox.exports.safe_get(export_path=src_e['export_path'], filesystem_id=replica.get_local_entity().id):
                continue
            else:
                data=export_properties(src_e,replica)
                dstibox.api.post('exports?approved=true', data=data)
            

# if export does not exist in source delete it from destination
def exports_deletion(fs_replica, srcibox, dstibox):
    for replica in fs_replica:
        dst_exports = dstibox.api.get('exports?filesystem_id={}'.format(replica.get_local_entity().id))
        for dst_e in dst_exports.get_result():
            if srcibox.exports.safe_get(export_path=dst_e['export_path'], filesystem_id=replica.get_remote_entity().id):
                continue
            else:
                exportdel = dstibox.exports.get(export_path=dst_e['export_path'])
                exportdel.delete()


def get_args():
    """
    Supports the command-line arguments listed below.
    """
    parser = argparse.ArgumentParser(description="Script for syncing exports.")
    # parser.add_argument('-o', '--option', choices=['create', 'query', 'delete', 'restore'], required=True, help='Choose the needed option')
    parser.add_argument('-s', '--source', nargs=1, required=True, help='FQDN or IP of source ibox')
    parser.add_argument('-d', '--destination', nargs=1, required=True, help='FQDN or IP of Destination ibox')
    parser.add_argument('-c', '--credfile', nargs=1, required=True, help='Path to Credentials file ')
    args = parser.parse_args()
    return args


if __name__ == '__main__':
    args = get_args()
    if os.path.isfile('{}'.format(args.credfile[0])):
        config = ConfigParser()
        config.read(args.credfile[0])
        pw = base64.b64decode(config['IBOX']['password']).decode("utf-8", "ignore")
        srcibox = iboxauth(args.source[0], config['IBOX']['user'], pw)
        dstibox = iboxauth(args.destination[0], config['IBOX']['user'], pw)
        dstibox.register_related_system(srcibox)
        fs_replica = get_replicas(dstibox, 'TARGET')
        exports_creation(fs_replica, srcibox, dstibox)
        exports_deletion(fs_replica, srcibox, dstibox)
        print('{}: Completed Successfully'.format(datetime.now().strftime('%D %H:%M:%S')))
    else:
        print("ERROR: Credentials File Not Found")
        exit(1)