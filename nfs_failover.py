#!/usr/bin/python3

from configparser import ConfigParser
from nfs_exports_sync import iboxauth, get_replicas, iboxevent
import base64, argparse, os, socket
from datetime import datetime
from infinisdk import InfiniBox
import urllib3
urllib3.disable_warnings()


def change_role(replicas):
    for replica in replicas:
        replica.change_role()

# Link detach \ attach
def link_detach(replica):
    link = replica.get_link()
    if link.is_up():
        link.detach()


def link_attach(ibox, replica):
    rep_ns=ibox.network_spaces.find(service='RMR_SERVICE')
    link = replica.get_link()
    if link.is_down():
        link.attach(network_space=rep_ns[0])
        link.refresh_connectivity()


def enable_ip(ibox):
    nas_nspaces=ibox.network_spaces.find(service='NAS_SERVICE')
    for ns in nas_nspaces:
        for ip in ns.get_ips():
            if not ip['enabled']:
                ns.enable_ip_address(ip['ip_address'])

def disable_ip(ibox):
    nas_nspaces=ibox.network_spaces.find(service='NAS_SERVICE')
    for ns in nas_nspaces:
        for ip in ns.get_ips():
                if ip['enabled']:
                    ns.disable_ip_address(ip['ip_address'])

def get_args():
    """
    Supports the command-line arguments listed below.
    """
    parser = argparse.ArgumentParser(description="Script for syncing exports.")
    parser.add_argument('-o', '--option', choices=['disable', 'enable', 'failover', 'reverse'], required=True, help='Choose the needed option')
    parser.add_argument('-i', '--ibox', nargs=1, required=True, help='FQDN or IP of Destination ibox')
    parser.add_argument('-c', '--credfile', nargs=1, required=True, help='Path to Credentials file ')
    args = parser.parse_args()
    return args




if __name__ == '__main__':
    args = get_args()
    if os.path.isfile('{}'.format(args.credfile[0])):
        config = ConfigParser()
        config.read(args.credfile[0])
        pw = base64.b64decode(config['IBOX']['password']).decode("utf-8", "ignore")
        dstibox = iboxauth(args.ibox[0], config['IBOX']['user'], pw)
        if args.option == 'disable':
            disable_ip(dstibox)
        if args.option == 'enable':
            enable_ip(dstibox)
        if args.option == 'failover':
            fs_replica = get_replicas(dstibox, 'TARGET')
            link_detach(fs_replica[0])
            change_role(fs_replica)
        if args.option == 'reverse':
            fs_replica = get_replicas(dstibox, 'SOURCE')
            link_attach(dstibox, fs_replica[0])
            change_role(fs_replica)
        print('{}: Completed Successfully'.format(datetime.now().strftime('%D %H:%M:%S')))
        iboxevent(dstibox, "script {} run from {}".format(os.path.basename(__file__), socket.gethostname()))


