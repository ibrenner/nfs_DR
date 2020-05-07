#!/usr/bin/python3

from configparser import ConfigParser
from nfs_exports_sync import iboxauth, get_replicas, iboxevent
from nfs_failover import change_role, link_attach, link_detach, enable_ip, disable_ip
import base64, argparse, os, socket, time
from datetime import datetime
from infinisdk import InfiniBox
import urllib3
urllib3.disable_warnings()


def get_args():
    """
    Supports the command-line arguments listed below.
    """
    parser = argparse.ArgumentParser(description="Script for syncing exports.")
    parser.add_argument('-o', '--option', choices=['failback', 'restore'], required=True, help='Choose the needed option')
    parser.add_argument('-s', '--source', nargs=1, required=True, help='FQDN or IP of source ibox')
    parser.add_argument('-d', '--destination', nargs=1, required=True, help='FQDN or IP of Destination ibox')
    parser.add_argument('-c', '--credfile', nargs=1, required=True, help='Path to Credentials file ')
    args = parser.parse_args()
    return args


def user_input():
    while True:
        user_input = str(input("press c to continue... "))
        if user_input == 'c':
            return True


        # choice = user_input()
        # if choice == 'c':


if __name__ == '__main__':
    args = get_args()
    if os.path.isfile('{}'.format(args.credfile[0])):
        config = ConfigParser()
        config.read(args.credfile[0])
        pw = base64.b64decode(config['IBOX']['password']).decode("utf-8", "ignore")
        srcibox = iboxauth(args.source[0], config['IBOX']['user'], pw)
        dstibox = iboxauth(args.destination[0], config['IBOX']['user'], pw)
        dstibox.register_related_system(srcibox)
        if args.option == 'failback':
            print("Disabling NAS Network spaces on {}".format(srcibox))
            if user_input():
                disable_ip(srcibox)
            print("Attaching Replication Link")
            if user_input():
                drep = get_replicas(dstibox, 'SOURCE')
                link_attach(dstibox, drep[0])
            print("Changing Role on {}".format(srcibox))
            if user_input():
                rep = get_replicas(srcibox, 'SOURCE')
                change_role(rep)
                for r in drep:
                    r.resume()
            iboxevent(dstibox, "script {} run from {}".format(os.path.basename(__file__), socket.gethostname()))
        if args.option == 'restore':
            print("Disabling NAS Network spaces on {}".format(dstibox))
            print("Enabling NAS Network spaces on {}".format(srcibox))
            if user_input():
                disable_ip(dstibox)
                enable_ip(srcibox)
            print("Changing Role on {} and {}".format(srcibox, dstibox))
            if user_input():
                rep = get_replicas(srcibox, 'TARGET')
                change_role(rep)
                time.sleep(8)
                drep = get_replicas(dstibox, 'SOURCE')
                change_role(drep)
                for r in rep:
                    r.resume()
            iboxevent(dstibox, "script {} run from {}".format(os.path.basename(__file__), socket.gethostname()))
