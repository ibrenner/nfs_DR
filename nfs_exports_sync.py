#!/usr/bin/python3

from configparser import ConfigParser
import base64, argparse, os, socket, json
from datetime import datetime
from infinisdk import InfiniBox
import urllib3
urllib3.disable_warnings()



def iboxevent(ibox,desc):
    ibox.events.create_custom_event(level='INFO', description='{}'.format(desc), visibility='CUSTOMER')


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


def share_properties(src_sh, replica):
    data={
        'filesystem_id':replica.get_local_entity().id,
        'name':src_sh['name'],
        'inner_path':src_sh['inner_path'],
        'offline_caching':src_sh['offline_caching'],
        'access_based_enumeration':src_sh['access_based_enumeration'],
        'snapdir_visible':src_sh['snapdir_visible'],
        'description':src_sh['description'],
        'permissions':src_sh['permissions'],
        'default_file_unix_permissions':src_sh['default_file_unix_permissions'],
        'default_folder_unix_permissions':src_sh['default_folder_unix_permissions'],
}
    return data


def exports_creation(replica, srcibox, dstibox):
        src_exports = srcibox.api.get('exports?filesystem_id={}'.format(replica.get_remote_entity().id))
        if len(src_exports.get_result())>0:
            for src_e in src_exports.get_result():
                if dstibox.exports.safe_get(export_path=src_e['export_path'], filesystem_id=replica.get_local_entity().id):
                    continue
                else:
                    data=export_properties(src_e,replica)
                    dstibox.api.post('exports?approved=true', data=data)


def shares_creation(replica, srcibox, dstibox):
        src_shares = srcibox.api.get('shares?filesystem_id={}'.format(replica.get_remote_entity().id))
        if len(src_shares.get_result())>0:
            for src_sh in src_shares.get_result():
                if dstibox.shares.safe_get(name=src_sh['name'], filesystem_id=replica.get_local_entity().id):
                    continue
                else:
                    data=share_properties(src_sh,replica)
                    new_data = {k: v for k, v in data.items() if k != "permissions"}
                    resp=dstibox.api.post('shares?approved=true', data=new_data)
                    #new_perm = [{k: v for k, v in item.items() if k not in ('id', 'share_id')} for item in data['permissions'] if item['sid'] != 'S-1-1-0']
                    #for p in new_perm:
                    #    dstibox.api.post('shares/{}/permissions'.format(resp.get_result()['id']), data=p)



#def handle_perms(src, dst):
#    src_shares = src.api.get('shares')
#    dst_shares = dst.api.get('shares')
#    for share in src_shares:
#        for dst_shr in dst_sha:
#

    # range over src and dst permissions and create\modify\delete each permission according to source

def get_permission_dict(permissions):
    """Create a dict: SID -> access."""
    return {p['sid']: p for p in permissions}

def compare_permissions(src_perms, dst_perms):
    src_dict = get_permission_dict(src_perms)
    dst_dict = get_permission_dict(dst_perms)

    missing_in_dst = []
    access_mismatch = []

    for sid, src_perm in src_dict.items():
        if sid not in dst_dict:
            missing_in_dst.append(src_perm)
        elif dst_dict[sid]['access'] != src_perm['access']:
            access_mismatch.append({
                'sid': sid,
                'access': src_perm['access'],
                'dst_access': dst_dict[sid]['access'],
                'permission_id': dst_dict[sid]['id']
            })

    extra_in_dst = [dst_dict[sid] for sid in dst_dict if sid not in src_dict]
    return missing_in_dst, access_mismatch, extra_in_dst


def normalize_permissions(permissions):
    # Sort and normalize permissions for comparison
    return sorted(
        [{'sid': p['sid'], 'access': p['access']} for p in permissions],
        key=lambda x: (x['sid'], x['access'])
    )

def build_share_dict(data):
    # Build a dict mapping share name to its permissions
    return {share['name']: share for share in data['result']}

#def permissions_equal(perms1, perms2):
    # Compare normalized permission lists
#    return normalize_permissions(perms1) == normalize_permissions(perms2)

def sync_permissions(source_data, dest_data, update_permissions_func,dst):
    source_shares = build_share_dict(source_data)
    dest_shares = build_share_dict(dest_data)

    for name, src_share in source_shares.items():
        if name in dest_shares:
            dst_share = dest_shares[name]
            missing, mismatched, extra = compare_permissions(src_share['permissions'], dst_share['permissions'])
            if missing or mismatched:
                print(f"\nShare '{name}':")
                if missing:
                    print(f"  Missing permissions in destination: {missing}")
                if mismatched:
                    print(f"  Permissions with access mismatch: {mismatched}")
                update_permissions_func(dst_share['id'], missing, mismatched,dst)
            else:
                print(f"\nShare '{name}': Permissions are identical.")
            if extra:
                print(f"  Extra permissions in destination (not in source): {extra}")
                del_permission(dst_share['id'],extra,dst)
        else:
            print(f"\nShare '{name}' not found in destination.")

def update_permissions_func(share_id, to_add, to_modify,dst):
    """
    Implement your API call to update permissions for share_id.
    For demonstration, this just prints the actions.
    """
    for perm in to_add:
        print(f"Would add permission {perm} to share {share_id}")
        inc = {'sid','access'}
        p={k: perm[k] for k in inc}
        # Example API call: requests.post(f"/shares/{share_id}/permissions", json=perm)
        #new_perm = [{k: v for k, v in item.items() if k not in ('id', 'share_id')} for item in data['permissions'] if item['sid'] != 'S-1-1-0']
        dst.api.post('shares/{}/permissions'.format(share_id), data=p)
    for perm in to_modify:
        print(f"Would update SID {perm['sid']} on share {share_id} from {perm['dst_access']} to {perm['access']}")
        inc = {'access'}
        p={k: perm[k] for k in inc}
        dst.api.put("shares/{}/permissions/{}".format(share_id, perm['permission_id']), data=p)

def del_permission(share_id, to_delete, dst):
    for perm in to_delete:
        print(f"Would delete permission {perm}")
        dst.api.delete("shares/{}/permissions/{}".format(share_id, perm['id']))

def handle_perms(src, dst):
    src_shares = src.api.get('shares')
    dst_shares = dst.api.get('shares')
    sync_permissions(src_shares.get_json(), dst_shares.get_json(), update_permissions_func,dst)


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


def shares_deletion(fs_replica, srcibox, dstibox):
    for replica in fs_replica:
        dst_shares = dstibox.api.get('shares?filesystem_id={}'.format(replica.get_local_entity().id))
        for dst_sh in dst_shares.get_result():
            if srcibox.shares.safe_get(name=dst_sh['name'], filesystem_id=replica.get_remote_entity().id):
                continue
            else:
                sharedel = dstibox.shares.get(name=dst_sh['name'])
                sharedel.delete()





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
        for fs in fs_replica:
            if fs.get_local_entity().get_security_style() == 'UNIX':
                exports_creation(fs, srcibox, dstibox)
                shares_creation(fs, srcibox, dstibox)
            else:
                shares_creation(fs, srcibox, dstibox)
                exports_creation(fs, srcibox, dstibox)
        handle_perms(srcibox, dstibox)
        exports_deletion(fs_replica, srcibox, dstibox)
        shares_deletion(fs_replica, srcibox, dstibox)
        print('{}: Completed Successfully'.format(datetime.now().strftime('%D %H:%M:%S')))
        iboxevent(dstibox, "script {} run from {}".format(os.path.basename(__file__), socket.gethostname()))
    else:
        print("ERROR: Credentials File Not Found")
        exit(1)
