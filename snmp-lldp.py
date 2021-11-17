import argparse
import itertools
import os
import pprint
import sqlite3
import sys

import pysnmp.hlapi as hlapi
import pysnmp.proto.rfc1902 as rfc1902
from pysnmp.hlapi import *

NEIGHBOUR_PORT_OID = '1.0.8802.1.1.2.1.4.1.1.8.0'
NEIGHBOUR_NAME_OID = '1.0.8802.1.1.2.1.4.1.1.9'
PARENT_NAME_OID = '1.0.8802.1.1.2.1.3.3'


def snmp_walk(host, oid, format='str', strip_prefix=True, community='public'):
    res = []
    for (errorIndication,
         errorStatus,
         errorIndex,
         varBinds) in hlapi.nextCmd(hlapi.SnmpEngine(),
                                    hlapi.CommunityData(community),
                                    hlapi.UdpTransportTarget((host, 161), timeout=4.0, retries=3),
                                    hlapi.ContextData(),
                                    hlapi.ObjectType(hlapi.ObjectIdentity(oid)),
                                    lookupMib=False,
                                    lexicographicMode=False):
        if errorIndication:
            raise ConnectionError(f'SNMP error: "{str(errorIndication)}". Status={str(errorStatus)}')
        elif errorStatus:
            raise ConnectionError('errorStatus: %s at %s' % (errorStatus.prettyPrint(),
                                                             errorIndex and varBinds[int(errorIndex) - 1][0] or '?'))
        else:
            for x in varBinds:
                k, v = x
                if strip_prefix:
                    k = str(k)[len(str(oid)) + 1:]
                if isinstance(v, rfc1902.Integer):
                    res.append((str(k), int(v)))
                else:
                    if format == 'numbers':
                        res.append((str(k), v.asNumbers()))
                    elif format == 'hex':
                        res.append((str(k), v.asOctets().hex()))
                    elif format == 'raw':
                        res.append((str(k), v))
                    elif format == 'bin':
                        res.append((str(k), v.asOctets()))
                    elif format == 'int':
                        res.append((str(k), int(v)))
                    elif format == 'preview':
                        res.append((str(k), str(v)))
                    elif format == 'any':
                        try:
                            res.append((str(k), v.asOctets().decode('utf-8')))
                        except UnicodeDecodeError:
                            res.append((str(k), '0x' + v.asOctets().hex()))
                    elif format == 'str':
                        res.append((str(k), v.asOctets().decode(v.encoding)))
                    else:
                        assert False, "Unknown format for walk()."
    res = {a: b for a, b in res}
    return res


def read_id_from_oid_tail(oid, with_len=True):
    parts = [int(x) for x in oid.split('.')]
    if with_len:
        assert (parts[-5] == 3)  # number of elements
    return '.'.join([str(x) for x in parts[-2:-1]])


class MissingOidParameter(Exception):
    """
    Custom exception used when the OID is missing.
    """
    pass


def is_file_valid(filepath):
    """
    Check if a file exists or not.

    Args:
        filepath (str): Path to the switches file
    Returns:
        filepath or raise exception if invalid
    """

    if not os.path.exists(filepath):
        raise ValueError('Invalid filepath')
    return filepath


def get_cli_arguments():
    """
    Simple command line parser function.
    """

    parser = argparse.ArgumentParser(description="")
    parser.add_argument(
        '-f',
        '--file',
        type=is_file_valid,
        help='Path to the switches file'
    )
    return parser


def get_switches_from_file():
    """Return data as a list from a file.

    The file format is the following:

    community_string1, snmp_port1, ip1
    community_string2, snmp_port2, ip2
    community_string3, snmp_port3, ip3

    The output:

    [
        {"community": "community_string1", "snmp_port": "snmp_port1", "ip": "ip1"},
        {"community": "community_string2", "snmp_port": "snmp_port2", "ip": "ip2"},
        {"community": "community_string3", "snmp_port": "snmp_port3", "ip": "ip3"},
    ]
    """

    args = get_cli_arguments().parse_args()
    switches_info = []
    with open(args.file) as switches_info_fp:
        for line in switches_info_fp:
            line = line.rstrip().split(',')
            switches_info.append({
                'community': line[0].strip(),
                'snmp_port': line[1].strip(),
                'ip': line[2].strip(),
            })
    return switches_info


def parse_neighbours_ports_result(result):
    """
    One line of result looks like this:

    result = iso.0.8802.1.1.2.1.4.1.1.8.0.2.3 = 2

    Where the last "2" from the OID is the local port and the value
    after '=' is the remote port (2)
    """
    if not result:
        raise MissingOidParameter('No OID provided.')

    value = result.split(' = ')
    if not value:
        return 'Missing entire value for OID={}'.format(result)
    else:
        oid, port = value
        local_port = re.search(r'{}\.(\d+)'.format(NEIGHBOUR_PORT_OID[2:]), oid).group(1)

        if port:
            remote_port = re.search(r'(\d+)', port).group(1)
        else:
            remote_port = 'Unknown'

    return 'local_port', local_port, 'remote_port', remote_port


def parse_parent_name(result):
    """
    One line of result looks like this:

    result = iso.0.8802.1.1.2.1.3.3.0 = Switch01

    The name of the parent is "Switch01"
    """

    if not result:
        raise MissingOidParameter('No OID provided.')

    value = result.split(' = ')
    if not value:
        return 'Missing entire value for OID={}'.format(result)
    else:
        return 'Unknown' if not value[-1] else value[-1]


def parse_neighbour_names_results(result):
    """
    One line of result looks like this:

    result = iso.0.8802.1.1.2.1.4.1.1.9.0.2.3 = HP-2920-24G

    The name of the parent is "Switch01"
    """

    if not result:
        raise MissingOidParameter('No OID provided.')

    value = result.split(' = ')
    if not value:
        return 'Missing entire value for OID={}'.format(result)
    else:
        return ('name', 'Unknown') if not value[-1] else ('name', value[-1])


def main():
    con = sqlite3.connect(':memory:')
    cursorObj = con.cursor()
    cursorObj.execute("CREATE TABLE lldpLocSysName(LocSysName text PRIMARY KEY)")
    con.commit()

    cursorObj.execute(
        "CREATE TABLE lldpLocPortId(LocSysName text,id text, LocPortId text, primary key (LocSysName,id) )")
    con.commit()

    cursorObj.execute(
        "CREATE TABLE lldpRemPortId(LocSysName text,RemSysName text,id text, RemPortId text, primary key (LocSysName,RemSysName,id) )")
    con.commit()

    data = {}
    switches_filedata = get_switches_from_file()

    for switch in switches_filedata:
        community = switch.get('community')
        snmp_port = switch.get('snmp_port')
        ip = switch.get('ip')
        # Read lldpLocSysName table
        print(" - Reading device lldpLocSysName table...", file=sys.stderr)
        lldpLocSysName = snmp_walk(ip, '1.0.8802.1.1.2.1.3.3', 'str', community=community)
        gLocSysName = ''
        for id, LocSysName in lldpLocSysName.items():
            print('id=', id)
            print('LocSysName=', LocSysName)
            gLocSysName = LocSysName
            cursorObj.execute("INSERT INTO lldpLocSysName VALUES('" + LocSysName + "')")
            con.commit()

        cursorObj.execute('SELECT * FROM lldpLocSysName')

        rows = cursorObj.fetchall()

        for row in rows:
            print(row)

        print(" - Reading device lldpLocPortId  table...", file=sys.stderr)
        lldpLocPortId = snmp_walk(ip, '1.0.8802.1.1.2.1.3.7.1.3', 'str', community=community)
        for id, LocPortId in lldpLocPortId.items():
            print('id=', id)
            print('LocPortId=', LocPortId)
            print(gLocSysName)
            cursorObj.execute(
                "INSERT INTO lldpLocPortId VALUES('" + gLocSysName + "','" + id + "','" + LocPortId + "')")
            con.commit()
        cursorObj.execute('SELECT * FROM lldpLocPortId')

        rows = cursorObj.fetchall()

        for row in rows:
            print(row)

        print(" - Reading device lldpRemSysName table...", file=sys.stderr)
        lldpRemSysName = snmp_walk(ip, '1.0.8802.1.1.2.1.4.1.1.9', 'str', community=community)
        for id, RemSysName in lldpRemSysName.items():
            print('id=', read_id_from_oid_tail(id, with_len=False))
            print('RemSysName=', RemSysName)
            cursorObj.execute(
                "INSERT INTO lldpRemPortId VALUES('" + gLocSysName + "','" + RemSysName + "','" + read_id_from_oid_tail(
                    id, with_len=False) + "','')")
            con.commit()

            print(" - Reading device lldpRemPortId table...", file=sys.stderr)
            lldpRemPortId = snmp_walk(ip, '1.0.8802.1.1.2.1.4.1.1.7', 'str', community=community)
            for id, RemPortId in lldpRemPortId.items():
                print('id=', read_id_from_oid_tail(id, with_len=False))
                print('RemPortId=', RemPortId)
                cursorObj.execute(
                    "UPDATE lldpRemPortId SET RemPortId='" + RemPortId + "' where LocSysName='" + gLocSysName + "' and RemSysName='" + RemSysName + "' and id='" + read_id_from_oid_tail(
                        id, with_len=False) + "'")
                con.commit()
            cursorObj.execute('SELECT * FROM lldpRemPortId')
            rows = cursorObj.fetchall()

            for row in rows:
                print(row)

        cursorObj.execute('SELECT * FROM lldpRemPortId')
        rows = cursorObj.fetchall()

        for row in rows:
            print(row)

        cursorObj.execute(
            'SELECT r.LocSysName,l.LocPortId,r.RemSysName,r.RemPortId FROM lldpRemPortId r,lldpLocPortId l where r.LocSysName=l.LocSysName and r.id=l.id and r.RemSysName in (SELECT * FROM lldpLocSysName)')
        rows = cursorObj.fetchall()
        dictLocRem = {}
        for row in rows:
            print(row)

            print('sorted:', sorted(row))
            dictLocRem[tuple(sorted(row))] = row
        print('dedup:\n')
        print(dictLocRem)
        print('dedup values:\n')
        for value in dictLocRem.values():
            print(value)

        name = ''
        for (error_indication, error_status, error_index, var_binds) in nextCmd(
                SnmpEngine(),
                CommunityData(community),
                UdpTransportTarget((ip, snmp_port)),
                ContextData(),
                ObjectType(ObjectIdentity(PARENT_NAME_OID)),
                lexicographicMode=False
        ):
            # this should always return one result
            name = parse_parent_name(str(var_binds[0]))

        if not name:
            print('Could not retrieve name of switch. Moving to the next one...')
            continue

        neighbour_names = []
        neighbour_local_remote_ports = []

        for (error_indication, error_status, error_index, var_binds) in nextCmd(
                SnmpEngine(),
                CommunityData(community),
                UdpTransportTarget((ip, snmp_port)),
                ContextData(),
                ObjectType(ObjectIdentity(NEIGHBOUR_NAME_OID)),
                lexicographicMode=False
        ):
            for var_bind in var_binds:
                neighbour_names.append(
                    parse_neighbour_names_results(str(var_bind))
                )

        for (error_indication, error_status, error_index, var_binds) in nextCmd(
                SnmpEngine(),
                CommunityData(community),
                UdpTransportTarget((ip, snmp_port)),
                ContextData(),
                ObjectType(ObjectIdentity(NEIGHBOUR_PORT_OID)),
                lexicographicMode=False
        ):
            for var_bind in var_binds:
                neighbour_local_remote_ports.append(
                    parse_neighbours_ports_result(str(var_bind))
                )

        neighbours = []
        for a, b in itertools.zip_longest(
                neighbour_names,
                neighbour_local_remote_ports,
                fillvalue='unknown'
        ):
            neighbours.append({
                a[0]: a[1],
                b[0]: b[1],
                b[2]: b[3]
            })

        data[name] = {
            'ip': ip,
            'neighbors': neighbours
        }
    strnodes = ''
    cursorObj.execute('SELECT * FROM lldpLocSysName')

    rows = cursorObj.fetchall()

    for row in rows:
        print(row[0])
        strnodes = strnodes + "{id: '" + row[0] + "', label: '" + row[0] + "'},"

    print(strnodes)

    stredges = ''
    cursorObj.execute(
        'SELECT r.LocSysName,l.LocPortId,r.RemSysName,r.RemPortId FROM lldpRemPortId r,lldpLocPortId l where r.LocSysName=l.LocSysName and r.id=l.id and r.RemSysName in (SELECT * FROM lldpLocSysName)')
    rows = cursorObj.fetchall()
    dictLocRem = {}
    for row in rows:
        print(row)

        print('sorted:', sorted(row))
        dictLocRem[tuple(sorted(row))] = row
    print('dedup:\n')
    print(dictLocRem)
    print('dedup values:\n')
    for row in dictLocRem.values():
        print(row)
        stredges = stredges + "{from: '" + row[0] + "', to: '" + row[2] + "', label: '" + "1G" + "', labelFrom: '" + \
                   row[1] + "', labelTo: '" + row[3] + "', arrows: '" + "from,to" + "'},"
    print(stredges)
    return data


if __name__ == '__main__':
    all_data = main()
    pprint.pprint(all_data, indent=4)
