#!/usr/bin/env python3
"""YakMobile v2: strictly local, read-only Yaklang gRPC integration milestone.

Only a small allowlist of audited RPC methods can ever be invoked. This script
is NOT an HTTP API and cannot execute arbitrary user-supplied Yaklang scripts.
"""
import argparse
import importlib
import json
import socket
import sys
import time
from pathlib import Path

# These RPCs query data, never create tasks, start proxies or execute plugins.
READ_RPC = frozenset({
    'GetBasicInfo', 'QueryHTTPFlows', 'QueryYakScript', 'QueryRisks',
    'QueryPorts', 'QueryHistoryHTTPFuzzerTask', 'QueryRiskTags',
})

# Presence means only 'method defined in protocol' until a live call succeeds.
MODULE_METHODS = {
    'engine': ('GetBasicInfo',),
    'traffic_history': ('QueryHTTPFlows',),
    'plugins_catalog': ('QueryYakScript',),
    'vulnerability_findings': ('QueryRisks',),
    'network_inventory': ('QueryPorts',),
    'fuzzer_history': ('QueryHistoryHTTPFuzzerTask',),
    'mitm_proxy': ('MITM',),
    'http_fuzzer': ('HTTPFuzzer',),
    'hybrid_vulnerability_scan': ('HybridScan',),
    'plugin_execution': ('ExecYakScript', 'DebugPlugin'),
    'script_console': ('Exec',),
    'http_repeater': ('HTTPFuzzer',),
    'asset_discovery': ('SimpleDetect',),
    'risk_management': ('QueryRisks',),
    'plugin_search': ('QueryYakScript',),
    'reporting': ('QueryReports',),
    'cve_database': ('QueryCVE',),
}


def load_protocol(root):
    root = Path(root)
    if not (root / 'yakgrpc_pb2.py').is_file():
        raise RuntimeError('Missing generated Yaklang protocol. Run install.sh first.')
    sys.path.insert(0, str(root))
    import grpc  # pylint: disable=import-outside-toplevel
    from google.protobuf import message_factory  # pylint: disable=import-outside-toplevel
    from google.protobuf.json_format import MessageToDict  # pylint: disable=import-outside-toplevel
    pb = importlib.import_module('yakgrpc_pb2')
    services = list(pb.DESCRIPTOR.services_by_name.values())
    service = next((s for s in services if s.name == 'Yak'), None)
    if service is None:
        raise RuntimeError('Protocol lacks service Yak; refusing to use guessed RPC names.')
    return grpc, message_factory, MessageToDict, service


def catalogue(service):
    names = {m.name: m for m in service.methods}
    return {
        key: {
            'methods': [n for n in expected if n in names],
            'missing': [n for n in expected if n not in names],
            'declared': any(n in names for n in expected),
            'verified_running': False,
        }
        for key, expected in MODULE_METHODS.items()
    }


def set_small_pagination(request):
    """Set conservative paging, regardless of proto version's field casing."""
    for field in request.DESCRIPTOR.fields:
        if field.name.lower() not in ('pagination', 'paging'):
            continue
        if field.message_type is None:
            continue
        page = getattr(request, field.name)
        for sub in page.DESCRIPTOR.fields:
            key = sub.name.lower()
            if key in ('page', 'pagenum', 'pagenumber', 'currentpage') and sub.cpp_type in (1, 2, 3, 4):
                setattr(page, sub.name, 1)
            if key in ('limit', 'pagesize', 'size', 'perpage') and sub.cpp_type in (1, 2, 3, 4):
                setattr(page, sub.name, 5)
        return


def sanitize_response(message):
    """Return statistics, NOT raw captured HTTP packets, secrets or plugin source."""
    stats = {'response_type': message.DESCRIPTOR.full_name}
    for field, value in message.ListFields():
        name = field.name.lower()
        if field.is_repeated:
            stats[field.name + '_count'] = len(value)
        elif name in ('total', 'count') and isinstance(value, int):
            stats[field.name] = value
        elif name in ('version', 'engineversion') and isinstance(value, str):
            stats[field.name] = value[:100]
        else:
            stats[field.name + '_present'] = True
    return stats


def invoke_read(grpc, factory, service, rpc_name, target='127.0.0.1:9999', timeout=5):
    if rpc_name not in READ_RPC:
        raise ValueError('RPC is not in the audited read-only allowlist.')
    method = next((m for m in service.methods if m.name == rpc_name), None)
    if method is None:
        return {'rpc': rpc_name, 'status': 'not_in_protocol'}
    if method.client_streaming or method.server_streaming:
        return {'rpc': rpc_name, 'status': 'streaming_not_exposed'}
    if target != '127.0.0.1:9999':
        raise ValueError('This bridge only talks to the local Yaklang engine.')
    request_type = factory.GetMessageClass(method.input_type)
    response_type = factory.GetMessageClass(method.output_type)
    request = request_type()
    set_small_pagination(request)
    address = '/' + service.full_name + '/' + rpc_name
    start = time.monotonic()
    with grpc.insecure_channel(target, options=[('grpc.max_receive_message_length', 1024 * 1024)]) as channel:
        call = channel.unary_unary(address, request_serializer=request.SerializeToString,
                                   response_deserializer=response_type.FromString)
        try:
            resp = call(request, timeout=timeout)
            return {'rpc': rpc_name, 'status': 'verified',
                    'duration_ms': round((time.monotonic()-start)*1000),
                    'data': sanitize_response(resp)}
        except grpc.RpcError as exc:
            return {'rpc': rpc_name, 'status': 'rpc_error', 'grpc_code': exc.code().name}


def main():
    parser = argparse.ArgumentParser(description='Yaklang read-only protocol compatibility check')
    parser.add_argument('--proto-dir', default='/opt/yakmobile-v2-bridge/protos')
    parser.add_argument('--command', choices=('doctor', 'catalogue', 'probe'), default='doctor')
    parser.add_argument('--rpc', choices=sorted(READ_RPC), default='GetBasicInfo')
    args = parser.parse_args()
    grpc, factory, _, service = load_protocol(args.proto_dir)
    payload = {'bridge': 'YakMobile v2 engine integration', 'mode': args.command,
               'service': service.full_name, 'method_count': len(service.methods)}
    if args.command == 'catalogue':
        payload['modules'] = catalogue(service)
    elif args.command == 'doctor':
        payload['methods_found'] = sorted(x for x in READ_RPC if any(m.name == x for m in service.methods))
        try:
            with socket.create_connection(('127.0.0.1', 9999), 3):
                payload['listener'] = 'reachable'
        except OSError:
            payload['listener'] = 'unreachable'
        payload['read_only_probe'] = invoke_read(grpc, factory, service, 'GetBasicInfo')
    else:
        payload['read_only_probe'] = invoke_read(grpc, factory, service, args.rpc)
    print(json.dumps(payload, indent=2, sort_keys=True))

if __name__ == '__main__':
    main()
