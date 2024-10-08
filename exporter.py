#! /usr/bin/python3

import argparse
import asyncio
import json
from asyncio.subprocess import PIPE

import aiorun
from aiohttp import web
from prometheus_client import REGISTRY, Counter, Gauge, generate_latest

RDP_PACKET_COUNT = Counter(
    'rdp_packet_count',
    'Number of packets RDP',
    ['ip_src', 'ip_dst'],
)

RDP_PACKET_BYTES = Counter(
    'rdp_packet_bytes',
    'Number of bytes of RDP payload',
    ['ip_src', 'ip_dst'],
)

RDP_DROP_COUNT = Counter(
    'rdp_drop_count',
    'Number of packets rdp dropped',
    ['ip_src', 'ip_dst'],
)

RDP_RTT_GAUGE  = Gauge(
    'rdp_rtt_seconds', 'Round-Trip Time for RDP requests',
    ['ip_src', 'ip_dst']
)

TSHARK_CMD = 'tshark -i ens3 -f "tcp and tcp port 3389"'
def convert_cmd_to_bytes(cmd):
    import shlex
    cmd_list = shlex.split(cmd)
    byte_cmd = [s.encode() for s in cmd_list]
    return byte_cmd

async def rdp_drop_packet_metrics():
    cmd = f'{TSHARK_CMD} -T ek -Y "tcp.analysis.retransmission"'
    process = await asyncio.create_subprocess_exec(*convert_cmd_to_bytes(cmd), stdout=PIPE)

    while True:
        try:
            line = await process.stdout.readline()
            event = json.loads(line)

            # We are only interested in valid data
            if 'timestamp' not in event:
                continue

            if 'layers' not in event or 'ip' not in event['layers']:
                continue

            labels = (
                event['layers']['ip']['ip_ip_src'],
                event['layers']['ip']['ip_ip_dst'],
            )

            RDP_DROP_COUNT.labels(*labels).inc()
        except ValueError:
            continue

async def rdp_packet_metrics():
    cmd = f'{TSHARK_CMD} -T ek -Y "tcp.len != 0"'
    process = await asyncio.create_subprocess_exec(*convert_cmd_to_bytes(cmd), stdout=PIPE)

    while True:
        try:
            line = await process.stdout.readline()
            event = json.loads(line)

            if 'timestamp' not in event or 'layers' not in event or 'ip' not in event['layers']:
                continue

            tcp_len = int(event['layers']['tcp']['tcp_tcp_len'])
            if tcp_len > 0:
                labels = (
                    event['layers']['ip']['ip_ip_src'],
                    event['layers']['ip']['ip_ip_dst'],
                )

                RDP_PACKET_COUNT.labels(*labels).inc()
                RDP_PACKET_BYTES.labels(*labels).inc(tcp_len)
        except ValueError:
            continue

packets_captured = {}
rtt_values = {}
async def rdp_rtt_metrics():
    async def collect():
        cmd = f'{TSHARK_CMD} -T fields -e frame.time_relative -e ip.src -e ip.dst -e tcp.seq -e tcp.ack -e tcp.len'
        process = await asyncio.create_subprocess_exec(*convert_cmd_to_bytes(cmd), stdout=PIPE)

        while True:
            try:
                line = await process.stdout.readline()
                if not line:
                    break

                fields = line.decode('utf-8').strip().split()
                if len(fields) != 6:
                    continue

                cur_frame_time_relative = float(fields[0])
                ip_src = fields[1]
                ip_dst = fields[2]
                cur_tcp_seq = int(fields[3])
                cur_tcp_ack = int(fields[4])
                cur_tcp_len = int(fields[5])

                if cur_tcp_len != 0:
                    if (ip_src, ip_dst) not in packets_captured:
                        packets_captured[(ip_src, ip_dst)] = {}
                    packets_captured[(ip_src, ip_dst)][cur_tcp_seq] = cur_frame_time_relative 
                else:
                    if (ip_dst, ip_src) not in packets_captured:
                        continue
                    to_remove = []
                    # mark acknowledged
                    for tcp_seq, time_relative in sorted(packets_captured[(ip_dst, ip_src)].items()):
                        if tcp_seq < cur_tcp_ack:
                            rtt = cur_frame_time_relative - time_relative
                            if (ip_dst, ip_src) not in rtt_values:
                                rtt_values[(ip_dst, ip_src)] = []

                            rtt_values[(ip_dst, ip_src)].append(rtt)
                            to_remove.append(tcp_seq)
                        else:
                            break
                    for seq in to_remove:
                        del packets_captured[(ip_dst, ip_src)][seq]
            except Exception as e:
                print(f"Error: {e}")
                continue

    async def set_metric():
        while True:
            for (src, dst), rtt_val in rtt_values.items():
                if len(rtt_val) != 0:
                    avg_rtt = sum(rtt_val) / len(rtt_val)
                else:
                    avg_rtt = 0
                    
                RDP_RTT_GAUGE.labels(src, dst).set(avg_rtt)
                rtt_values[(src, dst)] = []

            await asyncio.sleep(10)

    await asyncio.gather(
        collect(),
        set_metric()
    )

async def tshark_watcher(args):
    print('Spawning tshark')
    await asyncio.gather(
        rdp_drop_packet_metrics(),
        rdp_packet_metrics(),
        rdp_rtt_metrics(),
    )


async def metrics(request):
    data = generate_latest(REGISTRY)
    return web.Response(text=data.decode('utf-8'), content_type='text/plain', charset='utf-8')


async def start_metrics_server(host, port):
    app = web.Application()
    app.router.add_get('/metrics', metrics)

    runner = web.AppRunner(app, access_log=None)
    await runner.setup()

    site = web.TCPSite(runner, host, port)

    await site.start()

    return runner


async def main():
    parser = argparse.ArgumentParser(prog='tshark-exporter')
    parser.add_argument('--export', default='0.0.0.0:9431')
    args, unknown = parser.parse_known_args()

    metrics = await start_metrics_server(*args.export.split(':'))

    try:
        await tshark_watcher(unknown)
    except Exception as e:
        print(e)

    await metrics.shutdown()


if __name__ == '__main__':
    aiorun.run(main())
