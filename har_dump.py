"""
This inline script can be used to dump flows as HAR files.

example cmdline invocation:
mitmdump -s ./har_dump.py --set hardump=./dump.har

filename endwith '.zhar' will be compressed:
mitmdump -s ./har_dump.py --set hardump=./dump.zhar
"""


import json
import zlib
import os
import typing  # noqa

from datetime import datetime
from datetime import timezone

import mitmproxy

from mitmproxy import connection
from mitmproxy import ctx

HAR: typing.Dict = {}

# A list of server seen till now is maintained so we can avoid
# using 'connect' time for entries that use an existing connection.
SERVERS_SEEN: typing.Set[connection.Server] = set()


def tls_clienthello(data: mitmproxy.proxy.layers.tls.ClientHelloData):

    #print(f'SNI: {data.context.client.sni}')
    #ctx.log(f"tls_clienthello: {data=}")
    tdelta = (float(datetime.timestamp(datetime.now())) -
              float(ctx.options.timestamp)) * 1000

    entry = {
        "request": {
            "timestamp": round(tdelta),
            "proto": "tls",
            "remote_ip": f'{data.context.server.address[0]}:{data.context.server.address[1]}',
            "tls_sni": data.context.client.sni,
            "http_request_url": "",
            "http_request_method": "",
            "http_request_body_length": "",
            "http_response_status": "",
            "http_response_body_length": "",
        },
    }

    HAR["requests"].append(entry)


def load(l):
    l.add_option(
        "hardump", str, "", "HAR dump path.",
    )
    l.add_option(
        "timestamp", str, "", "Time from the app startup (ms).",
    )


def configure(updated):
    HAR.update({
        "requests": []
    })


def response(flow: mitmproxy.http.HTTPFlow):
    """
       Called when a server response has been received.
    """

    # -1 indicates that these values do not apply to current request
    ssl_time = -1
    connect_time = -1

    if flow.server_conn and flow.server_conn not in SERVERS_SEEN:
        connect_time = (flow.server_conn.timestamp_tcp_setup -
                        flow.server_conn.timestamp_start)

        if flow.server_conn.timestamp_tls_setup is not None:
            ssl_time = (flow.server_conn.timestamp_tls_setup -
                        flow.server_conn.timestamp_tcp_setup)

        SERVERS_SEEN.add(flow.server_conn)

    # Calculate raw timings from timestamps. DNS timings can not be calculated
    # for lack of a way to measure it. The same goes for HAR blocked.
    # mitmproxy will open a server connection as soon as it receives the host
    # and port from the client connection. So, the time spent waiting is actually
    # spent waiting between request.timestamp_end and response.timestamp_start
    # thus it correlates to HAR wait instead.
    timings_raw = {
        'send': flow.request.timestamp_end - flow.request.timestamp_start,
        'receive': flow.response.timestamp_end - flow.response.timestamp_start,
        'wait': flow.response.timestamp_start - flow.request.timestamp_end,
        'connect': connect_time,
        'ssl': ssl_time,
    }

    # HAR timings are integers in ms, so we re-encode the raw timings to that format.
    timings = {
        k: int(1000 * v) if v != -1 else -1
        for k, v in timings_raw.items()
    }

    # full_time is the sum of all timings.
    # Timings set to -1 will be ignored as per spec.
    full_time = sum(v for v in timings.values() if v > -1)

    started_date_time = datetime.fromtimestamp(
        flow.request.timestamp_start, timezone.utc).isoformat()

    # Response body size and encoding
    response_body_size = len(
        flow.response.raw_content) if flow.response.raw_content else 0
    response_body_decoded_size = len(
        flow.response.content) if flow.response.content else 0
    response_body_compression = response_body_decoded_size - response_body_size

    tdelta = (float(datetime.timestamp(datetime.now())) -
              float(ctx.options.timestamp)) * 1000

    entry = {
        "request": {
            "timestamp": round(tdelta),
            "proto": flow.request.http_version,
            "remote_ip": str(flow.server_conn.peername[0]),
            "tls_sni": "",
            "http_request_url": flow.request.url,
            "http_request_method": flow.request.method,
            "http_request_body_length": len(flow.request.content),
            "http_response_status": flow.response.status_code,
            "http_response_body_length": response_body_size,
        },
    }

    HAR["requests"].append(entry)


def done():
    """
        Called once on script shutdown, after any other events.
    """
    if ctx.options.hardump:
        json_dump: str = json.dumps(HAR, indent=2)

        if ctx.options.hardump == '-':
            mitmproxy.ctx.log(json_dump)
        else:
            raw: bytes = json_dump.encode()
            if ctx.options.hardump.endswith('.zhar'):
                raw = zlib.compress(raw, 9)

            with open(os.path.expanduser(ctx.options.hardump), "wb") as f:
                f.write(raw)

            mitmproxy.ctx.log(
                "HAR dump finished (wrote %s bytes to file)" % len(json_dump))


def name_value(obj):
    """
        Convert (key, value) pairs to HAR format.
    """
    return [{"name": k, "value": v} for k, v in obj.items()]
