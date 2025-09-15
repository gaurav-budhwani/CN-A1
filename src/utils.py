"""
utility helpers for parsing the custom header and applying the rule selection logic.
what has been done:
- parse_custom_header(header_bytes)
- find_time_period(hour, rules)
- select_ip_for_header(header_str, rules)
"""
from datetime import datetime, time

def parse_custom_header(header_bytes: bytes) -> dict:
    """
    parse the 8-byte custom header (ASCII) format HHMMSSID.
    returns a dict with keys: hour, minute, second, id, raw_header.
    raises ValueError if format invalid.
    """
    if len(header_bytes) != 8:
        raise ValueError("Header must be 8 bytes")
    header = header_bytes.decode('ascii')
    hh = int(header[0:2])
    mm = int(header[2:4])
    ss = int(header[4:6])
    sid = int(header[6:8])
    return {"hour": hh, "minute": mm, "second": ss, "id": sid, "raw": header}


def _time_from_hhmm(hhmm: str) -> time:
    """Return a datetime.time object from 'HH:MM' string"""
    h, m = hhmm.split(':')
    return time(int(h), int(m))


def find_time_period(hour: int, rules: dict) -> str:
    """
    using rules['timestamp_rules']['time_based_routing'],
    to determine which period (morning/afternoon/night) the hour falls in.
    handling the night wrap-around (e.g., 20:00-03:59).
    returns the key name (e.g., 'morning').
    """
    tbr = rules['timestamp_rules']['time_based_routing']
    for name, cfg in tbr.items():
        tr = cfg['time_range']
        start_str, end_str = tr.split('-')
        start = _time_from_hhmm(start_str)
        end = _time_from_hhmm(end_str)
        h_time = time(hour, 0)
        if start <= end:
            if start <= h_time <= end:
                return name
        else:
            # wraps around midnight (e.g., 20:00 - 03:59)
            if h_time >= start or h_time <= end:
                return name
    raise ValueError("No matching time period for hour {}".format(hour))


def select_ip_for_header(header_str: str, rules: dict) -> str:
    """
    given header_str 'HHMMSSID' and rules (loaded from rules.json),
    return the selected IP as per the selection algorithm.
    process:
    1. parse hour and id.
    2. find time period (morning/afternoon/night).
    3. use id % hash_mod to select offset within the 5-entry block.
    4. return rules['ip_pool'][ip_pool_start + offset]
    """
    h = int(header_str[0:2])
    sid = int(header_str[6:8])
    period_name = find_time_period(h, rules)
    p_cfg = rules['timestamp_rules']['time_based_routing'][period_name]
    hash_mod = int(p_cfg['hash_mod'])
    pool_start = int(p_cfg['ip_pool_start'])
    offset = sid % hash_mod
    final_index = pool_start + offset
    ip_pool = rules['ip_pool']
    if final_index < 0 or final_index >= len(ip_pool):
        raise IndexError("Computed IP index out of range: {}".format(final_index))
    return ip_pool[final_index]
