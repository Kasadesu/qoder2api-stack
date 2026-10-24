#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Comprehensive test suite for Qoder check-in scheduler and jitter logic."""
import importlib.util
import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
MODULE_PATH = os.path.join(os.path.dirname(HERE), "qoder-admin.py")

FAILS = []


def check(cond, label, extra=""):
    status = "OK" if cond else "FAIL"
    print(f"{label:<55} {status}" + (f"  ({extra})" if extra else ""))
    if not cond:
        FAILS.append(label)


def load_admin_module():
    spec = importlib.util.spec_from_file_location("qoder_admin_schedule_test", MODULE_PATH)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def make_time(hour, minute, year=2026, month=10, day=24):
    return time.struct_time((year, month, day, hour, minute, 0, 5, 297, 0))


def main():
    print("Testing Qoder Scheduler, Times Normalization & Jitter Logic...\n")
    adm = load_admin_module()

    # 1. Normalization of time strings
    times = adm._qoder_norm_times(["10:05", "21:30"])
    check(times == ["10:05", "21:30"], "Standard HH:MM times preserved and sorted")

    times_mix = adm._qoder_norm_times(["9", 21, "08:15", "9:00"])
    check(times_mix == ["08:15", "09:00", "21:00"], "Integer and single-digit hours normalized and deduplicated")

    try:
        adm._qoder_norm_times(["25:00"])
        check(False, "Out of bound hour rejected")
    except ValueError:
        check(True, "Out of bound hour correctly rejected with ValueError")

    try:
        adm._qoder_norm_times(["12:60"])
        check(False, "Out of bound minute rejected")
    except ValueError:
        check(True, "Out of bound minute correctly rejected with ValueError")

    try:
        adm._qoder_norm_times(["invalid-format"])
        check(False, "Invalid format string rejected")
    except ValueError:
        check(True, "Invalid format string correctly rejected with ValueError")

    # 2. Next run timestamp calculation
    base_t = make_time(9, 30)  # 09:30
    nxt = adm._qoder_next_run(["10:05", "21:30"], now=base_t)
    check(nxt.endswith("10:05"), "Next run picks subsequent time slot on the same day", nxt)

    base_t2 = make_time(22, 00)  # 22:00
    nxt2 = adm._qoder_next_run(["10:05", "21:30"], now=base_t2)
    check(nxt2.endswith("10:05") and "2026-10-25" in nxt2, "Next run wraps around across midnight to next day", nxt2)

    # Exact match moment should roll to the next schedule
    base_exact = make_time(10, 5)  # 10:05
    nxt_exact = adm._qoder_next_run(["10:05", "21:30"], now=base_exact)
    check(nxt_exact.endswith("21:30"), "Current minute considered passed; advances to next slot", nxt_exact)

    # 3. Due check pure function (_qoder_schedule_due)
    cfg = {"enabled": True, "times": ["10:05", "21:30"], "jitter_minutes": 5}

    # Enabled / disabled flag
    check(not adm._qoder_schedule_due({"enabled": False, "times": ["10:05"]}, make_time(10, 5)), "Disabled schedule never triggers")

    # Zero jitter exact match
    check(adm._qoder_schedule_due(cfg, make_time(10, 5), jitter_offset=0), "Due triggers on exact scheduled minute with zero jitter")
    check(not adm._qoder_schedule_due(cfg, make_time(10, 6), jitter_offset=0), "Due does not trigger on different minute with zero jitter")

    # Jitter offset handling
    # If scheduled time is 10:05 and jitter is 3 minutes, it should trigger at 10:08 (10:08 - 3min = 10:05)
    check(adm._qoder_schedule_due(cfg, make_time(10, 8), jitter_offset=3), "Triggers exactly at scheduled time plus jitter offset")
    check(not adm._qoder_schedule_due(cfg, make_time(10, 5), jitter_offset=3), "Does not trigger before jitter offset has elapsed")

    # Evening slot jitter check
    check(adm._qoder_schedule_due(cfg, make_time(21, 35), jitter_offset=5), "Evening slot triggers at 21:35 when jitter is 5 minutes")

    if FAILS:
        print(f"\nFailed tests ({len(FAILS)}): {FAILS}")
        return 1
    print("\nAll tests passed successfully.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
