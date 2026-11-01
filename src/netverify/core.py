import http.client
import struct

RANK = {"skip": 0, "ok": 1, "warn": 2, "fail": 3}


def finding(check, status, summary, details=None):
    return {"check": check, "status": status, "summary": summary, "details": details or {}}


def worst(statuses):
    statuses = list(statuses)
    return max(statuses, key=RANK.get) if statuses else "skip"


def attempt(function, *args):
    try:
        return function(*args)
    except (OSError, ValueError, KeyError, IndexError, struct.error, http.client.HTTPException):
        return None
