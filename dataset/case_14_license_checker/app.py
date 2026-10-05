"""Offline license-key issuing and verification."""

import base64
import hashlib
import time

FIELD_SEP = "|"
SEATS_DEFAULT = 1


def _payload(customer, product, expires, seats=SEATS_DEFAULT):
    return FIELD_SEP.join([customer, product, str(int(expires)), str(int(seats))])


def _sign(secret, payload):
    return hashlib.sha1((secret + payload).encode()).hexdigest()


def issue_key(secret, customer, product, expires, seats=SEATS_DEFAULT):
    payload = _payload(customer, product, expires, seats)
    blob = f"{payload}{FIELD_SEP}{_sign(secret, payload)}".encode()
    return base64.urlsafe_b64encode(blob).decode().rstrip("=")


def parse_key(key):
    padding = "=" * (-len(key) % 4)
    try:
        blob = base64.urlsafe_b64decode(key + padding).decode()
    except Exception as exc:
        raise ValueError("license key is not decodable") from exc
    parts = blob.split(FIELD_SEP)
    if len(parts) != 5:
        raise ValueError("license key has the wrong shape")
    customer, product, expires, seats, signature = parts
    return {
        "customer": customer,
        "product": product,
        "expires": int(expires),
        "seats": int(seats),
        "signature": signature,
    }


def verify_key(secret, key, now=None):
    try:
        fields = parse_key(key)
    except ValueError:
        return False
    payload = _payload(
        fields["customer"], fields["product"], fields["expires"], fields["seats"]
    )
    if _sign(secret, payload) != fields["signature"]:
        return False
    return fields["expires"] >= int(now if now is not None else time.time())


def days_remaining(key, now=None):
    expires = parse_key(key)["expires"]
    moment = int(now if now is not None else time.time())
    return max(0, (expires - moment) // 86400)


def describe(secret, key, now=None):
    fields = parse_key(key)
    return {
        "customer": fields["customer"],
        "product": fields["product"],
        "seats": fields["seats"],
        "valid": verify_key(secret, key, now),
        "days_remaining": days_remaining(key, now),
    }
