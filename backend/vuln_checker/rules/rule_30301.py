from . import rule_11303


def evaluate(ip: str, host_data: dict) -> list:
    return rule_11303.evaluate(ip, host_data)
