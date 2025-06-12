import re

from packaging import version


def match_version(ver: str, cond: str) -> bool:
    try:
        op = re.match(r"(<=|>=|<|>|==)", cond).group(1)
        target = cond[len(op):]
        ver_obj = version.parse(ver)
        target_obj = version.parse(target)
        return eval(f"ver_obj {op} target_obj")
    except:
        return False

def match_regex(text: str, pattern: str) -> bool:
    try:
        return re.match(pattern, text or "") is not None
    except:
        return False
