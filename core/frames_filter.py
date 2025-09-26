import operator

def _get_nested(path: str, dct: dict):
    keys = path.split(".")
    current = dct
    for key in keys:
        key_lower = key.lower()
        found = False
        for dct_key, dct_value in current.items():
            if dct_key.lower() == key_lower:
                current = dct_value
                found = True
                break
        if not found:
            return None
    return current

def _multi_get(paths: str, dct: dict):
    if not paths:
        return None
    paths = [path.strip() for path in paths.split(",")]
    result = {}
    for path in paths:
        result[path] = _get_nested(path, dct)
    return result

def _evaluate_condition(condition: str, parsed_frame: dict) -> bool:
    ops = {
        "==": operator.eq,
        "!=": operator.ne,
        ">": operator.gt,
        "<": operator.lt,
        ">=": operator.ge,
        "<=": operator.le
    }
    
    for op_str, op_func in ops.items():
        if op_str in condition:
            left, right = condition.split(op_str, 1)
            left = left.strip()
            right = right.strip()
            left_val = _get_nested(left, parsed_frame)
            if left_val is None:
                return False
            try:
                right_val = int(right)
            except ValueError:
                try:
                    right_val = float(right)
                except ValueError:
                    right_val = right.strip('"').strip("'")
                    if isinstance(left_val, str):
                        left_val = left_val.lower()
                        right_val = right_val.lower()
            return op_func(left_val, right_val)
    return False

def parse_filter_expr(filter_expr: str, parsed_frame: dict) -> bool:
    if " and " in filter_expr:
        return all(parse_filter_expr(f, parsed_frame) for f in filter_expr.split(" and "))
    if " or " in filter_expr:
        return any(parse_filter_expr(f, parsed_frame) for f in filter_expr.split(" or "))
    return _evaluate_condition(filter_expr, parsed_frame)
