import re
import operator

operators = {
    ">=": operator.ge,
    "<=": operator.le,
    "==": operator.eq,
    "!=": operator.ne,
    ">": operator.gt,
    "<": operator.lt,
}

def get_nested(path: str, dct: dict, default=None):
    keys = path.split(".")
    current = dct
    i = 0

    if isinstance(current, dict) and "parsed" in current:
        current = current["parsed"]

    while i < len(keys):
        if not isinstance(current, dict):
            return default

        key = keys[i]
        key_lower = str(key).lower()
        found = False

        for dct_key, dct_value in current.items():
            if str(dct_key).lower() == key_lower:
                current = dct_value
                found = True
                break

        if not found and _is_numeric_dict(current):
            result = _search_in_numeric_dict(current, keys[i:])
            return result if result is not None else default

        if not found:
            return default

        if isinstance(current, dict) and "parsed" in current:
            next_key = keys[i + 1] if i + 1 < len(keys) else None
            if next_key is None or str(next_key).lower() not in ("parsed", "value", "_metadata_"):
                current = current["parsed"]

        i += 1

    if isinstance(current, bytes):
        return current.hex()

    if isinstance(current, dict) and "parsed" in current:
        if all(k in ('parsed', 'value', '_metadata_') for k in current.keys()):
            return current.get('parsed', default)

    return current if current is not None else default

def _is_numeric_dict(d: dict) -> bool:
    return (
        isinstance(d, dict)
        and len(d) > 0
        and all(str(k).isdigit() for k in d.keys())
    )

def _search_in_numeric_dict(d: dict, remaining_keys: list[str]):
    results = []
    for entry in d.values():
        candidate = entry
        if isinstance(entry, dict) and "parsed" in entry and "value" in entry:
            candidate = entry["parsed"]

        result = get_nested(".".join(remaining_keys), candidate)
        if result is not None:
            results.append(result)

    if not results:
        return None
    if len(results) == 1:
        return results[0]
    return results

def _to_value(val: str, parsed_frame: dict):
    val = val.strip()
    if val.lower() == "true":
        return True
    if val.lower() == "false":
        return False
    if re.fullmatch(r"[-+]?\d+", val):
        return int(val)
    if re.fullmatch(r"[-+]?\d*\.\d+", val):
        return float(val)
    if (val.startswith('"') and val.endswith('"')) or (val.startswith("'") and val.endswith("'")):
        return val[1:-1]
    nested = get_nested(val, parsed_frame)
    if nested is not None:
        return nested
    return None

def _extract_tuple_values(text: str, parsed_frame: dict):
    text = text.strip()
    m = re.fullmatch(r"\(([^()]*)\)", text)
    if not m:
        return [_to_value(text, parsed_frame)]
    items = [i.strip() for i in m.group(1).split(",") if i.strip()]
    return [_to_value(i, parsed_frame) for i in items]

def _evaluate_simple(expr: str, parsed_frame: dict):
    expr = expr.strip()
    if " not in " in expr:
        left, right = expr.split(" not in ", 1)
        left_val = _to_value(left, parsed_frame)
        options = _extract_tuple_values(right, parsed_frame)
        if isinstance(left_val, list):
            return not any(v in options for v in left_val)
        return left_val not in options

    if " in " in expr:
        left, right = expr.split(" in ", 1)
        left_val = _to_value(left, parsed_frame)
        options = _extract_tuple_values(right, parsed_frame)
        if isinstance(left_val, list):
            return any(v in options for v in left_val)
        return left_val in options

    for op_str, op_func in operators.items():
        if op_str in expr:
            parts = expr.split(op_str, 1)
            if len(parts) == 2:
                left, right = parts
                left_val = _to_value(left.strip(), parsed_frame)
                right_val = _to_value(right.strip(), parsed_frame)
                if isinstance(left_val, list):
                    return any(op_func(v, right_val) for v in left_val)
                return op_func(left_val, right_val)

    val = _to_value(expr, parsed_frame)
    if isinstance(val, list):
        return len(val) > 0
    return bool(val)

def _split_by_operator(expr: str, operator: str):
    parts = []
    current = []
    paren_count = 0
    bracket_count = 0
    
    i = 0
    while i < len(expr):
        if expr[i] == '(':
            paren_count += 1
            current.append(expr[i])
        elif expr[i] == ')':
            paren_count -= 1
            current.append(expr[i])
        elif expr[i] == '[':
            bracket_count += 1
            current.append(expr[i])
        elif expr[i] == ']':
            bracket_count -= 1
            current.append(expr[i])
        elif paren_count == 0 and bracket_count == 0 and expr[i:i+len(operator)] == operator:
            parts.append(''.join(current).strip())
            current = []
            i += len(operator) - 1
        else:
            current.append(expr[i])
        i += 1
    
    if current:
        parts.append(''.join(current).strip())
    
    return parts if len(parts) > 1 else None

def _parse_filter_expression(expr: str, parsed_frame: dict) -> bool:
    expr = expr.strip()

    if expr.startswith('(') and expr.endswith(')'):
        balance = 0
        should_remove = True
        for i, char in enumerate(expr):
            if char == '(':
                balance += 1
            elif char == ')':
                balance -= 1
            if balance == 0 and i < len(expr) - 1:
                should_remove = False
                break
        if should_remove:
            expr = expr[1:-1].strip()

    if expr.lower().startswith("not "):
        return not _parse_filter_expression(expr[4:].strip(), parsed_frame)

    parts = _split_by_operator(expr, " and ")
    if parts and len(parts) > 1:
        return all(_parse_filter_expression(p, parsed_frame) for p in parts)

    parts = _split_by_operator(expr, " or ")
    if parts and len(parts) > 1:
        return any(_parse_filter_expression(p, parsed_frame) for p in parts)

    return _evaluate_simple(expr, parsed_frame)

def apply_filters(store_filter: str = None, display_filter: str = None, parsed_frame: dict = None):
    if parsed_frame is None:
        parsed_frame = {}
        
    store_filter_result = True
    if store_filter:
        store_filter_result = _parse_filter_expression(store_filter, parsed_frame)
        
    display_filter_result = None
    if display_filter:
        keys = [k.strip() for k in display_filter.split(",")]
        display_filter_result = {}
        
        for key in keys:
            value = get_nested(key, parsed_frame)
            if value is not None:
                display_filter_result[key] = value
                
    return store_filter_result, display_filter_result
