import operator
import re

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

operators = ["==","!=",">","<",">=","<="]

def _evaluate_condition(condition: str, parsed_frame: dict) -> bool:
    ops = {
        operators[0]: operator.eq,
        operators[1]: operator.ne,
        operators[2]: operator.gt,
        operators[3]: operator.lt,
        operators[4]: operator.ge,
        operators[5]: operator.le
    }
    
    for op_str, op_func in ops.items():
        if op_str in condition:
            left, right = condition.split(op_str, 1)
            left = left.strip()
            right = right.strip()
            left_val = _get_nested(left, parsed_frame)
            if left_val is False:
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

def _multi_get(paths: str, dct: dict):
    if not paths:
        #return False
        return None
    paths = [path.strip() for path in paths.split(",")]
    result = {}
    for path in paths:
        result[path] = _get_nested(path, dct)
    return result

def _parse_filter_expression(filter_expression: str, parsed_frame: dict) -> bool:
    filter_expression = filter_expression.strip()

    while "(" in filter_expression:
        inner = re.search(r'\(([^()]+)\)', filter_expression)
        if not inner:
            break
        inner_expr = inner.group(1)
        inner_result = _parse_filter_expression(inner_expr, parsed_frame)
        filter_expression = filter_expression[:inner.start()] + str(inner_result) + filter_expression[inner.end():]

    if " and " in filter_expression:
        return all(_parse_filter_expression(f, parsed_frame) for f in filter_expression.split(" and "))
    if " or " in filter_expression:
        return any(_parse_filter_expression(f, parsed_frame) for f in filter_expression.split(" or "))

    if any(op in filter_expression for op in operators):
        return _evaluate_condition(filter_expression, parsed_frame)

    value = _get_nested(filter_expression, parsed_frame)
    if isinstance(value, bool):
        return value
    return value is not None

def apply_filters(store_filter: str = "", display_filter: str = "", parsed_frame: dict = None):
    store_filter_result = False
    display_filter_result = None
    if parsed_frame is None:
        parsed_frame = {}
    if store_filter == "":
        store_filter_result = True
    else:
        store_filter_result = _parse_filter_expression(store_filter, parsed_frame)
    if display_filter:
        display_filter_result = _multi_get(display_filter, parsed_frame)
    return store_filter_result, display_filter_result
