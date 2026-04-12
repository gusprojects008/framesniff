def mgmt_beacon(**kwargs) -> dict:
    return {
        "fixed_parameters": fixed_parameters(),
        "tagged_parameters": tagged_parameters()
    }

def mgmt_probe_response(**kwargs) -> dict:
    return {
        "fixed_parameters": fixed_parameters(),
        "tagged_parameters": tagged_parameters()
    }

def mgmt_atim(**kwargs) -> dict:
    return unpack("<H", parser=lambda v: {"aid": v & 0x3FFF})

def mgmt_disassociation(**kwargs) -> dict:
    return unpack("<H", parser=lambda v: {"reason_code": v})

def mgmt_deauthentication(**kwargs) -> dict:
    return mgmt_disassociation()

def mgmt_authentication(**kwargs) -> dict:
    def _parser(value: tuple, **k) -> dict:
        alg, seq, status = value
        return {
            "auth_algorithm": alg,
            "auth_sequence": seq,
            "status_code": status,
            "fixed_parameters": fixed_parameters(),
            "tagged_parameters": tagged_parameters()
        }
    return unpack("<HHH", parser=_parser)

def mgmt_action(**kwargs) -> dict:
    def _parser(value: tuple, **k) -> dict:
        cat, act = value
        ctx = ParseContext.current()
        
        res = {"category": cat, "action": act}
        
        if ctx.offset < len(ctx.frame):
            res["tagged_parameters"] = tagged_parameters()
            
        return res
    return unpack("BB", parser=_parser)
