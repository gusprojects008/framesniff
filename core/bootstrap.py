from dataclasses import dataclass
from cli_core.deps import check_dependencies

@dataclass
class BootstrapResult:
    log_filename: str
    operations: object

def init(config: dict) -> BootstrapResult:
    MODULE_DEPENDENCIES = config.get("module_dependencies")
    SYSTEM_DEPENDENCIES = config.get("system_dependencies")
    args = config.get("args")
    check_dependencies(MODULE_DEPENDENCIES, SYSTEM_DEPENDENCIES)
    from cli_core.log import (setup_logging, build_logging_config)
    from core.app import Operations
    
    if args:
        logging_config = build_logging_config(args.verbose, args.output)
        log_filename = str(setup_logging(logging_config=logging_config))
    else:
        log_filename = str(setup_logging(verbose=True, output_fullpath="framesniff-test.log"))

    operations = Operations()
    
    return BootstrapResult(log_filename, operations)
