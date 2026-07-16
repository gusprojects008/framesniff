from cli_core.app import Config as AppConfig
from pktparser.app.app import make_config

# Não sei se está conceitualmente correto, ou se é melhor que o próprio framesniff defina seu make_config através das funções de config de pktparsers, e utilizando/chamando o próprio dataclass Config de cli_core.
def make_config() -> AppConfig:
    # It populates the standard AppConfig dataclass structure that cli_core provides.
    config = make_config()
    module_deps: ["rich", "dpkt", "textual"]
    system_deps: ["ip", "iw"]
    config.module_deps = module_deps
    config.system_deps = system_deps
    return config
