import os
import pwd
from pathlib import Path
from logging import getLogger

logger = getLogger(__name__)

class AppContext:
    def __init__(self, config):
        self.config = config

        self.real_user = os.environ.get("SUDO_USER") or os.getlogin()
        
        logger.debug(
            f"AppContext initialized — user={self.real_user} "
        )
