import os
import yaml
from pathlib import Path
from dotenv import load_dotenv

load_dotenv()

_cfg_path = Path(__file__).parent / "settings.yaml"
with open(_cfg_path) as f:
    _cfg = yaml.safe_load(f)

# Override secrets from env
_cfg["misp"]["url"] = os.getenv("MISP_URL", "")
_cfg["misp"]["key"] = os.getenv("MISP_KEY", "")
_cfg["enrichment"]["shodan_key"] = os.getenv("SHODAN_API_KEY", "")
_cfg["enrichment"]["vt_key"] = os.getenv("VT_API_KEY", "")
_cfg["enrichment"]["abuseipdb_key"] = os.getenv("ABUSEIPDB_KEY", "")
_cfg["storage"]["database_url"] = os.getenv("DATABASE_URL", "")
_cfg["storage"]["redis_url"] = os.getenv("REDIS_URL", _cfg["storage"]["redis_url"])
_cfg["tor"]["control_password"] = os.getenv("TOR_CONTROL_PASSWORD", "")
_cfg["counterfeit"]["canlii_api_key"] = os.getenv("CANLII_API_KEY", "")

cfg = _cfg
