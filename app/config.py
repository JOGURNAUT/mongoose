import os
from dotenv import load_dotenv

load_dotenv()

ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY", "").strip()
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "").strip()
DATABASE_PATH = os.getenv("DATABASE_PATH", "mongoose.db")

MOCK_MODE = not (ABUSEIPDB_API_KEY and VIRUSTOTAL_API_KEY)
