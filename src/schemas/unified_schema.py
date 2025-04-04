# src/schemas/unified_schema.py
from pydantic import BaseModel
from datetime import datetime
from typing import Optional, Literal

class UnifiedEventSchema(BaseModel):
    process_id: int
    event_type: Literal["process", "network", "file", "registry"]
    timestamp: datetime
    user: str
    # Optional fields for each event type
    executable_path: Optional[str]
    src_ip: Optional[str]
    file_path: Optional[str]
    registry_key: Optional[str]