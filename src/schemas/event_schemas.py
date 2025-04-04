# src/schemas/event_schemas.py
from pydantic import BaseModel, Field, validator
from datetime import datetime
from typing import Optional

class ProcessEventSchema(BaseModel):
    process_id: int
    parent_id: int
    start_time: datetime
    end_time: datetime
    executable_path: str
    user: str

    @validator('end_time')
    def validate_times(cls, end_time, values):
        if 'start_time' in values and end_time < values['start_time']:
            raise ValueError("end_time must be after start_time")
        return end_time

class NetworkEventSchema(BaseModel):
    process_id: int
    src_ip: Optional[str]
    dst_ip: str
    src_port: Optional[int] = Field(ge=1, le=65535)
    dst_port: int = Field(ge=1, le=65535)
    timestamp: datetime
    user: str

