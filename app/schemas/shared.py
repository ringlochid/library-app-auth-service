import re
from pydantic import BaseModel, field_validator


class EmailBase(BaseModel):
    email: str

    @field_validator("email")
    def validate_email(cls, v: str) -> str:
        cleaned = v.strip().lower()
        pattern = re.compile(r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$")
        if not pattern.match(cleaned):
            raise ValueError("Invalid email format")
        return cleaned
