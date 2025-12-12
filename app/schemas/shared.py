import re
from pydantic import BaseModel, field_validator


class EmailBase(BaseModel):
    email: str

    @field_validator("email")
    def validate_email(cls, v: str) -> str:
        """
        Basic email validation:
        - trim spaces
        - ensure simple local@domain.tld shape
        - normalize to lowercase
        """
        cleaned = v.strip().lower()
        pattern = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
        if not pattern.match(cleaned):
            raise ValueError("Invalid email format")
        return cleaned
