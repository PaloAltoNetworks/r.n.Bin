from pydantic import BaseModel, Field, ValidationError
from typing import Dict, Tuple



class FunctionDetails(BaseModel):
    DescriptiveName: str
    Description: str = Field(..., max_length=250)