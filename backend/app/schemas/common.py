from typing import TypeVar, Generic, List
from pydantic import BaseModel, ConfigDict
from pydantic.alias_generators import to_camel

T = TypeVar("T")


class CamelModel(BaseModel):
    model_config = ConfigDict(
        alias_generator=to_camel,
        populate_by_name=True,
        from_attributes=True,
    )


class RiskScore(CamelModel):
    score: int
    level: str
    factors: List[str] = []


class PaginatedResult(CamelModel, Generic[T]):
    items: List[T]
    total: int
    page: int
    page_size: int
