from pydantic import BaseModel, Field
from typing import Literal
#from app.utils import variables

TIME_INTERVAL_REGEX = r'^\d+(ns|us|µs|ms|s|m|h)$'

class CommonInputsParams(BaseModel):
    alias: str | None = None
    interval: str | None = Field(
        None, 
        pattern=TIME_INTERVAL_REGEX, 
        description="Пример: [10s, 10ms, 5m, 1h]"
    )
    precision: str | None = Field(
        None, 
        pattern=TIME_INTERVAL_REGEX, 
        description="Пример: [10s, 10ms, 5m, 1h]"
    )
    time_source: Literal["metric", "collection_start", "collection_end"] | None = None
    collection_jitter: str | None = Field(
        None, 
        pattern=TIME_INTERVAL_REGEX, 
        description="Пример: [10s, 10ms, 5m, 1h]"
    )
    collection_offset: str | None = Field(
        None, 
        pattern=TIME_INTERVAL_REGEX, 
        description="Пример: [10s, 10ms, 5m, 1h]"
    )
    name_override: str | None = None
    name_prefix: str | None = None
    name_suffix: str | None = None
    tags: dict[str, str | list[str]] | None = None
    log_level: Literal["error", "warn", "info", "debug", "trace"] | None = None
    namepass: list[str] | None = None
    namedrop: list[str] | None = None
    fieldinclude: list[str] | None = None
    fieldexclude: list[str] | None = None
    taginclude: list[str] | None = None
    tagexclude: list[str] | None = None

class CommonProcessorsParams(BaseModel):
    alias: str | None = None
    order: int | None = None
    log_level: Literal["error", "warn", "info", "debug", "trace"] | None = None
    namepass: list[str] | None = None
    namedrop: list[str] | None = None
    fieldinclude: list[str] | None = None
    fieldexclude: list[str] | None = None
    taginclude: list[str] | None = None
    tagexclude: list[str] | None = None

class CommonAggregatorsParams(BaseModel):
    alias: str | None = None
    period: str | None = Field(
        None, 
        pattern=TIME_INTERVAL_REGEX, 
        description="Пример: [10s, 10ms, 5m, 1h]"
    )
    delay: str | None = Field(
        None, 
        pattern=TIME_INTERVAL_REGEX, 
        description="Пример: [10s, 10ms, 5m, 1h]"
    )
    grace: str | None = None
    drop_original: bool | None = None
    name_override: str | None = None
    name_prefix: str | None = None
    name_suffix: str | None = None
    tags: dict[str, str] | None = None
    log_level: Literal["error", "warn", "info", "debug", "trace"] | None = None
    namepass: list[str] | None = None
    namedrop: list[str] | None = None
    fieldinclude: list[str] | None = None
    fieldexclude: list[str] | None = None
    taginclude: list[str] | None = None
    tagexclude: list[str] | None = None

class CommonOutputsParams(BaseModel):
    alias: str | None = None
    flush_interval: str | None = Field(
        None, 
        pattern=TIME_INTERVAL_REGEX, 
        description="Пример: [10s, 10ms, 5m, 1h]"
    )
    flush_jitter: str | None = Field(
        None, 
        pattern=TIME_INTERVAL_REGEX, 
        description="Пример: [10s, 10ms, 5m, 1h]"
    )
    metric_batch_size: int | None = None
    metric_buffer_limit: int | None = None
    name_override: str | None = None
    name_prefix: str | None = None
    name_suffix: str | None = None
    log_level: Literal["error", "warn", "info", "debug", "trace"] | None = None
    namepass: list[str] | None = None
    namedrop: list[str] | None = None
    fieldinclude: list[str] | None = None
    fieldexclude: list[str] | None = None
    taginclude: list[str] | None = None
    tagexclude: list[str] | None = None