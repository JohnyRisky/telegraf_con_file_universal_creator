from pydantic import BaseModel
from .common_params import CommonAggregatorsParams
from typing import Literal


class Basicstats(CommonAggregatorsParams): 
    stats: list[Literal["count", "diff", "rate", "min", "max", "mean",
                        "non_negative_diff", "non_negative_rate", "percent_change",
                        "stdev", "s2", "sum", "interval", "last"]] | None = None


class Derivative(CommonAggregatorsParams):
    suffix: str | None = None
    variable: str | None = None
    max_roll_over: int | None = None


class Final(CommonAggregatorsParams): 
    keep_original_field_names: bool | None = None 
    series_timeout: str | None = None
    output_strategy: Literal["timeout", "periodic"] | None = None

class HistogramConfig(BaseModel):
    buckets: list[float] | None = None
    measurement_name: str | None = None
    fields: list[str] | None = None

class Histogram(CommonAggregatorsParams):
    reset: bool | None = None
    cumulative: bool | None = None
    expiration_interval: str | None = None
    push_only_on_update: bool | None = None
    config: list[HistogramConfig] | None = None

class Merge(CommonAggregatorsParams):
    round_timestamp_to: str | None = None

class Minmax(CommonAggregatorsParams):
    pass

class Quantile(CommonAggregatorsParams):
    quantiles: list[float] | None = None
    algorithm: Literal["t-digest", "exact R7", "exact R8"] | None = None
    compression: float | None = None

class StarlarkConstants(BaseModel):
    max_size: int | None = None
    threshold: float | None = None
    default_name: str | None = None
    debug_mod: bool | None = None

class Starlark(CommonAggregatorsParams):
    source: str | None = None
    script: str | None = None
    constants: StarlarkConstants | None = None

class ValueCounter(CommonAggregatorsParams):
    fields: list[str] | None = None

