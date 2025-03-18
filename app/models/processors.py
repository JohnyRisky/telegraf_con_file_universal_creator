from pydantic import BaseModel
from .common_params import CommonProcessorsParams
from typing import Literal



class AwsEc2(CommonProcessorsParams):
    pass

class ConverterTagsParams(BaseModel):
    measurement: list[str] | None = None
    string: list[str] | None = None
    integer: list[str] | None = None
    unsigned: list[str] | None = None
    boolean: list[bool] | None = None
    float: list[str] | None = None
    timestamp: Literal["unix", "unix_ms", "unix_us", "unix_ns"] | None = None
    timestamp_format: str | None = None


class ConverterFieldsParams(ConverterTagsParams):
    tag: list[str] | None = None


class Converter(CommonProcessorsParams):
    tags: ConverterTagsParams | None = None
    fields: ConverterFieldsParams | None = None


class CloneTags(BaseModel):
    additional_tag: str | None = None


class Clone(CommonProcessorsParams):
    name_override: str | None = None
    name_prefix: str | None = None
    name_suffix: str | None = None
    tags: list[CloneTags] | None = None


class Date(CommonProcessorsParams):
    tag_key: str | None = None
    field_key: str | None = None
    date_format: str | None = None
    date_format: Literal["unix", "unix_ms", "unix_us", "unix_ns"] | None = None
    date_offset: str | None = None
    timezone: str | None = None


class Dedup(CommonProcessorsParams):
    dedup_interval: str | None = None


class DefaultsFields(BaseModel):
    field_1: str | None = None
    time_idle: int | None = None
    is_error: bool | None = None


class Defaults(CommonProcessorsParams):
    fields: DefaultsFields | None = None


class EnumValueMapping(BaseModel):
    green: int | None = None
    amber: int | None = None
    red: str | None = None


class EnumMapping(BaseModel):
    field: str | None = None
    tag: str | None = None
    dest: str | None = None
    default: int | None = None
    value_mapping: list[EnumValueMapping] | None = None


class Enum(CommonProcessorsParams):
    mapping: list[EnumMapping] | None = None


class Execd(CommonProcessorsParams):
    command: list[str] | None = None
    environment: list[str] | None = None
    restart_delay: str | None = None
    data_format: str | None = None


class FilterRule(BaseModel):
    name: list[str] | None = None
    tags: dict[str, str] | None = None
    fields: list[str] | None = None
    action: Literal["pass", "drop"] | None = None


class Filter(CommonProcessorsParams):
    default: str | None = None
    rule: list[FilterRule] | None = None
        

class GeoLookup(BaseModel):
    field: str | None = None
    dest_country: str | None = None
    dest_city: str | None = None
    dest_lat: str | None = None
    dest_lon: str | None = None

class Geoip(CommonProcessorsParams):
    db_path: str | None = None
    db_type: Literal["country", "city"] | None = None
    lookup: list[GeoLookup] | None = None


class Lookup(CommonProcessorsParams):
    files: list[str] | None = None
    format: Literal["json", "csv_key_name_value", "csv_key_values"] | None = None
    key: str | None = None


class Ifname(CommonProcessorsParams):
    tag: str | None = None
    dest: str | None = None
    agent: str | None = None
    timeout: str | None = None
    version: Literal[1, 2, 3] | None = None
    community: str | None = None
    retries: int | None = None
    max_repetitions: int | None = None
    sec_name: str | None = None
    auth_protocol: Literal["MD5", "SHA", ""] | None = None
    auth_password: str | None = None
    sec_level: Literal["noAuthNoPriv", "authNoPriv", "authPriv"] | None = None
    context_name: str | None = None
    priv_protocol: Literal["DES", "AES", ""] | None = None
    priv_password: str | None = None
    max_parallel_lookups: int | None = None
    ordered: bool | None = None
    cache_ttl: str | None = None


class Noise(CommonProcessorsParams): 
    type: Literal["laplacian", "gaussian", "uniform"] | None = None
    mu: float | None = None
    scale: float | None = None
    min: float | None = None
    max: float | None = None
    include_fields: list[str] | None = None
    exclude_fields: list[str] | None = None


class OverrideTag(BaseModel):
    additional_tag: str | None = None


class Override(CommonProcessorsParams):
    name_override: str | None = None
    name_prefix: str | None = None
    name_suffix: str | None = None
    tags: list[OverrideTag] | None = None


class Parser(CommonProcessorsParams):
    parse_fields: list[str] | None = None
    parse_fields_base64: list[str] | None = None
    parse_tags: list[str] | None = None
    drop_original: bool | None = None
    merge: Literal["override-with-timestamp", "override"] | None = None
    data_format: Literal["avro", "collectd", "dropwizard", "form_urlencoded", "influx", 
                        "binary", "carbon2", "cloudevents", "csv", "grok", "graphite", 
                        "json", "json_v2", "logfmt", "messagepack", "nagios", "parquet", 
                        "prometheus", "prometheusremotewrite", "openmetris", "opentsdb",
                        "servicenownetrics", "splunkmetric", "template", "value", 
                        "wavefront", "xpath_protobuf", "xml", "xpath_cbor", "xpath_json", 
                        "xpath_msgpack"]


class Pivot(CommonProcessorsParams):
    tag_key: str | None = None
    value_key: str | None = None


class PortName(CommonProcessorsParams):
    tag: str | None = None
    field: str | None = None
    dest: str | None = None
    default_protocol: Literal["tcp", "udp"] | None = None
    protocol_tag: Literal["tcp", "udp"] | None = None
    protocol_field: Literal["tcp", "udp"] | None = None


class Printer(CommonProcessorsParams):
    influx_max_line_bytes: int | None = None
    influx_sort_fields: bool | None = None
    influx_uint_support: bool | None = None
    influx_omit_timestamp: bool | None = None


class RegexCommonParams(BaseModel):
    pattern: str | None = None
    replacement: str | None = None


class RegexParamsResultKey(RegexCommonParams):
    result_key: str | None = None


class RegexPlusKey(RegexCommonParams):
    key: str | None = None


class Regex(CommonProcessorsParams):
    namepass: list[str] | None = None

    tags: list[RegexPlusKey] | None = None
    fields: list[RegexPlusKey] | None = None
    field_rename: list[RegexParamsResultKey] | None = None
    tag_rename: list[RegexParamsResultKey] | None = None
    metric_rename: list[RegexCommonParams] | None = None


class RenameReplace(BaseModel):
    measurement: str | None = None
    tag: str | None = None
    field: str | None = None 
    dest: str | None = None


class Rename(CommonProcessorsParams):
    replace: list[RenameReplace] | None = None


class ReverseDnsLookup(BaseModel):
    tag: str | None = None
    field: str | None = None
    dest: str | None = None


class ReverseDns(CommonProcessorsParams):
    namepass: list[str] | None = None
    cache_ttl: str | None = None
    lookup_timeout: str | None = None
    max_parallel_lookups: int | None = None
    ordered: bool | None = None
    lookup: list[ReverseDnsLookup] | None = None


class S2geo(CommonProcessorsParams):
    lat_field: str | None = None
    lon_field: str | None = None
    tag_key: str | None = None
    cell_level: int | None = None


class ScaleScaling(BaseModel):
    input_minimum: float | None = None
    input_maximum: float | None = None
    output_minimum: float | None = None
    output_maximum: float | None = None
    factor: float | None = None
    offset: float | None = None
    fields: list[str] | None = None


class Scale(CommonProcessorsParams):
    scaling: list[ScaleScaling] | None = None


class SnmpLookupTags(BaseModel):
    oid: str | None = None
    name: str | None = None
    conversion: Literal["hwaddr", "ipaddr", "enum"] | None = None


class SnmpLookup(CommonProcessorsParams):
    agent_tag: str | None = None
    index_tag: str | None = None
    timeout: str | None = None
    version: Literal[1, 2, 3] | None = None
    community: str | None = None
    retries: int | None = None
    max_repetitions: int | None = None
    sec_name: str | None = None
    auth_protocol: Literal["MD5", "SHA", ""] | None = None
    auth_password: str | None = None
    sec_level: Literal["noAuthNoPriv", "authNoPriv", "authPriv"] | None = None
    context_name: str | None = None
    priv_protocol: Literal["DES", "AES", ""] | None = None
    priv_password: str | None = None
    max_parallel_lookups: int | None = None
    max_cache_entries: int | None = None
    ordered: bool | None = None
    cache_ttl: str | None = None
    min_time_between_updates: str | None = None
    tag: list[SnmpLookupTags] | None = None


class SplitTemplate(BaseModel):
    name: str | None = None
    tags: list[str] | None = None
    fields: list[str] | None = None


class Split(CommonProcessorsParams):
    drop_original: bool | None = None
    template: list[SplitTemplate] | None = None


class StarlarkConstants(BaseModel):
    max_size: int | None = None
    threshold: float | None = None
    default_name: str | None = None
    debug_mode: bool | None = None


class Starlark(CommonProcessorsParams):
    source: str | None = None
    script: str | None = None
    constants: list[StarlarkConstants] | None = None


class StringsLowercase(BaseModel):
    field: str | None = None
    dest: str | None = None

class StringsUppercase(BaseModel):
    tag: str | None = None

class StringsTitlecase(BaseModel):
    field: str | None = None

class StringsTrim(BaseModel):
    field: str | None = None

class StringsTrimLeft(BaseModel):
    field: str | None = None
    cutset: str | None = None

class StringsTrimRight(BaseModel):
    field: str | None = None
    cutset: str | None = None

class StringsTrimPrefix(BaseModel):
    field: str | None = None
    prefix: str | None = None

class StringsTrimSuffix(BaseModel):
    field: str | None = None
    suffix: str | None = None

class StringsReplace(BaseModel):
    measurement: str | None = None
    old: str | None = None
    new: str | None = None

class StringsLeft(BaseModel):
    field: str | None = None
    width: int | None = None

class StringsBase64Decode(BaseModel):
    field: str | None = None
    
class StringsValidUTF(BaseModel):
    field: str | None = None
    replacement: str | None = None

class Strings(CommonProcessorsParams):
    lowercase: list[StringsLowercase] | None = None
    uppercase: list[StringsUppercase] | None = None
    titlecase: list[StringsTitlecase] | None = None
    trim: list[StringsTrim] | None = None
    trim_left: list[StringsTrimLeft] | None = None
    trim_right: list[StringsTrimRight] | None = None
    trim_prefix: list[StringsTrimPrefix] | None = None
    trim_suffix: list[StringsTrimSuffix] | None = None
    replace: list[StringsReplace] | None = None
    left: list[StringsLeft] | None = None
    base64decode: list[StringsBase64Decode] | None = None
    valid_utf8: list[StringsValidUTF] | None = None


class TagLimit(CommonProcessorsParams):
    limit: int | None = None
    keep: list[str] | None = None


class Template(CommonProcessorsParams):
    tag: str | None = None
    template: str | None = None

class Timestamp(CommonProcessorsParams):
    field: str | None = None
    source_timestamp_format: Literal["unix", "unix_ms", "unix_us", "unix_ns"] | None = None
    source_timestamp_timezone: str | None = None
    destination_timestamp_format: Literal["unix", "unix_ms", "unix_us", "unix_ns"] | None = None
    destination_timestamp_timezone: str | None = None

class Topk(CommonProcessorsParams):
    period: int | None = None
    k: int | None = None
    group_by: list[str] | None = None
    fields: list[str] | None = None
    aggregation: Literal["sum", "mean", "min", "max"] | None = None
    bottomk: bool | None = None
    add_groupby_tag: str | None = None
    add_rank_fields: list[str] | None = None
    add_aggregate_fields: list[str] | None = None


class Unpivot(CommonProcessorsParams):
    use_fieldname_as: Literal["tag", "metric"] | None = None
    tag_key: str | None = None
    value_key: str | None = None

