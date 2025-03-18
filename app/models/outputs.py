from typing import Literal

from pydantic import BaseModel
from .common_params import CommonOutputsParams


class Cloudwatch(CommonOutputsParams):
    pass

class CloudwatchLogs(CommonOutputsParams):
    pass

class Kinesis(CommonOutputsParams):
    pass

class Timestream(CommonOutputsParams):
    pass

class Amon(CommonOutputsParams):
    pass

class Amqp(CommonOutputsParams):
    pass


class KafkaTopicSuffix(BaseModel):
    method: str | None = None
    separator: str | None = None
    keys: list[str] | None = None


class Kafka(CommonOutputsParams):
    brokers: list[str] | None = None
    topic: str | None = None
    topic_tag: str | None = None
    exclude_topic_tag: bool | None = None
    client_id: str | None = None
    version: str | None = None
    routing_tag: str | None = None
    routing_key: Literal["random", "telegraf"] | None = None
    compression_codec: Literal[0, 1, 2, 3, 4] | None = None
    idempotent_writes: bool | None = None
    required_acks: Literal[1, 0, 1] | None = None
    max_retry: int | None = None
    max_message_bytes: int | None = None
    producer_timestamp: Literal["metric", "now"] | None = None
    metric_name_header: str | None = None
    tls_ca: str | None = None
    tls_cert: str | None = None
    tls_key: str | None = None
    insecure_skip_verify: bool | None = None
    keep_alive_period: str | None = None
    socks5_enabled: bool | None = None
    socks5_address: str | None = None
    socks5_username: str | None = None
    socks5_password: str | None = None
    sasl_username: str | None = None
    sasl_password: str | None = None
    sasl_mechanism: Literal["OAUTHBEARER", "PLAIN", "SCRAM-SHA-256", "SCRAM-SHA-512", "GSSAPI"] | None = None
    sasl_gssapi_service_name: str | None = None
    sasl_gssapi_auth_type: Literal["KRB5_USER_AUTH", "KRB5_KEYTAB_AUTH"] | None = None
    sasl_gssapi_kerberos_config_path: str | None = None
    sasl_gssapi_realm: str | None = None
    sasl_gssapi_key_tab_path: str | None = None
    sasl_gssapi_disable_pafxfast: bool | None = None
    sasl_access_token: str | None = None
    sasl_extensions: dict[str, str] | None = None
    sasl_version: int | None = None
    metadata_full: bool | None = None
    metadata_retry_max: int | None = None
    metadata_retry_type: Literal["constant", "exponential"] | None = None
    metadata_retry_backoff: int | None = None
    metadata_retry_max_duration: int | None = None
    data_format: Literal["influx", "binary", "carbon2", "cloudevents", "csv", 
                         "graphite", "json", "messagepack", "prometheus", 
                         "prometheusremotewrite", "servicenownetrics", "splunkmetric", 
                         "template", "wavefront"] | None = None
    topic_suffix: list[KafkaTopicSuffix] | None = None


class AzureDataExplorer(CommonOutputsParams):
    pass

class EventHubs(CommonOutputsParams):
    pass

class Bigquery(CommonOutputsParams):
    pass

class CrateDB(CommonOutputsParams):
    pass

class Clarify(CommonOutputsParams):
    pass

class Datalog(CommonOutputsParams):
    pass

class Discard(CommonOutputsParams):
    pass

class Dynatrace(CommonOutputsParams):
    pass

class ElasticSearch(CommonOutputsParams):
    urls: list[str] | None = None
    timeout: str | None = None
    enable_sniffer: bool | None = None
    enable_gzip: bool | None = None
    health_check_interval: str | None = None
    health_check_timeout: str | None = None
    username: str | None = None
    password: str | None = None
    auth_bearer_token: str | None = None
    default_tag_value: str | None = None
    index_name: str | None = None
    use_optype_create: bool | None = None
    tls_ca: str | None = None
    tls_key: str | None = None
    insecure_skip_verify: bool | None = None
    manage_template: bool | None = None
    template_name: str | None = None
    overwrite_template: bool | None = None
    force_document_id: bool | None = None
    float_handling: Literal["none", "drop", "replace"] | None = None
    float_replacement_value: float | None = None
    use_pipeline: str | None = None
    default_pipeline: str | None = None

class Exec(CommonOutputsParams):
    pass

class Execd(CommonOutputsParams):
    pass

class File(CommonOutputsParams):
    files: list[str] | None = None
    use_batch_format: bool | None = None
    rotation_interval: str | None = None
    rotation_max_size: str | None = None
    rotation_max_archives: int | None = None
    data_format: Literal["influx", "binary", "carbon2", "cloudevents", "csv", "graphite", 
                         "json", "messagepack", "prometheus", "prometheusremotewrite", 
                         "servicenownetrics", "splunkmetric", "template", "wavefront"] | None = None
    compression_algorithm: Literal["zstd", "gzip", "zlib", ""] | None = None
    compression_level: Literal[-1, 0, 1, 3, 7, 9, 11] | None = None

class CloudPursub(CommonOutputsParams):
    pass

class Graphite(CommonOutputsParams):
    servers: str | None = None
    local_address: str | None = None
    prefix: str | None = None
    template: str | None = None
    graphite_strict_sanitize_regex: str | None = None
    graphite_tag_support: bool | None = None
    graphite_tag_sanitize_mode: str | None = None
    graphite_separator: str | None = None
    timeout: str | None = None
    tls_ca: str | None = None
    tls_cert: str | None = None
    tls_key: str | None = None
    insecure_skip_verify: bool | None = None

class Loki(CommonOutputsParams):
    pass

class Graylog(CommonOutputsParams):
    pass

class Groundwork(CommonOutputsParams):
    pass

class HttpOutputHeaders(BaseModel):
    content_type: str | None = None

class HttpOutput(CommonOutputsParams):
    url: str | None = None
    timeout: str | None = None
    method: Literal["POST", "PUT", "PATCH"] | None = None
    username: str | None = None
    password: str | None = None
    client_id: str | None = None
    client_secret: str | None = None
    token_url: str | None = None
    audience: str | None = None
    scopes: list[str] | None = None
    google_application_credentials: str | None = None
    use_system_proxy: bool | None = None
    http_proxy_url: str | None = None
    tls_ca: str | None = None
    tls_cert: str | None = None
    tls_key: str | None = None
    insecure_skip_verify: bool | None = None
    cookie_auth_url: str | None = None
    cookie_auth_method: str | None = None
    cookie_auth_username: str | None = None
    cookie_auth_password: str | None = None
    cookie_auth_headers: str | None = None
    cookie_auth_body: str | None = None
    cookie_auth_renewal: str | None = None
    data_format: Literal["influx", "binary", "carbon2", "cloudevents", "csv", "graphite", 
                         "json", "messagepack", "prometheus", "prometheusremotewrite", 
                         "servicenownetrics", "splunkmetric", "template", "wavefront"] | None = None
    use_batch_format: bool | None = None
    content_encoding: str | None = None
    max_idle_conn: int | None = None
    max_idle_conn_per_host: int | None = None
    idle_conn_timeout: str | None = None
    region: str | None = None
    aws_service: str | None = None
    access_key: str | None = None
    secret_key: str | None = None
    token: str | None = None
    role_arn: str | None = None
    web_identity_token_file: str | None = None
    role_session_name: str | None = None
    profile: str | None = None
    shared_credential_file: str | None = None
    non_retryable_statuscodes: list[int] | None = None
    headers: list[HttpOutputHeaders] | None = None

class Health(CommonOutputsParams):
    pass

class InfluxDB(CommonOutputsParams):
    urls: list[str] | None = None
    local_address: str | None = None
    database: str | None = None
    database_tag: str | None = None
    exclude_database_tag: bool | None = None
    skip_database_creation: bool | None = None
    retention_policy: str | None = None
    retention_policy_tag: str | None = None
    exclude_retention_policy_tag: bool | None = None
    write_consistency: Literal["any", "one", "quorum", "all"] | None = None
    timeout: str | None = None
    username: str | None = None
    password: str | None = None
    user_agent: str | None = None
    udp_payload: str | None = None
    tls_ca: str | None = None
    tls_cert: str | None = None
    tls_key: str | None = None
    insecure_skip_verify: bool | None = None
    http_proxy: str | None = None
    content_encoding: Literal["gzip", "identity"] | None = None
    influx_uint_support: bool | None = None
    influx_omit_timestamp: bool | None = None

class InfluxDBV2(CommonOutputsParams):
    urls: list[str] | None = None
    local_address: str | None = None
    token: str | None = None
    organization: str | None = None
    bucket: str | None = None
    bucket_tag: str | None = None
    exclude_bucket_tag: bool | None = None
    timeout: str | None = None
    http_proxy: str | None = None
    user_agent: str | None = None
    content_encoding: str | None = None
    influx_uint_support: bool | None = None
    influx_omit_timestamp: bool | None = None
    ping_timeout: str | None = None
    read_idle_timeout: str | None = None
    tls_ca: str | None = None
    tls_cert: str | None = None
    tls_key: str | None = None
    insecure_skip_verify: bool | None = None

class Instrumental(CommonOutputsParams):
    pass

class IotDB(CommonOutputsParams):
    pass

class Librato(CommonOutputsParams):
    pass

class Logzio(CommonOutputsParams):
    pass

class ApplicationInsights(CommonOutputsParams):
    pass

class AzureMonitor(CommonOutputsParams):
    timeout: str | None = None
    namespace_prefix: str | None = None
    strings_as_dimensions: bool | None = None
    region: str | None = None
    resource_id: str | None = None
    endpoint_url: str | None = None

class MongoDB(CommonOutputsParams):
    dsn: str | None = None
    timeout: str | None = None
    authentication: Literal["NONE", "SCRAM", "X509"] | None = None
    username: str | None = None
    password: str | None = None
    tls_ca: str | None = None
    tls_key: str | None = None
    tls_key_pwd: str | None = None
    insecure_skip_verify: bool | None = None
    database: str | None = None
    granularity: Literal["seconds", "minutes", "hours"] | None = None
    ttl: str | None = None

class Mqtt(CommonOutputsParams):
    pass

class Nats(CommonOutputsParams):
    pass

class NebiusCloudMonitoring(CommonOutputsParams):
    pass

class Newrelic(CommonOutputsParams):
    pass

class Nsq(CommonOutputsParams):
    pass

class OpenSearch(CommonOutputsParams):
    urls: list[str] | None = None
    index_name: str | None = None
    timeout: str | None = None
    enable_sniffer: bool | None = None
    enable_gzip: bool | None = None
    health_check_interval: str | None = None
    health_check_timeout: str | None = None
    username: str | None = None
    password: str | None = None
    auth_bearer_token: str | None = None
    tls_enable: bool | None = None
    tls_ca: str | None = None
    tls_cert: str | None = None
    tls_key: str | None = None
    tls_server_name: str | None = None
    insecure_skip_verify: bool | None = None
    manage_template: bool | None = None
    template_name: str | None = None
    overwrite_template: bool | None = None
    force_document_id: bool | None = None
    float_handling: Literal["none", "drop", "replace"] | None = None
    float_replacement_value: float | None = None
    use_pipeline: str | None = None
    default_pipeline: str | None = None


class Opentelemetry(CommonOutputsParams):
    pass

class OpentsDB(CommonOutputsParams):
    pass

class Parquet(CommonOutputsParams):
    pass

class Postgresql(CommonOutputsParams):
    connection: str | None = None
    schema: str | None = None
    tags_as_foreign_keys: bool | None = None
    tag_table_suffix: str | None = None
    foreign_tag_constraint: bool | None = None
    tags_as_jsonb: bool | None = None
    fields_as_jsonb: bool | None = None
    timestamp_column_name: str | None = None
    timestamp_column_type: Literal["timestamp without time zone", "timestamp without time zone"] | None = None
    create_templates: list[str] | None = None
    add_column_templates: list[str] | None = None
    tag_table_add_column_templates: list[str] | None = None
    uint64_type: Literal["numeric", "uint8"] | None = None
    retry_max_backoff: str | None = None
    tag_cache_size: int | None = None
    log_level: Literal["warn", "trace", "debug", "info", "warn", "error", "none"] | None = None

class PrometheusClient(CommonOutputsParams):
    pass

class RedisTimeSeries(CommonOutputsParams):
    pass

class Remotefile(CommonOutputsParams):
    pass

class Riemann(CommonOutputsParams):
    pass

class Sensu(CommonOutputsParams):
    pass

class Sifnalfx(CommonOutputsParams):
    pass

class SocketWriter(CommonOutputsParams):
    pass

class Stackdriver(CommonOutputsParams):
    pass

class Stomp(CommonOutputsParams):
    pass


class SqlConvert(BaseModel):
    convert: Literal["integer", "real", "text", "timestamp", 
                     "defaultvalue", "unsigned", "bool"] | None = None


class Sql(CommonOutputsParams):
    driver: Literal["mssql", "mysql", "pgx", "sqlite", "snowflake", "clickhouse"] | None = None
    data_source_name: str | None = None
    timestamp_column: str | None = None
    table_template: str | None = None
    table_exists_template: str | None = None
    init_sql: str | None = None
    connection_max_idle_time: str | None = None
    connection_max_lifetime: str | None = None
    connection_max_idle: int | None = None
    connection_max_open: int | None = None
    convert: list[SqlConvert]  | None = None


class Sumologic(CommonOutputsParams):
    pass

class Syslog(CommonOutputsParams):
    pass

class Warp10(CommonOutputsParams):
    pass

class Wavefront(CommonOutputsParams):
    pass

class Websocket(CommonOutputsParams):
    pass

class YandexCloudMonitoring(CommonOutputsParams):
    pass

class Zabbix(CommonOutputsParams):
    pass

