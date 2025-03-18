from typing import Literal, Optional
from pydantic import BaseModel
from .common_params import CommonInputsParams


class AmqpConsumer(CommonInputsParams):
    brokers: list[str] | None = None
    username: str | None = None
    password: str | None = None
    exchange: str | None = None
    exchange_type: Literal["direct", "fanout", "topic", "header", "x-consistent-hash"] | None = None
    exchange_passive: bool | None = None
    exchange_durability: Literal["transient", "durable"] | None = None
    queue: str | None = None
    queue_durability: Literal["durable", "transient"] | None = None
    queue_passive: bool | None = None
    binding_key: str | None = None
    prefetch_count: int | None = None
    max_undelivered_messages: bool | None = None
    timeout : str | None = None
    auth_method: Literal["PLAIN", "EXTERNAL"]
    tls_ca: str | None = None
    tls_cert: str | None = None
    tls_key: str | None = None
    insecure_skip_verify: bool | None = None
    content_encoding: Literal["identity", "gzip", "auto"] | None = None
    max_decompression_size: str | None = None
    data_format: Literal["avro", "collectd", "dropwizard", "form_urlencoded", "influx", 
                        "binary", "carbon2", "cloudevents", "csv", "grok", "graphite", 
                        "json", "json_v2", "logfmt", "messagepack", "nagios", "parquet", 
                        "prometheus", "prometheusremotewrite", "openmetris", "opentsdb",
                        "servicenownetrics", "splunkmetric", "template", "value", 
                        "wavefront", "xpath_protobuf", "xml", "xpath_cbor", "xpath_json", 
                        "xpath_msgpack"]


class Activemq(CommonInputsParams):
    url: str | None = None
    username: str | None = None
    password: str | None = None
    webadmin: str | None = None
    response_timeout: str | None = None
    tls_ca: str | None = None
    tls_cert: str | None = None
    tls_key: str | None = None
    insecure_skip_verify: bool | None = None


class AliyuncmsMetrics(BaseModel):
    names: list[str] | None = None
    dimensions: str | None = None
    tag_query_path: list[str] | None = None
    allow_dps_without_discovery: bool | None = None


class Aliyuncms(CommonInputsParams):
    access_key_id: str | None = None
    access_key_secret: str | None = None
    access_key_sts_token: str | None = None
    role_arn: str | None = None
    role_session_name: str | None = None
    private_key: str | None = None
    public_key_id: str | None = None
    role_name: str | None = None
    regions: list[Literal["cn-qingdao", "cn-beijing", "cn-zhangjiakou", "cn-huhehaote", "cn-hangzhou", 
                          "cn-shanghai", "cn-shenzhen", "cn-heyuan", "cn-chengdu", "cn-hongkong", 
                          "ap-southeast-1", "ap-southeast-2", "ap-southeast-3", "ap-southeast-5", 
                          "ap-south-1", "ap-northeast-1", "us-west-1", "us-east-1", "eu-central-1", 
                          "eu-west-1", "me-east-1"]] | None = None
    period: str | None = None
    delay: str | None = None
    interval: str | None = None
    project: str | None = None
    ratelimit: int | None = None
    discovery_interval: str | None = None
    metrics: list[AliyuncmsMetrics] | None = None

class Awsalarms(CommonInputsParams):
    region: str | None = None
    secret_key: str | None = None
    token: str | None = None
    role_arn: str | None = None
    profile: str | None = None
    shared_credential_file: str | None = None
    state_value: str | None = None
    tags_include: list[str] | None = None
    tags_exclude: list[str] | None = None


class CloudwatchMetricsDimensions(BaseModel):
    name: str | None = None
    value: str | None = None


class CloudwatchMetrics(BaseModel):
    names: list[str] | None = None
    statistic_include: list[Literal["average", "sum", "minimum", "maximum", "sample_count"]] | None = None
    statistic_exclude: list[Literal["average", "sum", "minimum", "maximum", "sample_count"]] | None = None
    dimensions: list[CloudwatchMetricsDimensions] | None = None


class Cloudwatch(CommonInputsParams):
    region: str | None = None
    access_key: str | None = None
    secret_key: str | None = None
    token: str | None = None
    role_arn: str | None = None
    web_identity_token_file: str | None = None
    role_session_name: str | None = None
    profile: str | None = None
    shared_credential_file: str | None = None
    include_linked_accounts: bool | None = None
    endpoint_url: str | None = None
    http_proxy_url: str | None = None
    period: str | None = None
    delay: str | None = None
    interval: str | None = None
    recently_active: str | None = None
    cache_ttl: str | None = None
    namespaces: list[str] | None = None
    metric_format: str | None = None
    ratelimit: int | None = None
    timeout: str | None = None
    batch_size: int | None = None
    statistic_include: list[Literal["average", "sum", "minimum", "maximum", "sample_count"]] | None = None
    statistic_exclude: list[Literal["average", "sum", "minimum", "maximum", "sample_count"]] | None = None
    metrics: list[CloudwatchMetrics] | None = None


class KinesisConsumerCheckpointDynamoDB(BaseModel):
    app_name: str | None = None
    table_name: str | None = None


class KinesisConsumer(CommonInputsParams):
    region: str | None = None
    access_key: str | None = None
    secret_key: str | None = None
    token: str | None = None
    role_arn: str | None = None
    web_identity_token_file: str | None = None
    role_session_name: str | None = None
    profile: str | None = None
    shared_credential_file: str | None = None
    endpoint_url: str | None = None
    streamname: str | None = None
    shard_iterator_type: Literal["TRIM_HORIZON", "LATEST"] | None = None
    max_undelivered_messages: int | None = None
    data_format: Literal["avro", "collectd", "dropwizard", "form_urlencoded", "influx", 
                        "binary", "carbon2", "cloudevents", "csv", "grok", "graphite", 
                        "json", "json_v2", "logfmt", "messagepack", "nagios", "parquet", 
                        "prometheus", "prometheusremotewrite", "openmetris", "opentsdb",
                        "servicenownetrics", "splunkmetric", "template", "value", 
                        "wavefront", "xpath_protobuf", "xml", "xpath_cbor", "xpath_json", 
                        "xpath_msgpack"]
    content_encoding: Literal["identity", "gzip", "auto"] | None = None

    checkpoint_dynamodb: list[KinesisConsumerCheckpointDynamoDB] | None = None


class Aurora(CommonInputsParams):
    schedulers: list[str] | None = None
    roles: list[Literal["leader", "follower"]] | None = None
    timeout: str | None = None
    username: str | None = None
    password: str | None = None
    tls_ca: str | None = None
    tls_cert: str | None = None
    tls_key: str | None = None
    insecure_skip_verify: bool | None = None


class Apache(CommonInputsParams):
    urls: list[str] | None = None
    response_timeout: str | None = None
    username: str | None = None
    password: str | None = None
    tls_ca: str | None = None
    tls_cert: str | None = None
    tls_key: str | None = None
    insecure_skip_verify: bool | None = None


class Mesos(CommonInputsParams):
    timeout: int | None = None
    masters: list[str] | None = None
    master_collections: list[Literal["resources", "master", "system", "agents", "frameworks", 
                          "framework_offers", "tasks", "messages", "evqueue", 
                          "registrar", "allocator"]] | None = None
    slaves: list[str] | None = None
    slave_collections: list[Literal["resources", "agent", "system", 
                                    "executors", "tasks", "messages"]] | None = None
    tls_ca: str | None = None
    tls_cert: str | None = None
    tls_key: str | None = None
    insecure_skip_verify: bool | None = None


class Solr(CommonInputsParams):
    servers: list[str] | None = None
    cores: list[str] | None = None
    username: str | None = None
    password: str | None = None
    timeout: str | None = None


class Tomcat(CommonInputsParams):
    url: str | None = None
    timeout: str | None = None
    username: str | None = None
    password: str | None = None
    tls_ca: str | None = None
    tls_cert: str | None = None
    tls_key: str | None = None
    insecure_skip_verify: bool | None = None


class Zipkin(CommonInputsParams):
    path: str | None = None
    port: int | None = None
    read_timeout: str | None = None
    write_timeout: str | None = None


class Zookeeper(CommonInputsParams):
    servers: list[str] | None = None
    timeout: str | None = None
    parse_floats: str | None = None
    enable_tls: bool | None = None
    tls_ca: str | None = None
    tls_cert: str | None = None
    tls_key: str | None = None
    insecure_skip_verify: bool | None = None


class AzureMonitorSubscriptionTarget(BaseModel):
    resource_type: str | None = None
    metrics: list[str] | None = None
    aggregations: list[str] | None = None
    

class AzureMonitorResourceGroupTargetResource(BaseModel):
    resource_type: str | None = None
    metrics: list[str] | None = None
    aggregations: list[str] | None = None


class AzureMonitorResourceGroupTarget(BaseModel):
    resource_group: str | None = None
    resource: list[AzureMonitorResourceGroupTargetResource] | None = None


class AzureMonitorResourceTarget(BaseModel):
    resource_id: str | None = None
    metrics: list[str] | None = None
    aggregations: list[str] | None = None


class AzureMonitor(CommonInputsParams):
    subscription_id: str | None = None
    client_id: str | None = None
    client_secret: str | None = None
    tenant_id: str | None = None
    cloud_option: str | None = None
    resource_target: list[AzureMonitorResourceTarget] | None = None
    resource_group_target: list[AzureMonitorResourceGroupTarget] | None = None
    subscription_target: list[AzureMonitorSubscriptionTarget] | None = None


class Beat(CommonInputsParams):
    url: str | None = None
    include: list[Literal["beat", "libbeat", "system", "filebeat"]] | None = None
    method: str | None = None
    host_header: str | None = None
    timeout: str | None = None
    username: str | None = None
    password: str | None = None
    tls_ca: str | None = None
    tls_cert: str | None = None
    tls_key: str | None = None
    insecure_skip_verify: bool | None = None


class Bond(CommonInputsParams):
    host_proc: str | None = None
    host_sys: str | None = None
    bond_interfaces: list[str] | None = None
    collect_sys_details: bool | None = None


class Ceph(CommonInputsParams):
    interval: str | None = None
    ceph_binary: str | None = None
    socket_dir: str | None = None
    mon_prefix: str | None = None
    osd_prefix: str | None = None
    mds_prefix: str | None = None
    rgw_prefix: str | None = None
    socket_suffix: str | None = None
    ceph_user: str | None = None
    ceph_config: str | None = None
    gather_admin_socket_stats: bool | None = None
    gather_cluster_stats: bool | None = None


class Chrony(CommonInputsParams):
    server: str | None = None
    timeout: str | None = None
    dns_lookup: bool | None = None
    metrics: list[Literal["tracking", "activity", "serverstats", "sources", "sourcestats"]] | None = None
    socket_group: str | None = None
    socket_perms: str | None = None


class CiscoTelemetryMdtAliases(BaseModel):
    ifstats: str | None = None


class CiscoTelemetryMdtDmes(BaseModel):
    prop1: str | None = None
    prop2: str | None = None
    prop3: str | None = None
    prop4: str | None = None
    prop5: str | None = None
    dnpath: str | None = None
    dnpath2: str | None = None
    dnpath3: str | None = None


class CiscoTelemetryMdtGPRC(BaseModel):
    permit_keepalive_without_calls: bool | None = None
    keepalive_minimum_time: str | None = None


class CiscoTelemetryMdt(CommonInputsParams):
    transport: list[Literal["grpc", "tcp"]] | None = None
    service_address: str | None = None
    max_msg_size: int | None = None
    tls_cert: str | None = None
    tls_key: str | None = None
    tls_allowed_cacerts: list[str] | None = None
    embedded_tags: list[str] | None = None
    include_delete_field: bool | None = None
    source_field_name: str | None = None
    aliases: list[CiscoTelemetryMdtAliases] | None = None
    dmes: list[CiscoTelemetryMdtDmes] | None = None
    grpc_enforcement_policy: list[CiscoTelemetryMdtGPRC] | None = None


class Clickhouse(CommonInputsParams):
    username: str | None = None
    password: str | None = None
    timeout: str | None = None
    servers: list[str] | None = None
    variant: Literal["self-hosted", "managed"] | None = None
    auto_discovery: bool | None = None
    cluster_include: list[str] | None = None
    cluster_exclude: list[str] | None = None
    tls_ca: str | None = None
    tls_cert: str | None = None
    tls_key: str | None = None
    insecure_skip_verify: bool | None = None


class Cpu(CommonInputsParams):
    percpu: bool | None = None
    totalcpu: bool | None = None
    collect_cpu_time: bool | None = None
    report_active: bool | None = None
    core_tags: bool | None = None


class Disk(CommonInputsParams):
    mount_points: list[str] | None = None
    ignore_fs: list[Literal["tmpfs", "devtmpfs", "devfs", "iso9660", "overlay", "aufs", "squashfs"]] | None = None
    ignore_mount_opts: list[str] | None = None


class DnsQuery(CommonInputsParams):
    servers: list[str] | None = None
    network: str | None = None
    domains: list[str] | None = None
    record_type: list[Literal["A", "AAAA", "CNAME", "MX", "NS", "PTR", "TXT", "SOA", "SPF", "SRV"]] | None = None
    port: int | None = None
    timeout: str | None = None
    include_fields: list[Literal["all_ips", "first_ip"]] | None = None


class Docker(CommonInputsParams):
    endpoint: str | None = None
    gather_services: bool | None = None
    source_tag: bool | None = None
    container_name_include: list[str] | None = None
    container_name_exclude: list[str] | None = None
    container_state_include: list[Literal["created", "restarting", "running", "removing", "paused", "exited", "dead"]] | None = None
    container_state_exclude: list[Literal["created", "restarting", "running", "removing", "paused", "exited", "dead"]] | None = None
    storage_objects: list[Literal["container", "image", "volume"]] | None = None
    timeout: str | None = None
    perdevice_include: list[Literal["cpu", "blkio", "network"]] | None = None
    total_include: list[Literal["cpu", "blkio", "network"]] | None = None
    docker_label_include: list[str] | None = None
    docker_label_exclude: list[str] | None = None
    tag_env: list[Literal["JAVA_HOME", "HEAP_SIZE"]] | None = None
    tls_ca: str | None = None
    tls_cert: str | None = None
    tls_key: str | None = None
    insecure_skip_verify: bool | None = None


class ElasticSearch(CommonInputsParams):
    servers: list[str] | None = None
    local: bool | None = None
    cluster_health: bool | None = None
    cluster_health_level: Literal["indices", "cluster"] | None = None
    cluster_stats: bool | None = None
    cluster_stats_only_from_master: bool | None = None
    enrich_stats: bool | None = None
    indices_include: list[str] | None = None
    indices_level: Literal["shards", "cluster", "indices"] | None = None
    node_stats: Literal["indices", "os", "process", "jvm", "thread_pool", "fs", "transport", "http", "breaker"] | None = None
    username: str | None = None
    password: str | None = None
    tls_ca: str | None = None
    tls_cert: str | None = None
    tls_key: str | None = None
    insecure_skip_verify: bool | None = None
    use_system_proxy: bool | None = None
    http_proxy_url: str | None = None
    num_most_recent_indices: int | None = None

class ElasticSearchQueryAggregation(BaseModel):
    measurement_name: str | None = None
    index: str | None = None
    date_field: str | None = None
    date_field_custom_format: str | None = None
    query_period: str | None = None
    filter_query: str | None = None
    metric_fields: list[str] | None = None
    metric_function: Literal["avg", "sum", "min", "max", "sum"] | None = None
    tags: list[str] | None = None
    include_missing_tag: bool | None = None
    missing_tag_value: str | None = None

class ElasticSearchQuery(CommonInputsParams):
    urls: list[str] | None = None
    timeout: str | None = None
    enable_sniffer: bool | None = None
    health_check_interval: str | None = None
    username: str | None = None
    password: str | None = None
    tls_ca: str | None = None
    tls_cert: str | None = None
    tls_key: str | None = None
    insecure_skip_verify: bool | None = None
    use_system_proxy: bool | None = None
    http_proxy_url: str | None = None
    aggregation: list[ElasticSearchQueryAggregation] | None = None
        

class Ethtool(CommonInputsParams):
    interface_include: list[str] | None = None
    interface_exclude: list[str] | None = None
    down_interfaces: Literal["expose", "skip"]
    namespace_include: list[str] | None = None
    namespace_exclude: list[str] | None = None
    normalize_keys: list[Literal["snakecase", "trim", "lower", "underscore"]]


class Execd(CommonInputsParams):
    command: list[str] | None = None
    environment: list[str] | None = None
    signal: Literal["none", "STDIN", "SIGHUP", "SIGUSR1", "SIGUSR2"] | None = None
    restart_delay: str | None = None
    buffer_size: str | None = None
    stop_on_error: bool | None = None
    data_format: Literal["avro", "collectd", "dropwizard", "form_urlencoded", "influx", 
                        "binary", "carbon2", "cloudevents", "csv", "grok", "graphite", 
                        "json", "json_v2", "logfmt", "messagepack", "nagios", "parquet", 
                        "prometheus", "prometheusremotewrite", "openmetris", "opentsdb",
                        "servicenownetrics", "splunkmetric", "template", "value", 
                        "wavefront", "xpath_protobuf", "xml", "xpath_cbor", "xpath_json", 
                        "xpath_msgpack"]


class File(CommonInputsParams):
    files: list[str] | None = None
    character_encoding: Literal["utf-8", "utf-16le", "utf-16be", ""]
    data_format: Literal["avro", "collectd", "dropwizard", "form_urlencoded", "influx", 
                        "binary", "carbon2", "cloudevents", "csv", "grok", "graphite", 
                        "json", "json_v2", "logfmt", "messagepack", "nagios", "parquet", 
                        "prometheus", "prometheusremotewrite", "openmetris", "opentsdb",
                        "servicenownetrics", "splunkmetric", "template", "value", 
                        "wavefront", "xpath_protobuf", "xml", "xpath_cbor", "xpath_json", 
                        "xpath_msgpack"]
    file_tag: str | None = None
    file_path_tag: str | None = None


class Fireboard(CommonInputsParams):
    auth_token: str | None = None
    url: str | None = None
    http_timeout: str | None = None


class Fluentd(CommonInputsParams):
    endpoint: str | None = None
    exclude: list[str] | None = None


class Github(CommonInputsParams):
    repositories: list[str] | None = None
    access_token: str | None = None
    enterprise_base_url: str | None = None
    http_timeout: str | None = None
    additional_fields: list[str] | None = None


class CloudPubsub(CommonInputsParams):
    project: str | None = None
    subscription: str | None = None
    data_format: Literal["avro", "collectd", "dropwizard", "form_urlencoded", "influx", 
                        "binary", "carbon2", "cloudevents", "csv", "grok", "graphite", 
                        "json", "json_v2", "logfmt", "messagepack", "nagios", "parquet", 
                        "prometheus", "prometheusremotewrite", "openmetris", "opentsdb",
                        "servicenownetrics", "splunkmetric", "template", "value", 
                        "wavefront", "xpath_protobuf", "xml", "xpath_cbor", "xpath_json", 
                        "xpath_msgpack"]
    credentials_file: str | None = None
    retry_delay_seconds: int | None = None 
    max_message_len: int | None = None 
    max_undelivered_messages: int | None = None 
    max_extension: int | None = None 
    max_outstanding_messages: int | None = None 
    max_outstanding_bytes: int | None = None 
    max_receiver_go_routines: int | None = None 
    base64_data: bool | None = None
    content_encoding: Literal["identity", "gzip"] | None = None
    max_decompression_size: str | None = None


class Graylog(CommonInputsParams):
    servers: list[str] | None = None
    timeout: str | None = None
    metrics: list[str] | None = None
    username: str | None = None
    password: str | None = None
    tls_ca: str | None = None
    tls_cert: str | None = None
    tls_key: str | None = None
    insecure_skip_verify: bool | None = None


class Haproxy(CommonInputsParams):
    servers: list[str] | None = None
    keep_field_names: bool | None = None
    tls_ca: str | None = None
    tls_cert: str | None = None
    tls_key: str | None = None
    insecure_skip_verify: bool | None = None


class HttpInput(CommonInputsParams):
    urls: list[str] | None = None
    method: str | None = None
    headers: dict[str, str] | None = None
    body: str | None = None
    content_encoding: Literal["identity", "qzip"] | None = None
    
    token: str | None = None
    token_file: str | None = None
    
    username: str | None = None
    password: str | None = None
    
    client_id: str | None = None
    client_secret: str | None = None
    token_url: str | None = None
    scopes: list[str] | None = None
    
    use_system_proxy: bool | None = None
    http_proxy_url: str | None = None
    
    tls_enable: bool | None = None
    tls_ca: str | None = None
    tls_cert: str | None = None
    tls_key: str | None = None
    tls_key_pwd: str | None = None
    tls_server_name: str | None = None
    tls_min_version: str | None = None 
    tls_cipher_suites: list[Literal["all", "secure", "insecure"]] | None = None
    tls_renegotiation_method: Literal["never", "once", "freely"] | None = None
    insecure_skip_verify: bool | None = None
    
    cookie_auth_url: str | None = None
    cookie_auth_method: str | None = None
    cookie_auth_username: str | None = None
    cookie_auth_password: str | None = None
    cookie_auth_headers: dict[str, str] | None = None
    cookie_auth_body: str | None = None
    cookie_auth_renewal: str | None = None
    
    timeout: str | None = None
    success_status_codes: list[int] | None = None
    data_format: Literal["avro", "collectd", "dropwizard", "form_urlencoded", "influx", 
                         "binary", "carbon2", "cloudevents", "csv", "grok", "graphite", 
                         "json", "json_v2", "logfmt", "messagepack", "nagios", "parquet", 
                         "prometheus", "prometheusremotewrite", "openmetris", "opentsdb",
                         "servicenownetrics", "splunkmetric", "template", "value", 
                         "wavefront", "xpath_protobuf", "xml", "xpath_cbor", "xpath_json", 
                         "xpath_msgpack"] | None = None


class HttpListenerV2(CommonInputsParams):
    service_address: str | None = None
    socket_mode: str | None = None
    paths: list[str] | None = None
    path_tag: bool | None = None
    methods: list[Literal["POST", "PUT"]] | None = None
    http_success_code: int | None = None
    write_timeout: str | None = None
    max_body_size: str | None = None
    data_source: list[Literal["body", "query"]] | None = None
    tls_allowed_cacerts: list[str] | None = None
    tls_cert: str | None = None
    tls_key: str | None = None
    tls_min_version: str | None = None
    basic_username: str | None = None
    basic_password: str | None = None
    data_format: Literal["avro", "collectd", "dropwizard", "form_urlencoded", "influx", 
                         "binary", "carbon2", "cloudevents", "csv", "grok", "graphite", 
                         "json", "json_v2", "logfmt", "messagepack", "nagios", "parquet", 
                         "prometheus", "prometheusremotewrite", "openmetris", "opentsdb",
                         "servicenownetrics", "splunkmetric", "template", "value", 
                         "wavefront", "xpath_protobuf", "xml", "xpath_cbor", "xpath_json", 
                         "xpath_msgpack"] | None = None


class Huebridge(CommonInputsParams):
    bridges: list[str] | None = None
    timeout: int | None = None
    debug: bool | None = None


class Iptables(CommonInputsParams):
    use_sudo: bool | None = None
    use_lock: bool | None = None
    binary: str | None = None
    table: str | None = None
    chains: list[str] | None = None


class Influxdb(CommonInputsParams):
    urls: list[str] | None = None
    username: str | None = None
    password: str | None = None
    tls_ca: str | None = None
    tls_cert: str | None = None
    tls_key: str | None = None
    insecure_skip_verify: bool | None = None
    timeout: str | None = None


class IntelBaseband(CommonInputsParams):
    socket_path: str | None = None
    log_file_path: str | None = None
    unreachable_socket_behavior: Literal["error", "ignore"] | None = None
    socket_access_timeout: str | None = None
    wait_for_telemetry_timeout: str | None = None


class InternetSpeed(CommonInputsParams):
    interval: str | None = None
    memory_saving_mode: bool | None = None
    cache: bool | None = None
    connections: int | None = None
    test_mode: Literal["single", "multi"]
    server_id_exclude: list[str] | None = None
    server_id_include: list[str] | None = None


class Ipvs(CommonInputsParams):
    pass


class Jenkins(CommonInputsParams):
    url: str | None = None
    username: str | None = None
    password: str | None = None
    response_timeout: str | None = None
    tls_ca: str | None = None
    tls_cert: str | None = None
    tls_key: str | None = None
    insecure_skip_verify: bool | None = None
    max_build_age: str | None = None
    max_subjob_depth: int | None = None
    max_subjob_per_layer: int | None = None
    job_include: list[str] | None = None
    job_exclude: list[str] | None = None
    node_include: list[str] | None = None
    node_exclude: list[str] | None = None
    max_connections: int | None = None
    node_labels_as_tag: bool | None = None


class Kapacitor(CommonInputsParams):
    urls: list[str] | None = None
    timeout: str | None = None
    tls_ca: str | None = None
    tls_cert: str | None = None
    tls_key: str | None = None
    insecure_skip_verify: bool | None = None


class Kibana(CommonInputsParams):
    servers: list[str] | None = None
    timeout: str | None = None
    username: str | None = None
    password: str | None = None
    tls_ca: str | None = None
    tls_cert: str | None = None
    tls_key: str | None = None
    insecure_skip_verify: bool | None = None
    use_system_proxy: bool | None = None
    http_proxy_url: str | None = None


class Kubernetes(CommonInputsParams):
    url: str | None = None
    bearer_token_string: str | None = None
    node_metric_name: str | None = None
    label_include: list[str] | None = None
    label_exclude: list[str] | None = None
    response_timeout: str | None = None
    tls_ca: str | None = None
    tls_cert: str | None = None
    tls_key: str | None = None
    insecure_skip_verify: bool | None = None


class LogparserGrok(BaseModel):
    patterns: list[str] | None = None
    measurement: str | None = None
    custom_pattern_files: list[str] | None = None
    custom_patterns: bool | None = None
    timezone: Literal["Canada/Eastern", "Local", "UTC"] | None = None
    unique_timestamp: Literal["auto", "disable"] | None = None


class Logparser(CommonInputsParams):
    files: list[str] | None = None
    from_beginning: bool | None = None
    watch_method: Literal["inotify", "poll"] | None = None
    grok: list[LogparserGrok]


class Logstash(CommonInputsParams):
    url: str | None = None
    single_pipeline: bool | None = None
    collect: list[Literal["pipelines", "process", "jvm"]] | None = None
    timeout: str | None = None
    username: str | None = None
    password: str | None = None
    tls_ca: str | None = None
    tls_cert: str | None = None
    tls_key: str | None = None
    insecure_skip_verify: bool | None = None
    use_system_proxy: bool | None = None
    http_proxy_ur: str | None = None


class Mem(CommonInputsParams):
    pass


class Sqlserver(CommonInputsParams):
    servers: list[str] | None = None
    query_timeout: str | None = None
    auth_method: Literal["connection_string", "AAD"] | None = None
    client_id: str | None = None
    database_type: Literal["SQLServer", "AzureSQLDB", "AzureSQLPool"] | None = None
    include_query: list[str] | None = None
    exclude_query: list[str] | None = None
    query_version: int | None = None
    azuredb: bool | None = None
    health_metric: bool | None = None


class Mongodb(CommonInputsParams):
    servers: list[str] | None = None
    gather_cluster_status: bool | None = None
    gather_perdb_stats: bool | None = None
    gather_col_stats: bool | None = None
    gather_top_stat: bool | None = None
    col_stats_dbs: list[str] | None = None
    tls_ca: str | None = None
    tls_cert: str | None = None
    tls_key: str | None = None
    insecure_skip_verify: bool | None = None
    disconnected_servers_behavior: list[Literal["error", "skip"]] | None = None


class Mysql(CommonInputsParams):
    servers: list[str] | None = None
    metric_version: list[Literal[1, 2]] | None = None
    table_schema_databases: list[str] | None = None
    gather_table_schema: bool | None = None
    gather_process_list: bool | None = None
    gather_user_statistics: bool | None = None
    gather_info_schema_auto_inc: bool | None = None
    gather_innodb_metrics: bool | None = None
    gather_all_slave_channels: bool | None = None
    gather_slave_status: bool | None = None
    gather_replica_status: bool | None = None
    mariadb_dialect: bool | None = None
    gather_binary_logs: bool | None = None
    gather_global_variables: bool | None = None
    gather_table_io_waits: bool | None = None
    gather_table_lock_waits: bool | None = None
    gather_index_io_waits: bool | None = None
    gather_event_waits: bool | None = None
    gather_file_events_stats: bool | None = None
    gather_perf_events_statements: bool | None = None
    gather_perf_sum_per_acc_per_event: bool | None = None
    perf_summary_events: list[str] | None = None
    perf_events_statements_digest_text_limit: int | None = None
    perf_events_statements_limit: int | None = None
    perf_events_statements_time_limit: int | None = None
    interval_slow: str | None = None
    tls_ca: str | None = None
    tls_cert: str | None = None
    tls_key: str | None = None
    insecure_skip_verify: bool | None = None
    name_suffix: str | None = None


class Net(CommonInputsParams):
    interfaces: list[str] | None = None
    ignore_protocol_stats: bool | None = None


class Netstat(CommonInputsParams):
    pass


class Nginx(CommonInputsParams):
    urls: list[str] | None = None
    tls_ca: str | None = None
    tls_cert: str | None = None
    tls_key: str | None = None
    insecure_skip_verify: bool | None = None
    response_timeout: str | None = None


class Nsdp(CommonInputsParams):
    target: str | None = None
    device_limit: int | None = None
    timeout: int | None = None
    debug: bool | None = None


class OpensearchQueryAggreagation(BaseModel):
    measurement_name: str | None = None
    index: str | None = None
    date_field: str | None = None
    query_period: str | None = None
    filter_query: str | None = None
    metric_fields: list[str] | None = None
    metric_function: Literal["avg", "avg", "sum", "min", "max", "sum"] = None
    tags: list[str] | None = None
    include_missing_tag: bool | None = None
    missing_tag_value: str | None = None

class OpensearchQuery(CommonInputsParams):
    urls: list[str] | None = None
    timeout: str | None = None
    username: str | None = None
    password: str | None = None
    insecure_skip_verify: bool | None = None
    aggregation: list[OpensearchQueryAggreagation] | None = None
        

class Opentelemetry(CommonInputsParams):
    service_address: str | None = None
    timeout: str | None = None
    max_msg_size: str | None = None
    span_dimensions: list[str] | None = None
    log_record_dimensions: list[str] | None = None
    profile_dimensions: list[str] | None = None
    metrics_schema: str | None = None
    tls_ca: str | None = None
    tls_cert: str | None = None
    tls_key: str | None = None
    insecure_skip_verify: bool | None = None


class OpenLDAP(CommonInputsParams):
    host: str | None = None
    port: int | None = None
    tls: Literal["", "starttls", "ldaps"] | None = None
    insecure_skip_verify: bool | None = None
    tls_ca: str | None = None
    bind_dn: str | None = None
    bind_password: str | None = None
    reverse_metric_names: bool | None = None


class Oracle(CommonInputsParams):
    commands: list[str] | None = None
    timeout: str | None = None
    data_format: str | None = None
    interval: str | None = None


class Postgresql(CommonInputsParams):
    address: str | None = None
    outputaddress: str | None = None
    max_lifetime: str | None = None
    ignored_databases: list[str] | None = None
    databases: list[str] | None = None
    prepared_statements: bool | None = None


class PrometheusNamespaceDrop(BaseModel):
    some_annotation_key: list[str] | None = None


class PrometheusNamespacePass(BaseModel):
    annotation_key: list[str] | None = None


class PrometheusConsulQueryTags(BaseModel):
    host: str | None = None


class PrometheusConsulQuery(BaseModel):
    name: str | None = None
    tag: str | None = None
    url: str | None = None
    tags: list[PrometheusConsulQueryTags] | None = None


class PrometheusConsul(BaseModel):
    enabled: bool | None = None
    agent: str | None = None
    query_interval: str | None = None
    query: list[PrometheusConsulQuery] | None = None


class Prometheus(CommonInputsParams):
    urls: list[str] | None = None
    metric_version: Literal[1, 2] | None = None
    url_tag: str | None = None
    ignore_timestamp: bool | None = None
    content_type_override: Literal["text", "protobuf-delimiter", "protobuf-compact", "protobuf-text"] | None = None
    kubernetes_services: list[str] | None = None
    kube_config: str | None = None
    monitor_kubernetes_pods: bool | None = None
    monitor_kubernetes_pods_method: Literal["annotations", "settings", "defined settings"] | None = None
    monitor_kubernetes_pods_scheme: str | None = None
    monitor_kubernetes_pods_port: str | None = None
    monitor_kubernetes_pods_path: str | None = None
    pod_scrape_scope: Literal["cluster", "node"] | None = None
    node_ip: str | None = None
    pod_scrape_interval: int | None = None
    content_length_limit: str | None = None
    monitor_kubernetes_pods_namespace: str | None = None
    pod_namespace_label_name: str | None = None
    kubernetes_field_selector: str | None = None
    pod_annotation_include: list[str] | None = None
    pod_annotation_exclude: list[str] | None = None
    pod_label_include: list[str] | None = None
    pod_label_exclude: list[str] | None = None
    cache_refresh_interval: int | None = None
    bearer_token: str | None = None
    bearer_token_string: str | None = None
    username: str | None = None
    password: str | None = None
    timeout: str | None = None
    response_timeout: str | None = None
    http_proxy_url: str | None = None
    tls_ca: str | None = None
    tls_cert: str | None = None
    tls_key: str | None = None
    insecure_skip_verify: bool | None = None
    tls_server_name: str | None = None
    tls_renegotiation_method: Literal["never", "once", "freely"] | None = None
    tls_enable: bool | None = None
    enable_request_metrics: bool | None = None
    consul: list[PrometheusConsul] | None = None
    namespace_annotation_pass: list[PrometheusNamespacePass] | None = None
    namespace_annotation_drop: list[PrometheusNamespaceDrop] | None = None


class Rabbitmq(CommonInputsParams):
    url: str | None = None
    username: str | None = None
    password: str | None = None
    tls_ca: str | None = None
    tls_cert: str | None = None
    tls_key: str | None = None
    insecure_skip_verify: bool | None = None
    header_timeout: str | None = None
    client_timeout: str | None = None
    nodes: list[str] | None = None
    exchanges: list[str] | None = None
    metric_include: list[str] | None = None
    metric_exclude: list[str] | None = None
    queue_name_include: list[str] | None = None
    queue_name_exclude: list[str] | None = None
    federation_upstream_include: list[str] | None = None
    federation_upstream_exclude: list[str] | None = None


class RedisCommands(BaseModel):
    command: list[str] | None = None
    field: str | None = None
    type: list[Literal["string", "integer", "float"]] | None = None


class Redis(CommonInputsParams):
    servers: list[str] | None = None
    commands: list[RedisCommands] | None = None
    username: str | None = None
    password: str | None = None
    tls_ca: str | None = None
    tls_cert: str | None = None
    tls_key: str | None = None
    insecure_skip_verify: bool | None = None


class SNMPField(BaseModel):
    oid: str | None = None
    name: str | None = None
    conversion: str | None = None
    is_tag: bool | None = None
    oid_index_suffix: str | None = None
    oid_index_length: int | None = None
    translate: bool | None = None
    secondary_index_table: bool | None = None
    secondary_index_use: bool | None = None
    secondary_outer_join: bool | None = None

class SNMPTable(BaseModel):
    inherit_tags: list[str] | None = None
    name: str | None = None
    oid: str | None = None
    index_as_tag: bool | None = None
    field: list[SNMPField] | None = None


class Snmp(CommonInputsParams):
    agents: list[str] | None = None
    timeout: str | None = None
    version: Literal[1, 2, 3] | None = None
    unconnected_udp_socket: bool | None = None
    path: list[str] | None = None
    community: str | None = None
    agent_host_tag: Literal["source", "agent_host"] | None = None
    retries: int | None = None
    max_repetitions: int | None = None
    sec_name: str | None = None
    auth_protocol: Literal["MD5", "SHA", "SHA224", "SHA256", "SHA384", "SHA512", ""] | None = None
    auth_password: str | None = None
    sec_level: Literal["noAuthNoPriv", "authNoPriv", "authPriv"] | None = None
    context_name: str | None = None
    priv_protocol: Literal["AES192", "AES192", "AES256", "AES256C"] | None = None
    priv_password: str | None = None

    field: list[SNMPField] | None = None
    table: list[SNMPTable] | None = None


class SnmpTrap(CommonInputsParams):
    service_address: str | None = None
    path: list[str] | None = None
    timeout: str | None = None
    version: Literal["1", "2c", "3"] | None = None
    sec_name: str | None = None
    auth_protocol: Literal["MD5", "SHA", "SHA224", "SHA256", "SHA384", "SHA512", ""] | None = None
    auth_password: str | None = None
    sec_level: Literal["noAuthNoPriv", "authNoPriv", "authPriv"] | None = None
    priv_protocol: Literal["DES", "AES", "AES192", "AES192C", "AES256", "AES256C", ""] | None = None
    priv_password: str | None = None


class SqlQuery(BaseModel):
    query: str | None = None
    query_script: str | None = None
    measurement: str | None = None
    measurement_column: str | None = None
    time_column: str | None = None
    time_format: Literal["unix", "unix_ms", "unix_us", "unix_ns"] | None = None
    tag_columns_include: list[str] | None = None
    tag_columns_exclude: list[str] | None = None
    field_columns_float: list[str] | None = None
    field_columns_int: list[str] | None = None
    field_columns_uint: list[str] | None = None
    field_columns_bool: list[str] | None = None
    field_columns_string: list[str] | None = None
    field_columns_include: list[str] | None = None
    field_columns_exclude: list[str] | None = None


class Sql(CommonInputsParams):
    driver: str | None = None
    dsn: str | None = None
    timeout: str | None = None
    connection_max_idle_time: str | None = None
    connection_max_life_time: str | None = None
    connection_max_open: int | None = None
    connection_max_idle: str | None = None
    disconnected_servers_behavior: Literal["error", "ignore"] | None = None
    query: list[SqlQuery] | None = None


class Statsd(CommonInputsParams):
    protocol: Literal["tcp", "udp4", "udp6", "udp"] | None = None
    max_tcp_connections: int | None = None
    tcp_keep_alive: bool | None = None
    tcp_keep_alive_period: str | None = None
    service_address: str | None = None
    delete_gauges: bool | None = None
    delete_counters: bool | None = None
    delete_sets: bool | None = None
    delete_timings: bool | None = None
    enable_aggregation_temporality: bool | None = None
    percentiles: list[float] | None = None
    metric_separator: str | None = None
    datadog_extensions: bool | None = None
    datadog_distributions: bool | None = None
    datadog_keep_container_tag: bool | None = None
    templates: list[str] | None = None
    allowed_pending_messages: int | None = None
    number_workers_threads: int | None = None
    percentile_limit: int | None = None
    read_buffer_size: int | None = None
    max_ttl: str | None = None
    sanitize_name_method: str | None = None
    convert_names: bool | None = None
    float_counters: bool | None = None


class Syslog(CommonInputsParams):
    server: str | None = None
    socket_mode: str | None = None
    max_connections: int | None = None
    read_timeout: str | None = None
    tls_cert: str | None = None
    tls_key: str | None = None
    tls_allowed_cacerts: str | None = None
    read_buffer_size: str | None = None
    keep_alive_period: str | None = None
    content_encoding: Literal["identity", "gzip"]
    max_decompression_size: str | None = None
    framing: Literal["octet-counting", "non-transparent"]
    trailer: Literal["LF", "NUL"]
    best_effort: bool | None = None
    syslog_standard: Literal["RFC5424", "RFC3164"]
    sdparam_separator: str | None = None


class System(CommonInputsParams):
    pass


class Temp(CommonInputsParams):
    metric_format: Literal["v1", "v2"] | None = None
    add_device_tag: bool | None = None


class Vsphere(CommonInputsParams):
    vcenters: list[str] | None = None
    username: str | None = None
    password: str | None = None

    vm_include: list[str] | None = None
    vm_exclude: list[str] | None = None
    vm_metric_include: list[str] | None = None
    vm_metric_exclude: list[str] | None = None
    vm_instances: int | None = None

    host_include: list[str] | None = None
    host_exclude: list[str] | None = None
    host_metric_include: list[str] | None = None
    ip_addresses: list[Literal["ipv6", "ipv4"]] | None = None
    host_metric_exclude: list[str] | None = None
    host_instances: bool | None = None

    cluster_include: list[str] | None = None
    cluster_exclude: list[str] | None = None
    cluster_metric_include: list[str] | None = None
    cluster_metric_exclude: list[str] | None = None
    cluster_instances: bool | None = None

    resource_pool_include: list[str] | None = None
    resource_pool_exclude: list[str] | None = None
    resource_pool_metric_include: list[str] | None = None
    resource_pool_metric_exclude: list[str] | None = None
    resource_pool_instances: bool | None = None

    datastore_include: list[str] | None = None
    datastore_exclude: list[str] | None = None
    datastore_metric_include: list[str] | None = None
    datastore_metric_exclude: list[str] | None = None
    datastore_instances: bool | None = None

    datacenter_include: list[str] | None = None
    datacenter_exclude: list[str] | None = None
    datacenter_metric_include: list[str] | None = None
    datacenter_metric_exclude: list[str] | None = None
    datacenter_instances: bool | None = None

    vsan_metric_include: list[str] | None = None
    vsan_metric_exclude: list[str] | None = None
    vsan_metric_skip_verify: bool | None = None
    vsan_interval: str | None = None
    separator: str | None = None
    max_query_objects: int | None = None
    max_query_metrics: int | None = None
    collect_concurrency: int | None = None
    discover_concurrency: int | None = None
    object_discovery_interval: str | None = None
    timeout: str | None = None
    use_int_samples: bool | None = None
    custom_attribute_include: list[str] | None = None
    custom_attribute_exclude: list[str] | None = None
    metric_lookback: int | None = None
    
    ssl_ca: str | None = None
    ssl_cert: str | None = None
    ssl_key: str | None = None
    insecure_skip_verify: bool | None = None
    
    historical_interval: str | None = None
    disconnected_servers_behavior: Literal["error", "ignore"] | None = None
    http_proxy_url: str | None = None


class WinServices(CommonInputsParams):
    service_names: list[str] | None = None
    excluded_service_names: list[str] | None = None

