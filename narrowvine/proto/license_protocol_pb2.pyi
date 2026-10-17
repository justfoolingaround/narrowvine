from collections.abc import Iterable as _Iterable
from collections.abc import Mapping as _Mapping
from typing import ClassVar as _ClassVar

from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from google.protobuf.internal import containers as _containers
from google.protobuf.internal import enum_type_wrapper as _enum_type_wrapper

DESCRIPTOR: _descriptor.FileDescriptor

class LicenseType(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    STREAMING: _ClassVar[LicenseType]
    OFFLINE: _ClassVar[LicenseType]
    AUTOMATIC: _ClassVar[LicenseType]

class PlatformVerificationStatus(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    PLATFORM_UNVERIFIED: _ClassVar[PlatformVerificationStatus]
    PLATFORM_TAMPERED: _ClassVar[PlatformVerificationStatus]
    PLATFORM_SOFTWARE_VERIFIED: _ClassVar[PlatformVerificationStatus]
    PLATFORM_HARDWARE_VERIFIED: _ClassVar[PlatformVerificationStatus]
    PLATFORM_NO_VERIFICATION: _ClassVar[PlatformVerificationStatus]
    PLATFORM_SECURE_STORAGE_SOFTWARE_VERIFIED: _ClassVar[PlatformVerificationStatus]

class ProtocolVersion(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    VERSION_2_0: _ClassVar[ProtocolVersion]
    VERSION_2_1: _ClassVar[ProtocolVersion]
    VERSION_2_2: _ClassVar[ProtocolVersion]

class HashAlgorithmProto(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    HASH_ALGORITHM_UNSPECIFIED: _ClassVar[HashAlgorithmProto]
    HASH_ALGORITHM_SHA_1: _ClassVar[HashAlgorithmProto]
    HASH_ALGORITHM_SHA_256: _ClassVar[HashAlgorithmProto]
    HASH_ALGORITHM_SHA_384: _ClassVar[HashAlgorithmProto]
STREAMING: LicenseType
OFFLINE: LicenseType
AUTOMATIC: LicenseType
PLATFORM_UNVERIFIED: PlatformVerificationStatus
PLATFORM_TAMPERED: PlatformVerificationStatus
PLATFORM_SOFTWARE_VERIFIED: PlatformVerificationStatus
PLATFORM_HARDWARE_VERIFIED: PlatformVerificationStatus
PLATFORM_NO_VERIFICATION: PlatformVerificationStatus
PLATFORM_SECURE_STORAGE_SOFTWARE_VERIFIED: PlatformVerificationStatus
VERSION_2_0: ProtocolVersion
VERSION_2_1: ProtocolVersion
VERSION_2_2: ProtocolVersion
HASH_ALGORITHM_UNSPECIFIED: HashAlgorithmProto
HASH_ALGORITHM_SHA_1: HashAlgorithmProto
HASH_ALGORITHM_SHA_256: HashAlgorithmProto
HASH_ALGORITHM_SHA_384: HashAlgorithmProto

class LicenseIdentification(_message.Message):
    __slots__ = ("provider_session_token", "purchase_id", "request_id", "session_id", "type", "version")
    REQUEST_ID_FIELD_NUMBER: _ClassVar[int]
    SESSION_ID_FIELD_NUMBER: _ClassVar[int]
    PURCHASE_ID_FIELD_NUMBER: _ClassVar[int]
    TYPE_FIELD_NUMBER: _ClassVar[int]
    VERSION_FIELD_NUMBER: _ClassVar[int]
    PROVIDER_SESSION_TOKEN_FIELD_NUMBER: _ClassVar[int]
    request_id: bytes
    session_id: bytes
    purchase_id: bytes
    type: LicenseType
    version: int
    provider_session_token: bytes
    def __init__(self, request_id: bytes | None = ..., session_id: bytes | None = ..., purchase_id: bytes | None = ..., type: LicenseType | str | None = ..., version: int | None = ..., provider_session_token: bytes | None = ...) -> None: ...

class License(_message.Message):
    __slots__ = ("group_ids", "id", "key", "license_start_time", "platform_verification_status", "policy", "protection_scheme", "provider_client_token", "remote_attestation_verified", "srm_requirement", "srm_update")
    class Policy(_message.Message):
        __slots__ = ("always_include_client_id", "can_persist", "can_play", "can_renew", "license_duration_seconds", "play_start_grace_period_seconds", "playback_duration_seconds", "renew_with_usage", "renewal_delay_seconds", "renewal_recovery_duration_seconds", "renewal_retry_interval_seconds", "renewal_server_url", "rental_duration_seconds", "soft_enforce_playback_duration", "soft_enforce_rental_duration")
        CAN_PLAY_FIELD_NUMBER: _ClassVar[int]
        CAN_PERSIST_FIELD_NUMBER: _ClassVar[int]
        CAN_RENEW_FIELD_NUMBER: _ClassVar[int]
        RENTAL_DURATION_SECONDS_FIELD_NUMBER: _ClassVar[int]
        PLAYBACK_DURATION_SECONDS_FIELD_NUMBER: _ClassVar[int]
        LICENSE_DURATION_SECONDS_FIELD_NUMBER: _ClassVar[int]
        RENEWAL_RECOVERY_DURATION_SECONDS_FIELD_NUMBER: _ClassVar[int]
        RENEWAL_SERVER_URL_FIELD_NUMBER: _ClassVar[int]
        RENEWAL_DELAY_SECONDS_FIELD_NUMBER: _ClassVar[int]
        RENEWAL_RETRY_INTERVAL_SECONDS_FIELD_NUMBER: _ClassVar[int]
        RENEW_WITH_USAGE_FIELD_NUMBER: _ClassVar[int]
        ALWAYS_INCLUDE_CLIENT_ID_FIELD_NUMBER: _ClassVar[int]
        PLAY_START_GRACE_PERIOD_SECONDS_FIELD_NUMBER: _ClassVar[int]
        SOFT_ENFORCE_PLAYBACK_DURATION_FIELD_NUMBER: _ClassVar[int]
        SOFT_ENFORCE_RENTAL_DURATION_FIELD_NUMBER: _ClassVar[int]
        can_play: bool
        can_persist: bool
        can_renew: bool
        rental_duration_seconds: int
        playback_duration_seconds: int
        license_duration_seconds: int
        renewal_recovery_duration_seconds: int
        renewal_server_url: str
        renewal_delay_seconds: int
        renewal_retry_interval_seconds: int
        renew_with_usage: bool
        always_include_client_id: bool
        play_start_grace_period_seconds: int
        soft_enforce_playback_duration: bool
        soft_enforce_rental_duration: bool
        def __init__(self, can_play: bool | None = ..., can_persist: bool | None = ..., can_renew: bool | None = ..., rental_duration_seconds: int | None = ..., playback_duration_seconds: int | None = ..., license_duration_seconds: int | None = ..., renewal_recovery_duration_seconds: int | None = ..., renewal_server_url: str | None = ..., renewal_delay_seconds: int | None = ..., renewal_retry_interval_seconds: int | None = ..., renew_with_usage: bool | None = ..., always_include_client_id: bool | None = ..., play_start_grace_period_seconds: int | None = ..., soft_enforce_playback_duration: bool | None = ..., soft_enforce_rental_duration: bool | None = ...) -> None: ...
    class KeyContainer(_message.Message):
        __slots__ = ("anti_rollback_usage_table", "id", "iv", "key", "key_control", "level", "operator_session_key_permissions", "requested_protection", "required_protection", "track_label", "type", "video_resolution_constraints")
        class KeyType(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
            __slots__ = ()
            SIGNING: _ClassVar[License.KeyContainer.KeyType]
            CONTENT: _ClassVar[License.KeyContainer.KeyType]
            KEY_CONTROL: _ClassVar[License.KeyContainer.KeyType]
            OPERATOR_SESSION: _ClassVar[License.KeyContainer.KeyType]
            ENTITLEMENT: _ClassVar[License.KeyContainer.KeyType]
            OEM_CONTENT: _ClassVar[License.KeyContainer.KeyType]
        SIGNING: License.KeyContainer.KeyType
        CONTENT: License.KeyContainer.KeyType
        KEY_CONTROL: License.KeyContainer.KeyType
        OPERATOR_SESSION: License.KeyContainer.KeyType
        ENTITLEMENT: License.KeyContainer.KeyType
        OEM_CONTENT: License.KeyContainer.KeyType
        class SecurityLevel(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
            __slots__ = ()
            SW_SECURE_CRYPTO: _ClassVar[License.KeyContainer.SecurityLevel]
            SW_SECURE_DECODE: _ClassVar[License.KeyContainer.SecurityLevel]
            HW_SECURE_CRYPTO: _ClassVar[License.KeyContainer.SecurityLevel]
            HW_SECURE_DECODE: _ClassVar[License.KeyContainer.SecurityLevel]
            HW_SECURE_ALL: _ClassVar[License.KeyContainer.SecurityLevel]
        SW_SECURE_CRYPTO: License.KeyContainer.SecurityLevel
        SW_SECURE_DECODE: License.KeyContainer.SecurityLevel
        HW_SECURE_CRYPTO: License.KeyContainer.SecurityLevel
        HW_SECURE_DECODE: License.KeyContainer.SecurityLevel
        HW_SECURE_ALL: License.KeyContainer.SecurityLevel
        class KeyControl(_message.Message):
            __slots__ = ("iv", "key_control_block")
            KEY_CONTROL_BLOCK_FIELD_NUMBER: _ClassVar[int]
            IV_FIELD_NUMBER: _ClassVar[int]
            key_control_block: bytes
            iv: bytes
            def __init__(self, key_control_block: bytes | None = ..., iv: bytes | None = ...) -> None: ...
        class OutputProtection(_message.Message):
            __slots__ = ("cgms_flags", "disable_analog_output", "disable_digital_output", "hdcp", "hdcp_srm_rule")
            class HDCP(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
                __slots__ = ()
                HDCP_NONE: _ClassVar[License.KeyContainer.OutputProtection.HDCP]
                HDCP_V1: _ClassVar[License.KeyContainer.OutputProtection.HDCP]
                HDCP_V2: _ClassVar[License.KeyContainer.OutputProtection.HDCP]
                HDCP_V2_1: _ClassVar[License.KeyContainer.OutputProtection.HDCP]
                HDCP_V2_2: _ClassVar[License.KeyContainer.OutputProtection.HDCP]
                HDCP_V2_3: _ClassVar[License.KeyContainer.OutputProtection.HDCP]
                HDCP_NO_DIGITAL_OUTPUT: _ClassVar[License.KeyContainer.OutputProtection.HDCP]
            HDCP_NONE: License.KeyContainer.OutputProtection.HDCP
            HDCP_V1: License.KeyContainer.OutputProtection.HDCP
            HDCP_V2: License.KeyContainer.OutputProtection.HDCP
            HDCP_V2_1: License.KeyContainer.OutputProtection.HDCP
            HDCP_V2_2: License.KeyContainer.OutputProtection.HDCP
            HDCP_V2_3: License.KeyContainer.OutputProtection.HDCP
            HDCP_NO_DIGITAL_OUTPUT: License.KeyContainer.OutputProtection.HDCP
            class CGMS(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
                __slots__ = ()
                CGMS_NONE: _ClassVar[License.KeyContainer.OutputProtection.CGMS]
                COPY_FREE: _ClassVar[License.KeyContainer.OutputProtection.CGMS]
                COPY_ONCE: _ClassVar[License.KeyContainer.OutputProtection.CGMS]
                COPY_NEVER: _ClassVar[License.KeyContainer.OutputProtection.CGMS]
            CGMS_NONE: License.KeyContainer.OutputProtection.CGMS
            COPY_FREE: License.KeyContainer.OutputProtection.CGMS
            COPY_ONCE: License.KeyContainer.OutputProtection.CGMS
            COPY_NEVER: License.KeyContainer.OutputProtection.CGMS
            class HdcpSrmRule(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
                __slots__ = ()
                HDCP_SRM_RULE_NONE: _ClassVar[License.KeyContainer.OutputProtection.HdcpSrmRule]
                CURRENT_SRM: _ClassVar[License.KeyContainer.OutputProtection.HdcpSrmRule]
            HDCP_SRM_RULE_NONE: License.KeyContainer.OutputProtection.HdcpSrmRule
            CURRENT_SRM: License.KeyContainer.OutputProtection.HdcpSrmRule
            HDCP_FIELD_NUMBER: _ClassVar[int]
            CGMS_FLAGS_FIELD_NUMBER: _ClassVar[int]
            HDCP_SRM_RULE_FIELD_NUMBER: _ClassVar[int]
            DISABLE_ANALOG_OUTPUT_FIELD_NUMBER: _ClassVar[int]
            DISABLE_DIGITAL_OUTPUT_FIELD_NUMBER: _ClassVar[int]
            hdcp: License.KeyContainer.OutputProtection.HDCP
            cgms_flags: License.KeyContainer.OutputProtection.CGMS
            hdcp_srm_rule: License.KeyContainer.OutputProtection.HdcpSrmRule
            disable_analog_output: bool
            disable_digital_output: bool
            def __init__(self, hdcp: License.KeyContainer.OutputProtection.HDCP | str | None = ..., cgms_flags: License.KeyContainer.OutputProtection.CGMS | str | None = ..., hdcp_srm_rule: License.KeyContainer.OutputProtection.HdcpSrmRule | str | None = ..., disable_analog_output: bool | None = ..., disable_digital_output: bool | None = ...) -> None: ...
        class VideoResolutionConstraint(_message.Message):
            __slots__ = ("max_resolution_pixels", "min_resolution_pixels", "required_protection")
            MIN_RESOLUTION_PIXELS_FIELD_NUMBER: _ClassVar[int]
            MAX_RESOLUTION_PIXELS_FIELD_NUMBER: _ClassVar[int]
            REQUIRED_PROTECTION_FIELD_NUMBER: _ClassVar[int]
            min_resolution_pixels: int
            max_resolution_pixels: int
            required_protection: License.KeyContainer.OutputProtection
            def __init__(self, min_resolution_pixels: int | None = ..., max_resolution_pixels: int | None = ..., required_protection: License.KeyContainer.OutputProtection | _Mapping | None = ...) -> None: ...
        class OperatorSessionKeyPermissions(_message.Message):
            __slots__ = ("allow_decrypt", "allow_encrypt", "allow_sign", "allow_signature_verify")
            ALLOW_ENCRYPT_FIELD_NUMBER: _ClassVar[int]
            ALLOW_DECRYPT_FIELD_NUMBER: _ClassVar[int]
            ALLOW_SIGN_FIELD_NUMBER: _ClassVar[int]
            ALLOW_SIGNATURE_VERIFY_FIELD_NUMBER: _ClassVar[int]
            allow_encrypt: bool
            allow_decrypt: bool
            allow_sign: bool
            allow_signature_verify: bool
            def __init__(self, allow_encrypt: bool | None = ..., allow_decrypt: bool | None = ..., allow_sign: bool | None = ..., allow_signature_verify: bool | None = ...) -> None: ...
        ID_FIELD_NUMBER: _ClassVar[int]
        IV_FIELD_NUMBER: _ClassVar[int]
        KEY_FIELD_NUMBER: _ClassVar[int]
        TYPE_FIELD_NUMBER: _ClassVar[int]
        LEVEL_FIELD_NUMBER: _ClassVar[int]
        REQUIRED_PROTECTION_FIELD_NUMBER: _ClassVar[int]
        REQUESTED_PROTECTION_FIELD_NUMBER: _ClassVar[int]
        KEY_CONTROL_FIELD_NUMBER: _ClassVar[int]
        OPERATOR_SESSION_KEY_PERMISSIONS_FIELD_NUMBER: _ClassVar[int]
        VIDEO_RESOLUTION_CONSTRAINTS_FIELD_NUMBER: _ClassVar[int]
        ANTI_ROLLBACK_USAGE_TABLE_FIELD_NUMBER: _ClassVar[int]
        TRACK_LABEL_FIELD_NUMBER: _ClassVar[int]
        id: bytes
        iv: bytes
        key: bytes
        type: License.KeyContainer.KeyType
        level: License.KeyContainer.SecurityLevel
        required_protection: License.KeyContainer.OutputProtection
        requested_protection: License.KeyContainer.OutputProtection
        key_control: License.KeyContainer.KeyControl
        operator_session_key_permissions: License.KeyContainer.OperatorSessionKeyPermissions
        video_resolution_constraints: _containers.RepeatedCompositeFieldContainer[License.KeyContainer.VideoResolutionConstraint]
        anti_rollback_usage_table: bool
        track_label: str
        def __init__(self, id: bytes | None = ..., iv: bytes | None = ..., key: bytes | None = ..., type: License.KeyContainer.KeyType | str | None = ..., level: License.KeyContainer.SecurityLevel | str | None = ..., required_protection: License.KeyContainer.OutputProtection | _Mapping | None = ..., requested_protection: License.KeyContainer.OutputProtection | _Mapping | None = ..., key_control: License.KeyContainer.KeyControl | _Mapping | None = ..., operator_session_key_permissions: License.KeyContainer.OperatorSessionKeyPermissions | _Mapping | None = ..., video_resolution_constraints: _Iterable[License.KeyContainer.VideoResolutionConstraint | _Mapping] | None = ..., anti_rollback_usage_table: bool | None = ..., track_label: str | None = ...) -> None: ...
    ID_FIELD_NUMBER: _ClassVar[int]
    POLICY_FIELD_NUMBER: _ClassVar[int]
    KEY_FIELD_NUMBER: _ClassVar[int]
    LICENSE_START_TIME_FIELD_NUMBER: _ClassVar[int]
    REMOTE_ATTESTATION_VERIFIED_FIELD_NUMBER: _ClassVar[int]
    PROVIDER_CLIENT_TOKEN_FIELD_NUMBER: _ClassVar[int]
    PROTECTION_SCHEME_FIELD_NUMBER: _ClassVar[int]
    SRM_REQUIREMENT_FIELD_NUMBER: _ClassVar[int]
    SRM_UPDATE_FIELD_NUMBER: _ClassVar[int]
    PLATFORM_VERIFICATION_STATUS_FIELD_NUMBER: _ClassVar[int]
    GROUP_IDS_FIELD_NUMBER: _ClassVar[int]
    id: LicenseIdentification
    policy: License.Policy
    key: _containers.RepeatedCompositeFieldContainer[License.KeyContainer]
    license_start_time: int
    remote_attestation_verified: bool
    provider_client_token: bytes
    protection_scheme: int
    srm_requirement: bytes
    srm_update: bytes
    platform_verification_status: PlatformVerificationStatus
    group_ids: _containers.RepeatedScalarFieldContainer[bytes]
    def __init__(self, id: LicenseIdentification | _Mapping | None = ..., policy: License.Policy | _Mapping | None = ..., key: _Iterable[License.KeyContainer | _Mapping] | None = ..., license_start_time: int | None = ..., remote_attestation_verified: bool | None = ..., provider_client_token: bytes | None = ..., protection_scheme: int | None = ..., srm_requirement: bytes | None = ..., srm_update: bytes | None = ..., platform_verification_status: PlatformVerificationStatus | str | None = ..., group_ids: _Iterable[bytes] | None = ...) -> None: ...

class LicenseRequest(_message.Message):
    __slots__ = ("client_id", "content_id", "encrypted_client_id", "key_control_nonce", "key_control_nonce_deprecated", "protocol_version", "request_time", "type")
    class RequestType(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
        __slots__ = ()
        NEW: _ClassVar[LicenseRequest.RequestType]
        RENEWAL: _ClassVar[LicenseRequest.RequestType]
        RELEASE: _ClassVar[LicenseRequest.RequestType]
    NEW: LicenseRequest.RequestType
    RENEWAL: LicenseRequest.RequestType
    RELEASE: LicenseRequest.RequestType
    class ContentIdentification(_message.Message):
        __slots__ = ("existing_license", "init_data", "webm_key_id", "widevine_pssh_data")
        class WidevinePsshData(_message.Message):
            __slots__ = ("license_type", "pssh_data", "request_id")
            PSSH_DATA_FIELD_NUMBER: _ClassVar[int]
            LICENSE_TYPE_FIELD_NUMBER: _ClassVar[int]
            REQUEST_ID_FIELD_NUMBER: _ClassVar[int]
            pssh_data: _containers.RepeatedScalarFieldContainer[bytes]
            license_type: LicenseType
            request_id: bytes
            def __init__(self, pssh_data: _Iterable[bytes] | None = ..., license_type: LicenseType | str | None = ..., request_id: bytes | None = ...) -> None: ...
        class WebmKeyId(_message.Message):
            __slots__ = ("header", "license_type", "request_id")
            HEADER_FIELD_NUMBER: _ClassVar[int]
            LICENSE_TYPE_FIELD_NUMBER: _ClassVar[int]
            REQUEST_ID_FIELD_NUMBER: _ClassVar[int]
            header: bytes
            license_type: LicenseType
            request_id: bytes
            def __init__(self, header: bytes | None = ..., license_type: LicenseType | str | None = ..., request_id: bytes | None = ...) -> None: ...
        class ExistingLicense(_message.Message):
            __slots__ = ("license_id", "seconds_since_last_played", "seconds_since_started", "session_usage_table_entry")
            LICENSE_ID_FIELD_NUMBER: _ClassVar[int]
            SECONDS_SINCE_STARTED_FIELD_NUMBER: _ClassVar[int]
            SECONDS_SINCE_LAST_PLAYED_FIELD_NUMBER: _ClassVar[int]
            SESSION_USAGE_TABLE_ENTRY_FIELD_NUMBER: _ClassVar[int]
            license_id: LicenseIdentification
            seconds_since_started: int
            seconds_since_last_played: int
            session_usage_table_entry: bytes
            def __init__(self, license_id: LicenseIdentification | _Mapping | None = ..., seconds_since_started: int | None = ..., seconds_since_last_played: int | None = ..., session_usage_table_entry: bytes | None = ...) -> None: ...
        class InitData(_message.Message):
            __slots__ = ("init_data", "init_data_type", "license_type", "request_id")
            class InitDataType(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
                __slots__ = ()
                CENC: _ClassVar[LicenseRequest.ContentIdentification.InitData.InitDataType]
                WEBM: _ClassVar[LicenseRequest.ContentIdentification.InitData.InitDataType]
            CENC: LicenseRequest.ContentIdentification.InitData.InitDataType
            WEBM: LicenseRequest.ContentIdentification.InitData.InitDataType
            INIT_DATA_TYPE_FIELD_NUMBER: _ClassVar[int]
            INIT_DATA_FIELD_NUMBER: _ClassVar[int]
            LICENSE_TYPE_FIELD_NUMBER: _ClassVar[int]
            REQUEST_ID_FIELD_NUMBER: _ClassVar[int]
            init_data_type: LicenseRequest.ContentIdentification.InitData.InitDataType
            init_data: bytes
            license_type: LicenseType
            request_id: bytes
            def __init__(self, init_data_type: LicenseRequest.ContentIdentification.InitData.InitDataType | str | None = ..., init_data: bytes | None = ..., license_type: LicenseType | str | None = ..., request_id: bytes | None = ...) -> None: ...
        WIDEVINE_PSSH_DATA_FIELD_NUMBER: _ClassVar[int]
        WEBM_KEY_ID_FIELD_NUMBER: _ClassVar[int]
        EXISTING_LICENSE_FIELD_NUMBER: _ClassVar[int]
        INIT_DATA_FIELD_NUMBER: _ClassVar[int]
        widevine_pssh_data: LicenseRequest.ContentIdentification.WidevinePsshData
        webm_key_id: LicenseRequest.ContentIdentification.WebmKeyId
        existing_license: LicenseRequest.ContentIdentification.ExistingLicense
        init_data: LicenseRequest.ContentIdentification.InitData
        def __init__(self, widevine_pssh_data: LicenseRequest.ContentIdentification.WidevinePsshData | _Mapping | None = ..., webm_key_id: LicenseRequest.ContentIdentification.WebmKeyId | _Mapping | None = ..., existing_license: LicenseRequest.ContentIdentification.ExistingLicense | _Mapping | None = ..., init_data: LicenseRequest.ContentIdentification.InitData | _Mapping | None = ...) -> None: ...
    CLIENT_ID_FIELD_NUMBER: _ClassVar[int]
    CONTENT_ID_FIELD_NUMBER: _ClassVar[int]
    TYPE_FIELD_NUMBER: _ClassVar[int]
    REQUEST_TIME_FIELD_NUMBER: _ClassVar[int]
    KEY_CONTROL_NONCE_DEPRECATED_FIELD_NUMBER: _ClassVar[int]
    PROTOCOL_VERSION_FIELD_NUMBER: _ClassVar[int]
    KEY_CONTROL_NONCE_FIELD_NUMBER: _ClassVar[int]
    ENCRYPTED_CLIENT_ID_FIELD_NUMBER: _ClassVar[int]
    client_id: ClientIdentification
    content_id: LicenseRequest.ContentIdentification
    type: LicenseRequest.RequestType
    request_time: int
    key_control_nonce_deprecated: bytes
    protocol_version: ProtocolVersion
    key_control_nonce: int
    encrypted_client_id: EncryptedClientIdentification
    def __init__(self, client_id: ClientIdentification | _Mapping | None = ..., content_id: LicenseRequest.ContentIdentification | _Mapping | None = ..., type: LicenseRequest.RequestType | str | None = ..., request_time: int | None = ..., key_control_nonce_deprecated: bytes | None = ..., protocol_version: ProtocolVersion | str | None = ..., key_control_nonce: int | None = ..., encrypted_client_id: EncryptedClientIdentification | _Mapping | None = ...) -> None: ...

class MetricData(_message.Message):
    __slots__ = ("metric_data", "stage_name")
    class MetricType(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
        __slots__ = ()
        LATENCY: _ClassVar[MetricData.MetricType]
        TIMESTAMP: _ClassVar[MetricData.MetricType]
    LATENCY: MetricData.MetricType
    TIMESTAMP: MetricData.MetricType
    class TypeValue(_message.Message):
        __slots__ = ("type", "value")
        TYPE_FIELD_NUMBER: _ClassVar[int]
        VALUE_FIELD_NUMBER: _ClassVar[int]
        type: MetricData.MetricType
        value: int
        def __init__(self, type: MetricData.MetricType | str | None = ..., value: int | None = ...) -> None: ...
    STAGE_NAME_FIELD_NUMBER: _ClassVar[int]
    METRIC_DATA_FIELD_NUMBER: _ClassVar[int]
    stage_name: str
    metric_data: _containers.RepeatedCompositeFieldContainer[MetricData.TypeValue]
    def __init__(self, stage_name: str | None = ..., metric_data: _Iterable[MetricData.TypeValue | _Mapping] | None = ...) -> None: ...

class VersionInfo(_message.Message):
    __slots__ = ("license_sdk_version", "license_service_version")
    LICENSE_SDK_VERSION_FIELD_NUMBER: _ClassVar[int]
    LICENSE_SERVICE_VERSION_FIELD_NUMBER: _ClassVar[int]
    license_sdk_version: str
    license_service_version: str
    def __init__(self, license_sdk_version: str | None = ..., license_service_version: str | None = ...) -> None: ...

class SignedMessage(_message.Message):
    __slots__ = ("metric_data", "msg", "oemcrypto_core_message", "remote_attestation", "service_version_info", "session_key", "session_key_type", "signature", "type")
    class MessageType(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
        __slots__ = ()
        LICENSE_REQUEST: _ClassVar[SignedMessage.MessageType]
        LICENSE: _ClassVar[SignedMessage.MessageType]
        ERROR_RESPONSE: _ClassVar[SignedMessage.MessageType]
        SERVICE_CERTIFICATE_REQUEST: _ClassVar[SignedMessage.MessageType]
        SERVICE_CERTIFICATE: _ClassVar[SignedMessage.MessageType]
        SUB_LICENSE: _ClassVar[SignedMessage.MessageType]
        CAS_LICENSE_REQUEST: _ClassVar[SignedMessage.MessageType]
        CAS_LICENSE: _ClassVar[SignedMessage.MessageType]
        EXTERNAL_LICENSE_REQUEST: _ClassVar[SignedMessage.MessageType]
        EXTERNAL_LICENSE: _ClassVar[SignedMessage.MessageType]
    LICENSE_REQUEST: SignedMessage.MessageType
    LICENSE: SignedMessage.MessageType
    ERROR_RESPONSE: SignedMessage.MessageType
    SERVICE_CERTIFICATE_REQUEST: SignedMessage.MessageType
    SERVICE_CERTIFICATE: SignedMessage.MessageType
    SUB_LICENSE: SignedMessage.MessageType
    CAS_LICENSE_REQUEST: SignedMessage.MessageType
    CAS_LICENSE: SignedMessage.MessageType
    EXTERNAL_LICENSE_REQUEST: SignedMessage.MessageType
    EXTERNAL_LICENSE: SignedMessage.MessageType
    class SessionKeyType(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
        __slots__ = ()
        UNDEFINED: _ClassVar[SignedMessage.SessionKeyType]
        WRAPPED_AES_KEY: _ClassVar[SignedMessage.SessionKeyType]
        EPHERMERAL_ECC_PUBLIC_KEY: _ClassVar[SignedMessage.SessionKeyType]
    UNDEFINED: SignedMessage.SessionKeyType
    WRAPPED_AES_KEY: SignedMessage.SessionKeyType
    EPHERMERAL_ECC_PUBLIC_KEY: SignedMessage.SessionKeyType
    TYPE_FIELD_NUMBER: _ClassVar[int]
    MSG_FIELD_NUMBER: _ClassVar[int]
    SIGNATURE_FIELD_NUMBER: _ClassVar[int]
    SESSION_KEY_FIELD_NUMBER: _ClassVar[int]
    REMOTE_ATTESTATION_FIELD_NUMBER: _ClassVar[int]
    METRIC_DATA_FIELD_NUMBER: _ClassVar[int]
    SERVICE_VERSION_INFO_FIELD_NUMBER: _ClassVar[int]
    SESSION_KEY_TYPE_FIELD_NUMBER: _ClassVar[int]
    OEMCRYPTO_CORE_MESSAGE_FIELD_NUMBER: _ClassVar[int]
    type: SignedMessage.MessageType
    msg: bytes
    signature: bytes
    session_key: bytes
    remote_attestation: bytes
    metric_data: _containers.RepeatedCompositeFieldContainer[MetricData]
    service_version_info: VersionInfo
    session_key_type: SignedMessage.SessionKeyType
    oemcrypto_core_message: bytes
    def __init__(self, type: SignedMessage.MessageType | str | None = ..., msg: bytes | None = ..., signature: bytes | None = ..., session_key: bytes | None = ..., remote_attestation: bytes | None = ..., metric_data: _Iterable[MetricData | _Mapping] | None = ..., service_version_info: VersionInfo | _Mapping | None = ..., session_key_type: SignedMessage.SessionKeyType | str | None = ..., oemcrypto_core_message: bytes | None = ...) -> None: ...

class ClientIdentification(_message.Message):
    __slots__ = ("client_capabilities", "client_info", "device_credentials", "license_counter", "provider_client_token", "token", "type", "vmp_data")
    class TokenType(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
        __slots__ = ()
        KEYBOX: _ClassVar[ClientIdentification.TokenType]
        DRM_DEVICE_CERTIFICATE: _ClassVar[ClientIdentification.TokenType]
        REMOTE_ATTESTATION_CERTIFICATE: _ClassVar[ClientIdentification.TokenType]
        OEM_DEVICE_CERTIFICATE: _ClassVar[ClientIdentification.TokenType]
    KEYBOX: ClientIdentification.TokenType
    DRM_DEVICE_CERTIFICATE: ClientIdentification.TokenType
    REMOTE_ATTESTATION_CERTIFICATE: ClientIdentification.TokenType
    OEM_DEVICE_CERTIFICATE: ClientIdentification.TokenType
    class NameValue(_message.Message):
        __slots__ = ("name", "value")
        NAME_FIELD_NUMBER: _ClassVar[int]
        VALUE_FIELD_NUMBER: _ClassVar[int]
        name: str
        value: str
        def __init__(self, name: str | None = ..., value: str | None = ...) -> None: ...
    class ClientCapabilities(_message.Message):
        __slots__ = ("analog_output_capabilities", "anti_rollback_usage_table", "can_disable_analog_output", "can_update_srm", "client_token", "max_hdcp_version", "oem_crypto_api_version", "resource_rating_tier", "session_token", "srm_version", "supported_certificate_key_type", "video_resolution_constraints")
        class HdcpVersion(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
            __slots__ = ()
            HDCP_NONE: _ClassVar[ClientIdentification.ClientCapabilities.HdcpVersion]
            HDCP_V1: _ClassVar[ClientIdentification.ClientCapabilities.HdcpVersion]
            HDCP_V2: _ClassVar[ClientIdentification.ClientCapabilities.HdcpVersion]
            HDCP_V2_1: _ClassVar[ClientIdentification.ClientCapabilities.HdcpVersion]
            HDCP_V2_2: _ClassVar[ClientIdentification.ClientCapabilities.HdcpVersion]
            HDCP_V2_3: _ClassVar[ClientIdentification.ClientCapabilities.HdcpVersion]
            HDCP_NO_DIGITAL_OUTPUT: _ClassVar[ClientIdentification.ClientCapabilities.HdcpVersion]
        HDCP_NONE: ClientIdentification.ClientCapabilities.HdcpVersion
        HDCP_V1: ClientIdentification.ClientCapabilities.HdcpVersion
        HDCP_V2: ClientIdentification.ClientCapabilities.HdcpVersion
        HDCP_V2_1: ClientIdentification.ClientCapabilities.HdcpVersion
        HDCP_V2_2: ClientIdentification.ClientCapabilities.HdcpVersion
        HDCP_V2_3: ClientIdentification.ClientCapabilities.HdcpVersion
        HDCP_NO_DIGITAL_OUTPUT: ClientIdentification.ClientCapabilities.HdcpVersion
        class CertificateKeyType(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
            __slots__ = ()
            RSA_2048: _ClassVar[ClientIdentification.ClientCapabilities.CertificateKeyType]
            RSA_3072: _ClassVar[ClientIdentification.ClientCapabilities.CertificateKeyType]
            ECC_SECP256R1: _ClassVar[ClientIdentification.ClientCapabilities.CertificateKeyType]
            ECC_SECP384R1: _ClassVar[ClientIdentification.ClientCapabilities.CertificateKeyType]
            ECC_SECP521R1: _ClassVar[ClientIdentification.ClientCapabilities.CertificateKeyType]
        RSA_2048: ClientIdentification.ClientCapabilities.CertificateKeyType
        RSA_3072: ClientIdentification.ClientCapabilities.CertificateKeyType
        ECC_SECP256R1: ClientIdentification.ClientCapabilities.CertificateKeyType
        ECC_SECP384R1: ClientIdentification.ClientCapabilities.CertificateKeyType
        ECC_SECP521R1: ClientIdentification.ClientCapabilities.CertificateKeyType
        class AnalogOutputCapabilities(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
            __slots__ = ()
            ANALOG_OUTPUT_UNKNOWN: _ClassVar[ClientIdentification.ClientCapabilities.AnalogOutputCapabilities]
            ANALOG_OUTPUT_NONE: _ClassVar[ClientIdentification.ClientCapabilities.AnalogOutputCapabilities]
            ANALOG_OUTPUT_SUPPORTED: _ClassVar[ClientIdentification.ClientCapabilities.AnalogOutputCapabilities]
            ANALOG_OUTPUT_SUPPORTS_CGMS_A: _ClassVar[ClientIdentification.ClientCapabilities.AnalogOutputCapabilities]
        ANALOG_OUTPUT_UNKNOWN: ClientIdentification.ClientCapabilities.AnalogOutputCapabilities
        ANALOG_OUTPUT_NONE: ClientIdentification.ClientCapabilities.AnalogOutputCapabilities
        ANALOG_OUTPUT_SUPPORTED: ClientIdentification.ClientCapabilities.AnalogOutputCapabilities
        ANALOG_OUTPUT_SUPPORTS_CGMS_A: ClientIdentification.ClientCapabilities.AnalogOutputCapabilities
        CLIENT_TOKEN_FIELD_NUMBER: _ClassVar[int]
        SESSION_TOKEN_FIELD_NUMBER: _ClassVar[int]
        VIDEO_RESOLUTION_CONSTRAINTS_FIELD_NUMBER: _ClassVar[int]
        MAX_HDCP_VERSION_FIELD_NUMBER: _ClassVar[int]
        OEM_CRYPTO_API_VERSION_FIELD_NUMBER: _ClassVar[int]
        ANTI_ROLLBACK_USAGE_TABLE_FIELD_NUMBER: _ClassVar[int]
        SRM_VERSION_FIELD_NUMBER: _ClassVar[int]
        CAN_UPDATE_SRM_FIELD_NUMBER: _ClassVar[int]
        SUPPORTED_CERTIFICATE_KEY_TYPE_FIELD_NUMBER: _ClassVar[int]
        ANALOG_OUTPUT_CAPABILITIES_FIELD_NUMBER: _ClassVar[int]
        CAN_DISABLE_ANALOG_OUTPUT_FIELD_NUMBER: _ClassVar[int]
        RESOURCE_RATING_TIER_FIELD_NUMBER: _ClassVar[int]
        client_token: bool
        session_token: bool
        video_resolution_constraints: bool
        max_hdcp_version: ClientIdentification.ClientCapabilities.HdcpVersion
        oem_crypto_api_version: int
        anti_rollback_usage_table: bool
        srm_version: int
        can_update_srm: bool
        supported_certificate_key_type: _containers.RepeatedScalarFieldContainer[ClientIdentification.ClientCapabilities.CertificateKeyType]
        analog_output_capabilities: ClientIdentification.ClientCapabilities.AnalogOutputCapabilities
        can_disable_analog_output: bool
        resource_rating_tier: int
        def __init__(self, client_token: bool | None = ..., session_token: bool | None = ..., video_resolution_constraints: bool | None = ..., max_hdcp_version: ClientIdentification.ClientCapabilities.HdcpVersion | str | None = ..., oem_crypto_api_version: int | None = ..., anti_rollback_usage_table: bool | None = ..., srm_version: int | None = ..., can_update_srm: bool | None = ..., supported_certificate_key_type: _Iterable[ClientIdentification.ClientCapabilities.CertificateKeyType | str] | None = ..., analog_output_capabilities: ClientIdentification.ClientCapabilities.AnalogOutputCapabilities | str | None = ..., can_disable_analog_output: bool | None = ..., resource_rating_tier: int | None = ...) -> None: ...
    class ClientCredentials(_message.Message):
        __slots__ = ("token", "type")
        TYPE_FIELD_NUMBER: _ClassVar[int]
        TOKEN_FIELD_NUMBER: _ClassVar[int]
        type: ClientIdentification.TokenType
        token: bytes
        def __init__(self, type: ClientIdentification.TokenType | str | None = ..., token: bytes | None = ...) -> None: ...
    TYPE_FIELD_NUMBER: _ClassVar[int]
    TOKEN_FIELD_NUMBER: _ClassVar[int]
    CLIENT_INFO_FIELD_NUMBER: _ClassVar[int]
    PROVIDER_CLIENT_TOKEN_FIELD_NUMBER: _ClassVar[int]
    LICENSE_COUNTER_FIELD_NUMBER: _ClassVar[int]
    CLIENT_CAPABILITIES_FIELD_NUMBER: _ClassVar[int]
    VMP_DATA_FIELD_NUMBER: _ClassVar[int]
    DEVICE_CREDENTIALS_FIELD_NUMBER: _ClassVar[int]
    type: ClientIdentification.TokenType
    token: bytes
    client_info: _containers.RepeatedCompositeFieldContainer[ClientIdentification.NameValue]
    provider_client_token: bytes
    license_counter: int
    client_capabilities: ClientIdentification.ClientCapabilities
    vmp_data: bytes
    device_credentials: _containers.RepeatedCompositeFieldContainer[ClientIdentification.ClientCredentials]
    def __init__(self, type: ClientIdentification.TokenType | str | None = ..., token: bytes | None = ..., client_info: _Iterable[ClientIdentification.NameValue | _Mapping] | None = ..., provider_client_token: bytes | None = ..., license_counter: int | None = ..., client_capabilities: ClientIdentification.ClientCapabilities | _Mapping | None = ..., vmp_data: bytes | None = ..., device_credentials: _Iterable[ClientIdentification.ClientCredentials | _Mapping] | None = ...) -> None: ...

class EncryptedClientIdentification(_message.Message):
    __slots__ = ("encrypted_client_id", "encrypted_client_id_iv", "encrypted_privacy_key", "provider_id", "service_certificate_serial_number")
    PROVIDER_ID_FIELD_NUMBER: _ClassVar[int]
    SERVICE_CERTIFICATE_SERIAL_NUMBER_FIELD_NUMBER: _ClassVar[int]
    ENCRYPTED_CLIENT_ID_FIELD_NUMBER: _ClassVar[int]
    ENCRYPTED_CLIENT_ID_IV_FIELD_NUMBER: _ClassVar[int]
    ENCRYPTED_PRIVACY_KEY_FIELD_NUMBER: _ClassVar[int]
    provider_id: str
    service_certificate_serial_number: bytes
    encrypted_client_id: bytes
    encrypted_client_id_iv: bytes
    encrypted_privacy_key: bytes
    def __init__(self, provider_id: str | None = ..., service_certificate_serial_number: bytes | None = ..., encrypted_client_id: bytes | None = ..., encrypted_client_id_iv: bytes | None = ..., encrypted_privacy_key: bytes | None = ...) -> None: ...

class DrmCertificate(_message.Message):
    __slots__ = ("algorithm", "creation_time_seconds", "encryption_key", "expiration_time_seconds", "provider_id", "public_key", "rot_id", "serial_number", "service_types", "system_id", "test_device_deprecated", "type")
    class Type(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
        __slots__ = ()
        ROOT: _ClassVar[DrmCertificate.Type]
        DEVICE_MODEL: _ClassVar[DrmCertificate.Type]
        DEVICE: _ClassVar[DrmCertificate.Type]
        SERVICE: _ClassVar[DrmCertificate.Type]
        PROVISIONER: _ClassVar[DrmCertificate.Type]
    ROOT: DrmCertificate.Type
    DEVICE_MODEL: DrmCertificate.Type
    DEVICE: DrmCertificate.Type
    SERVICE: DrmCertificate.Type
    PROVISIONER: DrmCertificate.Type
    class ServiceType(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
        __slots__ = ()
        UNKNOWN_SERVICE_TYPE: _ClassVar[DrmCertificate.ServiceType]
        LICENSE_SERVER_SDK: _ClassVar[DrmCertificate.ServiceType]
        LICENSE_SERVER_PROXY_SDK: _ClassVar[DrmCertificate.ServiceType]
        PROVISIONING_SDK: _ClassVar[DrmCertificate.ServiceType]
        CAS_PROXY_SDK: _ClassVar[DrmCertificate.ServiceType]
    UNKNOWN_SERVICE_TYPE: DrmCertificate.ServiceType
    LICENSE_SERVER_SDK: DrmCertificate.ServiceType
    LICENSE_SERVER_PROXY_SDK: DrmCertificate.ServiceType
    PROVISIONING_SDK: DrmCertificate.ServiceType
    CAS_PROXY_SDK: DrmCertificate.ServiceType
    class Algorithm(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
        __slots__ = ()
        UNKNOWN_ALGORITHM: _ClassVar[DrmCertificate.Algorithm]
        RSA: _ClassVar[DrmCertificate.Algorithm]
        ECC_SECP256R1: _ClassVar[DrmCertificate.Algorithm]
        ECC_SECP384R1: _ClassVar[DrmCertificate.Algorithm]
        ECC_SECP521R1: _ClassVar[DrmCertificate.Algorithm]
    UNKNOWN_ALGORITHM: DrmCertificate.Algorithm
    RSA: DrmCertificate.Algorithm
    ECC_SECP256R1: DrmCertificate.Algorithm
    ECC_SECP384R1: DrmCertificate.Algorithm
    ECC_SECP521R1: DrmCertificate.Algorithm
    class EncryptionKey(_message.Message):
        __slots__ = ("algorithm", "public_key")
        PUBLIC_KEY_FIELD_NUMBER: _ClassVar[int]
        ALGORITHM_FIELD_NUMBER: _ClassVar[int]
        public_key: bytes
        algorithm: DrmCertificate.Algorithm
        def __init__(self, public_key: bytes | None = ..., algorithm: DrmCertificate.Algorithm | str | None = ...) -> None: ...
    TYPE_FIELD_NUMBER: _ClassVar[int]
    SERIAL_NUMBER_FIELD_NUMBER: _ClassVar[int]
    CREATION_TIME_SECONDS_FIELD_NUMBER: _ClassVar[int]
    EXPIRATION_TIME_SECONDS_FIELD_NUMBER: _ClassVar[int]
    PUBLIC_KEY_FIELD_NUMBER: _ClassVar[int]
    SYSTEM_ID_FIELD_NUMBER: _ClassVar[int]
    TEST_DEVICE_DEPRECATED_FIELD_NUMBER: _ClassVar[int]
    PROVIDER_ID_FIELD_NUMBER: _ClassVar[int]
    SERVICE_TYPES_FIELD_NUMBER: _ClassVar[int]
    ALGORITHM_FIELD_NUMBER: _ClassVar[int]
    ROT_ID_FIELD_NUMBER: _ClassVar[int]
    ENCRYPTION_KEY_FIELD_NUMBER: _ClassVar[int]
    type: DrmCertificate.Type
    serial_number: bytes
    creation_time_seconds: int
    expiration_time_seconds: int
    public_key: bytes
    system_id: int
    test_device_deprecated: bool
    provider_id: str
    service_types: _containers.RepeatedScalarFieldContainer[DrmCertificate.ServiceType]
    algorithm: DrmCertificate.Algorithm
    rot_id: bytes
    encryption_key: DrmCertificate.EncryptionKey
    def __init__(self, type: DrmCertificate.Type | str | None = ..., serial_number: bytes | None = ..., creation_time_seconds: int | None = ..., expiration_time_seconds: int | None = ..., public_key: bytes | None = ..., system_id: int | None = ..., test_device_deprecated: bool | None = ..., provider_id: str | None = ..., service_types: _Iterable[DrmCertificate.ServiceType | str] | None = ..., algorithm: DrmCertificate.Algorithm | str | None = ..., rot_id: bytes | None = ..., encryption_key: DrmCertificate.EncryptionKey | _Mapping | None = ...) -> None: ...

class SignedDrmCertificate(_message.Message):
    __slots__ = ("drm_certificate", "hash_algorithm", "signature", "signer")
    DRM_CERTIFICATE_FIELD_NUMBER: _ClassVar[int]
    SIGNATURE_FIELD_NUMBER: _ClassVar[int]
    SIGNER_FIELD_NUMBER: _ClassVar[int]
    HASH_ALGORITHM_FIELD_NUMBER: _ClassVar[int]
    drm_certificate: bytes
    signature: bytes
    signer: SignedDrmCertificate
    hash_algorithm: HashAlgorithmProto
    def __init__(self, drm_certificate: bytes | None = ..., signature: bytes | None = ..., signer: SignedDrmCertificate | _Mapping | None = ..., hash_algorithm: HashAlgorithmProto | str | None = ...) -> None: ...

class WidevinePsshData(_message.Message):
    __slots__ = ("algorithm", "content_id", "crypto_period_index", "crypto_period_seconds", "entitled_keys", "group_ids", "grouped_license", "key_ids", "key_sequence", "policy", "protection_scheme", "provider", "track_type", "type", "video_feature")
    class Type(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
        __slots__ = ()
        SINGLE: _ClassVar[WidevinePsshData.Type]
        ENTITLEMENT: _ClassVar[WidevinePsshData.Type]
        ENTITLED_KEY: _ClassVar[WidevinePsshData.Type]
    SINGLE: WidevinePsshData.Type
    ENTITLEMENT: WidevinePsshData.Type
    ENTITLED_KEY: WidevinePsshData.Type
    class Algorithm(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
        __slots__ = ()
        UNENCRYPTED: _ClassVar[WidevinePsshData.Algorithm]
        AESCTR: _ClassVar[WidevinePsshData.Algorithm]
    UNENCRYPTED: WidevinePsshData.Algorithm
    AESCTR: WidevinePsshData.Algorithm
    class EntitledKey(_message.Message):
        __slots__ = ("entitlement_key_id", "entitlement_key_size_bytes", "iv", "key", "key_id")
        ENTITLEMENT_KEY_ID_FIELD_NUMBER: _ClassVar[int]
        KEY_ID_FIELD_NUMBER: _ClassVar[int]
        KEY_FIELD_NUMBER: _ClassVar[int]
        IV_FIELD_NUMBER: _ClassVar[int]
        ENTITLEMENT_KEY_SIZE_BYTES_FIELD_NUMBER: _ClassVar[int]
        entitlement_key_id: bytes
        key_id: bytes
        key: bytes
        iv: bytes
        entitlement_key_size_bytes: int
        def __init__(self, entitlement_key_id: bytes | None = ..., key_id: bytes | None = ..., key: bytes | None = ..., iv: bytes | None = ..., entitlement_key_size_bytes: int | None = ...) -> None: ...
    KEY_IDS_FIELD_NUMBER: _ClassVar[int]
    CONTENT_ID_FIELD_NUMBER: _ClassVar[int]
    CRYPTO_PERIOD_INDEX_FIELD_NUMBER: _ClassVar[int]
    PROTECTION_SCHEME_FIELD_NUMBER: _ClassVar[int]
    CRYPTO_PERIOD_SECONDS_FIELD_NUMBER: _ClassVar[int]
    TYPE_FIELD_NUMBER: _ClassVar[int]
    KEY_SEQUENCE_FIELD_NUMBER: _ClassVar[int]
    GROUP_IDS_FIELD_NUMBER: _ClassVar[int]
    ENTITLED_KEYS_FIELD_NUMBER: _ClassVar[int]
    VIDEO_FEATURE_FIELD_NUMBER: _ClassVar[int]
    ALGORITHM_FIELD_NUMBER: _ClassVar[int]
    PROVIDER_FIELD_NUMBER: _ClassVar[int]
    TRACK_TYPE_FIELD_NUMBER: _ClassVar[int]
    POLICY_FIELD_NUMBER: _ClassVar[int]
    GROUPED_LICENSE_FIELD_NUMBER: _ClassVar[int]
    key_ids: _containers.RepeatedScalarFieldContainer[bytes]
    content_id: bytes
    crypto_period_index: int
    protection_scheme: int
    crypto_period_seconds: int
    type: WidevinePsshData.Type
    key_sequence: int
    group_ids: _containers.RepeatedScalarFieldContainer[bytes]
    entitled_keys: _containers.RepeatedCompositeFieldContainer[WidevinePsshData.EntitledKey]
    video_feature: str
    algorithm: WidevinePsshData.Algorithm
    provider: str
    track_type: str
    policy: str
    grouped_license: bytes
    def __init__(self, key_ids: _Iterable[bytes] | None = ..., content_id: bytes | None = ..., crypto_period_index: int | None = ..., protection_scheme: int | None = ..., crypto_period_seconds: int | None = ..., type: WidevinePsshData.Type | str | None = ..., key_sequence: int | None = ..., group_ids: _Iterable[bytes] | None = ..., entitled_keys: _Iterable[WidevinePsshData.EntitledKey | _Mapping] | None = ..., video_feature: str | None = ..., algorithm: WidevinePsshData.Algorithm | str | None = ..., provider: str | None = ..., track_type: str | None = ..., policy: str | None = ..., grouped_license: bytes | None = ...) -> None: ...

class FileHashes(_message.Message):
    __slots__ = ("signatures", "signer")
    class Signature(_message.Message):
        __slots__ = ("SHA512Hash", "filename", "main_exe", "signature", "test_signing")
        FILENAME_FIELD_NUMBER: _ClassVar[int]
        TEST_SIGNING_FIELD_NUMBER: _ClassVar[int]
        SHA512HASH_FIELD_NUMBER: _ClassVar[int]
        MAIN_EXE_FIELD_NUMBER: _ClassVar[int]
        SIGNATURE_FIELD_NUMBER: _ClassVar[int]
        filename: str
        test_signing: bool
        SHA512Hash: bytes
        main_exe: bool
        signature: bytes
        def __init__(self, filename: str | None = ..., test_signing: bool | None = ..., SHA512Hash: bytes | None = ..., main_exe: bool | None = ..., signature: bytes | None = ...) -> None: ...
    SIGNER_FIELD_NUMBER: _ClassVar[int]
    SIGNATURES_FIELD_NUMBER: _ClassVar[int]
    signer: bytes
    signatures: _containers.RepeatedCompositeFieldContainer[FileHashes.Signature]
    def __init__(self, signer: bytes | None = ..., signatures: _Iterable[FileHashes.Signature | _Mapping] | None = ...) -> None: ...
