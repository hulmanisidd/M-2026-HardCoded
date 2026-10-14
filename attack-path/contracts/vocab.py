"""Controlled vocabularies shared across the contracts package.

Values are scoped to the AWS IAM attack-path brief. Because these are
StrEnums, they serialize as plain strings in JSON.
"""
from enum import StrEnum


class NodeType(StrEnum):
    IAM_USER = "iam_user"
    IAM_ROLE = "iam_role"
    IAM_GROUP = "iam_group"
    IAM_POLICY = "iam_policy"
    EC2_INSTANCE = "ec2_instance"
    LAMBDA_FUNCTION = "lambda_function"
    S3_BUCKET = "s3_bucket"
    SECRET = "secret"
    KMS_KEY = "kms_key"
    EXTERNAL_PRINCIPAL = "external_principal"


class RelationType(StrEnum):
    MEMBER_OF = "member_of"
    HAS_POLICY = "has_policy"
    CAN_ASSUME = "can_assume"
    CAN_PASS_ROLE = "can_pass_role"
    RUNS_AS = "runs_as"
    CAN_READ = "can_read"
    CAN_WRITE = "can_write"
    CAN_INVOKE = "can_invoke"
    CAN_MODIFY_POLICY = "can_modify_policy"
    CAN_DECRYPT = "can_decrypt"


class Criticality(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"