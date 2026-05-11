"""Work around a2a-sdk + protobuf upb: ``FieldDescriptor`` may lack ``label``.

Upstream tracks this in ``a2a.utils.proto_utils`` (a2a-python issue #1011). On some
Python/protobuf builds, ``desc.fields`` yields descriptors without ``.label``; use
``is_repeated`` when available.

Call :func:`apply` before importing ``a2a.server`` or ``a2a.client``.
"""

from __future__ import annotations

from typing import Any, TYPE_CHECKING

from google.protobuf.descriptor import FieldDescriptor
from google.protobuf.json_format import ParseDict
from google.protobuf.message import Message as ProtobufMessage

if TYPE_CHECKING:
    from starlette.datastructures import QueryParams
else:
    try:
        from starlette.datastructures import QueryParams
    except ImportError:
        QueryParams = Any  # type: ignore[misc,assignment]


def _field_is_repeated(field: FieldDescriptor) -> bool:
    ir = getattr(field, "is_repeated", None)
    if ir is not None:
        return bool(ir)
    lab = getattr(field, "label", None)
    if lab is not None:
        return lab == FieldDescriptor.LABEL_REPEATED
    return False


def _patched_parse_params(params: QueryParams, message: ProtobufMessage) -> None:
    descriptor = message.DESCRIPTOR
    fields = {f.camelcase_name: f for f in descriptor.fields}
    processed: dict[str, Any] = {}

    for k in params.keys():
        if k not in fields:
            continue

        field = fields[k]
        v_list = params.getlist(k)

        if _field_is_repeated(field):
            accumulated: list[Any] = []
            for v in v_list:
                if not v:
                    continue
                if isinstance(v, str):
                    accumulated.extend([x for x in v.split(",") if x])
                else:
                    accumulated.append(v)
            processed[k] = accumulated
        else:
            raw_val = v_list[-1]
            if raw_val is not None:
                parsed_val: Any = raw_val
                if field.type == field.TYPE_BOOL and isinstance(raw_val, str):
                    parsed_val = raw_val.lower() == "true"
                processed[k] = parsed_val

    ParseDict(processed, message, ignore_unknown_fields=True)


def _patched_check_required_field_violation(
    msg: ProtobufMessage, field: FieldDescriptor,
):
    from a2a.utils.proto_utils import ValidationDetail

    val = getattr(msg, field.name)
    if _field_is_repeated(field):
        if not val:
            return ValidationDetail(
                field=field.name,
                message="Field must contain at least one element.",
            )
    elif field.has_presence:
        if not msg.HasField(field.name):
            return ValidationDetail(field=field.name, message="Field is required.")
    elif val == field.default_value:
        return ValidationDetail(field=field.name, message="Field is required.")
    return None


def _patched_recurse_validation(msg: ProtobufMessage, field: FieldDescriptor):
    from a2a.utils import proto_utils as pu

    errors: list = []
    if field.type != FieldDescriptor.TYPE_MESSAGE:
        return errors

    val = getattr(msg, field.name)
    if not _field_is_repeated(field):
        if msg.HasField(field.name):
            sub_errs = pu._validate_proto_required_fields_internal(val)
            pu._append_nested_errors(errors, field.name, sub_errs)
    elif field.message_type.GetOptions().map_entry:
        for k, v in val.items():
            if isinstance(v, ProtobufMessage):
                sub_errs = pu._validate_proto_required_fields_internal(v)
                pu._append_nested_errors(errors, f"{field.name}[{k}]", sub_errs)
    else:
        for i, item in enumerate(val):
            sub_errs = pu._validate_proto_required_fields_internal(item)
            pu._append_nested_errors(errors, f"{field.name}[{i}]", sub_errs)
    return errors


def apply() -> None:
    """Idempotent patch of ``a2a.utils.proto_utils`` for upb field descriptors."""
    from a2a.utils import proto_utils as pu

    if getattr(pu, "_autonomous_identity_upb_compat_applied", False):
        return

    pu.parse_params = _patched_parse_params  # type: ignore[assignment]
    pu._check_required_field_violation = _patched_check_required_field_violation  # type: ignore[assignment]
    pu._recurse_validation = _patched_recurse_validation  # type: ignore[assignment]
    pu._autonomous_identity_upb_compat_applied = True  # type: ignore[attr-defined]
