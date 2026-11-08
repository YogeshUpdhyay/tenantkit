"""Dynamic tenant metadata validation."""

from datetime import date
from typing import Any
import re
from tenantkit.domain.errors import TenantValidationError


def validate_attributes(attributes: dict[str, Any], schema: Any) -> dict[str, Any]:
    fields = schema.fields if hasattr(schema, "fields") else schema.get("fields", [])
    errors: list[str] = []

    def validate(data: Any, definitions: Any, prefix: str = "") -> dict[str, Any]:
        if not isinstance(data, dict):
            errors.append(prefix + ": expected object")
            return {}
        result = dict(data)
        names = {f.name if hasattr(f, "name") else f["name"] for f in definitions}
        errors.extend(prefix + k + ": unknown field" for k in data if k not in names)
        for definition in definitions:
            f = (
                definition.model_dump(by_alias=True)
                if hasattr(definition, "model_dump")
                else definition
            )
            name = f["name"]
            path = prefix + name
            if name not in result:
                if f.get("default") is not None:
                    result[name] = f["default"]
                elif f.get("required"):
                    errors.append(path + ": required")
                continue
            value = result[name]
            typ = f["type"]
            valid = {
                "string": isinstance(value, str),
                "integer": type(value) is int,
                "number": type(value) in (int, float),
                "boolean": type(value) is bool,
                "object": isinstance(value, dict),
                "list": isinstance(value, list),
                "date": isinstance(value, (str, date)),
            }.get(typ, False)
            if not valid:
                errors.append(path + ": invalid type")
                continue
            if typ == "date":
                try:
                    result[name] = (
                        date.fromisoformat(value).isoformat()
                        if isinstance(value, str)
                        else value.isoformat()
                    )
                except ValueError:
                    errors.append(path + ": invalid date")
            if typ == "object":
                result[name] = validate(value, f.get("fields") or [], path + ".")
            if typ == "list" and f.get("item_type"):
                for index, item in enumerate(value):
                    validate(
                        {"item": item},
                        [{"name": "item", "type": f["item_type"]}],
                        path + f"[{index}].",
                    )
            for rule, bound in [
                ("min_length", "min"),
                ("max_length", "max"),
                ("min_items", "min"),
                ("max_items", "max"),
            ]:
                if f.get(rule) is not None and hasattr(value, "__len__"):
                    if (bound == "min" and len(value) < f[rule]) or (
                        bound == "max" and len(value) > f[rule]
                    ):
                        errors.append(path + ": " + rule)
            for rule in ["min", "max"]:
                if f.get(rule) is not None and (
                    (rule == "min" and value < f[rule]) or (rule == "max" and value > f[rule])
                ):
                    errors.append(path + ": " + rule)
            if f.get("pattern") and not re.search(f["pattern"], value):
                errors.append(path + ": pattern")
            if f.get("choices") and value not in f["choices"]:
                errors.append(path + ": choices")
        return result

    result = validate(attributes, fields)
    if errors:
        raise TenantValidationError("; ".join(errors))
    return result
