import calendar
import collections
import datetime
import decimal
import inspect
import operator
import re
from collections import OrderedDict
from datetime import timezone
from functools import partial, wraps
from importlib import import_module
from math import ceil
from operator import attrgetter
from types import MethodType

import aniso8601
from flask import _app_ctx_stack, _request_ctx_stack
from flask import current_app,json, jsonify, make_response, request
from flask.signals import Namespace
from flask_sqlalchemy import Pagination as SAPagination
from jsonschema import Draft4Validator, FormatChecker, ValidationError
from sqlalchemy import String as String_, and_, or_
from sqlalchemy.dialects import postgresql
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import aliased, class_mapper
from sqlalchemy.orm.attributes import ScalarObjectAttributeImpl
from sqlalchemy.orm.collections import InstrumentedList
from sqlalchemy.orm.exc import NoResultFound
from werkzeug.exceptions import HTTPException
from werkzeug.http import HTTP_STATUS_CODES
from werkzeug.urls import url_parse
from werkzeug.utils import cached_property
from werkzeug.wrappers import Response

# 
# ---------------------------HTTP常量--------------------
HTTP_METHODS = ("GET", "PUT", "POST", "PATCH", "DELETE")
HTTP_METHOD_VERB_DEFAULTS = {
    "GET": "read",
    "PUT": "create",
    "POST": "create",
    "PATCH": "update",
    "DELETE": "destroy",
}

# ---------------------------信号量--------------------
_restone = Namespace()
before_create = _restone.signal("before-create")
after_create = _restone.signal("after-create")
before_update = _restone.signal("before-update")
after_update = _restone.signal("after-update")
before_delete = _restone.signal("before-delete")
after_delete = _restone.signal("after-delete")
before_add_to_relation = _restone.signal("before-add-to-relation")
after_add_to_relation = _restone.signal("after-add-to-relation")
before_remove_from_relation = _restone.signal("before-remove-from-relation")
after_remove_from_relation = _restone.signal("after-remove-from-relation")


# ---------------------------异常----------------------
class RestoneException(Exception):
    status_code = 500

    def as_dict(self):
        if self.args:
            message = str(self)
        else:
            message = HTTP_STATUS_CODES.get(self.status_code, "")
        return {"status": self.status_code, "message": message}

    def get_response(self):
        response = jsonify(self.as_dict())
        response.status_code = self.status_code
        return response


class ItemNotFound(RestoneException):
    status_code = 404

    def __init__(self, resource, where=None, id=None):
        super(ItemNotFound, self).__init__()
        self.resource = resource
        self.id = id
        self.where = where

    def as_dict(self):
        dct = super(ItemNotFound, self).as_dict()
        if self.id is not None:
            dct["item"] = {"$type": self.resource.meta.name, "$id": self.id}
        else:
            dct["item"] = {
                "$type": self.resource.meta.name,
                "$where": {
                    condition.attribute: {"${}".format(condition.filter.name): condition.value}
                    if condition.filter.name is not None
                    else condition.value
                    for condition in self.where
                }
                if self.where
                else None,
            }
        return dct

    def get_response(self):
        response = jsonify(self.as_dict())
        response.status_code = self.status_code
        return response


class RequestMustBeJSON(RestoneException):
    status_code = 415


class RestoneValidationError(RestoneException):
    status_code = 400

    def __init__(self, errors, root=None, schema_uri="#"):
        super(RestoneValidationError, self).__init__()
        self.root = root
        self.errors = errors
        self.schema_uri = schema_uri

    def _complete_path(self, error):
        path = tuple(error.absolute_path)
        if self.root is not None:
            return (self.root,) + path
        return path

    def _format_errors(self):
        for error in self.errors:
            error_data = {
                "validationOf": {error.validator: error.validator_value},
                "path": self._complete_path(error),
            }
            if current_app.debug:
                error_data["message"] = error.message
            yield error_data

    def as_dict(self):
        dct = super(RestoneValidationError, self).as_dict()
        dct["errors"] = list(self._format_errors())
        return dct


class DuplicateKey(RestoneException):
    status_code = 409

    def __init__(self, **kwargs):
        super(DuplicateKey, self).__init__()
        self.data = kwargs


class BackendConflict(RestoneException):
    status_code = 409

    def __init__(self, **kwargs):
        super(BackendConflict, self).__init__()
        self.data = kwargs

    def as_dict(self):
        dct = super(BackendConflict, self).as_dict()
        dct.update(self.data)
        return dct


class PageNotFound(RestoneException):
    status_code = 404


class InvalidJSON(RestoneException):
    status_code = 400


# ---------------------------请求与响应格式----------------------
class Schema:  # schema 就是规则格式，子类需实现 schema 语法和 format 格式化方法
    def schema(self):  # 二元组就是 rsp,rqs
        raise NotImplementedError()

    @cached_property
    def response(self):
        schema = self.schema()
        if isinstance(schema, tuple):
            return schema[0]
        return schema

    @cached_property
    def request(self):
        schema = self.schema()
        if isinstance(schema, tuple):
            return schema[1]
        return schema

    create = request  # 三元组就是 response create update #delete不用schema

    @cached_property
    def update(self):
        schema = self.schema()
        if isinstance(schema, tuple):
            return schema[-1]
        return schema

    @cached_property
    def _validator(self):  # 规则检查
        Draft4Validator.check_schema(self.request)
        return Draft4Validator(self.request, format_checker=FormatChecker())

    @cached_property
    def _update_validator(self):  # 更新规则检查
        Draft4Validator.check_schema(self.update)
        return Draft4Validator(self.update, format_checker=FormatChecker())

    def format(self, value):  # 格式化
        return value

    def convert(self, instance, update=False):  # 实例检查
        if update:
            validator = self._update_validator  # 运用update的语法检查实例
        else:
            validator = self._validator  # 用request语法检查实例
        try:
            validator.validate(instance)  # 没报错就返回实例
        except ValidationError:
            errors = validator.iter_errors(instance)  # 否则抛出验证错误
            raise RestoneValidationError(errors)
        return instance

    def parse_request(self, request):  # 解析请求并校验
        data = request.json
        if not data and request.method in ("GET", "HEAD"):
            data = dict(request.args)
        return self.convert(data, update=request.method in ("PUT", "PATCH"))

    def format_response(self, response):  # 解包响应并格式化json-data
        (data, code, headers) = unpack(response)
        return self.format(data), code, headers


class ResourceBound:  # 资源绑定插件
    resource = None

    def _on_bind(self, resource):  # 绑定钩子
        pass

    def bind(self, resource):
        if self.resource is None:
            self.resource = resource
            self._on_bind(resource)
        elif self.resource != resource:
            return self.rebind(resource)
        return self

    def rebind(self, resource):  # 重新绑定
        raise NotImplementedError(
            "{} is already bound to {} and does not support rebinding to {}".format(repr(self), self.resource, resource)
        )


class _SchemaDummy(Schema):  # 简化格式实现
    def __init__(self, schema):
        self._schema = schema

    def schema(self):
        return self._schema


class FieldSet(Schema, ResourceBound):  # 字段集 规则和资源绑定
    def __init__(self, fields, required_fields=None):
        self.fields = fields  # 字段字典
        self.required = set(required_fields or ())  # 必填项

    def _on_bind(self, resource):  # 字段字典内部字段能绑则绑
        self.fields = {
            key: field.bind(resource) if isinstance(field, ResourceBound) else field
            for (key, field) in self.fields.items()
        }

    def rebind(self, resource):
        return FieldSet(dict(self.fields), tuple(self.required)).bind(resource)

    def set(self, key, field):  # 设置字段并绑定资源
        if self.resource and isinstance(field, ResourceBound):
            field = field.bind(self.resource)
        self.fields[key] = field

    def _schema(self, patchable=False):  # _schema 内部规则
        read_schema = {
            "type": "object",
            "properties": OrderedDict(
                ((key, field.response) for (key, field) in self.fields.items() if "r" in field.io)
            ),
        }  # 响应的可读属性
        create_schema = {
            "type": "object",
            "additionalProperties": False,
            "properties": OrderedDict(
                ((key, field.request) for (key, field) in self.fields.items() if "c" in field.io)
            ),
        }  # 请求的可写属性
        update_schema = {
            "type": "object",
            "additionalProperties": False,
            "properties": OrderedDict(
                ((key, field.request) for (key, field) in self.fields.items() if "u" in field.io)
            ),
        }  # 请求的可更新属性
        for key, field in self.fields.items():
            if "c" in field.io and (not field.nullable) and (field.default is None):
                self.required.add(key)  # 不为空且无默认则为必填项
        if not patchable and self.required:  # 不可更新且必填项不为空
            create_schema["required"] = list(self.required)
        return read_schema, create_schema, update_schema

    @cached_property
    def readable_fields(self):  # 可读字段
        return {key: field for (key, field) in self.fields.items() if "r" in field.io}

    def schema(self):
        return self._schema()

    @cached_property
    def patchable(self):  # 可更新性的schema
        return _SchemaDummy(self._schema(True))

    @cached_property
    def all_fields_optional(self):  # 可选的字段
        return all((i.default is not None or i.nullable for i in (self.fields or {}).values()))

    def format(self, item):  # 格式化的item类似一个字典
        return OrderedDict(
            (
                (key, field.output(key, item))
                # 可读字段的输出用到name和字段集，每个字段需要 output
                for (key, field) in self.fields.items()
                if "r" in field.io
            )
        )

    def convert(
        self,
        instance,
        update=False,
        pre_resolved_properties=None,
        patchable=False,
        strict=False,
    ):  # 格式转换和检查
        result = dict(pre_resolved_properties) if pre_resolved_properties else {}
        if patchable:
            object_ = self.patchable.convert(instance, update)  # 就是基类的转化校验
        else:  # 区别在于语法
            object_ = super(FieldSet, self).convert(instance, update)
        for key, field in self.fields.items():
            if update and "u" not in field.io or (not update and "c" not in field.io):
                continue  # 不可更新字段或不更新
            if key in result:  # 已处理字段
                continue
            value = None
            try:
                value = object_[key]  # 转换校验后字典
                value = field.convert(value, validate=False)  # 字段本身的转换
            except KeyError:  # 如果字典中没有当前的键
                if patchable:
                    continue
                if field.default is not None:  # 有默认用默认
                    value = field.default
                elif field.nullable:  # 可为空设为None
                    value = None
                elif key not in self.required and (not strict):  # 键不再必须里且不严格
                    value = None
            result[field.attribute or key] = value  # 字段的显示名或键名
        return result

    def parse_request(self, request):
        if request.method in ("POST", "PATCH", "PUT", "DELETE"):
            if self.fields and request.mimetype != "application/json":
                if not self.all_fields_optional:  # 并非所有字段都是选填 且 请求非json
                    raise RequestMustBeJSON()
        data = request.get_json(silent=True)
        if data is None and self.all_fields_optional:
            data = {}  # 没有数据且所有字段可选则可为空
        if not self.fields:
            return {}  # 自身无字段则可为空
        if not data and request.method in ("GET", "HEAD"):
            data = {}
            for name, field in self.fields.items():
                try:
                    value = request.args[name]  # 参数中获取值
                    try:
                        data[name] = json.loads(value)  # 获取到了复制到data
                    except ValueError:  # todo 此处改进可生成关系资源
                        data[name] = value  # 类型错误直接赋值
                except KeyError:
                    pass
        return self.convert(
            data,
            update=request.method in ("PUT", "PATCH"),
            patchable=request.method == "PATCH",
        )


def _bind_schema(schema, resource) -> Schema:  # 将格式与资源绑定
    if isinstance(schema, ResourceBound):
        return schema.bind(resource)
    return schema


# ----------------字段格式------------
class Raw(Schema):
    def __init__(
        self,
        schema,
        io="rw",
        default=None,
        attribute=None,
        nullable=False,
        title=None,
        description=None,
    ):
        self._schema = schema # 字段格式
        self._default = default # 字段默认
        self.attribute = attribute # 名称
        self.nullable = nullable # 可为空
        self.title = title # 标题
        self.description = description # 描述
        self.io = io # 读写

    def _finalize_schema(self, schema, io):  # 单个字典
        schema = dict(schema)
        if self.io == "r" and "r" in io:
            schema["readOnly"] = True
        if "null" in schema.get("type", []): # type 就是类型
            self.nullable = True
        elif self.nullable:
            if "enum" in schema and None not in schema["enum"]:
                # 可以为空且枚举列表里没null
                schema["enum"].append(None)
            if "type" in schema:
                type_ = schema["type"] # 类型是字符串或字典 json 里只有三种
                if isinstance(type_, (str, dict)):
                    schema["type"] = [type_, "null"]
                else:
                    schema["type"].append("null") # 是列表
            if "anyOf" in schema: # 
                if not any(("null" in choice.get("type", []) for choice in schema["anyOf"])):
                    schema["anyOf"].append({"type": "null"})
            elif "oneOf" in schema:
                if not any(("null" in choice.get("type", []) for choice in schema["oneOf"])):
                    schema["oneOf"].append({"type": "null"})
            elif "type" not in schema:
                if len(schema) == 1 and "$ref" in schema: # 只有一个ref
                    schema = {"anyOf": [schema, {"type": "null"}]}
                else:
                    current_app.logger.warn('{} is nullable but "null" type cannot be added'.format(self))
        for attr in ("default", "title", "description"):
            value = getattr(self, attr)
            if value is not None:
                schema[attr] = value
        return schema

    @property
    def io(self):
        return self._io

    @io.setter
    def io(self, value):
        io = ""
        if "w" in value or "c" in value:
            io += "c"
        if "r" in value:
            io += "r"
        if "w" in value or "u" in value:
            io += "u"
        self._io = io

    @property
    def default(self):  # 字段可执行则执行
        if callable(self._default):
            return self._default()
        return self._default

    @default.setter
    def default(self, value):
        self._default = value

    def schema(self):
        schema = self._schema  # 格式可执行则执行
        if callable(schema):
            schema = schema()
        if isinstance(schema, Schema):
            (read_schema, write_schema) = (schema.response, schema.request)
        elif isinstance(schema, tuple):
            (read_schema, write_schema) = schema
        else:
            return (
                self._finalize_schema(schema, "r"),
                self._finalize_schema(schema, "w"),
            )
        return (
            self._finalize_schema(read_schema, "r"),
            self._finalize_schema(write_schema, "w"),
        )

    def format(self, value):
        if value is not None:
            return self.formatter(value)
        return value

    def convert(self, instance, update=False, validate=True):
        if validate:  # 需要验证则使用父类验证
            instance = super(Raw, self).convert(instance, update)
        if instance is not None:
            return self.converter(instance)
        return instance

    def formatter(self, value):  # 后续继承这个格式化
        return value

    def converter(self, value):
        return value

    def output(self, key, obj):
        key = key if self.attribute is None else self.attribute
        return self.format(get_value(key, obj, self.default))

    def __repr__(self):
        return "{}(attribute={})".format(self.__class__.__name__, repr(self.attribute))


class Any(Raw):  # 可以用字典初始化
    def __init__(self, **kwargs):
        super(Any, self).__init__({"type": ["null", "string", "number", "boolean", "object", "array"]}, **kwargs)


class Custom(Raw):  # 自定义字段
    def __init__(self, schema, converter=None, formatter=None, **kwargs):
        super(Custom, self).__init__(schema, **kwargs)
        self._converter = converter
        self._formatter = formatter

    def format(self, value):
        if self._formatter is None:
            return value
        return self._formatter(value)

    def converter(self, value):
        if self._converter is None:
            return value
        return self._converter(value)


class Array(Raw, ResourceBound):
    def __init__(self, schema_cls_or_obj, min_items=None, max_items=None, unique=None, **kwargs):
        self.container = container = _field_from_object(self, schema_cls_or_obj)
        schema_properties = [("type", "array")]
        schema_properties += [
            (k, v)
            for (k, v) in [
                ("minItems", min_items),
                ("maxItems", max_items),
                ("uniqueItems", unique),
            ]
            if v is not None
        ]
        schema = lambda s: dict([("items", s)] + schema_properties)
        super(Array, self).__init__(
            lambda: (schema(container.response), schema(container.request)),
            default=kwargs.pop("default", list),
            **kwargs
        )

    def bind(self, resource):
        if isinstance(self.container, ResourceBound):
            self.container = self.container.bind(resource)
        return self

    def format(self, value):
        if value is not None:
            return self.formatter(value)
        if not self.nullable:
            return []
        return value

    def formatter(self, value):
        return [self.container.format(v) for v in value]

    def converter(self, value):
        return [self.container.convert(v) for v in value]


class Object(Raw, ResourceBound):
    def __init__(self, properties=None, pattern=None, pattern_properties=None, additional_properties=None, **kwargs):
        self.properties = None
        self.pattern_properties = None
        self.additional_properties = None
        if isinstance(properties, dict):
            self.properties = properties
        elif isinstance(properties, (type, Raw)):
            field = _field_from_object(self, properties)
            if pattern:
                self.pattern_properties = {pattern: field}
            else:
                self.additional_properties = field
        if isinstance(additional_properties, (type, Raw)):
            self.additional_properties = _field_from_object(self, additional_properties)
        elif additional_properties is True:
            self.additional_properties = Any()
        if isinstance(pattern_properties, (type, Raw)):
            self.pattern_properties = _field_from_object(self, pattern_properties)
        elif isinstance(pattern_properties, dict):
            self.pattern_properties = {p: _field_from_object(self, f) for (p, f) in pattern_properties.items()}

        def schema():
            request = {"type": "object"}
            response = {"type": "object"}
            for schema, attr in ((request, "request"), (response, "response")):
                if self.properties:
                    schema["properties"] = {key: getattr(field, attr) for (key, field) in self.properties.items()}
                if self.pattern_properties:
                    schema["patternProperties"] = {
                        pattern: getattr(field, attr) for (pattern, field) in self.pattern_properties.items()
                    }
                if self.additional_properties:
                    schema["additionalProperties"] = getattr(self.additional_properties, attr)
                else:
                    schema["additionalProperties"] = False
            return response, request

        if self.pattern_properties and (len(self.pattern_properties) > 1 or self.additional_properties):
            raise NotImplementedError(
                "Only one pattern property is currently supported and it cannot be combined with additionalProperties"
            )
        super(Object, self).__init__(schema, **kwargs)

    def bind(self, resource):
        if self.properties:
            self.properties = {key: _bind_schema(value, resource) for (key, value) in self.properties.items()}
        if self.pattern_properties:
            self.pattern_properties = {
                key: _bind_schema(value, resource) for (key, value) in self.pattern_properties.items()
            }
        if self.additional_properties:
            self.additional_properties = _bind_schema(self.additional_properties, resource)
        return self

    @cached_property
    def _property_attributes(self):
        if not self.properties:
            return ()
        return [field.attribute or key for (key, field) in self.properties.items()]

    def formatter(self, value):
        if self.properties:
            output = {
                key: field.format(get_value(field.attribute or key, value, field.default))
                for (key, field) in self.properties.items()
            }
        else:
            output = {}
        if self.pattern_properties:
            (pattern, field) = next(iter(self.pattern_properties.items()))
            if not self.additional_properties:
                output.update({k: field.format(v) for (k, v) in value.items() if k not in self._property_attributes})
            else:
                raise NotImplementedError()
        elif self.additional_properties:
            field = self.additional_properties
            output.update({k: field.format(v) for (k, v) in value.items() if k not in self._property_attributes})
        return output

    def converter(self, instance):
        result = {}
        if self.properties:
            result = {
                field.attribute or key: field.convert(instance.get(key, field.default))
                for (key, field) in self.properties.items()
            }
        if self.pattern_properties:
            (pattern, field) = next(iter(self.pattern_properties.items()))
            if not self.additional_properties:
                result.update({key: field.convert(value) for (key, value) in instance.items() if key not in result})
            else:
                raise NotImplementedError()
        elif self.additional_properties:
            field = self.additional_properties
            result.update({key: field.convert(value) for (key, value) in instance.items() if key not in result})
        return result


class AttributeMapped(Object):  # fixme missing Raw
    def __init__(self, schema_cls_or_obj, mapping_attribute=None, **kwargs):
        self.mapping_attribute = mapping_attribute
        super(AttributeMapped, self).__init__(schema_cls_or_obj, **kwargs)

    def _set_mapping_attribute(self, obj, value):
        if isinstance(obj, dict):
            obj[self.mapping_attribute] = value
        else:
            setattr(obj, self.mapping_attribute, value)
        return obj

    def formatter(self, value):
        if self.pattern_properties:
            (pattern, field) = next(iter(self.pattern_properties.items()))
            return {get_value(self.mapping_attribute, v, None): field.format(v) for v in value}
        elif self.additional_properties:
            return {get_value(self.mapping_attribute, v, None): self.additional_properties.format(v) for v in value}

    def converter(self, value):
        if self.pattern_properties:
            (pattern, field) = next(iter(self.pattern_properties.items()))
            return [self._set_mapping_attribute(field.convert(v), k) for (k, v) in value.items()]
        elif self.additional_properties:
            return [self._set_mapping_attribute(self.additional_properties.convert(v), k) for (k, v) in value.items()]


# status = String(1,10,enum=["low","high"])
class String(Raw):
    url_rule_converter = "string"

    def __init__(
        self, min_length=None, max_length=None, pattern=None, enum=None, format=None, **kwargs
    ):  # 参数用于类型检查 pattern 应为正则表达式 enum 应为枚举
        schema = {"type": "string"}
        if enum is not None:
            enum = list(enum)
        for v, k in (
            (min_length, "minLength"),
            (max_length, "maxLength"),
            (pattern, "pattern"),
            (enum, "enum"),
            (format, "format"),
        ):
            if v is not None:
                schema[k] = v
        super(String, self).__init__(schema, **kwargs)


# id = UUID(io='r')
class UUID(String):
    url_rule_converter = "string"
    UUID_REGEX = "[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"

    def __init__(self, **kwargs):
        super(UUID, self).__init__(min_length=36, max_length=36, pattern=self.UUID_REGEX, **kwargs)


class Date(Raw):
    def __init__(self, **kwargs):
        super(Date, self).__init__(
            {
                "type": "object",
                "properties": {"$date": {"type": "integer"}},
                "additionalProperties": False,
            },
            **kwargs
        )

    def formatter(self, value):  # 时间戳
        return {"$date": int(calendar.timegm(value.timetuple()) * 1000)}

    def converter(self, value):
        return datetime.datetime.fromtimestamp(value["$date"] / 1000, timezone.utc).date()


class DateTime(Date):
    def formatter(self, value):
        return {"$date": int(calendar.timegm(value.utctimetuple()) * 1000)}

    def converter(self, value):
        return datetime.datetime.fromtimestamp(value["$date"] / 1000, timezone.utc)


class DateString(Raw):
    def __init__(self, **kwargs):
        super(DateString, self).__init__({"type": "string", "format": "date"}, **kwargs)

    def formatter(self, value):
        return value.strftime("%Y-%m-%d")

    def converter(self, value):
        return aniso8601.parse_date(value)


class DateTimeString(Raw):
    def __init__(self, **kwargs):
        super(DateTimeString, self).__init__({"type": "string", "format": "date-time"}, **kwargs)

    def formatter(self, value):
        if value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)
        return value.isoformat()

    def converter(self, value):
        return aniso8601.parse_datetime(value)


class Uri(String):
    def __init__(self, **kwargs):
        super(Uri, self).__init__(format="uri", **kwargs)


class Email(String):
    def __init__(self, **kwargs):
        super(Email, self).__init__(format="email", **kwargs)


class Boolean(Raw):
    def __init__(self, **kwargs):
        super(Boolean, self).__init__({"type": "boolean"}, **kwargs)

    def format(self, value):
        return bool(value)


class Integer(Raw):
    url_rule_converter = "int"

    def __init__(self, minimum=None, maximum=None, default=None, **kwargs):
        schema = {"type": "integer"}
        if minimum is not None:
            schema["minimum"] = minimum
        if maximum is not None:
            schema["maximum"] = maximum
        super(Integer, self).__init__(schema, default=default, **kwargs)

    def formatter(self, value):
        return int(value)


class PositiveInteger(Integer):
    def __init__(self, maximum=None, **kwargs):
        super(PositiveInteger, self).__init__(minimum=1, maximum=maximum, **kwargs)


class Number(Raw):
    def __init__(self, minimum=None, maximum=None, exclusive_minimum=False, exclusive_maximum=False, **kwargs):
        schema = {"type": "number"}
        if minimum is not None:
            schema["minimum"] = minimum
            if exclusive_minimum:
                schema["exclusiveMinimum"] = True
        if maximum is not None:
            schema["maximum"] = maximum
            if exclusive_maximum:
                schema["exclusiveMaximum"] = True
        super(Number, self).__init__(schema, **kwargs)

    def formatter(self, value):
        return float(value)


class ToOne(Raw, ResourceBound):
    def __init__(self, resource, **kwargs):  # resource可以是名称
        self.target_reference = ResourceReference(resource)

        def schema():
            target = self.target
            key_converters = self.target.meta.key_converters  # 键转
            response_schema = self.formatter_key.response
            if len(key_converters) > 1:
                request_schema = {"anyOf": [nk.request for nk in key_converters]}
            else:
                request_schema = self.formatter_key.request
            return response_schema, request_schema

        super(ToOne, self).__init__(schema, **kwargs)

    def rebind(self, resource):
        if self.target_reference.value == "self":
            return self.__class__(
                "self",
                default=self.default,
                attribute=self.attribute,
                nullable=self.nullable,
                title=self.title,
                description=self.description,
                io=self.io,
            ).bind(resource)
        else:
            return self

    @cached_property
    def target(self):
        return self.target_reference.resolve(self.resource)

    @cached_property
    def formatter_key(self):
        return self.target.meta.key_converters[0]

    def formatter(self, item):
        return self.formatter_key.format(item)

    def converter(self, value):  # 转换器
        for python_type, json_type in (
            (dict, "object"),
            (int, "integer"),
            ((list, tuple), "array"),
            ((str, bytes), "string"),
        ):
            if isinstance(value, python_type):
                return self.target.meta.key_converters_by_type[json_type].convert(value)


class ToMany(Array):
    def __init__(self, resource, **kwargs):
        super(ToMany, self).__init__(ToOne(resource, nullable=False), **kwargs)


class Inline(Raw, ResourceBound):  # 内联 默认不可更新 todo 设置可更新
    def __init__(self, resource, patchable=False, **kwargs):
        self.target_reference = ResourceReference(resource)
        self.patchable = patchable

        def schema():
            def _response_schema():
                if self.resource == self.target:
                    return {"$ref": "#"}
                return {"$ref": self.target.routes["describedBy"].rule_factory(self.target)}

            if not self.patchable:
                return _response_schema()
            else:  # 若可更新 self.target.schema.patchable.update 为 request 语法
                return _response_schema(), self.target.schema.patchable.update

        super(Inline, self).__init__(schema, **kwargs)

    def rebind(self, resource):
        if self.target_reference.value == "self":
            return self.__class__(
                "self",
                patchable=self.patchable,
                default=self.default,
                attribute=self.attribute,
                nullable=self.nullable,
                title=self.title,
                description=self.description,
                io=self.io,
            ).bind(resource)
        else:
            return self

    @cached_property
    def target(self):
        return self.target_reference.resolve(self.resource)

    def format(self, item):
        return self.target.schema.format(item)

    def convert(self, item, update=False, validate=True):  # 转换为输入 默认不可更新
        if not validate:
            raise NotImplementedError()
        return self.target.schema.convert(item, update=update, patchable=self.patchable)


class ItemType(Raw):
    def __init__(self, resource):
        self.resource = resource
        super(ItemType, self).__init__(lambda: {"type": "string", "enum": [self.resource.meta.name]}, io="r")

    def format(self, value):
        return self.resource.meta.name


class ItemUri(Raw):
    def __init__(self, resource, attribute=None):
        self.target_reference = ResourceReference(resource)
        super(ItemUri, self).__init__(
            lambda: {
                "type": "string",
                "pattern": "^{}\\/[^/]+$".format(re.escape(self.target.route_prefix)),
            },
            io="r",
            attribute=attribute,
        )

    @cached_property
    def target(self):
        return self.target_reference.resolve()

    def format(self, value):
        return "{}/{}".format(self.target.route_prefix, value)

    def converter(self, value):
        try:
            (endpoint, args) = route_from(value, "GET")
        except Exception as e:
            raise e
        return self.target.manager.id_field.convert(args["id"])


# -------------------过滤器-------------------------------------


class BaseFilter(Schema):
    def __init__(self, name, field=None, attribute=None):
        self.attribute = attribute or field.attribute
        self.field = field
        self.name = name

    def op(self, a, b):
        raise NotImplementedError()

    @property
    def filter_field(self):  # 过滤器字段
        return self.field

    def _schema(self):
        return self.filter_field.request

    def _convert(self, value):
        return self.filter_field.convert(value)

    def convert(self, instance):
        if self.name is None:
            return Condition(self.attribute, self, self._convert(instance))
        else:
            return Condition(self.attribute, self, self._convert(instance["${}".format(self.name)]))

    def schema(self):
        schema = simplify_schema_for_filter(self._schema())
        if self.name is None:
            return schema
        return {
            "type": "object",
            "properties": {"${}".format(self.name): schema},
            "required": ["${}".format(self.name)],
            "additionalProperties": False,
        }


class EqualFilter(BaseFilter):
    def op(self, a, b):
        return a == b


class NotEqualFilter(BaseFilter):
    def op(self, a, b):
        return a != b


class NumberBaseFilter(BaseFilter):
    @cached_property
    def filter_field(self):
        if isinstance(self.field, (Date, DateTime, DateString, DateTimeString)):
            return self.field
        return Number()


class LessThanFilter(NumberBaseFilter):
    def op(self, a, b):
        return a < b


class GreaterThanFilter(NumberBaseFilter):
    def op(self, a, b):
        return a > b


class LessThanEqualFilter(NumberBaseFilter):
    def op(self, a, b):
        return a <= b


class GreaterThanEqualFilter(NumberBaseFilter):
    def op(self, a, b):
        return a >= b


class InFilter(BaseFilter):
    min_items = 0

    @cached_property
    def filter_field(self):
        return Array(self.field, min_items=self.min_items, unique=True)

    def op(self, a, b):
        return a in b


class ContainsFilter(BaseFilter):
    @cached_property
    def filter_field(self):
        return self.field.container

    def op(self, a, b):
        return hasattr(a, "__iter__") and b in a


class StringBaseFilter(BaseFilter):
    @cached_property
    def filter_field(self):
        return String(min_length=1)


class StringContainsFilter(StringBaseFilter):
    def op(self, a, b):
        return a and b in a


class StringIContainsFilter(BaseFilter):
    @cached_property
    def filter_field(self):
        return String(min_length=1)

    def op(self, a, b):
        return a and b.lower() in a.lower()


class StartsWithFilter(StringBaseFilter):
    def op(self, a, b):
        return a.startswith(b)


class IStartsWithFilter(StringBaseFilter):
    def op(self, a, b):
        return a.lower().startswith(b.lower())


class EndsWithFilter(StringBaseFilter):
    def op(self, a, b):
        return a.endswith(b)


class IEndsWithFilter(StringBaseFilter):
    def op(self, a, b):
        return a.lower().endswith(b.lower())


class DateBetweenFilter(BaseFilter):
    @cached_property
    def filter_field(self):
        return Array(self.field, min_items=2, max_items=2)

    def op(self, a, b):
        (before, after) = b
        return before <= a <= after


EQUALITY_FILTER_NAME = "eq"
FILTER_NAMES = (
    (EqualFilter, None),
    (EqualFilter, "eq"),
    (NotEqualFilter, "ne"),
    (LessThanFilter, "lt"),
    (LessThanEqualFilter, "lte"),
    (GreaterThanFilter, "gt"),
    (GreaterThanEqualFilter, "gte"),
    (InFilter, "in"),
    (ContainsFilter, "contains"),
    (StringContainsFilter, "contains"),
    (StringIContainsFilter, "icontains"),
    (StartsWithFilter, "startswith"),
    (IStartsWithFilter, "istartswith"),
    (EndsWithFilter, "endswith"),
    (IEndsWithFilter, "iendswith"),
    (DateBetweenFilter, "between"),
)
FILTERS_BY_TYPE = (
    (Boolean, (EqualFilter, NotEqualFilter, InFilter)),
    (
        Integer,
        (
            EqualFilter,
            NotEqualFilter,
            LessThanFilter,
            LessThanEqualFilter,
            GreaterThanFilter,
            GreaterThanEqualFilter,
            InFilter,
        ),
    ),
    (
        Number,
        (
            EqualFilter,
            NotEqualFilter,
            LessThanFilter,
            LessThanEqualFilter,
            GreaterThanFilter,
            GreaterThanEqualFilter,
            InFilter,
        ),
    ),
    (
        String,
        (
            EqualFilter,
            NotEqualFilter,
            StringContainsFilter,
            StringIContainsFilter,
            StartsWithFilter,
            IStartsWithFilter,
            EndsWithFilter,
            IEndsWithFilter,
            InFilter,
        ),
    ),
    (
        Date,
        (
            EqualFilter,
            NotEqualFilter,
            LessThanFilter,
            LessThanEqualFilter,
            GreaterThanFilter,
            GreaterThanEqualFilter,
            DateBetweenFilter,
            InFilter,
        ),
    ),
    (
        DateTime,
        (
            EqualFilter,
            NotEqualFilter,
            LessThanFilter,
            LessThanEqualFilter,
            GreaterThanFilter,
            GreaterThanEqualFilter,
            DateBetweenFilter,
        ),
    ),
    (
        DateString,
        (
            EqualFilter,
            NotEqualFilter,
            LessThanFilter,
            LessThanEqualFilter,
            GreaterThanFilter,
            GreaterThanEqualFilter,
            DateBetweenFilter,
            InFilter,
        ),
    ),
    (
        DateTimeString,
        (
            EqualFilter,
            NotEqualFilter,
            LessThanFilter,
            LessThanEqualFilter,
            GreaterThanFilter,
            GreaterThanEqualFilter,
            DateBetweenFilter,
        ),
    ),
    (Array, (ContainsFilter,)),
    (ToOne, (EqualFilter, NotEqualFilter, InFilter)),
    (ToMany, (ContainsFilter,)),
)


class Condition:  # 属性 过滤器 值
    def __init__(self, attribute, filter, value):
        self.attribute = attribute
        self.filter = filter
        self.value = value

    def __call__(self, item):
        return self.filter.op(get_value(self.attribute, item, None), self.value)


def _get_names_for_filter(filter, filter_names=FILTER_NAMES):
    for f, name in filter_names:
        if f == filter:
            yield name


# 字段类型的过滤器
def filters_for_field_class(field_class, filters_by_type=FILTERS_BY_TYPE):
    field_class_filters = ()
    filters_by_type = dict(filters_by_type)
    for cls in (field_class,) + field_class.__bases__:
        if cls in filters_by_type:
            field_class_filters += filters_by_type[cls]
    return field_class_filters


def filters_for_fields(
    fields,
    filters_expression,
    filter_names=FILTER_NAMES,
    filters_by_type=FILTERS_BY_TYPE,
):
    filters = {}
    filters_by_type = dict(filters_by_type)
    for field_name, field in fields.items():
        field_filters = {
            name: filter
            for filter in filters_for_field_class(field.__class__, filters_by_type)
            for name in _get_names_for_filter(filter, filter_names)
        }
        if isinstance(filters_expression, dict):
            try:
                field_expression = filters_expression[field_name]
            except KeyError:
                try:
                    field_expression = filters_expression["*"]
                except KeyError:
                    continue
            if isinstance(field_expression, dict):
                field_filters = field_expression
            elif isinstance(field_expression, (list, tuple)):
                field_filters = {name: filter for (name, filter) in field_filters.items() if name in field_expression}
            elif field_expression is not True:
                continue
        elif filters_expression is not True:
            continue
        if field_filters:
            filters[field_name] = field_filters
    return filters


def convert_filters(value, field_filters):
    if isinstance(value, dict) and len(value) == 1:
        filter_name = next(iter(value))
        if len(filter_name) > 1 and filter_name.startswith("$"):
            filter_name = filter_name[1:]
            for filter in field_filters.values():
                if filter_name == filter.name:
                    return filter.convert(value)
    filter = field_filters[None]
    return filter.convert(value)


def simplify_schema_for_filter(schema):
    if schema:
        return {key: value for (key, value) in schema.items() if key not in ("readOnly",)}
    return schema


class PaginationMixin:
    query_params = ()

    @cached_property
    def _pagination_types(self):
        raise NotImplementedError()

    def format_response(self, data):
        if not isinstance(data, self._pagination_types):
            return self.format(data)
        links = [(request.path, data.page, data.per_page, "self")]
        if data.has_prev:
            links.append((request.path, 1, data.per_page, "first"))
            links.append((request.path, data.page - 1, data.per_page, "prev"))
        if data.has_next:
            links.append((request.path, data.page + 1, data.per_page, "next"))
        links.append((request.path, max(data.pages, 1), data.per_page, "last"))
        headers = {
            "Link": ",".join(('<{0}?page={1}&per_page={2}>; rel="{3}"'.format(*link) for link in links)),
            "X-Total-Count": data.total,
        }
        return self.format(data.items), 200, headers

    def format(self, data):
        raise NotImplementedError()


class RelationInstances(PaginationMixin, ToMany):
    @cached_property
    def _pagination_types(self):
        return self.container.target.manager.PAGINATION_TYPES


class Instances(PaginationMixin, Schema, ResourceBound):
    query_params = ("where", "sort")

    def rebind(self, resource):
        return self.__class__().bind(resource)

    @cached_property
    def _pagination_types(self):
        return self.resource.manager.PAGINATION_TYPES

    def _field_filters_schema(self, filters):
        if len(filters) == 1:
            return next(iter(filters.values())).request
        else:
            return {"anyOf": [filter.request for filter in filters.values()]}

    @cached_property
    def _filters(self):
        return self.resource.manager.filters

    @cached_property
    def _sort_fields(self):
        return {
            name: field
            for (name, field) in self.resource.schema.readable_fields.items()
            if name in self._filters and self.resource.manager._is_sortable_field(field)
        }

    @cached_property
    def _filter_schema(self):
        return {
            "type": "object",
            "properties": {name: self._field_filters_schema(filters) for (name, filters) in self._filters.items()},
            "additionalProperties": False,
        }

    @cached_property
    def _sort_schema(self):
        return {
            "type": "object",
            "properties": {
                name: {
                    "type": "boolean",
                    "description": "Sort by {} in descending order if 'true', ascending order if 'false'.".format(name),
                }
                for (name, field) in self._sort_fields.items()
            },
            "additionalProperties": False,
        }

    def schema(self):
        request_schema = {
            "type": "object",
            "properties": {
                "where": self._filter_schema,
                "sort": self._sort_schema,
                "page": {"type": "integer", "minimum": 1, "default": 1},
                "per_page": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": current_app.config["RESTONE_MAX_PER_PAGE"],
                    "default": current_app.config["RESTONE_DEFAULT_PER_PAGE"],
                },
            },
            "additionalProperties": True,
        }
        response_schema = {"type": "array", "items": {"$ref": "#"}}
        return response_schema, request_schema

    def _convert_filters(self, where):
        for name, value in where.items():
            yield convert_filters(value, self._filters[name])

    def _convert_sort(self, sort):
        for name, reverse in sort.items():
            field = self._sort_fields[name]
            yield field, field.attribute or name, reverse

    def parse_request(self, request):
        try:
            page = request.args.get("page", 1, type=int)
            per_page = request.args.get("per_page", current_app.config["RESTONE_DEFAULT_PER_PAGE"], type=int)
            # todo 改变这里即可改变查询方式
            where = json.loads(request.args.get("where", "{}"))
            sort = json.loads(
                request.args.get("sort", "{}"),
                object_pairs_hook=collections.OrderedDict,
            )
        except ValueError:
            raise InvalidJSON()
        result = self.convert({"page": page, "per_page": per_page, "where": where, "sort": sort})
        result["where"] = tuple(self._convert_filters(result["where"]))
        result["sort"] = tuple(self._convert_sort(result["sort"]))
        return result

    def parse_request2(self, request):
        try:
            page = request.args.get("page", 1, type=int)
            per_page = request.args.get("per_page", current_app.config["RESTONE_DEFAULT_PER_PAGE"], type=int)
            # todo 改变这里即可改变查询方式
            # name__eq=xxx&date__gt=200908&name__in=a,b,
            # c&date__sw=start
            # name = eq_100&date=bt_2000,3000&or
            where = json.loads(request.args.get("where", "{}"))
            sort = json.loads(
                request.args.get("sort", "{}"),
                object_pairs_hook=collections.OrderedDict,
            )
        except ValueError:
            raise InvalidJSON()
        result = self.convert({"page": page, "per_page": per_page, "where": where, "sort": sort})
        result["where"] = tuple(self._convert_filters(result["where"]))
        result["sort"] = tuple(self._convert_sort(result["sort"]))
        return result

    def format(self, items):
        return [self.resource.schema.format(item) for item in items]


class Pagination:
    def __init__(self, items, page, per_page, total):
        self.items = items
        self.page = page
        self.per_page = per_page
        self.total = total

    @property
    def pages(self):
        return max(1, int(ceil(self.total / self.per_page)))

    @property
    def has_prev(self):
        return self.page > 1

    @property
    def has_next(self):
        return self.page < self.pages

    @classmethod
    def from_list(cls, items, page, per_page):
        start = per_page * (page - 1)
        return Pagination(items[start : start + per_page], page, per_page, len(items))


class Manager:
    FILTER_NAMES = FILTER_NAMES
    FILTERS_BY_TYPE = FILTERS_BY_TYPE
    PAGINATION_TYPES = (Pagination,)

    def __init__(self, resource, model):
        self.resource = resource
        self.filters = {}
        resource.manager = self
        self._init_model(resource, model, resource.meta)
        self._init_filters(resource, resource.meta)
        self._init_key_converters(resource, resource.meta)
        self._post_init(resource, resource.meta)

    def _init_model(self, resource, model, meta):
        self.model = model
        self.id_attribute = id_attribute = meta.id_attribute or "id"
        self.id_field = meta.id_field_class(io="r", attribute=id_attribute)
        fs = resource.schema
        if meta.include_id:
            fs.set("$id", self.id_field)
        else:
            fs.set("$uri", ItemUri(resource, attribute=id_attribute))
        if meta.include_type:
            fs.set("$type", ItemType(resource))

    def _init_filter(self, filter_class, name, field, attribute):
        return filter_class(name, field=field, attribute=field.attribute or attribute)

    def _init_filters(self, resource, meta):
        fields = resource.schema.fields
        field_filters = filters_for_fields(
            resource.schema.readable_fields,
            meta.filters,
            filter_names=self.FILTER_NAMES,
            filters_by_type=self.FILTERS_BY_TYPE,
        )
        self.filters = {
            field_name: {
                name: self._init_filter(filter, name, fields[field_name], field_name)
                for (name, filter) in field_filters.items()
            }
            for (field_name, field_filters) in field_filters.items()
        }

    def _is_sortable_field(self, field):
        return isinstance(
            field,
            (
                String,
                Boolean,
                Number,
                Integer,
                Date,
                DateTime,
                DateString,
                DateTimeString,
                Uri,
                ItemUri,
            ),
        )

    def _init_key_converters(self, resource, meta):
        if "natural_key" in meta:
            if isinstance(meta.natural_key, str):
                meta["key_converters"] += (PropertyKey(meta.natural_key),)
            elif isinstance(meta.natural_key, (list, tuple)):
                meta["key_converters"] += (PropertiesKey(*meta.natural_key),)
        if "key_converters" in meta:
            meta.key_converters = [k.bind(resource) for k in meta["key_converters"]]
            meta.key_converters_by_type = {}
            for nk in meta.key_converters:
                if nk.matcher_type() in meta.key_converters_by_type:
                    raise RuntimeError("Multiple keys of type {} defined for {}".format(nk.matcher_type(), meta.name))
                meta.key_converters_by_type[nk.matcher_type()] = nk

    def _post_init(self, resource, meta):
        meta.id_attribute = self.id_attribute
        if meta.id_converter is None:
            meta.id_converter = getattr(meta.id_field_class, "url_rule_converter", None)

    @staticmethod
    def _get_field_from_python_type(python_type):
        try:
            return {
                str: String,
                int: Integer,
                float: Number,
                bool: Boolean,
                list: Array,
                dict: Object,
                datetime.date: Date,
                datetime.datetime: DateTime,
                decimal.Decimal: Number,
            }[python_type]
        except KeyError:
            raise RuntimeError('No appropriate field class for "{}" type found'.format(python_type))

    def get_field_comparators(self, field):
        pass

    def relation_instances(self, item, attribute, target_resource, page=None, per_page=None):
        raise NotImplementedError()

    def relation_add(self, item, attribute, target_resource, target_item):
        raise NotImplementedError()

    def relation_remove(self, item, attribute, target_resource, target_item):
        raise NotImplementedError()

    def paginated_instances(self, page, per_page, where=None, sort=None):
        pass

    def instances(self, where=None, sort=None):
        pass

    def first(self, where=None, sort=None):
        try:
            return self.instances(where, sort)[0]
        except IndexError:
            raise ItemNotFound(self.resource, where=where)

    def create(self, properties, commit=True):
        pass

    def read(self, id):
        pass

    def update(self, item, changes, commit=True):
        pass

    def delete(self, item):
        pass

    def delete_by_id(self, id):
        return self.delete(self.read(id))

    def commit(self):
        pass

    def begin(self):
        pass


class RelationalManager(Manager):
    def _query(self):
        raise NotImplementedError()

    def _query_filter(self, query, expression):
        raise NotImplementedError()

    def _query_filter_by_id(self, query, id):
        raise NotImplementedError()

    def _expression_for_join(self, attribute, expression):
        raise NotImplementedError()

    def _expression_for_ids(self, ids):
        raise NotImplementedError()

    def _expression_for_condition(self, condition):
        raise NotImplementedError()

    def _or_expression(self, expressions):
        raise NotImplementedError()

    def _and_expression(self, expressions):
        raise NotImplementedError()

    def _query_order_by(self, query, sort=None):
        raise NotImplementedError()

    def _query_get_paginated_items(self, query, page, per_page):
        raise NotImplementedError()

    def _query_get_all(self, query):
        raise NotImplementedError()

    def _query_get_one(self, query):
        raise NotImplementedError()

    def _query_get_first(self, query):
        raise NotImplementedError()

    def paginated_instances(self, page, per_page, where=None, sort=None):
        instances = self.instances(where=where, sort=sort)
        if isinstance(instances, list):
            return Pagination.from_list(instances, page, per_page)
        return self._query_get_paginated_items(instances, page, per_page)

    def instances(self, where=None, sort=None):
        query = self._query()
        if query is None:
            return []
        if where:
            expressions = [self._expression_for_condition(condition) for condition in where]
            query = self._query_filter(query, self._and_expression(expressions))
        return self._query_order_by(query, sort)

    def first(self, where=None, sort=None):
        try:
            return self._query_get_first(self.instances(where, sort))
        except IndexError:
            raise ItemNotFound(self.resource, where=where)

    def read(self, id):
        query = self._query()
        if query is None:
            raise ItemNotFound(self.resource, id=id)
        return self._query_filter_by_id(query, id)


class Key(Schema, ResourceBound):
    def matcher_type(self):
        type_ = self.response["type"]
        if isinstance(type_, str):
            return type_
        return type_[0]

    def rebind(self, resource):
        return self.__class__().bind(resource=resource)

    def schema(self):
        raise NotImplementedError()


class RefKey(Key):
    def matcher_type(self):
        return "object"

    def schema(self):
        return {
            "type": "object",
            "properties": {
                "$ref": {
                    "type": "string",
                    "pattern": "^{}\\/[^/]+$".format(re.escape(self.resource.route_prefix)),
                }
            },
            "additionalProperties": False,
        }

    def _item_uri(self, resource, item):
        return "{}/{}".format(resource.route_prefix, get_value(resource.manager.id_attribute, item, None))

    def format(self, item):
        return {"$ref": self._item_uri(self.resource, item)}

    def convert(self, value):
        try:
            (endpoint, args) = route_from(value["$ref"], "GET")
        except Exception as e:
            raise e
        return self.resource.manager.read(args["id"])


class PropertyKey(Key):
    def __init__(self, property):
        self.property = property

    def rebind(self, resource):
        return self.__class__(self.property).bind(resource)

    def schema(self):
        return self.resource.schema.fields[self.property].request

    def format(self, item):
        return self.resource.schema.fields[self.property].output(self.property, item)

    @cached_property
    def _field_filter(self):
        return self.resource.manager.filters[self.property][None]

    def convert(self, value):
        return self.resource.manager.first(where=[Condition(self.property, self._field_filter, value)])


class PropertiesKey(Key):
    def __init__(self, *properties):
        self.properties = properties

    def matcher_type(self):
        return "array"

    def rebind(self, resource):
        return self.__class__(*self.properties).bind(resource)

    def schema(self):
        return {
            "type": "array",
            "items": [self.resource.schema.fields[p].request for p in self.properties],
            "additionalItems": False,
        }

    def format(self, item):
        return [self.resource.schema.fields[p].output(p, item) for p in self.properties]

    @cached_property
    def _field_filters(self):
        return self.resource.manager.filters

    def convert(self, value):
        return self.resource.manager.first(
            where=[
                Condition(property, self._field_filters[property][None], value[i])
                for (i, property) in enumerate(self.properties)
            ]
        )


class IDKey(Key):
    def _on_bind(self, resource):
        self.id_field = resource.manager.id_field

    def schema(self):
        return self.id_field.request

    def format(self, item):
        return self.id_field.output(self.resource.manager.id_attribute, item)

    def convert(self, value):
        return self.resource.manager.read(self.id_field.convert(value))


class ResourceReference:
    def __init__(self, value):
        self.value = value

    def resolve(self, binding=None):
        name = self.value
        if name == "self":  # 返回自己
            return binding
        if inspect.isclass(name) and issubclass(name, ModelResource):
            return name  # 资源类
        restone = None
        if binding and binding.api:
            restone = binding.api
        if restone:
            if name in restone.resources:  # 资源名
                return restone.resources[name]
        try:
            if isinstance(name, str):  # 其他地方的资源名
                (module_name, class_name) = name.rsplit(".", 1)
                module = import_module(module_name)
                return getattr(module, class_name)
        except ValueError:
            pass
        if binding and binding.api:
            raise RuntimeError('Resource named "{}" is not registered with the Api it is bound to.'.format(name))
        raise RuntimeError('Resource named "{}" cannot be found; the reference is not bound to an Api.'.format(name))

    def __repr__(self):
        return "<ResourceReference '{}'>".format(self.value)


class AttributeDict(dict):
    __getattr__ = dict.__getitem__
    __setattr__ = dict.__setitem__


class ResourceMeta(type):
    def __new__(mcs, name, bases, members):
        class_ = super(ResourceMeta, mcs).__new__(mcs, name, bases, members)
        class_.routes = routes = dict(getattr(class_, "routes") or {})
        class_.meta = meta = AttributeDict(getattr(class_, "meta", {}) or {})

        def add_route(routes, route, name):
            if route.attribute is None:
                route.attribute = name
            for r in route._related_routes:
                if r.attribute is None:
                    r.attribute = name
                routes[r.relation] = r
            routes[route.relation] = route

        for base in bases:
            for n, m in inspect.getmembers(base, lambda m: isinstance(m, Route)):
                add_route(routes, m, n)
            if hasattr(base, "Meta"):
                meta.update(base.Meta.__dict__)
        if "Meta" in members:
            changes = members["Meta"].__dict__
            for k, v in changes.items():
                if not k.startswith("__"):
                    meta[k] = v
            if not changes.get("name", None):
                meta["name"] = name.lower()
        else:
            meta["name"] = name.lower()
        schema = {}
        for base in bases:
            if hasattr(base, "Schema"):
                schema.update(base.Schema.__dict__)
        if "Schema" in members:
            schema.update(members["Schema"].__dict__)
        if schema:
            class_.schema = fs = FieldSet(
                {k: f for (k, f) in schema.items() if not k.startswith("__")},
                required_fields=meta.get("required_fields", None),
            )
            for name in meta.get("read_only_fields", ()):
                if name in fs.fields:
                    fs.fields[name].io = "r"
            for name in meta.get("write_only_fields", ()):
                if name in fs.fields:
                    fs.fields[name].io = "w"
            fs.bind(class_)
        for n, m in members.items():
            if isinstance(m, Route):
                add_route(routes, m, n)
            if isinstance(m, ResourceBound):
                m.bind(class_)
        if meta.exclude_routes:
            for relation in meta.exclude_routes:
                routes.pop(relation, None)
        return class_


class Resource(metaclass=ResourceMeta):
    api = None
    meta = None
    routes = None
    schema = None
    route_prefix = None

    @Route.GET("/schema", rel="describedBy", attribute="schema")
    def described_by(self):
        schema = OrderedDict([("$schema", "http://json-schema.org/draft-04/hyper-schema#")])
        for prop in ("title", "description"):
            value = getattr(self.meta, prop)
            if value:
                schema[prop] = value
        links = [route for (name, route) in sorted(self.routes.items())]
        if self.schema:
            schema["type"] = "object"
            schema.update(self.schema.response)
        schema["links"] = [link.schema_factory(self) for link in sorted(links, key=attrgetter("relation"))]
        return schema, 200, {"Content-Type": "application/schema+json"}

    class Meta:
        name = None
        title = None
        description = None
        required_fields = None
        exclude_routes = ()
        route_decorators = {}
        read_only_fields = ()
        write_only_fields = ()


class ModelResourceMeta(ResourceMeta):
    def __new__(mcs, name, bases, members):
        class_ = super(ModelResourceMeta, mcs).__new__(mcs, name, bases, members)
        meta = class_.meta
        if "Meta" in members:
            changes = members["Meta"].__dict__
            if "model" in changes or ("model" in meta and "manager" in changes):
                if meta.manager is not None:
                    class_.manager = meta.manager(class_, meta.model)
        sort_attribute = meta.get("sort_attribute")
        if sort_attribute is not None and isinstance(sort_attribute, str):
            meta.sort_attribute = (sort_attribute, False)
        return class_


class ModelResource(Resource, metaclass=ModelResourceMeta):
    manager = None

    @Route.GET("", rel="instances")
    def instances(self, **kwargs):
        return self.manager.paginated_instances(**kwargs)

    instances.request_schema = instances.response_schema = Instances()

    @instances.POST(rel="create")  # 明白了rel是内部用的用于定位视图的，作为key
    def create(self, properties):
        item = self.manager.create(properties)
        return item

    create.request_schema = create.response_schema = Inline("self")

    @Route.GET(
        lambda r: "/<{}:id>".format(r.meta.id_converter),
        rel="self",
        attribute="instance",
    )
    def read(self, id):
        return self.manager.read(id)

    read.request_schema = None
    read.response_schema = Inline("self")

    @read.PATCH(rel="update")
    def update(self, properties, id):
        item = self.manager.read(id)
        updated_item = self.manager.update(item, properties)
        return updated_item

    update.request_schema = Inline("self", patchable=True)
    update.response_schema = update.request_schema

    @update.DELETE(rel="destroy")
    def destroy(self, id):
        self.manager.delete_by_id(id)
        return None, 204

    class Schema:  # 设置各个字段的语法用的
        pass

    class Meta:
        id_attribute = None  # id
        sort_attribute = None  # 排序列
        id_converter = None  # string
        id_field_class = Integer  # id域的类
        include_id = False  # 包括id
        include_type = False  # 包括类型
        manager = None  # 数据库管理
        include_fields = None  # 包括
        exclude_fields = None  # 不包括
        filters = True  # 过滤
        permissions = {
            "read": "anyone",
            "create": "nobody",
            "update": "create",
            "delete": "update",
        }
        postgres_text_search_fields = ()
        postgres_full_text_index = None
        cache = False  # 缓存
        key_converters = (RefKey(), IDKey())
        natural_key = None


def url_rule_to_uri_pattern(rule):
    return re.sub("<(\\w+:)?([^>]+)>", "{\\2}", rule)


def attribute_to_route_uri(s):
    return s.replace("_", "-")


def to_camel_case(s):
    return s[0].lower() + s.title().replace("_", "")[1:] if s else s


class RouteSet:
    def routes(self):
        return ()


class Relation(RouteSet, ResourceBound):  # 关系型也是RouteSet子类
    # author = Relation("UserResource",backref="book",attribute='author')
    def __init__(self, resource, backref=None, io="rw", attribute=None, **kwargs):
        self.reference = ResourceReference(resource)  # 找到关联的资源类
        self.attribute = attribute  # 属性名
        self.backref = backref  # 反向引用名
        self.io = io

    @cached_property
    def target(self):
        return self.reference.resolve(self.resource)  # 目标类

    def routes(self):
        io = self.io
        rule = "/{}".format(attribute_to_route_uri(self.attribute))  # /author
        relation_route = ItemRoute(
            rule="{}/<{}:target_id>".format(rule, self.target.meta.id_converter)
        )  # /book/001/author/<sid>
        relations_route = ItemRoute(rule=rule)  # /author
        if "r" in io:

            def relation_instances(resource, item, page, per_page):
                return resource.manager.relation_instances(item, self.attribute, self.target, page, per_page)

            yield relations_route.for_method(
                "GET",
                relation_instances,
                rel=self.attribute,
                response_schema=RelationInstances(self.target),
                schema=FieldSet(
                    {
                        "page": Integer(minimum=1, default=1),
                        "per_page": Integer(minimum=1, default=20, maximum=50),
                    }
                ),
            )
        if "w" in io or "u" in io:
            # book  #author
            def relation_add(resource, item, target_item):
                # book001  #'author' #UserResource, user001
                resource.manager.relation_add(item, self.attribute, self.target, target_item)
                resource.manager.commit()
                return target_item

            yield relations_route.for_method(
                "POST",
                relation_add,
                rel=to_camel_case("add_{}".format(self.attribute)),
                response_schema=ToOne(self.target),
                schema=ToOne(self.target),
            )

            def relation_remove(resource, item, target_id):
                target_item = self.target.manager.read(target_id)
                resource.manager.relation_remove(item, self.attribute, self.target, target_item)
                resource.manager.commit()
                return None, 204

            yield relation_route.for_method(
                "DELETE",
                relation_remove,
                rel=to_camel_case("remove_{}".format(self.attribute)),
            )


def route_from(url, method=None):
    appctx = _app_ctx_stack.top
    reqctx = _request_ctx_stack.top
    if appctx is None:
        raise RuntimeError(
            "Attempted to match a URL without the application context being pushed. This has to be executed when application context is available."
        )
    if reqctx is not None:
        url_adapter = reqctx.url_adapter
    else:
        url_adapter = appctx.url_adapter
        if url_adapter is None:
            raise RuntimeError(
                "Application was not able to create a URL adapter for request independent URL matching. You might be able to fix this by setting the SERVER_NAME config variable."
            )
    parsed_url = url_parse(url)
    if parsed_url.netloc != "" and parsed_url.netloc != url_adapter.server_name:
        raise PageNotFound()
    return url_adapter.match(parsed_url.path, method)


def unpack(value):
    if not isinstance(value, tuple):
        return value, 200, {}
    try:
        (data, code, headers) = value
        return data, code, headers
    except ValueError:
        pass
    try:
        (data, code) = value
        return data, code, {}
    except ValueError:
        pass
    return value, 200, {}


def get_value(key, obj, default):
    if hasattr(obj, "__getitem__"):
        try:
            return obj[key]
        except (IndexError, TypeError, KeyError):
            pass
    return getattr(obj, key, default)


# -----------------自动路由----------------------------------------------
def _route_decorator(method):  # 路由装饰器
    def decorator(cls, *args, **kwargs):
        if len(args) == 1 and len(kwargs) == 0 and callable(args[0]):
            return cls(method, args[0])  # 没有关键字参数只有一个位置参数的视图函数
            # 这个位置参数就是路由endpoint 如 /instances
        return lambda f: cls(method, f, *args, **kwargs)  # 返回函数 返回的是路由类

    decorator.__name__ = method
    return classmethod(decorator)


def _method_decorator(method):
    def wrapper(self, *args, **kwargs):
        if len(args) == 1 and len(kwargs) == 0 and callable(args[0]):
            return self.for_method(method, args[0], **kwargs)
        else:
            return lambda f: self.for_method(method, f, *args, **kwargs)

    wrapper.__name__ = method
    return wrapper


class Route:
    def __init__(
        self,
        method=None,
        view_func=None,
        rule=None,
        attribute=None,
        rel=None,
        title=None,
        description=None,
        schema=None,
        response_schema=None,
        format_response=True,
        success_code=None,
    ):
        self.rel = rel  # 关系
        self.rule = rule  # 规则
        self.method = method  # get/post
        self.attribute = attribute  # 属性？
        self.title = title  # 标题？网页标题
        self.description = description  # 网页描述？
        self.view_func = view_func  # 视图函数
        self.format_response = format_response  # 是否格式化响应
        self.success_code = success_code  # 状态码
        annotations = getattr(view_func, "__annotations__", None)  # 获取视图函数的标注
        if isinstance(annotations, dict) and len(annotations):
            self.request_schema = FieldSet(
                {name: field for (name, field) in annotations.items() if name != "return"}
            )  # 请求的语法就是参数名和参数字段类型的字段集，响应也有字段
            self.response_schema = annotations.get("return", response_schema)
        else:  # 没有标注则要指定参数
            self.request_schema = schema
            self.response_schema = response_schema
        self._related_routes = ()  # 相关的路由
        for method in HTTP_METHODS:
            setattr(self, method, MethodType(_method_decorator(method), self))
            setattr(self, method.lower(), getattr(self, method))  # 忽略大小写GET成为装饰器

    @property
    def relation(self):  # 关系型数据资源
        if self.rel:
            return self.rel  # 关联字符串 read_status?

        verb = HTTP_METHOD_VERB_DEFAULTS.get(self.method, self.method.lower())
        return to_camel_case("{}_{}".format(verb, self.attribute))

    def schema_factory(self, resource):  # 规则工厂 将路由的请求与响应规则绑定到资源上
        request_schema = _bind_schema(self.request_schema, resource)
        response_schema = _bind_schema(self.response_schema, resource)
        schema = OrderedDict(
            [
                ("rel", self.relation),  # 关联
                (
                    "href",
                    url_rule_to_uri_pattern(self.rule_factory(resource, relative=False)),
                ),
                ("method", self.method),
            ]
        )
        if self.title:
            schema["title"] = self.title
        if self.description:
            schema["description"] = self.description
        if request_schema:
            schema["schema"] = request_schema.request  # 请求格式的请求部分
        if response_schema:
            schema["targetSchema"] = response_schema.response  # 响应格式的响应部分
        return schema

    def for_method(
        self, method, view_func, rel=None, title=None, description=None, schema=None, response_schema=None, **kwargs
    ):
        attribute = kwargs.pop("attribute", self.attribute)
        format_response = kwargs.pop("format_response", self.format_response)
        instance = self.__class__(
            method,
            view_func,
            rule=self.rule,
            rel=rel,
            title=title,
            description=description,
            schema=schema,
            response_schema=response_schema,
            attribute=attribute,
            format_response=format_response,
            **kwargs
        )
        instance._related_routes = self._related_routes + (self,)
        return instance

    # 存在了__get__的方法的类称之为描述符类
    # descriptor 的实例自己访问自己是不会触发__get__ ，而会触发__call__，
    # 只有 descriptor 作为其它类的属性的时候才会触发 __get___
    def __get__(self, obj, owner):  # 返回的是个视图函数或类，obj是自己的对象，owner是自己的所属类
        if obj is None:
            return self
        return lambda *args, **kwargs: self.view_func.__call__(obj, *args, **kwargs)

    def __repr__(self):
        return "{}({})".format(self.__class__.__name__, repr(self.rule))

    @property
    def request_schema(self):
        return self.schema  # 先调用了setter方法所以存在

    @request_schema.setter
    def request_schema(self, schema):
        self.schema = schema

    def rule_factory(self, resource, relative=False):  # 规则工厂
        rule = self.rule  # 规则是个字符串
        if rule is None:
            rule = "/{}".format(attribute_to_route_uri(self.attribute))
            # self.attribute 可以关联到资源属性和rule二选一
            # Route.get('/status') 是 rule
            # Route.get(attribute='status') 是属性
        elif callable(rule):  # 规则可以调用资源
            rule = rule(resource)
        if relative or resource.route_prefix is None:
            return rule[1:]
        return "".join((resource.route_prefix, rule))

    def view_factory(self, name, resource):  # 视图工厂
        request_schema = _bind_schema(self.request_schema, resource)
        response_schema = _bind_schema(self.response_schema, resource)
        view_func = self.view_func

        def view(*args, **kwargs):
            instance = resource()  # 资源实例
            if isinstance(request_schema, (FieldSet, Instances)):  # 请求字段集和实例集
                kwargs.update(request_schema.parse_request(request))  # 上文实现了
            elif isinstance(request_schema, Schema):  # 普通的格式
                args += (request_schema.parse_request(request),)  # 为何是元组？
            response = view_func(instance, *args, **kwargs)
            if not isinstance(response, tuple) and self.success_code:
                response = (response, self.success_code)
            if response_schema is None or not self.format_response:
                return response
            else:
                return response_schema.format_response(response)  # 格式化

        return view


for method in HTTP_METHODS:
    setattr(Route, method.lower(), _route_decorator(method))
    setattr(Route, method, _route_decorator(method))


class ItemRoute(Route):  # 单个记录
    def rule_factory(self, resource, relative=False):
        rule = self.rule
        id_matcher = "<{}:id>".format(resource.meta.id_converter)
        if rule is None:
            rule = "/{}".format(attribute_to_route_uri(self.attribute))
        elif callable(rule):
            rule = rule(resource)
        if relative or resource.route_prefix is None:
            return rule[1:]
        return "".join((resource.route_prefix, "/", id_matcher, rule))

    def view_factory(self, name, resource):
        original_view = super(ItemRoute, self).view_factory(name, resource)

        def view(*args, **kwargs):
            id = kwargs.pop("id")
            item = resource.manager.read(id)
            return original_view(item, *args, **kwargs)

        return view


def _field_from_object(parent, schema_cls_or_obj):  # 从对象获取字段
    if isinstance(schema_cls_or_obj, type):
        container = schema_cls_or_obj()  # 类的实例
    else:
        container = schema_cls_or_obj  # 实例
    if not isinstance(container, Schema):  # 实例不是格式类
        raise RuntimeError("{} expected Raw or Schema, but got {}".format(parent, container.__class__.__name__))
    if not isinstance(container, Raw):  # 实例不是Raw类是Schema类
        container = Raw(container)  # 用Raw类包裹
    return container


class ItemAttributeRoute(RouteSet):  # 单个记录的属性路由
    def __init__(self, schema_cls_or_obj, io=None, attribute=None):
        self.field = _field_from_object(ItemAttributeRoute, schema_cls_or_obj)
        self.attribute = attribute
        self.io = io

    def routes(self):
        io = self.io or self.field.io
        field = self.field
        route = ItemRoute(attribute=self.attribute)
        attribute = field.attribute or route.attribute
        if "r" in io:  # 读属性的路由

            def read_attribute(resource, item):
                if hasattr(resource, "before_read_{}".format(attribute)):  # 直接调用source的钩子
                    getattr(resource, "before_read_{}".format(attribute))(item)  # 也可以直接改为信号发射

                resp = get_value(attribute, item, field.default)

                if hasattr(resource, "after_read_{}".format(attribute)):  # 直接调用source的钩子
                    getattr(resource, "after_read_{}".format(attribute))(item)

                return resp

            yield route.for_method(
                "GET",
                read_attribute,
                response_schema=field,
                rel=to_camel_case("read_{}".format(route.attribute)),
                # readDescription
            )
        if "u" in io:  # 更新属性的路由

            def update_attribute(resource, item, value):  # 直接post一个string即可
                if hasattr(resource, "before_update_{}".format(attribute)):  # 直接调用source的钩子
                    getattr(resource, "before_update_{}".format(attribute))(item, value)  # 也可以直接改为信号发射

                item = resource.manager.update(item, {attribute: value})

                if hasattr(resource, "after_update_{}".format(attribute)):  # 直接调用source的钩子
                    getattr(resource, "after_update_{}".format(attribute))(item, value)  # 也可以直接改为信号发射

                return get_value(attribute, item, field.default)

            yield route.for_method(
                "POST",
                update_attribute,
                schema=field,
                response_schema=field,
                rel=to_camel_case("update_{}".format(route.attribute)),
            )


def _make_response(data, code, headers=None):
    settings = {}
    if current_app.debug:
        settings.setdefault("indent", 4)
        settings.setdefault("sort_keys", True)
    data = json.dumps(data, **settings)
    resp = make_response(data, code)
    resp.headers.extend(headers or {})
    resp.headers["Content-Type"] = "application/json"
    return resp


class Api:
    def __init__(
        self,
        app=None,
        decorators=None,
        prefix=None,
        title=None,
        description=None,
        default_manager=None,
    ):
        self.app = app
        self.blueprint = None
        self.prefix = prefix or ""
        self.decorators = decorators or []
        self.title = title
        self.description = description
        self.endpoints = set()
        self.resources = {}
        self.views = []
        self.default_manager = None
        if default_manager is None:
            try:
                from flask_restone.contrib.alchemy import SQLAlchemyManager

                self.default_manager = SQLAlchemyManager
            except ImportError:
                pass
        else:
            self.default_manager = default_manager
        if app is not None:
            self.init_app(app)

    def init_app(self, app):
        try:
            app.record(self._deferred_blueprint_init)
        except AttributeError:
            self._init_app(app)
        else:
            self.blueprint = app

    def _deferred_blueprint_init(self, setup_state):
        self.prefix = "".join((setup_state.url_prefix or "", self.prefix))
        for resource in self.resources.values():
            resource.route_prefix = "".join((self.prefix, "/", resource.meta.name))
        self._init_app(setup_state.app)

    def _init_app(self, app):
        app.config.setdefault("RESTONE_MAX_PER_PAGE", 100)
        app.config.setdefault("RESTONE_DEFAULT_PER_PAGE", 20)
        app.config.setdefault("RESTONE_DECORATE_SCHEMA_ENDPOINTS", True)
        self._register_view(
            app,
            rule="".join((self.prefix, "/schema")),
            view_func=self._schema_view,
            endpoint="schema",
            methods=["GET"],
            relation="describedBy",
        )
        for route, resource, view_func, endpoint, methods, relation in self.views:
            rule = route.rule_factory(resource)
            self._register_view(app, rule, view_func, endpoint, methods, relation)
        app.handle_exception = partial(self._exception_handler, app.handle_exception)
        app.handle_user_exception = partial(self._exception_handler, app.handle_user_exception)

    def _register_view(self, app, rule, view_func, endpoint, methods, relation):
        decorate_view_func = relation != "describedBy" or app.config["RESTONE_DECORATE_SCHEMA_ENDPOINTS"]
        if self.blueprint:
            endpoint = "{}.{}".format(self.blueprint.name, endpoint)
        view_func = self.output(view_func)
        if decorate_view_func:
            for decorator in self.decorators:
                view_func = decorator(view_func)
        app.add_url_rule(rule, view_func=view_func, endpoint=endpoint, methods=methods)

    def _exception_handler(self, original_handler, e):
        if isinstance(e, RestoneException):
            return e.get_response()
        if not request.path.startswith(self.prefix):
            return original_handler(e)
        if isinstance(e, HTTPException):
            return _make_response({"status": e.code, "message": e.description}, e.code)
        return original_handler(e)

    def output(self, view):
        @wraps(view)
        def wrapper(*args, **kwargs):
            resp = view(*args, **kwargs)
            if isinstance(resp, Response):
                return resp
            (data, code, headers) = unpack(resp)
            return _make_response(data, code, headers)

        return wrapper

    def _schema_view(self):
        schema = OrderedDict()
        schema["$schema"] = "http://json-schema.org/draft-04/hyper-schema#"
        if self.title:
            schema["title"] = self.title
        if self.description:
            schema["description"] = self.description
        schema["properties"] = properties = OrderedDict([])
        for name, resource in sorted(self.resources.items(), key=operator.itemgetter(0)):
            resource_schema_rule = resource.routes["describedBy"].rule_factory(resource)
            properties[name] = {"$ref": "{}#".format(resource_schema_rule)}
        return OrderedDict(schema), 200, {"Content-Type": "application/schema+json"}

    def add_route(self, route, resource, endpoint=None, decorator=None):
        endpoint = endpoint or "_".join((resource.meta.name, route.relation))
        # services_status
        methods = [route.method]
        rule = route.rule_factory(resource)
        view_func = route.view_factory(endpoint, resource)
        if decorator:
            view_func = decorator(view_func)
        print(rule, view_func, endpoint, methods, route.relation)
        if self.app and (not self.blueprint):
            self._register_view(self.app, rule, view_func, endpoint, methods, route.relation)
        else:
            self.views.append((route, resource, view_func, endpoint, methods, route.relation))

    def add_resource(self, resource):
        if resource in self.resources.values():
            return
        if resource.api is not None and resource.api != self:
            raise RuntimeError("Attempted to register a resource that is already registered with a different Api.")
        if issubclass(resource, ModelResource) and resource.manager is None:
            if self.default_manager:
                resource.manager = self.default_manager(resource, resource.meta.get("model"))
            else:
                raise RuntimeError(
                    "'{}' has no manager, and no default manager has been defined. If you're using Restone with SQLAlchemy, ensure you have installed Flask-SQLAlchemy.".format(
                        resource.meta.name
                    )
                )
        resource.api = self
        resource.route_prefix = "".join((self.prefix, "/", resource.meta.name))
        for route in resource.routes.values():
            route_decorator = resource.meta.route_decorators.get(route.relation, None)
            # route.relation 是字符 如"read_xxx" 则是 装饰器字典，用于装饰这个函数
            self.add_route(route, resource, decorator=route_decorator)
        # 以键值对返回成员 返回满足 lambda m: isinstance(m, RouteSet) 的成员，也就是 RouteSet及子类的实例
        for name, rset in inspect.getmembers(resource, lambda m: isinstance(m, RouteSet)):
            if rset.attribute is None:
                rset.attribute = name
                # 没有属性就用自己名字做属性 如
                # status = ItemAttributeRoute(field_cls_or_instance,io='ru')
            for i, route in enumerate(rset.routes()):
                if route.attribute is None:
                    route.attribute = "{}_{}".format(rset.attribute, i)
                resource.routes["{}_{}".format(rset.attribute, route.relation)] = route
                # status_readStatus #todo 改变格式
                # _decorator = getattr(resource, route.relation, None) #同样的装饰 todo improvment
                # 把装饰放到 resource 下面
                # if callable()
                self.add_route(route, resource)  # ,decorator=_decorator)
        self.resources[resource.meta.name] = resource


class InlineModel(Object):
    """
    :param dict properties:
    :param model:
    """

    def __init__(self, properties, model, **kwargs):
        super(InlineModel, self).__init__(properties, **kwargs)
        self.model = model

    def converter(self, instance):
        instance = super(InlineModel, self).converter(instance)
        if instance is not None:
            instance = self.model(**instance)
        return instance


class SQLAlchemyBaseFilter(BaseFilter):
    def __init__(self, name, field=None, attribute=None, column=None):
        super(SQLAlchemyBaseFilter, self).__init__(name, field=field, attribute=attribute)
        self.column = column

    @classmethod
    def apply(cls, query, conditions):
        expressions = [condition.filter.expression(condition.value) for condition in conditions]
        if len(expressions) == 1:
            return query.filter(expressions[0])
        return query.filter(and_(*expressions))


class SQLEqualFilter(SQLAlchemyBaseFilter, EqualFilter):
    def expression(self, value):
        return self.column == value


class SQLNotEqualFilter(SQLAlchemyBaseFilter, NotEqualFilter):
    def expression(self, value):
        return self.column != value


class SQLLessThanFilter(SQLAlchemyBaseFilter, LessThanFilter):
    def expression(self, value):
        return self.column < value


class SQLLessThanEqualFilter(SQLAlchemyBaseFilter, LessThanEqualFilter):
    def expression(self, value):
        return self.column <= value


class SQLGreaterThanFilter(SQLAlchemyBaseFilter, GreaterThanFilter):
    def expression(self, value):
        return self.column > value


class SQLGreaterThanEqualFilter(SQLAlchemyBaseFilter, GreaterThanEqualFilter):
    def expression(self, value):
        return self.column >= value


class SQLInFilter(SQLAlchemyBaseFilter, InFilter):
    def expression(self, values):
        return self.column.in_(values) if len(values) else False


class SQLContainsFilter(SQLAlchemyBaseFilter, ContainsFilter):
    def expression(self, value):
        return self.column.contains(value)


class SQLStringContainsFilter(SQLAlchemyBaseFilter, StringContainsFilter):
    def expression(self, value):
        return self.column.like("%" + value.replace("%", "\\%") + "%")


class SQLStringIContainsFilter(SQLAlchemyBaseFilter, StringIContainsFilter):
    def expression(self, value):
        return self.column.ilike("%" + value.replace("%", "\\%") + "%")


class SQLStartsWithFilter(SQLAlchemyBaseFilter, StartsWithFilter):
    def expression(self, value):
        return self.column.startswith(value.replace("%", "\\%"))


class SQLIStartsWithFilter(SQLAlchemyBaseFilter, IStartsWithFilter):
    def expression(self, value):
        return self.column.ilike(value.replace("%", "\\%") + "%")


class SQLEndsWithFilter(SQLAlchemyBaseFilter, EndsWithFilter):
    def expression(self, value):
        return self.column.endswith(value.replace("%", "\\%"))


class SQLIEndsWithFilter(SQLAlchemyBaseFilter, IEndsWithFilter):
    def expression(self, value):
        return self.column.ilike("%" + value.replace("%", "\\%"))


class SQLDateBetweenFilter(SQLAlchemyBaseFilter, DateBetweenFilter):
    def expression(self, value):
        return self.column.between(value[0], value[1])


SQL_FILTER_NAMES = (
    (SQLEqualFilter, None),
    (SQLEqualFilter, "eq"),
    (SQLNotEqualFilter, "ne"),
    (SQLLessThanFilter, "lt"),
    (SQLLessThanEqualFilter, "lte"),
    (SQLGreaterThanFilter, "gt"),
    (SQLGreaterThanEqualFilter, "gte"),
    (SQLInFilter, "in"),
    (SQLContainsFilter, "contains"),
    (SQLStringContainsFilter, "contains"),
    (SQLStringIContainsFilter, "icontains"),
    (SQLStartsWithFilter, "startswith"),
    (SQLIStartsWithFilter, "istartswith"),
    (SQLEndsWithFilter, "endswith"),
    (SQLIEndsWithFilter, "iendswith"),
    (SQLDateBetweenFilter, "between"),
)

SQL_FILTERS_BY_TYPE = (
    (Uri, (SQLEqualFilter, SQLNotEqualFilter, SQLInFilter)),
    (ItemUri, (SQLEqualFilter, SQLNotEqualFilter, SQLInFilter)),
    (Boolean, (SQLEqualFilter, SQLNotEqualFilter, SQLInFilter)),
    (
        Integer,
        (
            SQLEqualFilter,
            SQLNotEqualFilter,
            SQLLessThanFilter,
            SQLLessThanEqualFilter,
            SQLGreaterThanFilter,
            SQLGreaterThanEqualFilter,
            SQLInFilter,
        ),
    ),
    (
        Number,
        (
            SQLEqualFilter,
            SQLNotEqualFilter,
            SQLLessThanFilter,
            SQLLessThanEqualFilter,
            SQLGreaterThanFilter,
            SQLGreaterThanEqualFilter,
            SQLInFilter,
        ),
    ),
    (
        String,
        (
            SQLEqualFilter,
            SQLNotEqualFilter,
            SQLStringContainsFilter,
            SQLStringIContainsFilter,
            SQLStartsWithFilter,
            SQLIStartsWithFilter,
            SQLEndsWithFilter,
            SQLIEndsWithFilter,
            SQLInFilter,
        ),
    ),
    (
        Date,
        (
            SQLEqualFilter,
            SQLNotEqualFilter,
            SQLLessThanFilter,
            SQLLessThanEqualFilter,
            SQLGreaterThanFilter,
            SQLGreaterThanEqualFilter,
            SQLDateBetweenFilter,
            SQLInFilter,
        ),
    ),
    (
        DateTime,
        (
            SQLEqualFilter,
            SQLNotEqualFilter,
            SQLLessThanFilter,
            SQLLessThanEqualFilter,
            SQLGreaterThanFilter,
            SQLGreaterThanEqualFilter,
            SQLDateBetweenFilter,
        ),
    ),
    (
        DateString,
        (
            SQLEqualFilter,
            SQLNotEqualFilter,
            SQLLessThanFilter,
            SQLLessThanEqualFilter,
            SQLGreaterThanFilter,
            SQLGreaterThanEqualFilter,
            SQLDateBetweenFilter,
            SQLInFilter,
        ),
    ),
    (
        DateTimeString,
        (
            SQLEqualFilter,
            SQLNotEqualFilter,
            SQLLessThanFilter,
            SQLLessThanEqualFilter,
            SQLGreaterThanFilter,
            SQLGreaterThanEqualFilter,
            SQLDateBetweenFilter,
        ),
    ),
    (Array, (SQLContainsFilter,)),
    (
        ToOne,
        (
            SQLEqualFilter,
            SQLNotEqualFilter,
            SQLInFilter,
        ),
    ),
    (ToMany, (SQLContainsFilter,)),
)


class SQLAlchemyManager(RelationalManager):
    FILTER_NAMES = SQL_FILTER_NAMES
    FILTERS_BY_TYPE = SQL_FILTERS_BY_TYPE
    PAGINATION_TYPES = (Pagination, SAPagination)

    def __init__(self, resource, model):
        super(SQLAlchemyManager, self).__init__(resource, model)

    def _init_model(self, resource, model, meta):
        mapper = class_mapper(model)

        self.model = model

        if meta.id_attribute:
            self.id_column = getattr(model, resource.meta.id_attribute)
            self.id_attribute = meta.id_attribute
        else:
            self.id_column = mapper.primary_key[0]
            self.id_attribute = mapper.primary_key[0].name

        self.id_field = self._get_field_from_column_type(self.id_column, self.id_attribute, io="r")
        self.default_sort_expression = self._get_sort_expression(model, meta, self.id_column)

        fs = resource.schema
        if meta.include_id:
            fs.set("$id", self.id_field)
        else:
            fs.set("$uri", ItemUri(resource, attribute=self.id_attribute))

        if meta.include_type:
            fs.set("$type", ItemType(resource))

        # resource name: use model table's name if not set explicitly
        if not hasattr(resource.Meta, "name"):
            meta["name"] = model.__tablename__.lower()

        fs = resource.schema
        include_fields = meta.get("include_fields", None)
        exclude_fields = meta.get("exclude_fields", None)
        read_only_fields = meta.get("read_only_fields", ())
        write_only_fields = meta.get("write_only_fields", ())
        pre_declared_fields = {f.attribute or k for k, f in fs.fields.items()}

        for name, column in mapper.columns.items():
            if (
                (include_fields and name in include_fields)
                or (exclude_fields and name not in exclude_fields)
                or not (include_fields or exclude_fields)
            ):
                if column.primary_key or column.foreign_keys:
                    continue
                if name in pre_declared_fields:
                    continue

                io = "rw"
                if name in read_only_fields:
                    io = "r"
                elif name in write_only_fields:
                    io = "w"

                if "w" in io and not (column.nullable or column.default):
                    fs.required.add(name)
                fs.set(name, self._get_field_from_column_type(column, name, io=io))

    @staticmethod
    def _get_sort_expression(model, meta, id_column):
        if meta.sort_attribute is None:
            return id_column.asc()

        attr_name, reverse = meta.sort_attribute
        attr = getattr(model, attr_name)
        return attr.desc() if reverse else attr.asc()

    def _get_field_from_column_type(self, column, attribute, io="rw"):
        args = ()
        kwargs = {}

        if isinstance(column.type, postgresql.ARRAY):
            field_class = Array
            args = (String,)
        elif isinstance(column.type, postgresql.UUID):
            field_class = UUID
        elif isinstance(column.type, String_) and column.type.length:
            field_class = String
            kwargs = {"max_length": column.type.length}
        elif isinstance(column.type, postgresql.HSTORE):
            field_class = Object
            args = (String,)
        elif hasattr(postgresql, "JSON") and isinstance(column.type, (postgresql.JSON, postgresql.JSONB)):
            field_class = Raw
            kwargs = {"schema": {}}
        else:
            try:
                python_type = column.type.python_type
            except NotImplementedError:
                raise RuntimeError(
                    "Unable to auto-detect the correct field type for {}! "
                    "You need to specify it manually in ModelResource.Schema".format(column)
                )
            field_class = self._get_field_from_python_type(python_type)

        kwargs["nullable"] = column.nullable

        if column.default is not None:
            if column.default.is_sequence:
                pass
            elif column.default.is_scalar:
                kwargs["default"] = column.default.arg

        return field_class(*args, io=io, attribute=attribute, **kwargs)

    def _init_filter(self, filter_class, name, field, attribute):
        return filter_class(
            name,
            field=field,
            attribute=field.attribute or attribute,
            column=getattr(self.model, field.attribute or attribute),
        )

    def _is_sortable_field(self, field):
        if super(SQLAlchemyManager, self)._is_sortable_field(field):
            return True
        elif isinstance(field, ToOne):
            return isinstance(field.target.manager, SQLAlchemyManager)
        else:
            return False

    @staticmethod
    def _get_session():
        return current_app.extensions["sqlalchemy"].session

    @staticmethod
    def _is_change(a, b):
        return (a is None) != (b is None) or a != b

    def _query(self):
        return self.model.query

    def _query_filter(self, query, expression):
        return query.filter(expression)

    def _expression_for_join(self, attribute, expression):
        relationship = getattr(self.model, attribute)
        if isinstance(relationship.impl, ScalarObjectAttributeImpl):
            return relationship.has(expression)
        else:
            return relationship.any(expression)

    def _expression_for_condition(self, condition):
        return condition.filter.expression(condition.value)

    def _expression_for_ids(self, ids):
        return self.id_column.in_(ids)

    def _or_expression(self, expressions):
        if not expressions:
            return True
        if len(expressions) == 1:
            return expressions[0]
        return or_(*expressions)

    def _and_expression(self, expressions):
        if not expressions:
            return False
        if len(expressions) == 1:
            return expressions[0]
        return and_(*expressions)

    def _query_filter_by_id(self, query, id):
        try:
            return query.filter(self.id_column == id).one()
        except NoResultFound:
            raise ItemNotFound(self.resource, id=id)

    def _query_order_by(self, query, sort=None):
        order_clauses = []

        if not sort:
            return query.order_by(self.default_sort_expression)

        for field, attribute, reverse in sort:
            column = getattr(self.model, attribute)

            if isinstance(field, ToOne):
                target_alias = aliased(field.target.meta.model)
                query = query.outerjoin(target_alias, column).reset_joinpoint()
                sort_attribute = None
                if field.target.meta.sort_attribute:
                    sort_attribute, _ = field.target.meta.sort_attribute
                column = getattr(target_alias, sort_attribute or field.target.manager.id_attribute)

            order_clauses.append(column.desc() if reverse else column.asc())

        return query.order_by(*order_clauses)

    def _query_get_paginated_items(self, query, page, per_page):
        return query.paginate(page=page, per_page=per_page)

    def _query_get_all(self, query):
        return query.all()

    def _query_get_one(self, query):
        return query.one()

    def _query_get_first(self, query):
        try:
            return query.one()
        except NoResultFound:
            raise IndexError()

    def create(self, properties, commit=True):
        # noinspection properties
        item = self.model()

        for key, value in properties.items():
            setattr(item, key, value)

        before_create.send(self.resource, item=item)

        session = self._get_session()

        try:
            session.add(item)
            self.commit_or_flush(commit)
        except IntegrityError as e:
            session.rollback()

            if hasattr(e.orig, "pgcode"):
                if e.orig.pgcode == "23505":  # duplicate key
                    raise DuplicateKey(detail=e.orig.diag.message_detail)

            if current_app.debug:
                raise BackendConflict(debug_info=dict(exception_message=str(e), statement=e.statement, params=e.params))
            raise BackendConflict()

        after_create.send(self.resource, item=item)
        return item

    def update(self, item, changes, commit=True):
        session = self._get_session()

        actual_changes = {
            key: value for key, value in changes.items() if self._is_change(get_value(key, item, None), value)
        }

        try:
            before_update.send(self.resource, item=item, changes=actual_changes)

            for key, value in changes.items():
                setattr(item, key, value)

            self.commit_or_flush(commit)
        except IntegrityError as e:
            session.rollback()

            # XXX need some better way to detect postgres engine.
            if hasattr(e.orig, "pgcode"):
                if e.orig.pgcode == "23505":  # duplicate key
                    raise DuplicateKey(detail=e.orig.diag.message_detail)

            if current_app.debug:
                raise BackendConflict(debug_info=dict(exception_message=str(e), statement=e.statement, params=e.params))
            raise BackendConflict()

        after_update.send(self.resource, item=item, changes=actual_changes)
        return item

    def delete(self, item, commit=True):
        session = self._get_session()

        before_delete.send(self.resource, item=item)

        try:
            session.delete(item)
            self.commit_or_flush(commit)
        except IntegrityError as e:
            session.rollback()

            if current_app.debug:
                raise BackendConflict(debug_info=dict(exception_message=str(e), statement=e.statement, params=e.params))
            raise BackendConflict()

        after_delete.send(self.resource, item=item)

    def relation_instances(self, item, attribute, target_resource, page=None, per_page=None):
        query = getattr(item, attribute)

        if isinstance(query, InstrumentedList):
            if page and per_page:
                return Pagination.from_list(query, page, per_page)
            return query

        if page and per_page:
            return self._query_get_paginated_items(query, page, per_page)

        return self._query_get_all(query)

    def relation_add(self, item, attribute, target_resource, target_item):
        before_add_to_relation.send(self.resource, item=item, attribute=attribute, child=target_item)  # 增加关联对象之前
        getattr(item, attribute).append(target_item)  # 一对多
        after_add_to_relation.send(self.resource, item=item, attribute=attribute, child=target_item)

    def relation_remove(self, item, attribute, target_resource, target_item):
        before_remove_from_relation.send(self.resource, item=item, attribute=attribute, child=target_item)
        try:
            getattr(item, attribute).remove(target_item)
            after_remove_from_relation.send(self.resource, item=item, attribute=attribute, child=target_item)
        except ValueError:
            pass  # if the relation does not exist, do nothing

    def commit(self):
        session = self._get_session()
        session.commit()

    def commit_or_flush(self, commit):
        session = self._get_session()
        if commit:
            session.commit()
        else:
            session.flush()
