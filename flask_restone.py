"""
restone makes you the rest one
restone 是集成了自动路由,过滤器,格式与字段校验，基于用户、角色、内容的鉴权，自动Swager接口自测
的Restful 的API
"""
import calendar
import datetime
import decimal
import inspect
from operator import itemgetter,attrgetter
import re
from collections import OrderedDict
from functools import partial, wraps
from importlib import import_module
from types import MethodType

from aniso8601 import parse_date, parse_datetime
from flasgger import swag_from
from flask import _app_ctx_stack, _request_ctx_stack
from flask import current_app, g, json, jsonify, make_response, request
from flask.signals import Namespace
from flask_principal import ItemNeed, Permission, RoleNeed, UserNeed
from flask_sqlalchemy import Pagination as SAPagination
from jsonschema import Draft4Validator, FormatChecker, ValidationError
from sqlalchemy import String as String_, and_, or_
from sqlalchemy.dialects import postgresql
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import aliased, class_mapper
from sqlalchemy.orm.attributes import ScalarObjectAttributeImpl
from sqlalchemy.orm.collections import InstrumentedList
from sqlalchemy.orm.exc import NoResultFound
from werkzeug.exceptions import Forbidden, HTTPException
from werkzeug.http import HTTP_STATUS_CODES
from werkzeug.urls import url_parse
from werkzeug.utils import cached_property
from werkzeug.wrappers import Response

# ---------------------------HTTP常量--------------------
HTTP_METHODS = ("GET", "PUT", "POST", "PATCH", "DELETE")
HTTP_VERBS = {"GET": "read", "PUT": "create", "POST": "create", "PATCH": "update", "DELETE": "destroy"}

PERMISSION_DEFAULTS = (("read", "yes"), ("create", "no"), ("update", "create"), ("delete", "update"))
DEFAULT_METHODS = ("read", "create", "update", "delete")
METHOD_ROUTE_RELATIONS = (
    ("read", ("read", "instances")),
    ("create", ("create",)),
    ("update", ("update",)),
    ("delete", ("destroy",)),
)
PERMISSION_DENIED_STRINGS = ("no", "nobody", "noone")
PERMISSION_GRANTED_STRINGS = ("yes", "everybody", "anybody", "everyone", "anyone")

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

    @property
    def as_dict(self):
        if self.args:
            message = str(self)
        else:
            message = HTTP_STATUS_CODES.get(self.status_code, "")
        return dict(status=self.status_code, message=message)

    def get_response(self):
        response = jsonify(self.as_dict)
        response.status_code = self.status_code
        return response


class ItemNotFound(RestoneException):
    status_code = 404

    def __init__(self, resource, where=None, id=None):
        self.resource = resource
        self.id = id
        self.where = where

    def as_dict(self):
        dct = super().as_dict
        if self.id is not None:
            dct["item"] = {"$type": self.resource.meta.name, "$id": self.id}
        else:
            dct["item"] = {
                "$type": self.resource.meta.name,
                "$where": {cond.attribute: {f"${cond.filter.name}": cond.value} if cond.filter.name is not None else cond.value for cond in self.where}
                if self.where
                else None,
            }
        return dct


class RequestMustBeJSON(RestoneException):
    status_code = 415


class RestoneValidationError(RestoneException):
    status_code = 400

    def __init__(self, errors, root=None, schema_uri="#"):
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
            error_data = {"validationOf": {error.validator: error.validator_value}, "path": self._complete_path(error)}
            if current_app.debug:
                error_data["message"] = error.message
            yield error_data

    def as_dict(self):
        dct = super().as_dict
        dct["errors"] = list(self._format_errors())
        return dct


class DuplicateKey(RestoneException):
    status_code = 409

    def __init__(self, **kwargs):
        self.data = kwargs


class BackendConflict(RestoneException):
    status_code = 409

    def __init__(self, **kwargs):
        self.data = kwargs

    def as_dict(self):
        dct = super().as_dict
        dct.update(self.data)
        return dct


class PageNotFound(RestoneException):
    status_code = 404


class InvalidJSON(RestoneException):
    status_code = 400


# JSON Schema，也称为JSON模式。JSON Schema是描述你的JSON数据格式；
# 主要有以下作用：
# 对现有的json数据格式进行描述（字段类型、内容长度、是否必须存在、取值示例等）；
# 是一个描述清晰、人机可读的文档；
# 自动测试、验证客户端提交的数据；
# ---------------------------请求与响应格式----------------------
class Schema:  # schema 就是规则格式，子类需实现 schema 语法和 format 格式化方法
    def schema(self):  # 二元组就是 rsp,rqs
        raise NotImplementedError()

    @cached_property
    def response(self):
        schema = self.schema()
        return schema[0] if isinstance(schema, tuple) else schema

    @cached_property
    def request(self):
        schema = self.schema()
        return schema[1] if isinstance(schema, tuple) else schema

    create = request  # 三元组就是 response create update #delete不用schema

    @cached_property
    def update(self):
        schema = self.schema()
        return schema[-1] if isinstance(schema, tuple) else schema

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
        validator = self._update_validator if update else self._validator  # 运用update的语法检查实例
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
        data, code, headers = unpack(response)
        return self.format(data), code, headers


class ResourceMixin:  # 资源绑定插件
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
        raise NotImplementedError(f"{repr(self)} is already bound to {self.resource} and does not support rebinding to {resource}")


class _SchemaDummy(Schema):  # 简化格式实现
    def __init__(self, schema):
        self._schema = schema

    def schema(self):
        return self._schema


class FieldSet(Schema, ResourceMixin):  # 字段集 规则和资源绑定
    def __init__(self, fields, required_fields=None):
        self.fields = fields  # 字段字典
        self.required = set(required_fields or ())  # 必填项

    def _on_bind(self, resource):  # 字段字典内部字段能绑则绑
        self.fields = {key: field.bind(resource) if isinstance(field, ResourceMixin) else field for (key, field) in self.fields.items()}

    def rebind(self, resource):
        return FieldSet(dict(self.fields), tuple(self.required)).bind(resource)

    def set(self, key, field):  # 设置字段并绑定资源
        if self.resource and isinstance(field, ResourceMixin):
            field = field.bind(self.resource)
        self.fields[key] = field

    def _schema(self, patchable=False):  # _schema 内部规则
        read_schema = {
            "type": "object",
            "properties": OrderedDict(((key, field.response) for (key, field) in self.fields.items() if "r" in field.io)),
        }  # 响应的可读属性
        create_schema = {
            "type": "object",
            "additionalProperties": False,
            "properties": OrderedDict(((key, field.request) for (key, field) in self.fields.items() if "c" in field.io)),
        }  # 请求的可写属性
        update_schema = {
            "type": "object",
            "additionalProperties": False,
            "properties": OrderedDict(((key, field.request) for (key, field) in self.fields.items() if "u" in field.io)),
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

    def convert(self, instance, update=False, pre_resolved_properties=None, patchable=False, strict=False):  # 格式转换和检查
        result = dict(pre_resolved_properties) if pre_resolved_properties else {}
        if patchable:
            object_ = self.patchable.convert(instance, update)  # 就是基类的转化校验
        else:  # 区别在于语法
            object_ = super().convert(instance, update)
        for key, field in self.fields.items():
            if update and "u" not in field.io or (not update and "c" not in field.io):
                continue  # 不可更新字段或不更新
            if key in result:  # 已处理字段
                continue
            value = None
            try:
                value = object_[key]  # 转换校验后字典
                value = field.convert(value, )  # 字段本身的转换
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
                    except ValueError:
                        data[name] = value  # 类型错误直接赋值
                except KeyError:
                    pass
        return self.convert(data, update=request.method in ("PUT", "PATCH"), patchable=request.method == "PATCH")


def _bind_schema(schema, resource) -> Schema:  # 将格式与资源绑定
    if isinstance(schema, ResourceMixin):
        return schema.bind(resource)
    return schema


# ----------------字段格式------------
class BaseField(Schema):
    def __init__(self, schema, io="rw", default=None, attribute=None, nullable=False, title=None, description=None):
        self._schema = schema  # 字段格式
        self._default = default  # 字段默认
        self.attribute = attribute  # 名称
        self.nullable = nullable  # 可为空
        self.title = title  # 标题
        self.description = description  # 描述,可以用中文
        self.io = io  # 读写

    def _finalize_schema(self, schema, io):  # 单个字典
        schema = dict(schema)
        if self.io == "r" and "r" in io:
            schema["readOnly"] = True
        if "null" in schema.get("type", []):  # type 就是类型
            self.nullable = True

        if self.nullable:  # ??
            if "enum" in schema and None not in schema["enum"]:
                # 可以为空且枚举列表里没null
                schema["enum"].append(None)
            if "type" in schema:
                type_ = schema["type"]  # 类型是字符串或字典 json 里只有三种
                if isinstance(type_, (str, dict)):
                    schema["type"] = [type_, "null"]
                else:
                    schema["type"].append("null")  # 是列表
            if "anyOf" in schema:  #
                if not any(("null" in choice.get("type", []) for choice in schema["anyOf"])):
                    schema["anyOf"].append({"type": "null"})
            elif "oneOf" in schema:
                if not any(("null" in choice.get("type", []) for choice in schema["oneOf"])):
                    schema["oneOf"].append({"type": "null"})
            elif "type" not in schema:
                if len(schema) == 1 and "$ref" in schema:  # 只有一个ref
                    schema = {"anyOf": [schema, {"type": "null"}]}
                else:
                    current_app.logger.warn(f'{self} is nullable but "null" type cannot be added')
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
        self._io = "".join(set(value.replace("w", "cu")))

    @property
    def default(self):  # 字段可执行则执行
        return self._default() if callable(self._default) else self._default

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
            return self._finalize_schema(schema, "r"), self._finalize_schema(schema, "w")
        return self._finalize_schema(read_schema, "r"), self._finalize_schema(write_schema, "w")

    def format(self, value):
        return self.formatter(value) if value is not None else value

    def convert(self, instance, update=False, validate=True):
        if validate:  # 需要验证则使用父类验证
            instance = super().convert(instance, update)
        return self.converter(instance) if instance is not None else instance

    def formatter(self, value):  # 后续继承这个格式化
        return value

    def converter(self, value):
        return value

    def output(self, key, obj):
        key = key if self.attribute is None else self.attribute
        return self.format(get_value(key, obj, self.default))

    def __repr__(self):
        return f"{self.__class__.__name__}(attribute={repr(self.attribute)})"


class Any(BaseField):  # 可以用字典初始化
    def __init__(self, **kwargs):
        super().__init__({"type": ["null", "string", "number", "boolean", "object", "array"]}, **kwargs)


class Custom(BaseField):  # 自定义字段
    def __init__(self, schema, converter=None, formatter=None, **kwargs):
        super().__init__(schema, **kwargs)
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


# status = String(1,10,enum=["low","high"])
class String(BaseField):
    url_rule_converter = "string"

    def __init__(self, min_length=None, max_length=None, pattern=None, enum=None, format=None, **kwargs):  # 参数用于类型检查 pattern 应为正则表达式 enum 应为枚举
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
        super().__init__(schema, **kwargs)


class UUID(String):
    UUID_REGEX = "[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"

    def __init__(self, **kwargs):
        super().__init__(min_length=36, max_length=36, pattern=self.UUID_REGEX, **kwargs)


class Uri(String):
    def __init__(self, **kwargs):
        super().__init__(format="uri", **kwargs)


class Email(String):
    def __init__(self, **kwargs):
        super().__init__(format="email", **kwargs)


class Date(BaseField):
    def __init__(self, **kwargs):
        super().__init__({"type": "object", "properties": {"$date": {"type": "integer"}}, "additionalProperties": False}, **kwargs)

    def formatter(self, value):  # 时间戳
        return {"$date": int(calendar.timegm(value.timetuple()) * 1000)}

    def converter(self, value):
        return datetime.datetime.fromtimestamp(value["$date"] / 1000, datetime.timezone.utc).date()


class DateTime(Date):
    def formatter(self, value):
        return {"$date": int(calendar.timegm(value.utctimetuple()) * 1000)}

    def converter(self, value):
        return datetime.datetime.fromtimestamp(value["$date"] / 1000, datetime.timezone.utc)


class DateString(BaseField):
    def __init__(self, **kwargs):
        super().__init__({"type": "string", "format": "date"}, **kwargs)

    def formatter(self, value):
        return value.strftime("%Y-%m-%d")

    def converter(self, value):
        return parse_date(value)


class DateTimeString(BaseField):
    def __init__(self, **kwargs):
        super().__init__({"type": "string", "format": "date-time"}, **kwargs)

    def formatter(self, value):
        if value.tzinfo is None:
            value = value.replace(tzinfo=datetime.timezone.utc)
        return value.isoformat()

    def converter(self, value):
        return parse_datetime(value)


class Boolean(BaseField):
    def __init__(self, **kwargs):
        super().__init__({"type": "boolean"}, **kwargs)

    def format(self, value):
        return bool(value)


class Integer(BaseField):
    url_rule_converter = "int"

    def __init__(self, minimum=None, maximum=None, default=None, **kwargs):
        schema = {"type": "integer"}
        if minimum is not None:
            schema["minimum"] = minimum
        if maximum is not None:
            schema["maximum"] = maximum
        super().__init__(schema, default=default, **kwargs)

    def formatter(self, value):
        return int(value)


class PositiveInteger(Integer):
    def __init__(self, maximum=None, **kwargs):
        super().__init__(minimum=1, maximum=maximum, **kwargs)


class Number(BaseField):
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
        super().__init__(schema, **kwargs)

    def formatter(self, value):
        return float(value)


class Array(BaseField, ResourceMixin):
    def __init__(self, schema_cls_or_obj, min_items=None, max_items=None, unique=None, **kwargs):
        self.container = container = _field_from_object(self, schema_cls_or_obj)
        schema_properties = [("type", "array")]
        schema_properties += [(k, v) for (k, v) in [("minItems", min_items), ("maxItems", max_items), ("uniqueItems", unique)] if v is not None]
        schema = lambda s: dict([("items", s)] + schema_properties)
        super().__init__(
            lambda: (schema(container.response), schema(container.request)),
            default=kwargs.pop("default", list),
            **kwargs,
        )

    def bind(self, resource):
        if isinstance(self.container, ResourceMixin):
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


class Object(BaseField, ResourceMixin):
    def __init__(self, properties=None, pattern=None, pattern_props=None, other_props=None, **kwargs):
        self.properties = None
        self.pattern_props = None
        self.other_props = None
        if isinstance(properties, dict):  # proprerties 是键名和字段的字典
            self.properties = properties  # 如果不给字典，就没有这个属性
        elif isinstance(properties, (type, BaseField)):  # 类或字段
            field = _field_from_object(self, properties)
            if pattern:
                self.pattern_props = {pattern: field}
            else:
                self.other_props = field
        if isinstance(other_props, (type, BaseField)):
            self.other_props = _field_from_object(self, other_props)
        elif other_props is True:
            self.other_props = Any()
        if isinstance(pattern_props, (type, BaseField)):
            self.pattern_props = _field_from_object(self, pattern_props)
        elif isinstance(pattern_props, dict):
            self.pattern_props = {p: _field_from_object(self, f) for (p, f) in pattern_props.items()}

        def schema():
            request_schema = {"type": "object"}
            response_schema = {"type": "object"}
            for _schema, attr in ((request_schema, "request"), (response_schema, "response")):
                if self.properties:
                    _schema["properties"] = {k: getattr(f, attr) for (k, f) in self.properties.items()}
                if self.pattern_props:
                    _schema["patternProperties"] = {p: getattr(f, attr) for (p, f) in self.pattern_props.items()}
                if self.other_props:
                    _schema["additionalProperties"] = getattr(self.other_props, attr)
                else:
                    _schema["additionalProperties"] = False
            return response_schema, request_schema

        if self.pattern_props and (len(self.pattern_props) > 1 or self.other_props):
            raise NotImplementedError("Only one pattern property is currently supported and it cannot be combined with additionalProperties")
        super().__init__(schema, **kwargs)

    def bind(self, resource):
        if self.properties:
            self.properties = {key: _bind_schema(value, resource) for (key, value) in self.properties.items()}
        if self.pattern_props:
            self.pattern_props = {key: _bind_schema(value, resource) for (key, value) in self.pattern_props.items()}
        if self.other_props:
            self.other_props = _bind_schema(self.other_props, resource)
        return self

    @cached_property
    def _property_attributes(self):
        if not self.properties:
            return ()
        return [field.attribute or k for (k, field) in self.properties.items()]

    def formatter(self, value):
        output = {}
        if self.properties:
            output = {k: f.format(get_value(f.attribute or k, value, f.default)) for (k, f) in self.properties.items()}
        if self.pattern_props:  # 只能二选一，初始化的时候就抛出异常了，下面的异常不可达，删掉省一个判断
            field = next(iter(self.pattern_props.values()))
            output.update({k: field.format(v) for (k, v) in value.items() if k not in self._property_attributes})
        elif self.other_props:
            field = self.other_props
            output.update({k: field.format(v) for (k, v) in value.items() if k not in self._property_attributes})
        return output

    def converter(self, instance):
        result = {}
        if self.properties:
            result = {field.attribute or key: field.convert(
                instance.get(key, field.default), ) for (key, field) in self.properties.items()}
        if self.pattern_props:
            field = next(iter(self.pattern_props.values()))
            result.update({key: field.convert(value, ) for (key, value) in instance.items() if key not in result})
        elif self.other_props:
            field = self.other_props
            result.update({key: field.convert(value) for (key, value) in instance.items() if key not in result})
        return result


class AttributeMapped(Object):
    def __init__(self, schema_cls_or_obj, mapping_attribute=None, **kwargs):
        self.mapping_attribute = mapping_attribute
        super().__init__(schema_cls_or_obj, **kwargs)

    def _set_mapping_attribute(self, obj, value):
        if isinstance(obj, dict):
            obj[self.mapping_attribute] = value
        else:
            setattr(obj, self.mapping_attribute, value)
        return obj

    def formatter(self, value):
        if self.pattern_props:
            field = next(iter(self.pattern_props.values()))
            return {get_value(self.mapping_attribute, v, None): field.format(v) for v in value}
        if self.other_props:
            return {get_value(self.mapping_attribute, v, None): self.other_props.format(v) for v in value}
        return {}

    def converter(self, value):
        if self.pattern_props:
            field = next(iter(self.pattern_props.values()))
            return [self._set_mapping_attribute(field.convert(v, ), k) for (k, v) in value.items()]
        if self.other_props:
            return [self._set_mapping_attribute(self.other_props.convert(v), k) for (k, v) in value.items()]
        return {}


class ToOne(BaseField, ResourceMixin):
    def __init__(self, resource, **kwargs):  # resource可以是名称
        self.target_reference = ResourceReference(resource)

        def schema():
            key_converters = self.target.meta.key_converters  # 键转
            response_schema = key_converters[0].response
            if len(key_converters) == 1:
                request_schema = key_converters[0].request
            else:
                request_schema = {"anyOf": [kc.request for kc in key_converters]}
            return response_schema, request_schema

        super().__init__(schema, **kwargs)

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
        return self

    @cached_property
    def target(self):
        return self.target_reference.resolve(self.resource)

    @cached_property
    def formatter_key(self):
        return self.target.meta.key_converters[0]

    def formatter(self, item):
        return self.formatter_key.format(item)  # 响应

    def converter(self, value):  # 转换器
        for python_type, json_type in (
            (dict, "object"),
            (int, "integer"),
            ((list, tuple), "array"),
            ((str, bytes), "string"),
        ):
            if isinstance(value, python_type):
                return self.target.meta.key_converters_by_type[
                    json_type].convert(value, )


class ToMany(Array):
    def __init__(self, resource, **kwargs):
        super().__init__(ToOne(resource, nullable=False), **kwargs)


#
class Inline(BaseField, ResourceMixin):  # 内联 默认不可更新 todo 设置可更新
    def __init__(self, resource, patchable=True, **kwargs):
        self.target_reference = ResourceReference(resource)
        self.patchable = patchable

        def schema():
            def _response_schema():
                if self.resource == self.target:
                    return {"$ref": "#"}
                return {"$ref": self.target.routes["describedBy"].rule_factory(self.target)}

            # 若可更新 self.target.schema.patchable.update 为 request 语法
            if self.patchable:
                return _response_schema(), self.target.schema.patchable.update
            return _response_schema()

        super().__init__(schema, **kwargs)

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
        return self

    @cached_property
    def target(self):
        return self.target_reference.resolve(self.resource)

    def format(self, item):
        return self.target.schema.format(item)

    def convert(self, item, update=False, validate=True):  # 转换为输入 默认不可更新
        # if not validate:
        #     raise NotImplementedError()
        return self.target.schema.convert(item, )


class ItemType(BaseField):
    def __init__(self, resource):
        self.resource = resource
        super().__init__(lambda: {"type": "string", "enum": [self.resource.meta.name]}, io="r")

    def format(self, value):
        return self.resource.meta.name


class ItemUri(BaseField):
    def __init__(self, resource, attribute=None):
        self.target_reference = ResourceReference(resource)
        super().__init__(
            lambda: {"type": "string", "pattern": f"^{re.escape(self.target.route_prefix)}\\/[^/]+$"},
            io="r",
            attribute=attribute,
        )

    @cached_property
    def target(self):
        return self.target_reference.resolve()

    def format(self, value):
        return f"{self.target.route_prefix}/{value}"

    def converter(self, value):
        _, args = route_from(value, "GET")
        return self.target.manager.id_field.convert(args["id"], )


# -------------------过滤器-------------------------------------
class Condition:  # 属性 过滤器 值
    def __init__(self, attribute, filter, value):
        self.attribute = attribute
        self.filter = filter
        self.value = value

    def __call__(self, item):
        return self.filter.op(get_value(self.attribute, item, None), self.value)


class FilterMeta(type):
    def __new__(mcs, name, bases, members):
        if "name" in members:
            name = members["name"].upper()
        if "op" in members:
            func = members["op"]
            members["op"] = classmethod(lambda s, a, b: func(a, b))
        class_ = super(FilterMeta, mcs).__new__(mcs, name, bases, members)
        return class_


class BaseFilter(Schema):
    name = None
    namespace = "base"

    def __init__(self, field=None, attribute=None):
        self._attribute = attribute
        self._field = field

    @property
    def field(self):  # 被过滤的字段,只是使用field.convert
        if self.name == "in":
            return Array(self._field, min_items=0, unique=True)
        if self.name == "has":
            return self._field.container
        if self.name == "bt":
            return Array(self._field, min_items=2, max_items=2)
        if self.name in ("ct", "ict", "sw", "isw", "ew", "iew"):
            return String(min_length=1)
        if not isinstance(self._field, (Date, DateTime, DateString, DateTimeString)):
            return Number()
        return self._field

    @property
    def attribute(self):
        return self._attribute or self.field.attribute

    def convert(self, instance, **kwargs):
        if self.name is None:  # 过滤器的转换就是所过滤字段的转换
            return Condition(self.attribute, self, self.field.convert(instance))
        return Condition(self.attribute, self, self.field.convert(instance[f"${self.name}"]))

    def schema(self):
        schema = self.field.request  # 过滤器只能针对请求模式，过滤器的模式就是所过滤字段的请求模式
        if schema:
            _schema = {k: v for k, v in schema.items() if k != "readOnly"}
        else:
            _schema = schema
        if self.name is None:
            return _schema
        return {
            "type": "object",
            "properties": {f"${self.name}": _schema},
            "required": [f"${self.name}"],
            "additionalProperties": False,
        }

    @classmethod
    def named_filters(cls):
        dct = {}
        for c in cls.__subclasses__():
            if c.name is not None:
                dct[c.name] = c
            elif c.namespace == cls.namespace:
                dct.update(c.named_filters())
        return dct


def filter_factory(name, func):
    return FilterMeta(name, (BaseFilter,), {"op": func, "name": name})


# 属性过滤
LessThanFilter = filter_factory("lt", lambda a, b: a < b)
GreaterThanFilter = filter_factory("gt", lambda a, b: a > b)
EqualFilter = filter_factory("eq", lambda a, b: a == b)
NotEqualFilter = filter_factory("ne", lambda a, b: a != b)
LessThanEqualFilter = filter_factory("lte", lambda a, b: a <= b)
GreaterThanEqualFilter = filter_factory("gte", lambda a, b: a >= b)
InFilter = filter_factory("in", lambda a, b: a in b)
ContainsFilter = filter_factory("has", lambda a, b: hasattr(a, "__iter__") and b in a)
StringContainsFilter = filter_factory("ct", lambda a, b: a and b in a)
StringIContainsFilter = filter_factory("ict", lambda a, b: a and b.lower() in a.lower())
StartsWithFilter = filter_factory("sw", lambda a, b: a.startswith(b))
IStartsWithFilter = filter_factory("isw", lambda a, b: a.lower().startswith(b.lower()))
EndsWithFilter = filter_factory("ew", lambda a, b: a.endswith(b))
IEndsWithFilter = filter_factory("iew", lambda a, b: a.lower().endswith(b.lower()))
DateBetweenFilter = filter_factory("bt", lambda a, b: b[0] <= a <= [1])


FIELD_FILTERS_DICT = {
    Array: ("has",),
    Boolean: ("eq", "ne", "in"),
    Date: ("eq", "ne", "lt", "lte", "gt", "gte", "bt", "in"),
    DateString: ("eq", "ne", "lt", "lte", "gt", "gte", "bt", "in"),
    DateTime: ("eq", "ne", "lt", "lte", "gt", "gte", "bt"),
    DateTimeString: ("eq", "ne", "lt", "lte", "gt", "gte", "bt"),
    Integer: ("eq", "ne", "lt", "lte", "gt", "gte", "in"),
    ItemUri: ("eq", "ne", "in"),
    Number: ("eq", "ne", "lt", "lte", "gt", "gte", "in"),
    String: ("eq", "ne", "ct", "ict", "sw", "isw", "ew", "iew", "in"),
    ToMany: ("has",),
    ToOne: ("eq", "ne", "in"),
    Uri: ("eq", "ne", "in"),
}


def filters_for_field_class(field_class, field_filters_dict):
    field_class_filters = ()
    for cls in (field_class,) + field_class.__bases__:  # 字段和其父类
        if cls in field_filters_dict:
            field_class_filters += field_filters_dict[cls]
    return field_class_filters


# 字段集和对应的过滤器表达式得到的过滤器字典
def filters_for_fields(fields, filters_expression, field_filters_dict, filters_name_dict):
    filters = {}
    for field_name, field in fields.items():
        field_filters = {name: filters_name_dict[name] for name in filters_for_field_class(field.__class__, field_filters_dict)}
        if isinstance(filters_expression, dict):
            try:
                field_expression = filters_expression[field_name]
            except KeyError:
                try:
                    field_expression = filters_expression["*"]
                except KeyError:
                    continue
            if isinstance(field_expression, dict):  # 字段名下表达式还是字典
                field_filters = field_expression
            elif isinstance(field_expression, (list, tuple)):  # 如果是名称元组
                field_filters = {name: filter for (name, filter) in field_filters.items() if name in field_expression}
            elif field_expression is not True:
                continue
        elif filters_expression is not True:
            continue
        if field_filters:
            filters[field_name] = field_filters  # 某个字段的所有过滤器名的字典
    return filters


def convert_filters(value, field_filters):
    if isinstance(value, dict) and len(value) == 1:
        filter_name = next(iter(value))
        if len(filter_name) > 1 and filter_name.startswith("$"):
            filter_name = filter_name[1:]
            for filter in field_filters.values():
                if filter_name == filter.name:
                    return filter.convert(value, )
    filter = field_filters["eq"]  # 没有名为None的了
    return filter.convert(value, )


class PaginationMixin:  # 分页插件不能单独使用
    query_params = ()

    @cached_property
    def _pagination_types(self):
        raise NotImplementedError()

    def format_response(self, data):
        if not isinstance(data, self._pagination_types):
            return self.format(data)

        # 这里怎么会用到全局的request
        links = [(request.path, data.page, data.per_page, "self")]
        if data.has_prev:
            links.append((request.path, 1, data.per_page, "first"))
            links.append((request.path, data.page - 1, data.per_page, "prev"))
        if data.has_next:
            links.append((request.path, data.page + 1, data.per_page, "next"))
        links.append((request.path, max(data.pages, 1), data.per_page, "last"))
        headers = {
            "Link": ",".join(['<{0}?page={1}&per_page={2}>; rel="{3}"'.format(*link) for link in links]),
            "X-Total-Count": data.total,
        }
        return self.format(data.items), 200, headers

    def format(self, data):
        pass


class RelationInstances(PaginationMixin, ToMany):
    @cached_property
    def _pagination_types(self):
        return self.container.target.manager.PAGINATION_TYPES


def parse_where_sort_by_args(request):
    where = OrderedDict()
    sort = OrderedDict()
    for key, value in request.args.items():
        if key in ("page", "per_page", "sort"):
            continue
        if "__" in key:
            attr, op = key.rsplit("__", 1)
            if op == "sort":  # attr__sort=1
                sort[attr] = value in ("1", "true", "desc")  # 降序为true
                continue
            if where.get(attr, None) is None:
                where[attr] = {f"${op}": value}
            else:
                where[attr][f"${op}"] = value
        else:
            where[key] = {"$eq": value}
    return sort, where


def parse_where_sort_by_json(request):
    where = json.loads(request.args.get("where", "{}"))
    sort = json.loads(request.args.get("sort", "{}"), object_pairs_hook=OrderedDict)
    for k, v in where.items():
        if not isinstance(v, dict):
            where[k] = {"$eq": v}
    return sort, where


class Instances(PaginationMixin, Schema, ResourceMixin):
    query_params = ("where", "sort")

    def rebind(self, resource):
        return self.__class__().bind(resource)

    @cached_property
    def _pagination_types(self):
        return self.resource.manager.PAGINATION_TYPES

    @staticmethod
    def _field_filters_schema(filters):
        if len(filters) == 1:
            return next(iter(filters.values())).request
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
            "additionalProperties": True,
        }

    @cached_property
    def _sort_schema(self):
        return {
            "type": "object",
            "properties": {
                name: {
                    "type": "boolean",
                    "description": f"Sort by {name} in descending order if 'true', ascending order if 'false'.",
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
            if "." in name:
                # Todo 这里初步实现了联合查询，只支持一个级别的外键，即只有1个.号
                k, v = name.rsplit(".", 1)
                target = self.resource.schema.fields[k].target
                condition = convert_filters(value, target.manager.filters[v])
                expression = target.manager._expression_for_condition(condition)
                yield self.resource.manager._expression_for_join(k, expression)  # 返回表达式
            else:
                yield convert_filters(value, self._filters[name])  # Condition条件实力

    def _convert_sort(self, sort):
        for name, reverse in sort.items():
            field = self._sort_fields[name]
            yield field, field.attribute or name, reverse

    def parse_request(self, request):  # where 和 sort 是json字符串
        page = request.args.get("page", 1, type=int)
        per_page = request.args.get("per_page", current_app.config["RESTONE_DEFAULT_PER_PAGE"], type=int)
        style = current_app.config["RESTONE_DEFAULT_PARSE_STYLE"]  # 新增了可配置的查询风格
        try:
            if style == "json":
                sort, where = parse_where_sort_by_json(request)
            else:
                sort, where = parse_where_sort_by_args(request)
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
        return max(1, self.total // self.per_page + bool(self.total % self.per_page))

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


# 数据管理器，接入数据一端，可以是不同的数据库，只要实现了相同的方法
class Manager:
    base_filter = BaseFilter  # 指定过滤器基类，自动搜刮对应类

    field_filters_dict = FIELD_FILTERS_DICT  # 可能会被重写的放在这里

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
        field_set = resource.schema  # resource的schema决定这边能用的字段
        if meta.include_id:
            field_set.set("$id", self.id_field)
        else:
            field_set.set("$uri", ItemUri(resource, attribute=id_attribute))
        if meta.include_type:
            field_set.set("$type", ItemType(resource))

    def _init_filter(self, filter_class, name, field, attribute):
        return filter_class(field=field, attribute=field.attribute or attribute)

    def _init_filters(self, resource, meta):
        fields = resource.schema.fields
        field_filters = filters_for_fields(
            resource.schema.readable_fields,
            meta.filters,  # meta里面还有 filters= [x,y]指定了哪些字段可以用于过滤
            field_filters_dict=self.field_filters_dict,
            filters_name_dict=self.base_filter.named_filters(),
        )
        self.filters = {
            field_name: {name: self._init_filter(filter, name, fields[field_name], field_name) for (name, filter) in field_filters.items()}
            for (field_name, field_filters) in field_filters.items()
        }
        print(self.filters.keys())

    def _is_sortable_field(self, field):
        return isinstance(field, (String, Boolean, Number, Integer, Date, DateTime, DateString, DateTimeString, Uri, ItemUri))

    def _init_key_converters(self, resource, meta):
        if "natural_key" in meta:
            if isinstance(meta.natural_key, str):
                meta["key_converters"] += (PropertyKey(meta.natural_key),)
            elif isinstance(meta.natural_key, (list, tuple)):
                meta["key_converters"] += (PropertiesKey(*meta.natural_key),)
        if "key_converters" in meta:
            meta.key_converters = [k.bind(resource) for k in meta["key_converters"]]
            meta.key_converters_by_type = {}
            for kc in meta.key_converters:
                if kc.matcher_type() in meta.key_converters_by_type:
                    raise RuntimeError(f"Multiple keys of type {kc.matcher_type()} defined for {meta.name}")
                meta.key_converters_by_type[kc.matcher_type()] = kc

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
            raise RuntimeError(f'No appropriate field class for "{python_type}" type found')

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
        return []

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
        if isinstance(instances, list):  # 这里是方便我们实现别的接口返回list
            return Pagination.from_list(instances, page, per_page)
        return self._query_get_paginated_items(instances, page, per_page)

    def instances(self, where=None, sort=None):
        query = self._query()
        if query is None:
            return []
        if where:
            expressions = [self._expression_for_condition(condition) if isinstance(condition, Condition) else condition for condition in where]
            #####
            print("expre", self._and_expression(expressions))
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


class Key(Schema, ResourceMixin):
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
            "properties": {"$ref": {"type": "string", "pattern": f"^{re.escape(self.resource.route_prefix)}\\/[^/]+$"}},
            "additionalProperties": False,
        }

    @staticmethod
    def _item_uri(resource, item):
        return f"{resource.route_prefix}/{get_value(resource.manager.id_attribute, item, None)}"

    def format(self, item):
        return {"$ref": self._item_uri(self.resource, item)}

    def convert(self, value, **kwargs):
        _, args = route_from(value["$ref"], "GET")
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

    def convert(self, value, **kwargs):
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

    def convert(self, value, **kwargs):
        return self.resource.manager.first(
            where=[Condition(property, self._field_filters[property][None], value[i]) for (i, property) in enumerate(self.properties)]
        )


class IDKey(Key):
    def _on_bind(self, resource):
        self.id_field = resource.manager.id_field

    def schema(self):
        return self.id_field.request

    def format(self, item):
        return self.id_field.output(self.resource.manager.id_attribute, item)

    def convert(self, value, **kwargs):
        return self.resource.manager.read(self.id_field.convert(value, ))

def _(s):
    return s.replace("_", "-")

def camel_case(s):
    return s[0].lower() + s.title().replace("_", "")[1:] if s else s


class RouteSet:
    def routes(self):
        return ()


class Relation(RouteSet, ResourceMixin):  # 关系型也是RouteSet子类
    # 用法 author = Relation("UserResource",backref="book",attribute='author')
    def __init__(self, resource, backref=None, io="rw", attribute=None):
        self.reference = ResourceReference(resource)  # 找到关联的资源类
        self.attribute = attribute  # 属性名
        self.backref = backref  # 反向引用名
        self.io = io

    @cached_property
    def target(self):
        return self.reference.resolve(self.resource)  # 目标类

    def routes(self):
        io = self.io
        rule = f"/{_(self.attribute)}"  # /author
        relation_route = ItemRoute(rule=f"{rule}/<{self.target.meta.id_converter}:target_id>")  # /book/001/author/<sid>
        relations_route = ItemRoute(rule=rule)  # /author
        if "r" in io:

            def relation_instances(resource, item, page, per_page):
                return resource.manager.relation_instances(item, self.attribute, self.target, page, per_page)

            yield relations_route.for_method(
                "GET",
                relation_instances,
                rel=self.attribute,
                response_schema=RelationInstances(self.target),
                schema=FieldSet({"page": Integer(minimum=1, default=1), "per_page": Integer(minimum=1, default=20, maximum=50)}),
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
                rel=camel_case(f"add_{self.attribute}"),
                response_schema=ToOne(self.target),
                schema=ToOne(self.target),
            )

            def relation_remove(resource, item, target_id):
                target_item = self.target.manager.read(target_id)
                resource.manager.relation_remove(item, self.attribute, self.target, target_item)
                resource.manager.commit()
                return None, 204

            yield relation_route.for_method("DELETE", relation_remove, rel=camel_case(f"remove_{self.attribute}"))


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
    if parsed_url.netloc not in ("", url_adapter.server_name):
        raise PageNotFound()
    return url_adapter.match(parsed_url.path, method)


def unpack(value):
    if not isinstance(value, tuple):
        return value, 200, {}
    if len(value) == 2:
        return *value, {}
    if len(value) == 3:
        return value
    return value, 200, {}


def get_value(key, obj, default=None):
    if hasattr(obj, "__getitem__"):
        try:
            return obj[key]
        except (IndexError, TypeError, KeyError):
            pass
    # ...联合查询
    if "." in key:
        keys = key.split(".")
        for k in keys:
            obj = get_value(k, obj)
        return obj

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
        if isinstance(annotations, dict) and annotations:
            self.request_schema = FieldSet({name: field for (name, field) in annotations.items() if name != "return"})  # 请求的语法就是参数名和参数字段类型的字段集，响应也有字段
            self.response_schema = annotations.get("return", response_schema)
        else:  # 没有标注则要指定参数
            self.request_schema = schema
            self.response_schema = response_schema
        self._related_routes = ()  # 相关的路由
        for method in HTTP_METHODS:
            setattr(self, method, MethodType(_method_decorator(method), self))  # 把方法绑定到类的实例中
            setattr(self, method.lower(), getattr(self, method))  # 忽略大小写GET成为装饰器

    @property
    def relation(self):  # 关系型数据资源
        if self.rel:
            return self.rel  # 关联字符串 read_status?

        verb = HTTP_VERBS.get(self.method, self.method.lower())
        return camel_case(f"{verb}_{self.attribute}")

    def schema_factory(self, resource):  # 规则工厂 将路由的请求与响应规则绑定到资源上
        request_schema = _bind_schema(self.request_schema, resource)
        response_schema = _bind_schema(self.response_schema, resource)
        schema = OrderedDict(
            [
                ("rel", self.relation),
                ("href", re.sub("<(\\w+:)?([^>]+)>", "{\\2}",self.rule_factory(resource, relative=False))),
                ("method", self.method),
            ]  # 关联
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

    def for_method(self, method, view_func, rel=None, title=None, description=None, schema=None, response_schema=None, **kwargs):
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
            **kwargs,
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
        return f"{self.__class__.__name__}({repr(self.rule)})"

    @property
    def request_schema(self):
        return self.schema  # 先调用了setter方法所以存在

    @request_schema.setter
    def request_schema(self, schema):
        self.schema = schema

    def rule_factory(self, resource, relative=False):  # 规则工厂
        rule = self.rule  # 规则是个字符串
        if rule is None:
            rule = f"/{_(self.attribute)}"
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
            return response_schema.format_response(response)  # 格式化

        return view


for method in HTTP_METHODS:
    setattr(Route, method, _route_decorator(method))
    setattr(Route, method.lower(), getattr(Route, method))


class ItemRoute(Route):  # 单个记录
    def rule_factory(self, resource, relative=False):
        rule = self.rule
        id_matcher = f"<{resource.meta.id_converter}:id>"
        if rule is None:
            rule = f"/{_(self.attribute)}"
        elif callable(rule):
            rule = rule(resource)
        if relative or resource.route_prefix is None:
            return rule[1:]
        return "".join((resource.route_prefix, "/", id_matcher, rule))

    def view_factory(self, name, resource):
        original_view = super().view_factory(name, resource)

        def view(*args, **kwargs):
            id = kwargs.pop("id")  # 可以不pop 用于过滤id
            item = resource.manager.read(id)
            return original_view(item, *args, **kwargs)

        return view


def _field_from_object(parent, schema_cls_or_obj):  # 从对象获取字段
    if isinstance(schema_cls_or_obj, type):
        container = schema_cls_or_obj()  # 类的实例
    else:
        container = schema_cls_or_obj  # 实例
    if not isinstance(container, Schema):  # 实例不是格式类
        raise RuntimeError(f"{parent} expected Raw or Schema, but got {container.__class__.__name__}")
    if not isinstance(container, BaseField):  # 实例不是Raw类是Schema类
        container = BaseField(container)  # 用Raw类包裹
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
                if hasattr(resource, f"before_read_{attribute}"):  # 直接调用source的钩子
                    getattr(resource, f"before_read_{attribute}")(item)  # 也可以直接改为信号发射

                resp = get_value(attribute, item, field.default)

                if hasattr(resource, f"after_read_{attribute}"):  # 直接调用source的钩子
                    getattr(resource, f"after_read_{attribute}")(item)

                return resp

            yield route.for_method(
                "GET",
                read_attribute,
                response_schema=field,
                rel=camel_case(f"read_{route.attribute}"),
                # readDescription
            )
        if "u" in io:  # 更新属性的路由

            def update_attribute(resource, item, value):  # 直接post一个string即可
                if hasattr(resource, f"before_update_{attribute}"):  # 直接调用source的钩子
                    getattr(resource, f"before_update_{attribute}")(item, value)  # 也可以直接改为信号发射

                item = resource.manager.update(item, {attribute: value})

                if hasattr(resource, f"after_update_{attribute}"):  # 直接调用source的钩子
                    getattr(resource, f"after_update_{attribute}")(item, value)  # 也可以直接改为信号发射

                return get_value(attribute, item, field.default)

            yield route.for_method(
                "POST",
                update_attribute,
                schema=field,
                response_schema=field,
                rel=camel_case(f"update_{route.attribute}"),
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
            raise RuntimeError(f'Resource named "{name}" is not registered with the Api it is bound to.')
        raise RuntimeError(f'Resource named "{name}" cannot be found; the reference is not bound to an Api.')

    def __repr__(self):
        return f"<ResourceReference '{self.value}'>"


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
        schema = {}
        if "Meta" in members:
            changes = members["Meta"].__dict__
            for k, v in changes.items():
                if not k.startswith("__"):
                    meta[k] = v
            # 20日新增功能，指定默认日期
            model = meta.get("model", None)
            datetime_field_class = meta.get("datetime_formater")
            if model and datetime_field_class:
                for k, field in model.__dict__.items():
                    if not k.startswith("__") and hasattr(field, "type"):
                        if str(field.type) == "DATETIME":
                            schema[k] = datetime_field_class(io="r")

            if not changes.get("name", None):
                meta["name"] = name.lower()
        else:
            meta["name"] = name.lower()

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
            if isinstance(m, ResourceMixin):
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
        links = [route for (name, route) in sorted(self.routes.items())]  # name,Route
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


# todo ：设计一个以pandas为后端的资源，和资源管理器


# 模型资源是专门为数据库orm设计的资源
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
        # 新增 如果是内联的字典且其field 是inline 则创建先创建之
        props = {}
        inlines = []

        for k, v in properties.items():
            field = self.schema.fields[k]
            if isinstance(field, Inline):
                inst = field.target.manager.create(v, commit=False)  # 使用目标字段的create方法，这样即使还有内联也可以直接创建
                props[f"{k}_id"] = inst.id
                inlines.append(field.target.manager)
            else:
                props[k] = v
        # 全部能创建成功才能打包提交
        item = self.manager.create(props, commit=False)
        self.manager.commit()
        for manager in inlines:
            manager.commit()

        return item

    create.request_schema = create.response_schema = Inline("self")

    @Route.GET(lambda r: f"/<{r.meta.id_converter}:id>", rel="self", attribute="instance")
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
        permissions = {"read": "anyone", "create": "nobody", "update": "create", "delete": "update"}
        postgres_text_search_fields = ()
        postgres_full_text_index = None
        cache = False  # 缓存
        key_converters = (RefKey(), IDKey())
        datetime_formater = DateTimeString
        natural_key = None


def schema_to_swag_dict(schema, tags=None):
    rel = schema.get("rel")
    parameters = []
    if rel in ("self", "destroy") or rel.startswith("read"):
        parameters = [{"name": "id", "type": "string", "in": "path", "required": True, "description": "the data source's uuid"}]

    elif rel.startswith("update"):
        parameters = [
            {"name": "id", "type": "string", "in": "path", "required": True, "description": "the data source's uuid"},
            {"name": "Item", "in": "body", "schema": schema.get("schema", {})},
        ]
    elif rel == "instances":
        parameters = []  # 查询的字段在参数里
    elif rel == "create":
        parameters = [{"name": "Item", "in": "body", "schema": schema.get("schema", {})}]
    else:
        parameters = []

    dct = {
        "tags": tags,
        "parameters": parameters,
        "responses": {"200": {"description": "正常返回", "examples": {"result": "success"}}},
    }
    return dct


class Api:
    def __init__(self, app=None, decorators=None, prefix=None, title=None, description=None, default_manager=None):
        self.app = app
        self.blueprint = None
        self.prefix = prefix or ""
        self.decorators = decorators or []
        self.title = title
        self.description = description
        self.endpoints = set()
        self.resources = {}
        self.views = []
        self.default_manager = default_manager or SQLAlchemyManager
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
        app.config.setdefault("RESTONE_DEFAULT_PARSE_STYLE", "json")
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
            self._register_swag_view(app, route, resource, view_func)
            self._register_view(app, rule, view_func, endpoint, methods, relation)
        app.handle_exception = partial(self._exception_handler, app.handle_exception)
        app.handle_user_exception = partial(self._exception_handler, app.handle_user_exception)

    @staticmethod
    def _register_swag_view(app, route, resource, view_func):
        """注册到swager"""
        with app.app_context():
            schema = route.schema_factory(resource)
            tags = [resource.meta.title or resource.meta.name]
            if schema["rel"] != "describedBy":
                swag_from(schema_to_swag_dict(schema, tags))(view_func)

    def _register_view(self, app, rule, view_func, endpoint, methods, relation):
        decorate_view_func = relation != "describedBy" or app.config["RESTONE_DECORATE_SCHEMA_ENDPOINTS"]
        if self.blueprint:
            endpoint = f"{self.blueprint.name}.{endpoint}"
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
        for name, resource in sorted(self.resources.items(), key=itemgetter(0)):
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
        # print(rule, view_func, endpoint, methods, route.relation)
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
                    f"'{resource.meta.name}' has no manager, and no default manager has been defined. If you're using Restone with SQLAlchemy, ensure you have installed Flask-SQLAlchemy."
                )
        resource.api = self
        resource.route_prefix = "".join((self.prefix, "/", resource.meta.name))
        for route in resource.routes.values():
            route_decorator = resource.meta.route_decorators.get(route.relation, None)
            # route.relation 是字符 如"read_xxx" 则是 装饰器字典，用于装饰这个函数
            # todo 此处介入swag_from

            self.add_route(route, resource, decorator=route_decorator)
        # 以键值对返回成员 返回满足 lambda m: isinstance(m, RouteSet) 的成员，也就是 RouteSet及子类的实例
        for name, rset in inspect.getmembers(resource, lambda m: isinstance(m, RouteSet)):
            if rset.attribute is None:
                rset.attribute = name
                # 没有属性就用自己名字做属性 如
                # status = ItemAttributeRoute(field_cls_or_instance,io='ru')
            for i, route in enumerate(rset.routes()):
                if route.attribute is None:
                    route.attribute = f"{rset.attribute}_{i}"
                resource.routes[f"{rset.attribute}_{route.relation}"] = route
                # status_readStatus #todo 改变格式
                # _decorator = getattr(resource, route.relation, None) #同样的装饰 todo improvment
                # 把装饰放到 resource 下面
                # if callable()
                self.add_route(route, resource)  # ,decorator=_decorator)
        self.resources[resource.meta.name] = resource


# 使用的时候
class InlineModel(Object):
    def __init__(self, properties, model, **kwargs):
        super().__init__(properties, **kwargs)
        self.model = model

    def converter(self, instance):
        instance = super().converter(instance)
        if instance is not None:
            instance = self.model(**instance)
        return instance


class SQLAlchemyBaseFilter(BaseFilter):
    namespace = "sql"

    def __init__(self, field=None, attribute=None, column=None):
        super().__init__(field=field, attribute=attribute)
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


class SQLAlchemyManager(RelationalManager):
    base_filter = SQLAlchemyBaseFilter
    PAGINATION_TYPES = (Pagination, SAPagination)

    def __init__(self, resource, model):
        super().__init__(resource, model)

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
            if (include_fields and name in include_fields) or (exclude_fields and name not in exclude_fields) or not (include_fields or exclude_fields):
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
            field_class = BaseField
            kwargs = {"schema": {}}
        else:
            try:
                python_type = column.type.python_type
            except NotImplementedError:
                raise RuntimeError(f"Unable to auto-detect the correct field type for {column}! You need to specify it manually in ModelResource.Schema")
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
            field=field,
            attribute=field.attribute or attribute,
            column=getattr(self.model, field.attribute or attribute),
        )

    def _is_sortable_field(self, field):
        if super()._is_sortable_field(field):
            return True
        if isinstance(field, ToOne):
            return isinstance(field.target.manager, SQLAlchemyManager)
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

    #  _expression_for_join('service',)
    def _expression_for_join(self, attribute, expression):
        relationship = getattr(self.model, attribute)
        if isinstance(relationship.impl, ScalarObjectAttributeImpl):
            return relationship.has(expression)
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
            if current_app.debug:
                raise BackendConflict(debug_info=dict(exception_message=str(e), statement=e.statement, params=e.params))
            raise BackendConflict()

        after_create.send(self.resource, item=item)
        return item

    def update(self, item, changes, commit=True):
        session = self._get_session()

        actual_changes = {key: value for key, value in changes.items() if self._is_change(get_value(key, item, None), value)}

        try:
            before_update.send(self.resource, item=item, changes=actual_changes)

            for key, value in changes.items():
                setattr(item, key, value)

            self.commit_or_flush(commit)
        except IntegrityError as e:
            session.rollback()
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


# ----------------------permissions----------------------------------
class HybridNeed:  # 混合需求
    def __call__(self, item):
        raise NotImplementedError()

    def __hash__(self):
        return hash(self.__repr__())

    def identity_get_item_needs(self):
        return None


class HybridItemNeed(HybridNeed):  # HyHridItemNeed("creat","user") 创建用户的权限
    def __init__(self, method, resource, type_=None):
        self.method = method
        self.type = type_ or resource.meta.name
        self.resource = resource  # todo 改成引用
        self.fields = []

    def identity_get_item_needs(self):
        if self.method == "id":
            prototype = ("id", None)
        else:
            prototype = (self.method, None, self.type)

        for need in g.identity.provides:
            if len(need) == len(prototype):
                if all(p is None or n == p for n, p in zip(need, prototype)):
                    yield need[1]

    def extend(self, field):
        return HybridRelationshipNeed(self.method, field)

    def __call__(self, item):
        if self.method == "id":
            return UserNeed(get_value(item, self.resource.manager.id_attribute, None))
        return ItemNeed(self.method, get_value(item, self.resource.manager.id_attribute, None), self.type)

    def __eq__(self, other):
        return isinstance(other, HybridItemNeed) and self.method == other.method and self.type == other.type and self.resource == other.resource

    def __hash__(self):
        return hash(self.__repr__())

    def __repr__(self):
        return f"<HybridItemNeed method='{self.method}' type='{self.type}'>"


class HybridRelationshipNeed(HybridItemNeed):
    def __init__(self, method, *fields):
        super().__init__(method, fields[-1].resource, fields[-1].target.meta.name)
        self.fields = fields
        self.final_field = self.fields[-1]

    def __call__(self, item):
        for field in self.fields:
            item = get_value(item, field.attribute)

            if item is None:
                if self.method == "id":
                    return UserNeed(None)
                return ItemNeed(self.method, None, self.type)

        item_id = get_value(item, self.final_field.resource.manager.id_attribute, None)

        if self.method == "id":
            return UserNeed(item_id)
        return ItemNeed(self.method, item_id, self.type)

    def __eq__(self, other):
        return isinstance(other, HybridItemNeed) and self.method == other.method and self.resource == other.resource and self.fields == other.fields

    def extend(self, field):
        return HybridRelationshipNeed(self.method, field, *self.fields)

    def __hash__(self):
        return hash((self.method, self.type, self.fields))

    def __repr__(self):
        return f"<HybridRelationshipNeed method='{self.method}' type='{self.type}' {self.fields}>"


class HybridUserNeed(HybridRelationshipNeed):
    def __init__(self, field):
        super().__init__("id", field)

    def __repr__(self):
        return f"<HybridUserNeed {self.type} {self.fields}>"


class HybridPermission(Permission):
    def __init__(self, *needs):
        super().__init__(*needs)
        self.hybrid_needs = set()
        self.standard_needs = set()

        for need in needs:
            if isinstance(need, HybridNeed):
                self.hybrid_needs.add(need)
            else:
                self.standard_needs.add(need)

    def allows(self, identity):
        if self.standard_needs and not self.standard_needs.intersection(identity.provides):
            return False
        # 检查权限就是判断所需权限和当前用户的权限有没有交集，没有交集就没有权限
        if self.excludes and self.excludes.intersection(identity.provides):
            return False
        # 不包括的权限和用户权限有交集，也没权限
        if self.needs and not self.standard_needs:
            return False

        return True

    def can(self, item=None):
        if not item:
            return self.require().can()
        if self.require().can():
            return True
        for need in self.hybrid_needs:
            resolved_need = need(item)  # hybrid_need 可以调用item
            if resolved_need in g.identity.provides:
                return True
        return False


class PrincipalMixin:  # 鉴权插件
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        raw_needs = dict(PERMISSION_DEFAULTS)
        raw_needs.update(self.resource.meta.get("permissions", {}))
        self._raw_needs = raw_needs  # 粗的权限字典

    @cached_property
    def _needs(self):
        needs_map = self._raw_needs.copy()
        methods = needs_map.keys()  # 资源的权限只有四个词curd

        def convert(method, needs, map, path=()):
            options = set()  # 权限集合 Permission obj

            if isinstance(needs, str):  # 权限字符
                needs = [needs]  # 原来的needs可能是字符串和tuple
            if isinstance(needs, set):  # 权限集合直接返回
                return needs

            for need in needs:
                if need in PERMISSION_GRANTED_STRINGS:  # 全权
                    return {True}
                if need in PERMISSION_DENIED_STRINGS:  # 无权
                    options.add(Permission(("permission-denied",)))
                elif need in methods:  # 如果权限也是 curd 词
                    if need in path:
                        raise RuntimeError(f"Circular permissions in {self.resource} (path: {path})")
                    if need == method:  # 和自身相同
                        options.add(HybridItemNeed(method, self.resource))
                    else:
                        path += (method,)  # 用过的方法不可再用
                        options |= convert(need, map[need], map, path)  # 递归

                elif ":" in need:
                    role, value = need.split(":")
                    field = self.resource.schema.fields[value]
                    # shema中的字段
                    if field.attribute is None:
                        field.attribute = value
                    # {"creat":"role:user"}
                    # TODO implement this for ToMany as well as ToOne
                    if isinstance(field, ToOne):  # 一对一的
                        target = field.target  # 目标

                        if role == "user":  # user:attr
                            options.add(HybridUserNeed(field))  # 盲猜需要user的field字段为true
                        elif role == "role":  # role:xxx
                            options.add(RoleNeed(value))  # 需要用户的角色为xxx
                        else:  # 既不是user又不是role会是啥
                            for imported_need in target.manager._needs[role]:  # 目标的_needmaps取
                                if isinstance(imported_need, HybridItemNeed):
                                    imported_need = imported_need.extend(field)  # 目标集合增加当前字段
                                options.add(imported_need)

                    elif role == "user" and value in ["$id", "$uri"]:  # user:$id
                        options.add(HybridItemNeed("id", self.resource))  # HybridItemNeed 需要id与当前用户id相同
                else:
                    options.add(RoleNeed(need))  # 角色

            return options

        for method, needs in needs_map.items():
            converted_needs = convert(method, needs, needs_map)
            needs_map[method] = converted_needs

        # TODO exclude routes for impossible permissions

        return needs_map

    @cached_property
    def _permissions(self):
        permissions = {}

        for method, needs in self._needs.items():
            if True in needs:
                needs = set()
            permissions[method] = HybridPermission(*needs)

        return permissions

    def get_permissions_for_item(self, item):  # 获取某个对象的权限这个权限可以用在这个方法操作当前item
        return {operation: permission.can(item) for operation, permission in self._permissions.items()}

    def _query_filter_read_permission(self, query):
        read_permission = self._permissions["read"]
        return self._query_filter_permission(query, read_permission)

    def _query_filter_permission(self, query, permission):
        if permission.can():
            return query

        # filters must not be applied if not present:
        if not permission.hybrid_needs:
            return None

        expressions = []

        for need in permission.hybrid_needs:
            ids = list(need.identity_get_item_needs())

            if not ids:
                continue

            if len(need.fields) == 0:
                expression = self._expression_for_ids(ids)
            else:
                expression = need.fields[-1].target.manager._expression_for_ids(ids)

                for field in reversed(need.fields):
                    expression = field.resource.manager._expression_for_join(field.attribute, expression)

            expressions.append(expression)

        if not expressions:
            return None

        return self._query_filter(query, self._or_expression(expressions))

    def _query(self, **kwargs):
        query = super()._query(**kwargs)

        read_permission = self._permissions["read"]
        query = self._query_filter_permission(query, read_permission)

        if query is None and all(need.method == "role" for need in read_permission.needs):
            raise Forbidden()

        return query

    def relation_instances(self, item, attribute, target_resource, page=None, per_page=None):
        query = getattr(item, attribute)

        if isinstance(query, InstrumentedList):
            if page and per_page:
                return Pagination.from_list(query, page, per_page)
            return query

        target_manager = target_resource.manager
        if isinstance(target_manager, PrincipalMixin):
            query = target_manager._query_filter_read_permission(query)

        if page and per_page:
            return target_manager._query_get_paginated_items(query, page, per_page)

        return target_manager._query_get_all(query)

    def create(self, properties, commit=True):
        if self._permissions["create"].can(properties):
            return super().create(properties, commit)
        raise Forbidden()

    def update(self, item, changes, *args, **kwargs):
        if self._permissions["update"].can(item):
            return super().update(item, changes, *args, **kwargs)
        raise Forbidden()

    def delete(self, item):
        if self._permissions["delete"].can(item):
            return super().delete(item)
        raise Forbidden()


def principals(manager):
    if not issubclass(manager, RelationalManager):
        raise RuntimeError("principals() only works with managers that inherit from RelationalManager")

    class PrincipalsManager(PrincipalMixin, manager):
        pass

    return PrincipalsManager
