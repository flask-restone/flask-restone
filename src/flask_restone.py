# restone makes you the rest one
# 尽最大可能节约代码行数

import ast
import decimal
import inspect
import random
import re
from abc import ABC, abstractmethod
from collections import OrderedDict
from datetime import date, datetime, timezone
from functools import partial, wraps
from importlib import import_module
from operator import attrgetter, itemgetter
from types import MethodType
from urllib.parse import urlsplit

import exrex
from blinker import Namespace
from faker import Faker
from flasgger import swag_from
from flask import current_app, g, json, jsonify, make_response, request, url_for
from flask.globals import app_ctx, request_ctx
from flask_principal import ItemNeed, Permission, RoleNeed, UserNeed
from flask_sqlalchemy.pagination import Pagination as _Pagination
from jsonschema import (
    Draft4Validator,
    FormatChecker,
    ValidationError as _ValidationError,
)
from sqlalchemy import String, and_, or_
from sqlalchemy.dialects import postgresql
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import aliased, class_mapper
from sqlalchemy.orm.attributes import ScalarObjectAttributeImpl
from sqlalchemy.orm.collections import InstrumentedList  # noqa
from sqlalchemy.orm.exc import NoResultFound
from werkzeug.exceptions import HTTPException
from werkzeug.http import HTTP_STATUS_CODES
from werkzeug.utils import cached_property
from werkzeug.wrappers import Response

# ----------------------------------------通用常量-------------------------------


HTTP_METHODS = (GET, PUT, POST, PATCH, DELETE, HEAD) = ("GET", "PUT", "POST", "PATCH", "DELETE", "HEAD")

PAGE = "page"
PER_PAGE = "per_page"
DEFAULT_PER_PAGE = 20
MAX_PER_PAGE = 100
# ----------------------------------------内置信号-------------------------------

_signals = Namespace()
before_create = _signals.signal("before-create")
after_create = _signals.signal("after-create")
before_update = _signals.signal("before-update")
after_update = _signals.signal("after-update")
before_delete = _signals.signal("before-delete")
after_delete = _signals.signal("after-delete")
before_relate = _signals.signal("before-relate")
after_relate = _signals.signal("after-relate")
before_remove = _signals.signal("before-remove")
after_remove = _signals.signal("after-remove")


# ----------------------------------------异常处理-------------------------------
class RestoneException(Exception):
    status_code = 500

    def as_dict(self):
        if self.args:
            message = str(self)
        else:
            message = HTTP_STATUS_CODES.get(self.status_code, "")
        return dict(status=self.status_code, message=message)

    def get_response(self):
        response = jsonify(self.as_dict())
        response.status_code = self.status_code
        return response


class ItemNotFound(RestoneException):
    status_code = 404

    def __init__(self, resource, where=None, id=None):  # noqa
        self.resource = resource
        self.id = id
        self.where = where

    def as_dict(self):
        dct = super().as_dict()
        if self.id is not None:
            dct["item"] = {"$type": self.resource.meta.name, "$id": self.id}
        else:
            dct["item"] = {
                "$type": self.resource.meta.name,
                "$where": self.where,
            }
        return dct


class RequestMustBeJSON(RestoneException):
    status_code = 415


class ValidationError(RestoneException):
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
            error_data = {
                "validationOf": {error.validator: error.validator_value},
                "path": self._complete_path(error),
            }
            if current_app.debug:
                error_data["message"] = error.message
            yield error_data

    def as_dict(self):
        dct = super().as_dict()
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
        dct = super().as_dict()
        dct.update(self.data)
        return dct


class PageNotFound(RestoneException):
    status_code = 404


class InvalidJSON(RestoneException):
    status_code = 400


class InvalidFilter(RestoneException):
    status_code = 400


class InvalidUrl(RestoneException):
    status_code = 400


class OperationNotAllowed(RestoneException):
    status_code = 405


class Forbidden(RestoneException):
    status_code = 403


# JSON _Schema，也称为JSON模式。JSON Schema是描述你的JSON数据格式；
# 主要有以下作用：
# 对现有的json数据格式进行描述（字段类型、内容长度、是否必须存在、取值示例等）；
# 是一个描述清晰、人机可读的文档；
# 自动测试、验证客户端提交的数据；


# ---------------------------请求与响应格式化-------------------------------------
class _Schema(ABC):
    """
    _Schema 描述JSON数据格式

    schema 返回二元组或三元组
    二元组
        response 响应体模式
        request 请求体模式
    三元组
        (response,create,update)
    format 用当前模式对 item 进行响应体格式化
    convert 用当前模式对请求体数据转换

    """

    # schema 就是规则格式，子类需实现 schema 语法和 format 格式化方法
    @abstractmethod
    def schema(self):
        pass  # 二元组就是 rsp,rqs

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
        except _ValidationError:
            errors = validator.iter_errors(instance)  # 否则抛出验证错误
            raise ValidationError(errors)
        return instance

    def parse_request(self, request):  # noqa 解析请求并校验
        data = request.json
        if not data and request.method in (GET, HEAD):
            data = dict(request.args)
        return self.convert(data, update=request.method in (PUT, PATCH))

    def format_response(self, response):  # 解包响应并格式化json-data
        data, code, headers = _unpack(response)
        return self.format(data), code, headers


# ----------------------------------------字段格式-------------------------------
class Field(_Schema):
    """
    基本字段模式
    属性：
        schema 本字段的请求模式和响应模式
        io 本字段的可读写性 r 只读 w 只写
        default 默认值 或 默认调用方法
        attribute 属性名
        nullable 可否为空
        title 标题
        description 字段描述
    基本上和 ORM 的模型字段参数一样

    JSON Schema的一般格式包括以下几个部分：
    $schema：指定所使用的JSON Schema版本，
    例如："$schema": "http://json-schema.org/draft-07/schema#"
    type：指定所描述的数据结构的类型，可以是object、array、number、string、integer、boolean、null等
    title：指定所描述的数据结构的名称
    description：对所描述的数据结构进行详细描述
    properties：指定对象类型的属性及其约束条件，是一个键值对，其中键是属性名，值是约束条件，
    例如："properties": {"name": {"type": "string"}, "age": {"type": "integer", "minimum": 0}}
    items：指定数组类型的元素及其约束条件，可以是单个元素的约束条件，也可以是元素类型的约束条件，
    例如："items": {"type": "string"}或"items": [{"type": "string"}, {"type": "integer"}]}
    required：指定对象类型的必选属性，是一个数组，例如："required": ["name", "age"]
    additionalProperties：指定对象类型的其他属性的约束条件，如果不允许任何其他属性，可以将其设置为false，
    例如："additionalProperties": false
    minimum、maximum、exclusiveMinimum、exclusiveMaximum：指定数值类型的最小值、最大值及其开闭区间，
    例如："minimum": 0, "maximum": 100, "exclusiveMaximum": true
    minLength、maxLength、pattern：指定字符串类型的长度和格式约束条件，
    例如："minLength": 3, "maxLength": 10, "pattern": "^[a-z]+$"
    enum：指定枚举类型的取值范围，例如："enum": ["male", "female"]
    format：指定字符串类型的格式约束条件，例如："format": "email"
    $ref：引用其他JSON Schema定义的约束条件，例如："$ref": "http://json-schema.org/draft-07/schema#"
    """

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
        self._schema = schema  # 字段格式
        self._default = default  # 字段默认
        self.attribute = attribute  # 名称
        self.nullable = nullable  # 可为空
        self.title = title  # 标题
        self.description = description  # 描述,可以用中文
        self.io = io  # 读写

    def __class_getitem__(cls, item):
        if isinstance(item, tuple):
            return cls(*item)
        return cls(item)

    def _finalize_schema(self, schema, io):  # 单个字典
        schema = dict(schema)
        if self.io == "r" and "r" in io:
            schema["readOnly"] = True
        if "null" in schema.get("type", []):  # type 就是类型
            self.nullable = True
        elif self.nullable:
            if "enum" in schema and None not in schema["enum"]:
                schema["enum"].append(None)  # noqa 可以为空且枚举列表里没null
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
                    current_app.logger.warning(f'{self} is nullable but "null" type cannot be added')
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
        if isinstance(schema, _Schema):
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
        key = self.attribute or key
        return self.format(_getattr(obj, key, self.default))

    def faker(self):
        """假数据生成，用于测试"""
        return f"{self.attribute}"


_faker = Faker()  # todo it's heavy and to be replace


class Str(Field):
    """
    JSON Schema的string类型的format包括：

    date-time：日期时间格式，如：2018-11-13T20:20:39+00:00
    date：日期格式，如：2018-11-13
    time：时间格式，如：20:20:39+00:00
    email：电子邮件地址格式，如：user@example.com
    idn-email：国际化电子邮件地址格式，如：user@示例.公司
    hostname：主机名格式，如：example.com
    idn-hostname：国际化主机名格式，如：示例.公司
    ipv4：IPv4地址格式，如：192.0.2.1
    ipv6：IPv6地址格式，如：2001:0db8:85a3:0000:0000:8a2e:0370:7334
    uri：URI格式，如：https://example.com/path/to/resource
    uri-reference：URI引用格式，如：/path/to/resource
    uri-template：URI模板格式，如：/path/{id}
    json-pointer：JSON指针格式，如：/path/to/property
    relative-json-pointer：相对JSON指针格式，如：2/property
    regex：正则表达式格式，如：^[a-z]+$
    uuid：UUID格式，如：123e4567-e89b-12d3-a456-426655440000
    """

    url_rule_converter = "string"

    def __init__(
        self,
        min_length=None,
        max_length=None,
        pattern=None,
        enum=None,
        format=None,  # noqa
        **kwargs,
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
        super().__init__(schema, **kwargs)

    def faker(self):
        enum = self.response.get("enum", None)
        if enum:
            return random.choice(enum)

        pattern = self.response.get("pattern", None)
        if pattern:
            return exrex.getone(pattern)

        fmt = self.response.get("format", None)
        if fmt and hasattr(_faker, fmt):
            return getattr(_faker, fmt)()
        elif fmt == "uuid":
            return _faker.uuid4()
        default = self.response.get("default", None)
        if default is not None:
            return default
        min_length = self.response.get("minLength", 6)
        max_length = self.response.get("maxLength", 6)
        return "x" * random.randint(min_length, max_length)

    def __class_getitem__(cls, item):
        # Str[1:5]
        if isinstance(item, slice):
            return cls(item.start, item.stop)
        # Str["\d+","default"]
        # Str["a","b","c"]
        # Str["uuid"]
        # str[20]
        if isinstance(item, int) and item >= 0:
            return cls(item, item)
        # Str["^default$"]
        if isinstance(item, str):
            if item.startswith("^") and item.endswith("$"):
                return cls(pattern=item)
            elif "|" in item:
                return cls(enum=item.split("|"))
            elif item.startswith("%") and item.endswith("%"):  # Str["%uuid%"]
                return cls(format=item[1:-1])
            return cls(default=item)

        if isinstance(item, tuple) and len(item) == 2:
            # Str[1:5,"app"]
            if isinstance(item[0], slice) and isinstance(item[1], str):
                return cls(item[0].start, item[0].stop, default=item[1])
            # Str[3,"app"]
            if isinstance(item[0], int) and isinstance(item[1], str):
                return cls(item[0], item[0], default=item[1])

        raise KeyError(f"Key {item} not Support")


class Int(Field):
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

    def faker(self):
        minimum = self.response.get("minimum", 1)
        maximum = self.response.get("maximum", 100)
        return random.randint(minimum, maximum)

    def __class_getitem__(cls, item):
        # int[0:5]
        if isinstance(item, slice):
            return cls(item.start, item.stop)
        # int[0:9,0]
        if isinstance(item, tuple) and len(item) == 2:
            if isinstance(item[0], slice) and isinstance(item[1], int):
                return cls(item[0].start, item[0].stop, default=item[1])
        # int[0]
        if isinstance(item, int):
            return cls(default=item)
        raise KeyError(f"Key {item} not Support")


class Float(Field):
    def __init__(
        self,
        minimum=None,
        maximum=None,
        exclusive_minimum=False,
        exclusive_maximum=False,
        **kwargs,
    ):
        schema = {"type": "number"}
        if minimum is not None:
            schema["minimum"] = minimum
            if exclusive_minimum:
                schema["exclusiveMinimum"] = True
        if maximum is not None:
            schema["maximum"] = maximum
            if exclusive_maximum:
                schema["exclusiveMaximum"] = True
        self.minimum = minimum
        self.maximum = maximum
        self.exclusive_minimum = exclusive_minimum
        self.exclusive_maximum = exclusive_maximum
        self.kwargs = kwargs
        super().__init__(schema, **kwargs)

    def formatter(self, value):
        return float(value)

    def faker(self):
        minimum = self.minimum or 0
        maximum = self.maximum if self.maximum is not None else 1
        epsilon = 1e-6  # 设置一个极小的正数 epsilon
        if self.exclusive_minimum:
            minimum += epsilon
        if self.exclusive_maximum:
            maximum -= epsilon
        return round(random.uniform(minimum, maximum), 2)

    def __class_getitem__(cls, item):
        if isinstance(item, (int, float)):
            return cls(default=item)

        if isinstance(item, Float):  # 增加对于 Float[1<x<2]等格式的支持,copy操作
            class_ = cls(
                item.minimum,
                item.maximum,
                item.exclusive_minimum,
                item.exclusive_maximum,
            )
            item.minimum = None  # copy 新类,旧的重置
            item.maximum = None
            item.exclusive_minimum = False
            item.exclusive_maximum = False
            return class_
        raise KeyError(f"Key {item} not Support")

    def __le__(self, n):
        self.maximum = n
        self.exclusive_maximum = False
        return self

    def __lt__(self, n):
        self.maximum = n
        self.exclusive_maximum = True
        return self

    def __ge__(self, n):
        self.minimum = n
        self.exclusive_minimum = False
        return self

    def __gt__(self, n):
        self.minimum = n
        self.exclusive_minimum = True
        return self


x = Float()  # 这是一个占位符 ,用于支持 Float[1<x<2] 语法


class Bool(Field):
    def __init__(self, **kwargs):
        super().__init__({"type": "boolean"}, **kwargs)

    def format(self, value):
        return bool(value)

    def faker(self):
        return random.choice([True, False])

    def __class_getitem__(cls, item):
        return cls(default=bool(item))


class Date(Field):
    TYPE_MAPPING = {
        "string": {"type": "string", "format": "date"},
        "integer": {"type": "integer"},
        "object": {
            "type": "object",
            "properties": {"$date": {"type": "integer"}},
            "additionalProperties": False,
        },
    }

    def __init__(self, type="string", **kwargs):  # noqa
        self.type = type
        schema = self.TYPE_MAPPING.get(type)
        if not schema:
            raise ValueError(f"Invalid type '{type}'")
        super().__init__(schema, **kwargs)

    def formatter(self, value):
        _formatter = {
            "string": lambda v: v.isoformat(),
            "integer": lambda v: int(v.timestamp() / 86400),
            "object": lambda v: {"$date": int(v.timestamp() / 86400)},
        }.get(self.type)
        return _formatter(value)

    def converter(self, value):
        _converter = {
            "string": lambda v: datetime.strptime(v, "%Y-%m-%d").date(),
            "integer": lambda v: date.fromtimestamp(v * 86400),
            "object": lambda v: date.fromtimestamp(v["$date"] * 86400),
        }.get(self.type)
        return _converter(value)

    def faker(self):
        return datetime.utcnow()


class DateTime(Date):
    TYPE_MAPPING = {
        "string": {"type": "string", "format": "date-time"},
        "integer": {"type": "integer"},
        "number": {"type": "number"},
        "object": {
            "type": "object",
            "properties": {"$date": {"type": "integer"}},
            "additionalProperties": False,
        },
    }

    def formatter(self, value):
        if value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)
        _formatter = {
            "string": lambda v: v.isoformat(),
            "integer": lambda v: int(v.timestamp()),
            "number": lambda v: v.timestamp(),
            "object": lambda v: {"$date": int(v.timestamp())},
        }.get(self.type)
        return _formatter(value)

    def converter(self, value):
        _converter = {
            "string": lambda v: datetime.fromisoformat(v.rstrip("Z")),
            "integer": lambda v: datetime.fromtimestamp(v, timezone.utc),
            "number": lambda v: datetime.fromtimestamp(v, timezone.utc),
            "object": lambda v: datetime.fromtimestamp(v["$date"], timezone.utc),
        }.get(self.type)
        return _converter(value)


def _init_field(schema):  # 从对象获取字段
    if isinstance(schema, type):
        container = schema()  # 类的实例
    elif isinstance(schema, str):  # 增加对字符串的支持
        container = Str[schema]
    else:
        container = schema  # 实例

    if not isinstance(container, _Schema):  # 实例不是格式类
        raise RuntimeError(f"{schema} expected Field or _Schema or str")
    if not isinstance(container, Field):  # 实例不是BaseField 类,是json
        container = Field(container)
    return container


class _BindMixin:
    """
    资源绑定插件
    """

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
            f"{repr(self)} is already bound to {self.resource} and does not support rebinding to {resource}"
        )


def _bind(schema, resource) -> _Schema:  # 将格式与资源绑定
    if isinstance(schema, _BindMixin):
        return schema.bind(resource)
    return schema


class List(Field, _BindMixin):
    def __init__(self, schema, min_items=None, max_items=None, unique=None, **kwargs):
        self.container = container = _init_field(schema)
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

        def schema(s):
            return dict([("items", s)] + schema_properties)

        super().__init__(
            lambda: (schema(container.response), schema(container.request)),
            default=kwargs.pop("default", list),
            **kwargs,
        )

    def bind(self, resource):
        if isinstance(self.container, _BindMixin):
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

    def faker(self):
        return [self.container.faker() for _ in range(self.response.get("minItems", 2))]

    def __class_getitem__(cls, item):
        if isinstance(item, tuple) and len(item) == 2:
            if isinstance(item[1], slice):
                min_items, max_items, unique = (
                    item[1].start,
                    item[1].stop,
                    item[1].step,
                )
                return cls(item[0], min_items, max_items, unique)
            elif isinstance(item[1], int):
                return cls(item[0], item[1], item[1])
        elif isinstance(item, Field):
            return cls(item)
        elif issubclass(item, Field):
            return cls(item)
        raise KeyError(f"Key {item} not Support")


class Tuple(Field):
    """表示固定长度的列表元组"""

    def __init__(self, *schemas, **kwargs):
        schemas = [_init_field(item) for item in schemas]
        count = len(schemas)
        schema = {
            "type": "array",
            "items": [schema.response for schema in schemas],
            "minItems": count,
            "maxItems": count,
        }
        super().__init__(schema, **kwargs)


class Dict(Field, _BindMixin):
    """
    在 JSON _Schema 中，'patternProperties是一个关键字，用于描述对象属性的模式。
    它是一个用于限制 JSON 数据中对象属性模式的关键字，可以用来描述对象中所有匹配某个
    正则表达式模式的属性的限制条件。
    'patternProperties关键字的值是一个对象，其中每个属性的名称是一个正则表达式模式，
    用于匹配对象中的属性名；每个属性的值是一个 JSON _Schema 对象，用于描述对象中对应属性的限制条件。
    例如，以下 JSON _Schema 用于描述一个具有两个属性的对象，其中属性名必须以大写字母'A'或'B'开头，属性值必须为整数：

    {
      "type": "object",
      "patternProperties": {
        "^A": {
          "type": "integer"
        },
        "^B": {
          "type": "integer"
        }
      },
      "additionalProperties": false
    }
    在这个例子中，'patternProperties的值是一个对象，其中包含两个属性，分别是以'A'和'B'开头的属性名的正则表达式模式。
    每个属性的值是一个 JSON _Schema 对象，用于描述属性的限制条件。
    该 JSON _Schema 还使用了'additionalProperties'关键字，用于禁止出现除了以'A'和'B'开头的属性名以外的其他属性。
    使用'patternProperties'关键字可以使 JSON _Schema 更加灵活，可以描述更加复杂的数据结构。
    """

    def __init__(
        self,
        properties=None,
        pattern=None,  # 正则表达式
        pattern_props=None,
        other_props=None,
        io="rw",
        default=None,
        attribute=None,
        nullable=False,
        title=None,
        description=None,
        **kwargs,
    ):
        if isinstance(properties, str):  # todo 优化这里的逻辑，目前是只能展示不能校验
            if properties == "self":
                super().__init__({"$ref": "#"})
                return
        self.properties = None
        self.pattern_props = None
        self.other_props = None

        if properties is None and kwargs:
            self.properties = {
                k: _init_field(v) for k, v in kwargs.items() if isinstance(v, (type, Field, str))
            }

        elif isinstance(properties, dict):  # properties 是键名和字段的字典
            self.properties = {k: _init_field(v) for k, v in properties.items()}  # 如果不给字典，就没有这个属性
        elif isinstance(properties, (type, Field)):  # 类或字段
            field = _init_field(properties)
            if pattern:
                self.pattern_props = {pattern: field}
            else:
                self.other_props = field
        if isinstance(other_props, (type, Field)):
            self.other_props = _init_field(other_props)
        elif other_props is True:
            self.other_props = Any()
        if isinstance(pattern_props, (type, Field)):
            self.pattern_props = _init_field(pattern_props)
        elif isinstance(pattern_props, dict):
            self.pattern_props = {p: _init_field(f) for (p, f) in pattern_props.items()}

        def schema():
            request_schema = {"type": "object"}
            response_schema = {"type": "object"}
            for _schema, attr in (
                (request_schema, "request"),
                (response_schema, "response"),
            ):
                if self.properties:
                    _schema["properties"] = {k: getattr(f, attr) for (k, f) in self.properties.items()}
                if self.pattern_props:  # 模式属性
                    _schema["patternProperties"] = {p: getattr(f, attr) for (p, f) in self.pattern_props.items()}  #
                if self.other_props:
                    _schema["additionalProperties"] = getattr(self.other_props, attr)
                else:
                    _schema["additionalProperties"] = False  # 其他属性
            return response_schema, request_schema

        if self.pattern_props and (len(self.pattern_props) > 1 or self.other_props):
            raise NotImplementedError(
                "Only one pattern property is currently supported and it cannot be combined with additionalProperties"
            )

        super().__init__(
            schema,
            io=io,
            default=default,
            attribute=attribute,
            nullable=nullable,
            title=title,
            description=description,
        )

    def bind(self, resource):
        # 满足某个模式的字段都用一个字段类，比如 {{".*_time":DateTime}}
        if self.properties:
            self.properties = {key: _bind(value, resource) for (key, value) in self.properties.items()}
        if self.pattern_props:
            self.pattern_props = {key: _bind(value, resource) for (key, value) in self.pattern_props.items()}
        if self.other_props:
            self.other_props = _bind(self.other_props, resource)
        return self

    @cached_property
    def _property_attributes(self):
        if not self.properties:
            return ()
        return [field.attribute or k for (k, field) in self.properties.items()]

    def formatter(self, value):
        output = {}
        if self.properties:
            output = {k: f.format(_getattr(value, f.attribute or k, f.default)) for (k, f) in self.properties.items()}
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
            result = {
                field.attribute
                or key: field.convert(
                    instance.get(key, field.default),
                )
                for (key, field) in self.properties.items()
            }
        if self.pattern_props:
            field = next(iter(self.pattern_props.values()))
            result.update(
                {
                    key: field.convert(
                        value,
                    )
                    for (key, value) in instance.items()
                    if key not in result
                }
            )
        elif self.other_props:
            field = self.other_props
            result.update({key: field.convert(value) for (key, value) in instance.items() if key not in result})
        return result

    def faker(self):
        output = {}
        if self.properties:
            output = {k: f().faker() if isinstance(f, type) else f.faker() for (k, f) in self.properties.items()}
        return output

    def __class_getitem__(cls, item):
        if isinstance(item, str):
            return cls(item)

        if isinstance(item, tuple) and all(isinstance(i, slice) for i in item):
            properties = {}
            for index in item:
                key, value, step = index.start, index.stop, index.step
                properties[key] = _init_field(value)
            return cls(properties=properties)

        if isinstance(item, tuple) and len(item) == 2 and item[0].startswith("^") and item[0].endswith("$"):
            return cls(properties=item[1], pattern=item[0])

        return cls(item)


class ModelDict(Dict):
    def __init__(self, properties, model, **kwargs):
        super().__init__(properties, **kwargs)
        self.model = model

    def converter(self, instance):
        instance = super().converter(instance)
        if instance is not None:
            instance = self.model(**instance)
        return instance


class _ResourceRef:
    def __init__(self, value):
        self.value = value

    def resolve(self, binding=None):
        name = self.value
        if name == "self":  # 返回自己
            return binding
        if inspect.isclass(name) and issubclass(name, ModelResource):
            return name  # 资源类
        if binding and binding.api and name in binding.api.resources:
            return binding.api.resources[name]

        try:
            if isinstance(name, str):  # 其他地方的资源名
                (module_name, class_name) = name.rsplit(".", 1)
                module = import_module(module_name)
                return getattr(module, class_name)
        except (ValueError, ModuleNotFoundError):
            pass
        if binding and binding.api:
            raise RuntimeError(f'Resource named "{name}" is not registered with the Api it is bound to.')
        raise RuntimeError(f'Resource named "{name}" cannot be found; the reference is not bound to an Api.')


class Ref(Field, _BindMixin):
    """表示一个资源对象的引用
    Ref('books')
    Ref(BookRes)

    """

    def __init__(self, resource, **kwargs):  # resource可以是名称
        self.target_reference = _ResourceRef(resource)

        def schema():
            # key_converters 是个元组，第一个是响应体中的键转换器，第二个是请求体中的键转换器
            # 如果有两个就可以是任何一个转换器的请求格式
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
        return self.target.meta.key_converters[0]  # 响应体如RefKey

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
                return self.target.meta.key_converters_by_type[json_type].convert(value)


class Res(Field, _BindMixin):  # 内联 默认不可更新
    """内联对象就是将一个资源完整嵌入

    JSON _Schema 可以使用 $ref 关键字来表示递归的数据结构。
    $ref 关键字用于引用另一个位置的 JSON _Schema，
    这样可以在同一个 _Schema 中多次使用同一个定义，或者在不同的 _Schema 中使用相同的定义。
    """

    def __init__(self, resource, patchable=False, **kwargs):
        self.target_reference = _ResourceRef(resource)
        self.patchable = patchable

        def schema():
            def _response_schema():
                if self.resource == self.target:
                    return {"$ref": "#"}  # 特殊语法
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
        #     raise NotImplementedError
        return self.target.schema.convert(item, update=update, patchable=self.patchable)

    def faker(self):
        return self.target.schema.faker()

    def example(self):
        schema = self.target.schema.response
        faker_data = self.faker()
        for k, v in schema["properties"].items():
            v["example"] = faker_data.get(k, "*")
        serializable_schema = json.loads(json.dumps(schema, default=str))
        return serializable_schema


class Many(List):
    def __init__(self, resource, **kwargs):
        super().__init__(Res(resource, nullable=False), **kwargs)


class Any(Field):
    def __init__(self, **kwargs):
        super().__init__(
            {
                "type": [
                    "null",
                    "string",
                    "number",
                    "boolean",
                    "object",
                    "array",
                ]
            },
            **kwargs,
        )


class Union(Field):
    def __init__(self, *schemas, **kwargs):
        self.sub_schemas = [_init_field(s) for s in schemas]
        super().__init__(
            {"anyOf": [schema.response for schema in self.sub_schemas]},
            **kwargs,
        )

    def faker(self):
        return random.choice(self.sub_schemas).faker()


class Optional(Field):
    """提议
    兼容 Optional[Int]
    和 Optional|Int
    """

    def __class_getitem__(cls, schema):
        schema = _init_field(schema)
        schema.nullable = True
        return schema


class ResUri(Field):
    def __init__(self, resource, attribute=None):
        self.target_reference = _ResourceRef(resource)
        super().__init__(
            lambda: {
                "type": "string",
                "pattern": f"^{re.escape(self.target.route_prefix)}\\/[^/]+$",
            },
            io="r",
            attribute=attribute,
        )

    @cached_property
    def target(self):
        return self.target_reference.resolve()

    def format(self, value):
        return f"{self.target.route_prefix}/{value}"

    def converter(self, value):
        _, args = _route_from(value, GET)
        return self.target.manager.id_field.convert(args["id"])

    def faker(self):
        return f"{self.target.route_prefix}/{self.target.manager.id_field.faker()}"


class _DummySchema(_Schema):  # 简化格式实现
    def __init__(self, schema):
        self._schema = schema

    def schema(self):
        return self._schema


class FieldSet(_Schema, _BindMixin):
    """
    字段集:
        用于描述资源所有的字段

    FieldSet({'name':Str,'age':Int})
    FieldSet(name=Str,age=Int)
    """

    def __init__(self, fields, required_fields=None):
        self.fields = fields  # 字段字典
        self.required = set(required_fields or ())  # 必填项

    def _on_bind(self, resource):  # 字段字典内部字段能绑则绑
        self.fields = {
            key: field.bind(resource) if isinstance(field, _BindMixin) else field
            for (key, field) in self.fields.items()
        }

    def rebind(self, resource):
        return FieldSet(dict(self.fields), tuple(self.required)).bind(resource)

    def set(self, key, field):  # 设置字段并绑定资源
        if self.resource and isinstance(field, _BindMixin):
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
        return _DummySchema(self._schema(True))

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

    def faker(self):
        return OrderedDict(
            (
                (key, field.faker())
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
            object_ = self.patchable.convert(instance, update)
        else:
            object_ = super().convert(instance, update)
        for key, field in self.fields.items():
            if update and "u" not in field.io or (not update and "c" not in field.io):
                continue
            if key in result:
                continue
            value = object_.get(key)  # 通过get方法获取值
            if value is not None:  # 如果值存在
                value = field.convert(value)
            elif field.default is not None:
                value = field.default
            elif field.nullable:
                value = None
            elif key not in self.required and not strict:
                value = None
            result[field.attribute or key] = value
        return result

    def parse_request(self, request):  # noqa
        if request.method in (POST, PATCH, PUT, DELETE):
            if self.fields and request.mimetype != "application/json":
                if not self.all_fields_optional:  # 并非所有字段都是选填 且 请求非json
                    raise RequestMustBeJSON()
        data = request.get_json(silent=True)
        if data is None and self.all_fields_optional:
            data = {}  # 没有数据且所有字段可选则可为空
        if not self.fields:
            return {}  # 自身无字段则可为空
        if not data and request.method in (GET, HEAD):
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
        return self.convert(
            data,
            update=request.method in (PUT, PATCH),
            patchable=request.method == PATCH,
        )


class _PaginationMixin:  # 分页插件不能单独使用
    @cached_property
    def _pagination_types(self):
        raise NotImplementedError

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
            "Link": ",".join(
                [
                    '<{0}?{page}={1}&{per_page}={2}>; rel="{3}"'.format(*link, page=PAGE, per_page=PER_PAGE)
                    for link in links
                ]
            ),
            "X-Total-Count": data.total,
        }
        return self.format(data.items), 200, headers

    def format(self, data):
        pass


class Instances(_PaginationMixin, _Schema, _BindMixin):
    def __init__(self, required_fields=None, item_decorator=None):  # 2.23 新增可选展示的字段
        self.required_fields = required_fields
        self.item_decorator = item_decorator
        super().__init__()

    def rebind(self, resource):
        return self.__class__().bind(resource)

    @cached_property
    def _pagination_types(self):
        return self.resource.manager.pagination_classes

    @staticmethod
    def _field_filters_schema(filters):
        if len(filters) == 1:
            return next(iter(filters.values())).request
        return {"anyOf": [f.request for f in filters.values()]}

    @cached_property
    def _filters(self):
        return self.resource.manager.filters

    @cached_property
    def _sort_fields(self):
        return self.resource.manager._sort_fields  # noqa

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
                PAGE: {"type": "integer", "minimum": 1, "default": 1},
                PER_PAGE: {
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

    def parse_request(self, request):  # noqa where 和 sort 是json字符串
        page = request.args.get(PAGE, 1, type=int)
        per_page = request.args.get(PER_PAGE, current_app.config["RESTONE_DEFAULT_PER_PAGE"], type=int)
        style = current_app.config["RESTONE_DEFAULT_PARSE_STYLE"]  # 新增了可配置的查询风格
        try:
            if style == "json":
                sort, where = self.parse_where_sort_by_json(request)
            else:
                sort, where = self.parse_where_sort_by_args(request)
        except ValueError:
            raise InvalidJSON()
        result = {
            "page": page,
            "per_page": per_page,
            "where": where,
            "sort": sort,
        }
        # todo:条件校验系统由bug暂时不校验
        # result = self.convert({PAGE: page, PER_PAGE: per_page, "where": where, "sort": sort})
        return result

    def format(self, items):
        result = [self.resource.schema.format(item) for item in items]
        if self.item_decorator is not None:
            result = [self.item_decorator(item) for item in result]
        if self.required_fields is None:
            return result
        return self._filter_required(result)

    def faker(self):
        result = [self.resource.schema.faker() for _ in range(2)]
        if self.required_fields is None:
            return result
        return self._filter_required(result)

    def example(self):
        schema = self.resource.schema.response  # 此处是cache_property
        faker_data = self.resource.schema.faker()
        for k, v in schema["properties"].items():
            v["example"] = faker_data.get(k, "*")
        serializable_schema = json.loads(json.dumps(schema, default=str))
        return {"type": "array", "items": serializable_schema}

    def _filter_required(self, result):
        out = []
        for item in result:
            new = OrderedDict()
            for k, v in item.items():
                if k[0] == "$" and k[1:] in self.required_fields:
                    new[k] = v
                elif k in self.required_fields:
                    new[k] = v
            out.append(new)
        return out

    @staticmethod
    def parse_where_sort_by_args(request):  # noqa
        where = OrderedDict()
        sort = OrderedDict()
        for key, value in request.args.items():
            if key in (PAGE, PER_PAGE, "sort"):
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

    @staticmethod
    def parse_where_sort_by_json(request):  # noqa
        where = json.loads(request.args.get("where", "{}"))
        sort = json.loads(request.args.get("sort", "{}"), object_pairs_hook=OrderedDict)
        for k, v in where.items():
            if not isinstance(v, dict):
                where[k] = {"$eq": v}
        return sort, where


class _Key(_Schema, _BindMixin):  # noqa still ABC
    @property
    def matcher_type(self):
        type_ = self.response["type"]
        if isinstance(type_, str):
            return type_
        return type_[0]

    def rebind(self, resource):
        return self.__class__().bind(resource=resource)


class RefKey(_Key):
    @property
    def matcher_type(self):
        return "object"

    def schema(self):
        return {
            "type": "object",
            "properties": {
                "$ref": {
                    "type": "string",
                    "pattern": f"^{re.escape(self.resource.route_prefix)}\\/[^/]+$",
                }
            },
            "additionalProperties": False,
        }

    @staticmethod
    def _item_uri(resource, item):
        return f"{resource.route_prefix}/{_getattr(item, resource.manager.id_attribute, None)}"

    def format(self, item):
        return {"$ref": self._item_uri(self.resource, item)}

    def convert(self, value, **kwargs):
        _, args = _route_from(value["$ref"], GET)
        return self.resource.manager.read(args["id"])


class IDKey(_Key):
    def _on_bind(self, resource):
        self.id_field = resource.manager.id_field

    def schema(self):
        return self.id_field.request

    def format(self, item):
        return self.id_field.output(self.resource.manager.id_attribute, item)

    def convert(self, value, **kwargs):
        return self.resource.manager.read(self.id_field.convert(value))


class _NaturalKey(_Key):
    def __init__(self, prop):
        self.property = prop

    def rebind(self, resource):
        return self.__class__(self.property).bind(resource)

    def schema(self):
        return self.resource.schema.fields[self.property].request

    def format(self, item):
        return self.resource.schema.fields[self.property].output(self.property, item)

    @cached_property
    def _field_filter(self):
        return self.resource.manager.filters[self.property]["$eq"]

    def convert(self, value, **kwargs):
        return self.resource.manager.first(where={self.property: value})


class _MultiNaturalKey(_Key):
    def __init__(self, *properties):
        self.properties = properties

    @property
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
        return self.resource.manager.first(where={prop: value[i] for (i, prop) in enumerate(self.properties)})


def _(s):
    return s.replace("_", "-")


def _camel_case(s):
    return s[0].lower() + s.title().replace("_", "")[1:] if s else s


def _route_from(url, method=None):
    if app_ctx is None:
        raise RuntimeError(
            "Attempted to match a URL without the application context being pushed. "
            "This has to be executed when application context is available."
        )

    url_adapter = request_ctx.url_adapter if request_ctx else app_ctx.url_adapter

    if url_adapter is None:
        raise RuntimeError(
            "Application was not able to create a URL adapter for request independent URL matching. "
            "You might be able to fix this by setting the SERVER_NAME config variable."
        )

    parsed_url = urlsplit(url)
    if parsed_url.netloc not in ("", url_adapter.server_name):
        raise PageNotFound()
    return url_adapter.match(parsed_url.path, method)


def _unpack(value):
    if not isinstance(value, tuple):
        return value, 200, {}
    if len(value) == 2:
        return value[0], value[1], {}
    return value


def _getattr(obj, key, default=None):
    if hasattr(obj, "__getitem__"):
        try:
            return obj[key]
        except (IndexError, TypeError, KeyError):
            pass
    return getattr(obj, key, default)


# ----------------------------------------自动路由-------------------------------
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


_HTTP_VERBS = {
    GET: "read",
    PUT: "update",
    POST: "create",
    PATCH: "update",
    DELETE: "destroy",
}


def has_only_docstring(fn):
    """判断函数或方法是否只有 docstring，没有其他内容"""
    # 获取函数/方法定义的源代码
    source_lines, _ = inspect.getsourcelines(fn)
    leading_spaces = len(source_lines[0]) - len(source_lines[0].lstrip())
    stripped_source = "".join(line[leading_spaces:] for line in source_lines)
    # 使用 ast 模块解析源代码，获取函数/方法定义的抽象语法树
    tree = ast.parse(stripped_source)
    # 遍历抽象语法树，检查函数/方法定义中是否包含其他内容
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            # 如果函数/方法定义中只有一个表达式语句且表达式是字符串字面值，则函数/方法只包含 docstring
            if (
                len(node.body) == 1 and isinstance(node.body[0], ast.Expr) and isinstance(node.body[0].value, ast.Str)  # noqa
            ):
                return True
            # 如果函数/方法定义中只有一个简单语句且是 pass，则函数/方法只包含 docstring
            elif len(node.body) == 1 and isinstance(node.body[0], ast.Pass):
                return True
            # 如果函数/方法定义中包含除了 docstring 或 pass 以外的其他内容，则函数/方法不止包含 docstring
            else:
                return False
    # 如果函数/方法定义中没有任何内容，则认为它只包含 docstring
    return True


class route:  # noqa
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
        self.attribute = attribute  # 属性
        self.title = title  # 标题
        if not description and view_func.__doc__:  # 从docstring中获取description
            description = view_func.__doc__.splitlines()[0].strip()
        self.description = description
        self.view_func = view_func  # 视图函数
        self.format_response = format_response  # 是否格式化响应
        self.success_code = success_code  # 状态码

        annotations = getattr(view_func, "__annotations__", None)  # 获取视图函数的注解
        if isinstance(annotations, dict) and annotations:
            self.request_schema = FieldSet(
                {name: _init_field(field) for (name, field) in annotations.items() if name != "return"}
            )  # 请求的语法就是参数名和参数字段类型的字段集，响应也有字段

            self.response_schema = annotations.get("return", response_schema)
        else:  # 没有标注则要指定参数
            self.request_schema = schema
            self.response_schema = response_schema

        self.related_routes = ()  # 相关的路由

        for method in HTTP_METHODS:  # 把方法绑定到类的实例中
            setattr(self, method.lower(), MethodType(_method_decorator(method), self))

    @property
    def relation(self):  # 关系型数据资源
        if self.rel:
            return self.rel  # 关联字符串 read_status?

        verb = _HTTP_VERBS.get(self.method, self.method.lower())
        return _camel_case(f"{verb}_{self.attribute}")

    def schema_factory(self, resource):  # 规则工厂 将路由的请求与响应规则绑定到资源上
        request_schema = _bind(self.request_schema, resource)
        response_schema = _bind(self.response_schema, resource)
        schema = OrderedDict(
            [
                ("rel", self.relation),
                (
                    "href",
                    re.sub(
                        "<(\\w+:)?([^>]+)>",
                        "{\\2}",
                        self.rule_factory(resource, relative=False),
                    ),
                ),
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

    def for_method(
        self,
        method,
        view_func,
        rel=None,
        title=None,
        description=None,
        schema=None,
        response_schema=None,
        **kwargs,
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
            **kwargs,
        )

        instance.related_routes = self.related_routes + (self,)
        return instance

    # 存在了__get__的方法的类称之为描述符类
    # descriptor 的实例自己访问自己是不会触发__get__ ，而会触发__call__，
    # 只有 descriptor 作为其它类的属性的时候才会触发 __get___
    # 可以通过ModelResource().get()
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

    def response_example(self, resource):
        if isinstance(self.response_schema, (Instances, Res)):
            response_schema = _bind(self.response_schema, resource)
            return response_schema.example()  # noqa
        elif isinstance(self.response_schema, Field):
            response_schema = self.response_schema.response
            response_schema["example"] = self.response_schema.faker()
            return response_schema
        return {}

    def rule_factory(self, resource, relative=False):  # 规则工厂
        rule = self.rule  # 规则是个字符串
        if rule is None:
            rule = f"/{_(self.attribute)}"
            # self.attribute 可以关联到资源属性和rule二选一
            # route.get('/status') 是 rule
            # route.get(attribute='status') 是属性
        elif callable(rule):  # 规则可以调用资源
            rule = rule(resource)
        if relative or resource.route_prefix is None:
            return rule[1:]
        return "".join((resource.route_prefix, rule))

    def view_factory(self, name, resource):  # 视图工厂
        request_schema = _bind(self.request_schema, resource)
        response_schema = _bind(self.response_schema, resource)
        view_func = self.view_func

        def view(*args, **kwargs):
            instance = resource()  # 资源实例
            if isinstance(request_schema, (FieldSet, Instances)):  # 请求字段集和实例集
                kwargs.update(request_schema.parse_request(request))  # 上文实现了
            elif isinstance(request_schema, _Schema):  # 普通的格式
                args += (request_schema.parse_request(request),)  # 为何是元组

            # 如果方法只有字符串和pass 就返回假数据
            if has_only_docstring(view_func) and response_schema is not None:
                return _init_field(response_schema).faker()

            response = view_func(instance, *args, **kwargs)

            if not isinstance(response, tuple) and self.success_code:
                response = (response, self.success_code)
            if response_schema is None or not self.format_response:
                return response
            return response_schema.format_response(response)  # 格式化

        return view

    get = _route_decorator("get")
    post = _route_decorator("post")
    patch = _route_decorator("patch")
    put = _route_decorator("put")
    delete = _route_decorator("delete")

    # for method in HTTP_METHODS:
    #     locals()[method] = _route_decorator(method)
    #     locals()[method.lower()] = locals()[method]
    # 使用locals 在当前作用域来设置批量类方法


class itemroute(route):  # noqa
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
            item = resource.manager.read(kwargs.pop("id"))
            return original_view(item, *args, **kwargs)

        return view


class _RouteSet(ABC):
    @abstractmethod
    def routes(self):
        pass


class Relation(_RouteSet, _BindMixin):  # 关系型也是RouteSet子类
    def __init__(self, resource, uselist=True, io="rw", attribute=None):
        self.reference = _ResourceRef(resource)  # 找到关联的资源类
        self.attribute = attribute  # 属性名
        self.io = io
        self.uselist = uselist

    @cached_property
    def target(self):
        return self.reference.resolve(self.resource)  # 目标类

    def routes(self):
        io = self.io
        rule = f"/{_(self.attribute)}"  # /author
        relation_route = itemroute(rule=f"{rule}/<{self.target.meta.id_converter}:target_id>")  # /book/001/author/<sid>
        relations_route = itemroute(rule=rule)  # /author
        if not self.uselist:
            if "r" in io:

                def relation_instance(resource, item):  # noqa
                    return getattr(item, self.attribute)

                yield relations_route.for_method(
                    GET,
                    relation_instance,
                    rel=_camel_case(f"read_{self.attribute}"),
                    response_schema=Res(self.target),
                )
            if "w" in io or "c" in io:

                def create_relation_instance(resource, item, properties):  # 一对一
                    target_item = self.target.manager.create(properties)
                    resource.manager.update(item, {self.attribute: target_item})
                    return target_item

                yield relations_route.for_method(
                    POST,
                    create_relation_instance,
                    rel=_camel_case(f"create_{self.attribute}"),
                    response_schema=Ref(self.target),
                    schema=Res(self.target),
                )
            if "w" in io or "u" in io:

                def update_relation_instance(resource, item, changes):  # noqa
                    target_item = getattr(item, self.attribute)
                    target_item = self.target.manager.update(target_item, changes)
                    return target_item

                yield relations_route.for_method(
                    PUT,
                    update_relation_instance,
                    rel=_camel_case(f"update_{self.attribute}"),
                    response_schema=Ref(self.target),
                    schema=Res(self.target, patchable=True),
                )

                def delete_relation_instance(resource, item):  # 删除单个item并移除关系
                    target_item = getattr(item, self.attribute)
                    resource.manager.relation_remove(item, self.attribute, self.target, target_item)
                    resource.manager.commit()
                    self.target.manager.delete(target_item)
                    return None, 204

                yield relations_route.for_method(
                    DELETE,
                    delete_relation_instance,
                    rel=_camel_case(f"remove_{self.attribute}"),
                )
        else:
            if "r" in io:

                def relation_instances(resource, item, **kwargs):  # 一对多
                    page = kwargs.get(PAGE, None)
                    per_page = kwargs.get(PER_PAGE, None)
                    return resource.manager.relation_instances(
                        item,
                        self.attribute,
                        self.target,
                        page=page,
                        per_page=per_page,
                    )

                yield relations_route.for_method(
                    GET,
                    relation_instances,
                    rel=self.attribute,
                    response_schema=Many(self.target),
                    schema=FieldSet(
                        {
                            PAGE: Int(minimum=1, nullable=True),
                            PER_PAGE: Int(minimum=1, nullable=True),
                        }
                    ),
                )
            if "w" in io or "u" in io:

                def relation_add(resource, item, target_item):
                    target_item = self.target.manager.create(target_item)  # fixme
                    resource.manager.relation_add(item, self.attribute, self.target, target_item)
                    resource.manager.commit()
                    return target_item

                yield relations_route.for_method(
                    POST,
                    relation_add,
                    rel=_camel_case(f"add_{self.attribute}"),
                    response_schema=Res(self.target),
                    schema=Res(self.target),
                )

                def relation_remove(resource, item, target_id):
                    target_item = self.target.manager.read(target_id)
                    resource.manager.relation_remove(item, self.attribute, self.target, target_item)
                    resource.manager.commit()
                    return None, 204

                yield relation_route.for_method(
                    DELETE,
                    relation_remove,
                    rel=_camel_case(f"remove_{self.attribute}"),
                )


class AttrRoute(_RouteSet):  # 单个记录的属性路由
    def __init__(self, schema, io=None, attribute=None, description=None):
        self.field = _init_field(schema)
        self.attribute = attribute
        self.io = io
        self.description = description

    def routes(self):
        io = self.io or self.field.io
        field = self.field
        _route = itemroute(attribute=self.attribute)
        attribute = field.attribute or _route.attribute

        if "r" in io:  # 读属性的路由

            def read_attribute(resource, item):  # noqa
                return _getattr(item, attribute, field.default)

            yield _route.for_method(
                GET,
                read_attribute,
                response_schema=field,
                rel=_camel_case(f"read_{_route.attribute}"),
                description=self.description,
            )
        if "u" in io:  # 更新属性的路由

            def update_attribute(resource, item, value):  # 直接post一个string即可
                item = resource.manager.update(item, {attribute: value})
                return _getattr(item, attribute, field.default)

            yield _route.for_method(
                POST,
                update_attribute,
                schema=field,
                response_schema=field,
                rel=_camel_case(f"update_{_route.attribute}"),
                description=self.description,
            )


class TaskRoute(_RouteSet):
    def __init__(self, func, attribute=None):
        self.long_task = func
        annotations = func.__annotations__

        self.schema = FieldSet(
            {name: _init_field(field) for (name, field) in annotations.items() if name != "return"}
        )

        self.attribute = attribute

    def routes(self):
        rule = f"/{_(self.attribute)}"

        task_status_route = itemroute(rule=f"{rule}/<string:task_id>")
        task_action_route = itemroute(rule=rule)

        def task_start(resource, item, **kwargs):
            task = self.long_task.apply_async(kwargs=kwargs)

            return (
                "",
                202,
                {
                    "Location": url_for(
                        f"{resource.meta.name}_readTaskStatus",
                        id=item.id,
                        task_id=task.id,
                    )
                },
            )

        yield task_action_route.for_method(
            POST,
            task_start,
            rel=f"startTask",
            schema=self.schema,
            description="start task",
        )

        def task_status(resource, item, task_id):  # noqa placeholder
            task = self.long_task.AsyncResult(task_id)
            if task.state == "PENDING":
                response = {
                    "state": task.state,
                    "current": 0,
                    "total": 1,
                    "status": "Pending...",
                    "remaining": "",
                }
            elif task.state != "FAILURE":
                response = {
                    "state": task.state,
                    "current": task.info.get("current", 0),
                    "total": task.info.get("total", 1),
                    "status": task.info.get("status", ""),
                    "remaining": task.info.get("remaining", ""),
                }
                if "result" in task.info:
                    response["result"] = task.info["result"]
            else:
                # something went wrong in the background job
                response = {
                    "state": task.state,
                    "current": 1,
                    "total": 1,
                    "status": str(task.info),  # this is the exception raised
                    "remaining": "",
                }
            return jsonify(response)

        yield task_status_route.for_method(
            GET,
            task_status,
            rel="readTaskStatus",
            description="start task",
        )

        def task_stop(resource, item, task_id):  # noqa placeholder
            task = self.long_task.AsyncResult(task_id)
            task.revoke(terminate=True)
            return "", 204

        yield task_status_route.for_method(
            DELETE,
            task_stop,
            rel="stopTask",
            description="stop task",
        )


class attrdict(dict):  # noqa
    __getattr__ = dict.__getitem__
    __setattr__ = dict.__setitem__


class _ResourceMeta(type):
    def __new__(mcs, name, bases, members):
        class_ = super(_ResourceMeta, mcs).__new__(mcs, name, bases, members)
        class_.routes = routes = dict(getattr(class_, "routes") or {})
        class_.meta = meta = attrdict(getattr(class_, "meta", {}) or {})

        def add_route(routes, route, name):  # noqa placeholder
            if route.attribute is None:
                route.attribute = name
            for r in route.related_routes:
                if r.attribute is None:
                    r.attribute = name
                routes[r.relation] = r
            routes[route.relation] = route

        for base in bases:
            for n, m in inspect.getmembers(base, lambda r: isinstance(r, route)):
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
            datetime_field_class = meta.get("datetime_formatter")
            if model and datetime_field_class:
                for k, field in model.__dict__.items():
                    if not k.startswith("__") and hasattr(field, "type"):
                        if str(field.type) == "DATETIME":
                            schema[k] = datetime_field_class(io="r", description=field.info)

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
                {k: _init_field(f) for (k, f) in schema.items() if not k.startswith("__")},
                required_fields=meta.get("required", None),
            )

            for name in meta.get("read_only", ()):
                if name in fs.fields:
                    fs.fields[name].io = "r"
            for name in meta.get("write_only", ()):
                if name in fs.fields:
                    fs.fields[name].io = "w"
            fs.bind(class_)
        for n, m in members.items():
            if isinstance(m, route):
                add_route(routes, m, n)
            if isinstance(m, _BindMixin):
                m.bind(class_)

        if meta.exclude_routes:
            for relation in meta.exclude_routes:
                routes.pop(relation, None)
        return class_


class Resource(metaclass=_ResourceMeta):
    api = None
    meta = None
    routes = None
    schema = None
    route_prefix = None

    @route.get("/schema", rel="describedBy", attribute="schema")
    def described_by(self):
        schema = OrderedDict([("$schema", "http://json-schema.org/draft-04/hyper-schema#")])
        for prop in ("title", "description"):
            value = getattr(self.meta, prop)
            if value:
                schema[prop] = value
        links = [r for (name, r) in sorted(self.routes.items())]  # name,route
        if self.schema:
            schema["type"] = "object"
            schema.update(self.schema.response)
        schema["links"] = [link.schema_factory(self) for link in sorted(links, key=attrgetter("relation"))]
        return schema, 200, {"Content-Type": "application/schema+json"}

    class Meta:
        name = None
        title = None
        description = None
        exclude_routes = ()
        route_decorators = {}
        read_only = ()
        write_only = ()
        required = None


class _ModelResourceMeta(_ResourceMeta):
    """模型资源是专门为数据库orm设计的资源"""

    def __new__(mcs, name, bases, members):
        class_ = super(_ModelResourceMeta, mcs).__new__(mcs, name, bases, members)
        meta = class_.meta
        if "Meta" in members:
            changes = members["Meta"].__dict__
            if "model" in changes or ("model" in meta and "manager" in changes):
                if meta.manager is not None:
                    class_.manager = meta.manager(class_, meta.model)
        sort_attribute = meta.get("sort_attribute")
        if sort_attribute is not None and isinstance(sort_attribute, str):
            meta.sort_attribute = (sort_attribute, False)
        # 预绑定信号接收函数
        for name, signal in _signals.items():
            receiver_name = f"on_{name.replace('-', '_')}"
            if receiver_name in members:
                signal.connect(members[receiver_name], class_)
        return class_


_RFC6902_PATCH = List(
    Dict(
        {
            "op": Str(enum=("add", "replace", "remove", "move", "copy", "test")),
            "path": Str(pattern="^/.+"),
            "value": Any(nullable=True),
        }
    )
)


class ModelResource(Resource, metaclass=_ModelResourceMeta):
    manager = None

    @classmethod
    def faker(cls, io="r"):
        if io == "r":
            return {k: f.faker() for k, f in cls.schema.fields.items()}
        return {k: f.faker() for k, f in cls.schema.fields.items() if f.io != "r"}

    @route.get("", rel="instances")
    def instances(self, **kwargs):
        return self.manager.paginated_instances(**kwargs)

    instances.request_schema = instances.response_schema = Instances()

    @instances.post(rel="create")  # 明白了rel是内部用的用于定位视图的，作为key
    def create(self, properties):
        # 新增 如果是内联的字典且其field 是inline 则创建先创建之
        props = {}
        inlines = []

        for k, v in properties.items():
            field = self.schema.fields[k]
            if isinstance(field, Res):
                inst = field.target.manager.create(v, commit=False)  # 使用目标字段的create方法，这样即使还有内联也可以直接创建
                props[f"{k}_id"] = inst.id
                inlines.append(field.target.manager)
            else:
                props[k] = v
        # 全部能创建成功才能打包提交
        item = self.manager.create(props, commit=True)
        for manager in inlines:
            manager.commit()

        return item

    create.request_schema = create.response_schema = Res("self")

    @route.get(
        lambda r: f"/<{r.meta.id_converter}:id>",
        rel="self",
        attribute="instance",
    )
    def read(self, id):  # noqa
        return self.manager.read(id)

    read.request_schema = None
    read.response_schema = Res("self")

    @read.put(rel="update")
    def update(self, properties, id):  # noqa
        item = self.manager.read(id)
        updated_item = self.manager.update(item, properties)
        return updated_item

    update.request_schema = Res("self", patchable=True)
    update.response_schema = update.request_schema

    @update.delete(rel="destroy")
    def destroy(self, id):  # noqa
        self.manager.delete_by_id(id)
        return None, 204

    @route.patch("", rel="patch")
    def patch(self):
        """
        根据 RFC 6902 规范执行指定路径下资源的操作。
        Raises:
            OperationNotAllowed: 如果指定的操作不在允许的操作列表中，则引发此异常。
            InvalidUrl: 如果指定的路径不存在，则引发此异常。
            OperationNotAllowed: 如果指定的操作被允许但未实现，则引发此异常。
            InvalidJSON: 如果参数值不是预期的格式，则引发此异常。
            AssertionError: 如果指定路径对应的值与参数值不匹配，则引发此异常。
        Returns:
            无返回值，HTTP状态码为200。
        """
        patch = request.json  # 以列表形式提供不具名
        patch = _RFC6902_PATCH.convert(patch)
        for p in patch:
            op = p.pop("op")  # 可用操作
            if op not in self.meta.allowed_operations:
                raise OperationNotAllowed(f"{op} is not allowed")
            path = p.pop("path")  # 操作路径
            if not self.path_exists(path):
                raise InvalidUrl(f"{path} not found")
            value = p.pop("value", None)  # 可选参数值
            func = getattr(self, op, None)
            if func is None:
                raise OperationNotAllowed(f"{op} is allowed but not implemented")
            func(path, value)
        # 统一提交，中途报错则不会提交
        self.manager.commit()
        return None, 200

    @staticmethod
    def is_root_path(path):
        return path == "/"

    @staticmethod
    def is_item_path(path):
        return path[0] == "/" and path.strip("/").count("/") == 0

    @staticmethod
    def is_attr_path(path):
        return path[0] == "/" and path.strip("/").count("/") == 1

    def path_exists(self, path: str) -> bool:
        """判断路径是否存在,目前只支持三级"""
        if self.is_root_path(path):
            return True
        parts = path.rstrip("/").split("/")

        try:
            item = self.manager.read(parts[1])
        except ItemNotFound:
            return False
        if len(parts) == 2:
            return True
        if hasattr(item, parts[2]):
            return True
        return False

    def add(self, path, value):
        if self.is_root_path(path):
            return self.manager.create(value, commit=False)
        raise InvalidUrl("add only support root path")

    def replace(self, path, value):
        if self.is_item_path(path):
            item = self.manager.read(path[1:])
            return self.manager.update(item, value, commit=False)
        elif self.is_attr_path(path):
            id_, attr = path.strip("/").split("/")
            item = self.manager.read(id_)
            return self.manager.update(item, {attr: value}, commit=False)
        raise InvalidUrl("replace not support root path")

    def remove(self, path, value=None):  # noqa keep the value for soft|elegant|hard delete
        if self.is_item_path(path):
            item = self.manager.read(path[1:])
            return self.manager.delete(item, commit=False)
        raise InvalidUrl("remove only support item path")

    def move(self, path, value):
        if self.is_item_path(path):
            item = self.manager.read(path[1:])
            id_attribute = self.meta.id_attribute or "id"
            if isinstance(value, str) and self.is_item_path(value) and not self.path_exists(value):
                return self.manager.update(item, {id_attribute: value[1:]}, commit=False)
            elif isinstance(value, dict):  # 可能有其他属性表示资源实体路径
                return self.manager.update(item, value, commit=False)
            raise InvalidJSON("value must be path string or object")
        raise InvalidUrl("move only support item path")

    def copy(self, path, value=None):
        if self.is_item_path(path):
            item = self.manager.read(path[1:])
            props = vars(item)
            props.pop("id")
            props.pop("_sa_instance_state")
            if isinstance(value, dict):
                props.update(value)  # copy 并更新数据
            return self.manager.create(props, commit=False)  # copy
        raise InvalidUrl("copy only support item path")

    def test(self, path, value):
        # 此处的test实际上是测试路径对应的值是否与value相同
        if self.is_attr_path(path):
            id_, attr = path.strip("/").split("/")
            item = self.manager.read(id_)
            if not hasattr(item, attr):
                raise InvalidUrl(f"{path} not found")
            if getattr(item, attr) != value:
                raise AssertionError(f"{path} does not match {value}")
            return None
        raise InvalidUrl("test only support attr path")

    class Schema:  # 设置各个字段的语法用的
        pass

    class Meta:
        id_attribute = None  # id
        sort_attribute = None  # 排序列
        id_converter = None  # string
        id_field_class = Int  # id域的类
        include_id = False  # 包括id
        manager = None  # 数据库管理
        include_fields = None  # 包括
        exclude_fields = None  # 不包括
        filters = True  # 过滤
        fuzzy_fields = ()
        permissions = {
            "read": "anyone",
            "create": "none",
            "update": "create",
            "delete": "update",
        }
        allowed_operations = (
            "add",
            "replace",
            "remove",
            "move",
            "copy",
            "test",
        )
        key_converters = (RefKey(), IDKey())
        datetime_formatter = DateTime
        natural_key = None


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


# ----------------------------------------过滤查询-------------------------------
class _Condition:  # 属性 过滤器 值
    def __init__(self, attribute, filter, value):  # noqa
        self.attribute = attribute
        self.filter = filter
        self.value = value

    def __call__(self, item):
        return self.filter.op(_getattr(item, self.attribute, None), self.value)


class _BaseFilter(_Schema):
    name = None
    filters = {}

    def __init__(self, field=None, attribute=None):
        self._attribute = attribute
        self._field = field

    @property
    def field(self):  # 被过滤的字段,只是使用field.convert
        if self.name in ("eq", "ne"):
            return self._field
        if self.name in ("in", "ni"):
            return List(self._field, min_items=0, unique=True)
        if self.name == "ha":
            return self._field.container
        if self.name == "bt":
            return List(self._field, min_items=2, max_items=2)
        if self.name in ("ct", "ci", "sw", "si", "ew", "ei"):
            return Str(1)
        if not isinstance(self._field, (Date, DateTime)):
            return Float()
        return self._field

    @property
    def attribute(self):
        return self._attribute or self.field.attribute

    def convert(self, instance, **kwargs):
        if self.name is None:  # 过滤器的转换就是所过滤字段的转换
            return _Condition(self.attribute, self, self.field.convert(instance))
        return _Condition(self.attribute, self, self.field.convert(instance[f"${self.name}"]))

    def schema(self):  # 过滤器只能针对请求模式，过滤器的模式就是所过滤字段的请求模式
        schema = self.field.request
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
    def make_filter(cls, name, func):
        return type(
            name.upper(),
            (cls,),
            {"op": classmethod(lambda s, a, b: func(a, b)), "name": name},
        )

    @classmethod
    def register(cls, name, func):  # 类方法返回子类
        class_ = cls.make_filter(name, func)
        cls.filters[name] = class_


# 属性过滤
_BaseFilter.register("lt", lambda a, b: a < b)
_BaseFilter.register("gt", lambda a, b: a > b)
_BaseFilter.register("eq", lambda a, b: a == b)
_BaseFilter.register("ne", lambda a, b: a != b)
_BaseFilter.register("le", lambda a, b: a <= b)
_BaseFilter.register("ge", lambda a, b: a >= b)
_BaseFilter.register("in", lambda a, b: a in b)
_BaseFilter.register("ni", lambda a, b: a not in b)
_BaseFilter.register("ha", lambda a, b: hasattr(a, "__iter__") and b in a)
_BaseFilter.register("ct", lambda a, b: a and b in a)
_BaseFilter.register("ci", lambda a, b: a and b.lower() in a.lower())
_BaseFilter.register("sw", lambda a, b: a.startswith(b))
_BaseFilter.register("si", lambda a, b: a.lower().startswith(b.lower()))
_BaseFilter.register("ew", lambda a, b: a.endswith(b))
_BaseFilter.register("ei", lambda a, b: a.lower().endswith(b.lower()))
_BaseFilter.register("bt", lambda a, b: b[0] <= a <= b[1])


class _SQLAlchemyFilter(_BaseFilter):
    filters = {}

    def __init__(self, field=None, attribute=None, column=None):
        super().__init__(field=field, attribute=attribute)
        self.column = column

    @classmethod
    def apply(cls, query, conditions):
        expressions = [condition.filter.expression(condition.value) for condition in conditions]
        if len(expressions) == 1:
            return query.filter(expressions[0])
        return query.filter(and_(*expressions))

    @classmethod
    def make_filter(cls, name, func):
        return type(
            name.upper(),
            (cls,),
            {
                "expression": lambda self, value: func(self.column, value),
                "name": name,
            },
        )


_SQLAlchemyFilter.register("eq", lambda c, v: c == v)  # 隐式的创建过滤器
_SQLAlchemyFilter.register("ne", lambda c, v: c != v)
_SQLAlchemyFilter.register("lt", lambda c, v: c < v)
_SQLAlchemyFilter.register("le", lambda c, v: c <= v)
_SQLAlchemyFilter.register("gt", lambda c, v: c > v)
_SQLAlchemyFilter.register("ge", lambda c, v: c >= v)
_SQLAlchemyFilter.register("in", lambda c, v: c.in_(v) if len(v) else False)
_SQLAlchemyFilter.register("ni", lambda c, v: c.notin_(v) if len(v) else True)
_SQLAlchemyFilter.register("ha", lambda c, v: c.contains(v))
_SQLAlchemyFilter.register("ct", lambda c, v: c.like("%" + v.replace("%", "\\%") + "%"))
_SQLAlchemyFilter.register("ci", lambda c, v: c.ilike("%" + v.replace("%", "\\%") + "%"))
_SQLAlchemyFilter.register("sw", lambda c, v: c.startswith(v.replace("%", "\\%")))
_SQLAlchemyFilter.register("si", lambda c, v: c.ilike(v.replace("%", "\\%") + "%"))
_SQLAlchemyFilter.register("ew", lambda c, v: c.endswith(v.replace("%", "\\%")))
_SQLAlchemyFilter.register("ei", lambda c, v: c.ilike("%" + v.replace("%", "\\%")))
_SQLAlchemyFilter.register("bt", lambda c, v: c.between(v[0], v[1]))

_FIELD_FILTERS_DICT = {
    Bool: ("eq", "ne", "in", "ni"),
    Date: ("eq", "ne", "lt", "le", "gt", "ge", "bt", "in", "ni"),
    DateTime: ("eq", "ne", "lt", "le", "gt", "ge", "bt"),
    Float: ("eq", "ne", "lt", "le", "gt", "ge", "in", "ni"),
    Int: ("eq", "ne", "lt", "le", "gt", "ge", "in", "ni"),
    ResUri: ("eq", "ne", "in", "ni"),
    List: ("ha",),
    Str: ("eq", "ne", "ct", "ci", "sw", "si", "ew", "ei", "in", "ni"),
    Many: ("ha",),
    Ref: ("eq", "ne", "in", "ni"),
}


# 数据管理器，接入数据一端，可以是不同的数据库，只要实现了相同的方法
class Manager:
    filter_class = _BaseFilter  # 指定过滤器基类，自动搜刮对应类

    field_filters_dict = _FIELD_FILTERS_DICT  # 可能会被重写的放在这里

    pagination_classes = (Pagination,)

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
            field_set.set("$uri", ResUri(resource, attribute=id_attribute))

    def _init_filter(self, filter_class, name, field, attribute):
        return filter_class(field=field, attribute=field.attribute or attribute)

    def _init_filters(self, resource, meta):
        fields = resource.schema.fields
        # fixed 将可读字段和可过滤字段区分，有的字段不可读但是可过滤
        field_filters = self.filters_for_fields(
            fields,
            meta.filters,  # meta里面还有 filters= [x,y]指定了哪些字段可以用于过滤
            field_filters_dict=self.field_filters_dict,
            filters_name_dict=self.filter_class.filters,
        )
        self.filters = {
            field_name: {
                name: self._init_filter(ft, name, fields[field_name], field_name)
                for (name, ft) in field_filters.items()
            }
            for (field_name, field_filters) in field_filters.items()
        }

    @staticmethod
    def filters_for_fields(fields, filters_expression, field_filters_dict, filters_name_dict):
        """
        搜刮每个字段可用的过滤器
        meta.filters = {"name":{},"*":{}} 废弃，需要指明过滤器的类
        meta.filters = {"name":["eq","ne"],"*":{}}
        meta.filters = ("name","id")

        :param fields: 字段实例
        :param filters_expression: 资源指定的过滤器
        :param field_filters_dict: 字段可用过滤器字典
        :param filters_name_dict: 过滤字名称字典
        :return:
        """
        filters = {}
        for field_name, field in fields.items():
            field_class_filters = set()  # 名称
            # todo:此处的逻辑是子类必然会使用父类的过滤器 应该是子类只能优先用自己的过滤器 x
            for cls in (field.__class__,) + field.__class__.__bases__:  # 字段和其父类
                if cls in field_filters_dict:
                    field_class_filters.update(field_filters_dict[cls])

            field_filters = {name: filters_name_dict[name] for name in field_class_filters}
            if isinstance(filters_expression, dict):
                try:
                    field_expression = filters_expression[field_name]
                except KeyError:
                    try:
                        field_expression = filters_expression["*"]
                    except KeyError:
                        continue
                if isinstance(field_expression, (list, tuple)):  # 如果是名称元组
                    field_filters = {name: ft for (name, ft) in field_filters.items() if name in field_expression}
                elif field_expression is not True:
                    continue
            elif isinstance(filters_expression, (tuple, list)):  # 可以用的过滤器
                if field_name in filters_expression:
                    filters[field_name] = field_filters
                continue
            elif filters_expression is not True:
                continue
            if field_filters and "r" in field.io:  # filters_expression 为True，只增加可读的
                filters[field_name] = field_filters  # 某个字段的所有过滤器名的字典
        return filters

    def _is_sortable_field(self, field):
        return isinstance(
            field,
            (
                Str,
                Bool,
                Float,
                Int,
                Date,
                DateTime,
                ResUri,
            ),
        )

    @staticmethod
    def _init_key_converters(resource, meta):
        if "natural_key" in meta:
            if isinstance(meta.natural_key, str):
                meta["key_converters"] += (_NaturalKey(meta.natural_key),)
            elif isinstance(meta.natural_key, (list, tuple)):
                meta["key_converters"] += (_MultiNaturalKey(*meta.natural_key),)
        if "key_converters" in meta:
            meta.key_converters = [k.bind(resource) for k in meta["key_converters"]]
            meta.key_converters_by_type = {}
            for kc in meta.key_converters:
                if kc.matcher_type in meta.key_converters_by_type:
                    raise RuntimeError(f"Multiple keys of type {kc.matcher_type} defined for {meta.name}")
                meta.key_converters_by_type[kc.matcher_type] = kc

    def _post_init(self, resource, meta):  # noqa
        meta.id_attribute = self.id_attribute
        if meta.id_converter is None:
            meta.id_converter = getattr(meta.id_field_class, "url_rule_converter", None)

    @staticmethod
    def _get_field_from_python_type(python_type):
        try:
            return {
                str: Str,
                int: Int,
                float: Float,
                bool: Bool,
                list: List,
                dict: Dict,
                date: Date,
                datetime: DateTime,
                decimal.Decimal: Float,
            }[python_type]
        except KeyError:
            raise RuntimeError(f'No appropriate field class for "{python_type}" type found')

    def relation_instances(self, item, attribute, target_resource, page=None, per_page=None):
        raise NotImplementedError

    def relation_add(self, item, attribute, target_resource, target_item):
        raise NotImplementedError

    def relation_remove(self, item, attribute, target_resource, target_item):
        raise NotImplementedError

    def paginated_instances(self, page, per_page, where=None, sort=None, options=None):
        pass

    def instances(self, where=None, sort=None, options=None):
        return []

    def first(self, where=None, sort=None):
        try:
            return self.instances(where, sort)[0]
        except IndexError:
            raise ItemNotFound(self.resource, where=where)

    def all(self, where=None, sort=None):
        pass

    def create(self, properties, commit=True):
        pass

    def read(self, id):  # noqa
        pass

    def update(self, item, changes, commit=True):
        pass

    def delete(self, item):
        pass

    def delete_by_id(self, id):  # noqa
        return self.delete(self.read(id))

    def commit(self):
        pass

    def begin(self):
        pass


class _RelationManager(Manager):
    def _query(self):
        raise NotImplementedError

    def _query_filter(self, query, expression):
        raise NotImplementedError

    def _query_filter_by_id(self, query, id):  # noqa
        raise NotImplementedError

    def _expression_for_join(self, attribute, expression):
        raise NotImplementedError

    def _expression_for_ids(self, ids):
        raise NotImplementedError

    def _expression_for_condition(self, condition):
        raise NotImplementedError

    def _or_expression(self, expressions):
        raise NotImplementedError

    def _and_expression(self, expressions):
        raise NotImplementedError

    def _query_order_by(self, query, sort=None):
        raise NotImplementedError

    def _query_get_paginated_items(self, query, page, per_page):
        raise NotImplementedError

    def _query_get_all(self, query):
        raise NotImplementedError

    def _query_get_one(self, query):
        raise NotImplementedError

    def _query_get_first(self, query):
        raise NotImplementedError

    def paginated_instances(self, page, per_page, where=None, sort=None, options=None):
        instances = self.instances(where=where, sort=sort, options=options)
        if isinstance(instances, list):  # 这里是方便我们实现别的接口返回list
            return Pagination.from_list(instances, page, per_page)
        return self._query_get_paginated_items(instances, page, per_page)

    def instances(self, where=None, sort=None, options=None):
        query = self._query()
        if query is None:
            return []
        if where:
            where = tuple(self._convert_filters(where))
            expressions = [
                self._expression_for_condition(condition) if isinstance(condition, _Condition) else condition
                for condition in where
            ]
            query = self._query_filter(query, self._and_expression(expressions))
        if sort:
            sort = tuple(self._convert_sort(sort))
            query = self._query_order_by(query, sort)
        if options:
            query = query.with_entities(*options)
        return query

    @cached_property
    def _sort_fields(self):
        return {
            name: field
            for (name, field) in self.resource.schema.readable_fields.items()
            if name in self.filters and self._is_sortable_field(field)
        }

    def _convert_sort(self, sort):
        for name, reverse in sort.items():
            field = self._sort_fields[name]
            yield field, field.attribute or name, reverse

    def first(self, where=None, sort=None):
        try:
            return self._query_get_first(self.instances(where, sort))
        except IndexError:
            raise ItemNotFound(self.resource, where=where)

    def read(self, id):  # noqa
        query = self._query()
        if query is None:
            raise ItemNotFound(self.resource, id=id)
        return self._query_filter_by_id(query, id)

    def all(self, where=None, sort=None):
        try:
            return self._query_get_all(self.instances(where, sort))
        except IndexError:
            raise ItemNotFound(self.resource, where=where)

    @staticmethod
    def convert_filters(value, field_filters):
        if isinstance(value, dict) and len(value) == 1:
            filter_name = next(iter(value))
            if filter_name.startswith("$") and len(filter_name) > 1:
                filter_name = filter_name[1:]
                ft = field_filters.get(filter_name, None)
                if ft is not None:
                    return ft.convert(value)
        ft = field_filters.get("eq", None)
        if ft is None:
            raise ValueError("Filter 'eq' is not defined")
        return ft.convert({"$eq": value})

    def _convert_filters(self, where):  # 将转换where的步骤移到manager中，使得在查询之前可以修改where
        for name, value in where.items():
            if "." in name:
                # Todo 这里初步实现了联合查询，只支持一个级别的外键，即只有1个.号
                k, v = name.rsplit(".", 1)
                target = self.resource.schema.fields[k].target
                condition = self.convert_filters(value, target.manager.filters[v])
                expression = target.manager._expression_for_condition(condition)  # noqa
                yield self._expression_for_join(k, expression)  # 返回表达式
            elif name == "$like":
                or_expressions = []
                for field_name in self.resource.meta.get("fuzzy_fields", ()):
                    condition = self.convert_filters({"$ci": value["$eq"]}, self.filters[field_name])
                    or_expressions.append(self._expression_for_condition(condition))
                yield self._or_expression(or_expressions)
            else:
                try:
                    yield self.convert_filters(value, self.filters[name])  # Condition条件实力
                except KeyError:
                    raise InvalidFilter(f"Filter <{name}> is not allowed")


class SQLAlchemyManager(_RelationManager):
    filter_class = _SQLAlchemyFilter
    pagination_classes = (Pagination, _Pagination)

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

        self.id_field = self._get_field_from_column(self.id_column, self.id_attribute, io="r")
        self.default_sort_expression = self._get_sort_expression(model, meta, self.id_column)

        fs = resource.schema
        if meta.include_id:
            fs.set("$id", self.id_field)
        else:
            fs.set("$uri", ResUri(resource, attribute=self.id_attribute))

        # resource name: use model table's name if not set explicitly
        if not hasattr(resource.Meta, "name"):
            meta["name"] = model.__tablename__.lower()

        fs = resource.schema
        include_fields = meta.get("include_fields", None)
        exclude_fields = meta.get("exclude_fields", None)
        read_only = meta.get("read_only", ())
        write_only = meta.get("write_only", ())
        pre_declared_fields = {f.attribute or k for k, f in fs.fields.items()}
        # note this is the magic
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
                if name in read_only:
                    io = "r"
                elif name in write_only:
                    io = "w"

                if "w" in io and not (column.nullable or column.default):
                    fs.required.add(name)
                fs.set(name, self._get_field_from_column(column, name, io=io))

    @staticmethod
    def _get_sort_expression(model, meta, id_column):
        if meta.sort_attribute is None:
            return id_column.asc()

        attr_name, reverse = meta.sort_attribute
        attr = getattr(model, attr_name)
        return attr.desc() if reverse else attr.asc()

    def _get_field_from_column(self, column, attribute, io="rw"):
        args = ()
        kwargs = {}

        if isinstance(column.type, postgresql.ARRAY):
            field_class = List
            args = (Str,)
        # elif isinstance(column.type, postgresql.UUID):
        #     field_class = UUID
        elif isinstance(column.type, String) and column.type.length:
            field_class = Str
            kwargs = {"max_length": column.type.length}
        elif isinstance(column.type, postgresql.HSTORE):
            field_class = Dict
            args = (Str,)
        elif hasattr(postgresql, "JSON") and isinstance(column.type, (postgresql.JSON, postgresql.JSONB)):
            field_class = Field
            kwargs = {"schema": {}}
        else:
            try:
                python_type = column.type.python_type
            except NotImplementedError:
                raise RuntimeError(
                    f"Unable to auto-detect the correct field type for {column}! "
                    f"You need to specify it manually in ModelResource.Schema"
                )
            field_class = self._get_field_from_python_type(python_type)

        kwargs["nullable"] = column.nullable
        if column.info and not kwargs.get("description"):
            kwargs["description"] = column.info

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
        if isinstance(field, Ref):
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

    def _query_filter_by_id(self, query, id):  # noqa
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

            if isinstance(field, Ref):
                target_alias = aliased(field.target.meta.model)
                query = query.outerjoin(target_alias, column).reset_joinpoint()
                sort_attribute = None
                if field.target.meta.sort_attribute:
                    sort_attribute, _ = field.target.meta.sort_attribute
                column = getattr(
                    target_alias,
                    sort_attribute or field.target.manager.id_attribute,
                )

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
                raise BackendConflict(
                    debug_info=dict(
                        exception_message=str(e),
                        statement=e.statement,
                        params=e.params,
                    )
                )
            raise BackendConflict()

        after_create.send(self.resource, item=item)
        return item

    def update(self, item, changes, commit=True):
        session = self._get_session()

        actual_changes = {
            key: value for key, value in changes.items() if self._is_change(_getattr(item, key, None), value)
        }

        try:
            before_update.send(self.resource, item=item, changes=actual_changes)

            for key, value in changes.items():
                setattr(item, key, value)

            self.commit_or_flush(commit)
        except IntegrityError as e:
            session.rollback()
            if current_app.debug:
                raise BackendConflict(
                    debug_info=dict(
                        exception_message=str(e),
                        statement=e.statement,
                        params=e.params,
                    )
                )
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
                raise BackendConflict(
                    debug_info=dict(
                        exception_message=str(e),
                        statement=e.statement,
                        params=e.params,
                    )
                )
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
        before_relate.send(self.resource, item=item, attribute=attribute, child=target_item)  # 增加关联对象之前
        getattr(item, attribute).append(target_item)  # 一对多
        after_relate.send(self.resource, item=item, attribute=attribute, child=target_item)

    def relation_remove(self, item, attribute, target_resource, target_item):
        session = self._get_session()
        before_remove.send(self.resource, item=item, attribute=attribute, child=target_item)
        try:
            session.delete(target_item)
            getattr(item, attribute).remove(target_item)
            after_remove.send(self.resource, item=item, attribute=attribute, child=target_item)
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


# ----------------------------------------权限控制-------------------------------
class _Need:  # 混合需求
    def __call__(self, item):
        raise NotImplementedError

    def __hash__(self):  # 需要可以放到 set 里
        return hash(self.__repr__())

    def load_needs_from_identity(self):
        return None


class _ItemNeed(_Need):
    """权限的描述
    Need(method,value)
    UserNeed('12345') 表示id为‘12345’的用户有的权限，yield need[1]->12345
    RoleNeed('admin') 表示角色为admin的用户有的权限, yield need[1]->admin
    TypeNeed('old') 表示类型为old的用户有的权限, yield need[1]->old
    ActionNeed('start') 表示有 start 这个动作的权限，yield need[1]->start
    ItemNeed(method,value,type)
    ItemNeed('update',20,'user') 表示拥有更新某个实体的权限 yield need[1]->200

    _ItemNeed(method,resource,type_)
    表示操作某个资源的权限，method 是curd等
    调用: id 退回 UserNeed 否则退回 ItemNeed

    """

    def __init__(self, method, resource, type_=None):
        self.method = method
        self.type = type_ or resource.meta.name
        self.resource = resource  # todo 改成引用
        self.fields = []

    def load_needs_from_identity(self):
        if self.method == "id":
            prototype = ("id", None)
        else:
            prototype = (self.method, None, self.type)

        for need in g.identity.provides:
            if len(need) == len(prototype):
                if all(p is None or n == p for n, p in zip(need, prototype)):
                    yield need[1]

    def extend(self, field):
        return _RelationNeed(self.method, field)

    def __call__(self, item):
        if self.method == "id":
            return UserNeed(_getattr(self.resource.manager.id_attribute, item, None))
        return ItemNeed(
            self.method,
            _getattr(self.resource.manager.id_attribute, item, None),
            self.type,
        )

    def __eq__(self, other):
        return (
            isinstance(other, _ItemNeed)
            and self.method == other.method
            and self.type == other.type
            and self.resource == other.resource
        )

    def __repr__(self):
        return f"<_ItemNeed method='{self.method}' type='{self.type}'>"


class _RelationNeed(_ItemNeed):
    """
    用于表示关系要求:
        联系实际：你爸是局长，这就是一个关系的权限
        翻译成代码就是：user.father.role: police
        _RelationNeed('role','police','father')
        更长的话：你爸爸的妈妈是老师
        _RelationNeed('role','teacher','father','mother')
    """

    def __init__(self, method, *fields):
        super().__init__(method, fields[-1].resource, fields[-1].target.meta.name)
        self.fields = fields
        self.final_field = self.fields[-1]

    def __call__(self, item):
        if item is None:
            if self.method == "id":
                return UserNeed(None)
            return ItemNeed(self.method, None, self.type)

        for field in self.fields:
            item = getattr(item, field.attribute)

        item_id = getattr(item, self.final_field.resource.manager.id_attribute, None)

        if self.method == "id":
            return UserNeed(item_id)
        return ItemNeed(self.method, item_id, self.type)

    def __eq__(self, other):
        return (
            isinstance(other, _ItemNeed)
            and self.method == other.method
            and self.resource == other.resource
            and self.fields == other.fields
        )

    def extend(self, field):
        return _RelationNeed(self.method, field, *self.fields)

    def __repr__(self):
        return f"<_RelationNeed method='{self.method}' type='{self.type}' {self.fields}>"


class _UserNeed(_RelationNeed):
    def __init__(self, field):
        super().__init__("id", field)

    def __repr__(self):
        return f"<_UserNeed {self.type} {self.fields}>"


class _Permission(Permission):
    def __init__(self, *needs):
        super().__init__(*needs)
        self.needs = set()
        self.standard_needs = set()

        for need in needs:
            if isinstance(need, _Need):
                self.needs.add(need)
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
        for need in self.needs:
            resolved_need = need(item)  # need 可以调用item
            if resolved_need in g.identity.provides:
                return True
        return False


class _PrincipalMixin:  # 鉴权插件
    resource = None

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        raw_needs = dict(read="yes", creat="no", update="create", delete="update")
        raw_needs.update(self.resource.meta.get("permissions", {}))
        self._raw_needs = raw_needs  # 粗的权限字典

    @cached_property
    def _needs(self):
        """
        class _Schema:
            id = UUID()
            name = Str()
            age = Int()
            father = Ref('self')

        - {'create':'yes'} --> {'create':{True}}
        - {'create':'no'} --> {'create':{Permission(("permission-denied",)),}}
        - {'update':'create'}
        - {'create':'create'}-->{'create':{_ItemNeed('create',ModelResource)}}
        - {'create':'user:father'} -->{'create':{_UserNeed('father')}}
        - {'create':'role:father'} -->{'create':{RoleNeed('father')}}
        - {'create':'create:father'} -->{'create':{RoleNeed('father')}}
        - {'create':'admin'} -->{'create':{RoleNeed('admin')}}
        - {'create':'user:$id'} -->{'create':{_ItemNeed('id',HumanResource)}}
        :return:
        :rtype:
        """
        needs_map = self._raw_needs.copy()
        methods = needs_map.keys()  # 资源的权限只有四个词curd

        def convert(method, needs, map, path=()):  # noqa
            options = set()  # 权限集合 Permission obj

            if isinstance(needs, str):  # 权限字符
                needs = [needs]  # noqa 原来的needs可能是字符串和tuple
            if isinstance(needs, set):  # 权限集合直接返回
                return needs

            for need in needs:
                if need in ("yes", "everyone", "anyone"):  # 全权
                    return {True}
                if need in ("no", "nobody", "none"):  # 无权
                    options.add(Permission(("permission-denied",)))
                elif need in methods:  # 如果权限也是 curd 词
                    if need in path:
                        raise RuntimeError(f"Circular permissions in {self.resource} (path: {path})")
                    if need == method:  # 和自身相同
                        options.add(_ItemNeed(method, self.resource))
                    else:
                        path += (method,)  # 用过的方法不可再用
                        options |= convert(need, map[need], map, path)  # 递归

                elif ":" in need:
                    role, value = need.split(":")
                    field = self.resource.schema.fields[value]
                    # schema中的字段
                    if field.attribute is None:
                        field.attribute = value

                    if isinstance(field, Ref):  # 一对一的
                        target = field.target  # 目标

                        if role == "user":  # user:attr
                            options.add(_UserNeed(field))
                        elif role == "role":  # role:xxx
                            options.add(RoleNeed(value))  # 需要用户的角色为xxx
                        else:  # 既不是user又不是role会是啥
                            for imported_need in target.manager.needs[role]:
                                if isinstance(imported_need, _ItemNeed):
                                    imported_need = imported_need.extend(field)  # 目标集合增加当前字段
                                options.add(imported_need)

                    elif role == "user" and value in [
                        "$id",
                        "$uri",
                    ]:  # user:$id
                        options.add(_ItemNeed("id", self.resource))  # _ItemNeed 需要id与当前用户id相同
                else:
                    options.add(RoleNeed(need))  # 角色

            return options

        for method, needs in needs_map.items():
            converted_needs = convert(method, needs, needs_map)
            needs_map[method] = converted_needs  # noqa

        return needs_map

    @cached_property
    def _permissions(self):
        permissions = {}

        for method, needs in self._needs.items():
            if True in needs:  # noqa
                needs = set()
            permissions[method] = _Permission(*needs)

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
        if not permission.needs:
            return None

        expressions = []

        for need in permission.needs:
            ids = list(need.load_needs_from_identity())

            if not ids:
                continue

            if len(need.fields) == 0:
                expression = self._expression_for_ids(ids)  # noqa
            else:
                expression = need.fields[-1].target.manager._expression_for_ids(ids)  # noqa

                for field in reversed(need.fields):
                    expression = field.resource.manager._expression_for_join(field.attribute, expression)  # noqa

            expressions.append(expression)

        if not expressions:
            return None

        return self._query_filter(query, self._or_expression(expressions))  # noqa

    def _query(self, **kwargs):
        query = super()._query(**kwargs)  # noqa

        read_permission = self._permissions["read"]
        query = self._query_filter_permission(query, read_permission)

        if query is None and all(need.method == "role" for need in read_permission.needs):  # noqa
            raise Forbidden()

        return query

    def relation_instances(self, item, attribute, target_resource, page=None, per_page=None):  # noqa
        query = getattr(item, attribute)

        if isinstance(query, InstrumentedList):
            if page and per_page:
                return Pagination.from_list(query, page, per_page)
            return query

        target_manager = target_resource.manager
        if isinstance(target_manager, _PrincipalMixin):
            query = target_manager._query_filter_read_permission(query)

        if page and per_page:
            return target_manager._query_get_paginated_items(query, page, per_page)  # noqa

        return target_manager._query_get_all(query)  # noqa

    def create(self, properties, commit=True, force=False):
        """force供内部更新,绕过权限检查"""
        if force or self._permissions["create"].can(properties):
            return super().create(properties, commit)  # noqa
        raise Forbidden()

    def update(self, item, changes, commit=True, force=False):
        if force or self._permissions["update"].can(item):
            return super().update(item, changes, commit)  # noqa
        raise Forbidden()

    def delete(self, item, commit=True, force=False):
        if force or self._permissions["delete"].can(item):
            return super().delete(item, commit)  # noqa
        raise Forbidden()


def principals(manager):
    if not issubclass(manager, _RelationManager):
        raise RuntimeError("principals() only works with managers that inherit from _RelationManager")

    class PrincipalsManager(_PrincipalMixin, manager):
        pass

    return PrincipalsManager


_HTTP_VERBS_CN = {
    "create": "创建{}",
    "destroy": "删除{}",
    "instances": "查询{}列表",
    "self": "查询{}详情",
    "update": "修改{}",
}


def _get_description(resource, name):
    field = resource.schema.fields.get(name, None)
    if field and field.description:
        return field.description
    model_field = getattr(resource.meta.model, name, None)
    if model_field and model_field.info:
        return model_field.info
    return name


def _get_example(resource, name):
    field = resource.schema.fields.get(name, None)
    if field:
        return field.faker()
    return name


def _schema_to_swag_dict(route, resource):  # noqa
    schema = route.schema_factory(resource)
    tags = [resource.meta.title or resource.meta.name]
    method = schema.get("method", "")
    href = schema.get("href", "")
    rel = schema.get("rel", "")
    rel_cn = _HTTP_VERBS_CN.get(rel, None)
    title = rel_cn.format(tags[0]) if rel_cn else rel
    summary = route.description or title
    flasgger_dict = {
        "summary": summary,
        "tags": tags or [],
        "parameters": [],
        "responses": {"200": {"description": "success", "examples": ""}},
    }

    _schema = schema.get("schema", {})

    for i in re.findall("{(.+?)}", href):
        parameter = {
            "in": "path",
            "name": i,
            "type": "string",
            "required": True,
            "description": f"the {i} of the {resource.meta.name}",
        }
        flasgger_dict["parameters"].append(parameter)

    if method == GET:
        required_props = _schema.get("required", [])
        for prop, details in _schema.get("properties", {}).items():
            parameter = {
                "name": prop,
                "in": "query",
                "type": details.get("type", "string") if details.get("type") != "null" else "string",
                "required": prop in required_props,
                "description": details.get("description", ""),
            }
            if prop == "where":
                parameter["description"] = (
                    '过滤条件,格式如{field:{"$op":value}},'
                    + f"当前field有{resource.meta.filters}"
                    + "其中op可以是eq|ne|lt|le|gt|ge|si|sw|ei|ew|cw|ct等."
                    "特例，如果是等于关系可省去$eq,如{field:value}，"
                    "如果是模糊查询可不指定字段，而使用$like,如{$like:value}"
                )
            elif prop == "sort":
                parameter["description"] = '排序条件,格式如{"name":true,"age":false} 表示按name降序,按age升序'
            elif prop == PAGE:
                parameter["description"] = "分页页码,默认为 1"
            elif prop == PER_PAGE:
                parameter["description"] = f"每页数量,默认为{DEFAULT_PER_PAGE},最大值为{MAX_PER_PAGE}"
            flasgger_dict["parameters"].append(parameter)
        # 获取输出样例
        response_schema = route.response_example(resource)
        flasgger_dict["responses"]["200"] = {  # noqa
            "description": "success",
            "schema": response_schema,
        }

    elif method[0] == "P":
        if rel == "create":
            request_schema = resource.schema.request
        elif rel == "update":
            request_schema = resource.schema.update
        else:
            request_schema = route.request_schema.request if route.request_schema else {}

        for k, v in request_schema.get("properties", {}).items():
            v["description"] = _get_description(resource, k)
            v["example"] = _get_example(resource, k)

        flasgger_dict["parameters"].append(
            {
                "in": "body",
                "name": "Item",
                "schema": request_schema,
            }
        )

    return flasgger_dict


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
        self.default_manager = default_manager or SQLAlchemyManager
        if app is not None:
            self.init_app(app)

    def init_app(self, app):
        app.config.setdefault("RESTONE_MAX_PER_PAGE", MAX_PER_PAGE)
        app.config.setdefault("RESTONE_DEFAULT_PER_PAGE", DEFAULT_PER_PAGE)
        app.config.setdefault("RESTONE_DEFAULT_PARSE_STYLE", "json")
        app.config.setdefault("RESTONE_DECORATE_SCHEMA_ENDPOINTS", True)
        app.config.setdefault("RESTONE_REGISTER_SWAGGER_ENDPOINTS", True)

        self._register_view(
            app,
            rule="".join((self.prefix, "/schema")),
            view_func=self._schema_view,
            endpoint="schema",
            methods=[GET],
            relation="describedBy",
        )
        for (
            route,  # noqa
            resource,
            view_func,
            endpoint,
            methods,
            relation,
        ) in self.views:
            rule = route.rule_factory(resource)
            if app.config["RESTONE_DECORATE_SCHEMA_ENDPOINTS"]:
                self._register_swag_view(app, route, resource, view_func)

            self._register_view(app, rule, view_func, endpoint, methods, relation)
        app.handle_exception = partial(self._exception_handler, app.handle_exception)
        app.handle_user_exception = partial(self._exception_handler, app.handle_user_exception)

    @staticmethod
    def _register_swag_view(app, route, resource, view_func):  # noqa
        """注册到 swagger"""
        with app.app_context():
            swag_from(_schema_to_swag_dict(route, resource))(view_func)

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

    @staticmethod
    def output(view):
        @wraps(view)
        def wrapper(*args, **kwargs):
            resp = view(*args, **kwargs)
            if isinstance(resp, Response):
                return resp
            (data, code, headers) = _unpack(resp)
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
        return (
            OrderedDict(schema),
            200,
            {"Content-Type": "application/schema+json"},
        )

    def add_route(self, route, resource, endpoint=None, decorator=None):  # noqa
        endpoint = endpoint or "_".join((resource.meta.name, route.relation))
        methods = [route.method]
        rule = route.rule_factory(resource)
        view_func = route.view_factory(endpoint, resource)
        if decorator:
            view_func = decorator(view_func)
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
                    f"'{resource.meta.name}' has no manager, and no default manager has been defined. "
                    f"If you're using Restone with SQLAlchemy, ensure you have installed Flask-SQLAlchemy."
                )
        resource.api = self
        resource.route_prefix = "".join((self.prefix, "/", resource.meta.name))
        for rt in resource.routes.values():
            route_decorator = resource.meta.route_decorators.get(rt.relation, None)
            # route.relation 是字符 如"read_xxx" 则是 装饰器字典，用于装饰这个函数
            self.add_route(rt, resource, decorator=route_decorator)
        # 以键值对返回成员 返回满足 lambda m: isinstance(m, _RouteSet) 的成员，也就是 RouteSet及子类的实例
        for name, route_set in inspect.getmembers(resource, lambda m: isinstance(m, _RouteSet)):
            if route_set.attribute is None:
                route_set.attribute = name
                # 没有属性就用自己名字做属性 如 status = AttrRoute(field_cls_or_instance,io='ru')
            for i, rt in enumerate(route_set.routes()):
                if rt.attribute is None:
                    rt.attribute = f"{route_set.attribute}_{i}"
                resource.routes[f"{route_set.attribute}_{rt.relation}"] = rt
                self.add_route(rt, resource)
        self.resources[resource.meta.name] = resource
