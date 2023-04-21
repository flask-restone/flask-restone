![logo](./docs/restone.png)
# flask_restone
## 特性
flask_restone 是一个基于 Flask 的 RESTful API 框架，提供了以下特性：

### Abstract:

- Schema：用于数据模型的定义
- BaseField：模型属性的基础类

### Fields:

- String：字符串类型
- Integer：整数类型
- Number：数值类型
- Boolean：布尔类型
- Object：对象类型
- Array：数组类型
- Any：任意类型
- AnyOf：其中一个类型
- ToOne：一对一关系
- ToMany：一对多关系
- Inline：内联对象
- InlineModel：内联模型
- Instances：实例类型
### Types:

Str：字符串类型
- Str[1:9]：表示长度为 1~9 的字符串
- Str[:9]：表示长度小于等于 9 的字符串
- Str[9:]：表示长度大于等于 9 的字符串
- Str[9]：表示固定长度为 9 的字符串

Int：整数类型
- Int[1:9]：表示取值范围为 1~9 的整数，包括端点
- Int[0:]：表示大于等于 0 的整数
- Int[:9]：表示小于等于 9 的整数
- Int[9]：表示默认值为 9 的整数

Float：浮点数类型
- Float[0<x<1]：表示取值范围为 0 和 1 之间的浮点数
- Float[0<=x<=1]：表示取值范围为 0 和 1 之间的浮点数，包括端点
- Float[0<x<=1]：表示取值范围为 0 和 1，但不包括 0 的浮点数
- Float[x>0]：表示大于 0 的浮点数

Bool：布尔类型
- Bool[0] 或 Bool[False]：表示默认值为 0 或 False 的布尔类型
- Bool[1] 或 Bool[True]：表示默认值为 1 或 True 的布尔类型

Dict：字典类型
- Dict["self"]：表示对自身的引用，可以实现嵌套字典
- Dict[Pattern["\d"], Str]：指定键名的模式和值的类型，可以实现带约束的字典
- Dict["name":Str,"age":Int]：列出键名和对应值的类型，方便使用

List：列表类型
- List[Str]：表示字符串列表
- List[Str,1:5]：表示长度为 1~5 的字符串列表
- List[Str,5]：表示长度为 5 的字符串列表
- List[Str,1:]：表示至少包含一个元素的字符串列表
- List[Str,:5]：表示长度小于等于 5 的字符串列表

Tuple：元组类型
- Tuple[Str,Int]：表示由字符串和整数组成的元组
- Tuple[Int,Int,Int]：表示含有三个整数元素的元组

Format：格式化类型
- Format["uuid"]：表示符合 UUID 规范的字符串
- UUID：表示 UUID 类型
- URI：表示 URI 类型
- EMAIL：表示 EMAIL 类型
- ...

Pattern：模式类型
- Pattern["\d{4}"]：表示匹配满足正则表达式 "\d{4}" 的字符串

Literal：字面量
- Literal["a","b","c"]：表示枚举类型，取值为 a、b 或 c

Optional：可选类型
- Optional[Str]：表示可选字符串类型

ReadOnly：只读类型
- ReadOnly[Str]：表示只读字符串类型

WriteOnly：只写类型
- WriteOnly[Str]：表示不可读、只写字符串类型

Union：联合类型
- Union[Str,Int]：表示字符串或整数类型

Any：任意类型
- Any：表示任何数据类型，不做特定的检查

### Route:

- @Route.get：GET 请求
- @Route.post：POST 请求
- @Route.patch：PATCH 请求，用于批量操作
- @ItemRoute.get：获取单个资源
- @ItemRoute.put：更新单个资源
- @ItemRoute.delete：删除单个资源
### RouteSet:

- AttrRoute：属性路由
- Relation：关系路由
### Resource:

- ModelResource：模型资源
- Resource：资源
### Filters:

- BaseFilter：基础过滤器
- SqlAlchemyFilter：SQLAlchemy 过滤器
Pagination:

### Manager:

- RelationManager：关系管理器
- SQLAlchemyManager：SQLAlchemy 管理器
- DataFrameManager：DataFrame 管理器
- PricipalManager：权限管理器
### Needs & Permissions:

需求和权限
### Signals:

- before_create：创建资源前的信号
- after_create：创建资源后的信号
- before_update：更新资源前的信号
- after_update：更新资源后的信号
- before_delete：删除资源前的信号
- after_delete：删除资源后的信号
- before_relate：关联资源前的信号
- after_relate：关联资源后的信号
- before_unrelate：解除关联资源前的信号
- after_unrelate：解除关联资源后的信号 
- ModelResource.on_before_create：模型资源创建前的信号

### API:

- swagger：API 文档生成
- docxtemplate：使用模板生成 Word 文档
