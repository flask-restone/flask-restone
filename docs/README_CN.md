### Abstract:

- Schema：用于数据模型的定义
- Field：模型属性的基础类

### Fields:
- ModelDict：内联模型
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

Optional：可选类型
- Optional[Str]：表示可选字符串类型

Any：任意类型
- Any：表示任何数据类型，不做特定的检查

### route:

- @route.get：GET 请求
- @route.post：POST 请求
- @route.patch：PATCH 请求，用于批量操作
- @itemroute.get：获取单个资源
- @itemroute.put：更新单个资源
- @itemroute.delete：删除单个资源

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
- PrincipalManager：权限管理器
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
- before_remove：解除关联资源前的信号
- after_remove：解除关联资源后的信号 
- ModelResource.on_before_create：模型资源创建前的信号

### API:

- swagger：API 文档生成
