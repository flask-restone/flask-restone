from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flasgger import Swagger
from src.flask_restone import *

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///test.db'

db = SQLAlchemy(app)

Swagger(app)

_need_map = {'u': 'id', 'r': 'role', 'f': 'action', 'b': 'type'}


class need:
    
    def __init__(self, *args):
        self.args = args
    
    def __call__(self, func):
        """权限设置"""
        perms = []
        source = (inspect.getsource(func))
        tree = ast.parse(source)
        for node in tree.body[0].decorator_list:
            if isinstance(node, ast.Call) and node.func.id == 'need':
                for annotation in node.args:
                    value = None
                    kind = None
                    
                    if isinstance(annotation, ast.Constant):
                        value = annotation.value
                        if isinstance(value, bytes):
                            value = value.decode()
                            kind = 'b'
                        else:
                            kind = annotation.kind or 'r'
                    
                    elif isinstance(annotation, ast.JoinedStr):
                        value = annotation.values[0].value
                        kind = 'f'
                    
                    if kind:
                        perms.append(Need(_need_map[kind], value))
                break
        if perms:
            permission = Permission(*perms)
        else:
            permission = None
        
        @wraps(func)
        def wraper(*args, **kwargs):
            if permission:
                return func(*args, **kwargs)
            else:
                raise PermissionError
        
        return wraper


class Human(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50))
    age = db.Column(db.Integer)

    def __repr__(self):
        return '<Human %r>' % self.name


with app.app_context():
    db.create_all()


class HumanResource(ModelResource):
    """人力资源"""

    class Schema:
        name = Str
        age = Int

    class Meta:
        model = Human
        include_id = True

    @route.get
    def count(self) -> Int:
        """查询总量"""

    @itemroute.get
    @need
    def gender(self, item) -> Str['M|F']:
        """查询性别"""

    def on_after_create(self, item):
        pass


@app.route('/')
def index():
    # 创建 Human 对象并插入到数据库中
    human = Human(name='Tom', age=20)
    db.session.add(human)
    db.session.commit()

    # 从数据库中查询并展示所有的 Human 对象
    humans = Human.query.all()
    result = []
    for h in humans:
        result.append('Name: {}, Age: {}'.format(h.name, h.age))
    return '<br>'.join(result)


api = Api(prefix='/v1', default_manager=SQLAlchemyManager)

api.add_resource(HumanResource)
api.init_app(app)

if __name__ == '__main__':
    app.run('0.0.0.0', port=5000, debug=True)
