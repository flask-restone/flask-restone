import ast
import inspect
# from celery import Celery
from functools import wraps

from flasgger import Swagger
from flask import Flask, jsonify
from flask_login import LoginManager, UserMixin
from flask_principal import (AnonymousIdentity, Identity, Permission, Principal,
                             RoleNeed, UserNeed, identity_loaded)
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import backref
from werkzeug.exceptions import Forbidden

from src.flask_restone import (Api, Dict, Int, ModelResource, need, Relation,
                               Res, Str, itemroute, need, route)

app = Flask(__name__)
# celery = Celery(app.name,
#                 broker='redis://localhost:6379/0',
#                 backend='redis://localhost:6379/0')

# 应用配置
app.config['SQLALCHEMY_DATABASE_URI'] = "sqlite:///restone.db"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'xxx123'

# 方式1: 初始化组件对象, 直接关联Flask应用
db = SQLAlchemy(app)


class Author(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(), nullable=False)
    last_name = db.Column(db.String(), nullable=False)


class Book(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    author_id = db.Column(db.Integer, db.ForeignKey(Author.id), nullable=False)
    
    title = db.Column(db.String(), nullable=False)
    year_published = db.Column(db.Integer)
    
    author = db.relationship(Author, backref=backref('books'))


with app.app_context():
    db.create_all()

# @celery.task(bind=True)
# def long_task(self, total: Int, message: Str = 100):
#     """长时间任务"""
#     # 解析需要的参数
#     verb = ['Starting up', 'Booting', 'Repairing', 'Loading', 'Checking']
#     adjective = ['master', 'radiant', 'silent', 'harmonic', 'fast']
#     noun = ['solar array', 'particle reshaper', 'cosmic ray', 'orbiter', 'bit']
#     # 利用tqdm的进度条
#     with tqdm(total=total) as pbar:
#         # 内部进行具体的耗时任务
#         for i in range(total):
#             if not message or random.random() < 0.25:
#                 message = '{0} {1} {2}...'.format(random.choice(verb),
#                                                   random.choice(adjective),
#                                                   random.choice(noun))
#             time.sleep(1)
#
#             # 每一步结尾，更新状态信息
#             pbar.update()
#             pbar.set_description(desc=message)
#             rate = pbar.format_dict['rate']
#             n = pbar.format_dict['n']
#             remaining = (total - n) / rate if rate and total else 0
#             remaining_str = tqdm.format_interval(remaining) if rate else '?'
#
#             self.update_state(state='PROGRESS',
#                               meta={'current'  : i,
#                                     'total'    : total,
#                                     'status'   : message,
#                                     'remaining': remaining_str,
#                                     })
#
#     return {'current'  : total, 'total': total, 'status': 'Task completed!',
#             'remaining': '00:00', 'result': 42}

login_manager = LoginManager(app)


class BookResource(ModelResource):
    # task = TaskRoute(long_task)
    
    class Schema:
        author = Res("authors", io='r')
        title = Str
        year_published = Int
        author_id = Int(io='w')
    
    class Meta:
        model = Book
        name = 'books'
        include_id = True
    
    @itemroute.get
    def year_published(self: need(r'author',f'author'), item) -> Int():
        return item.year_published
    
    @route.post("/person")
    def person(self,  # 路由权限注解
               name: Str[1:5],  # 参数注解
               age: Int[0:100],
               gender: Str("M|F"),
               address: Dict(name=Str, city=Str, street=Int)):
        """文档由 docstring 自动生成"""
        
        return jsonify(dict(name=name, age=age, gender=gender, address=address))


# func = BookResource.year_published
# print(func.__annotations__)




class AuthorResource(ModelResource):
    books = Relation('books', uselist=True)
    
    class Schema:
        first_name = Str
        last_name = Str
    
    class Meta:
        model = Author
        name = 'authors'
        include_id = True


principals = Principal(app)


@principals.identity_loader
def read_identity_from_flask_login():
    return Identity(1)


@identity_loaded.connect_via(app)
def on_identity_loaded(sender, identity):
    if not isinstance(identity, AnonymousIdentity):
        identity.provides.add(UserNeed(identity.id))
        identity.provides.add(RoleNeed('author'))


@login_manager.user_loader
def load_user():
    return Author.query.get(1)


Swagger(app)

api = Api(prefix="/v1")
api.add_resources(BookResource,AuthorResource)

api.init_app(app)

if __name__ == '__main__':
    # login_user(Author.query.get_id(1))

    app.run(host="0.0.0.0", port="8080", debug=True)
