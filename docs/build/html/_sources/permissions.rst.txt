
.. _permissions:

===================================
Permissions with *Flask-Principal*
===================================

.. module:: flask_restone

Flask-Restone includes a permission system. The permissions system is
built on `Flask-Principal <https://pythonhosted.org/Flask-Principal/>`_.
and enabled by decorating a :class:`SQLAlchemyManager` with :class:`principals`, which returns a class
extending both the manager and `PrincipalMixin`.

Permissions are specified as a ``dict`` in ``Meta.permissions``.


Defining Permissions
====================

There are four basic *actions* --- read, create, update, delete --- for which permissions must be defined. Additional
virtual actions can be declared for various purposes.

For example, the default permission declaration looks somewhat like this:

.. code-block:: python

    class Meta:
        permissions = {
            'read': 'yes',
            'create': 'no',
            'update': 'create',
            'delete': 'update'
        }


Patterns and *Needs* they produce:

==================== ===================================== ===================================================
Pattern              Matches                               Description
==================== ===================================== ===================================================
{action}             a key in the ``permissions`` dict  If equal to the action it is declared for
                                                           --- e.g. ``{'create': 'create'}`` --- evaluate to:

                                                           ``Need({action}, resource_name)``

                                                           Otherwise re-use needs from other action.
{role}               not a key in the ``permissions`` dict ``RoleNeed({role})``
{action}:{field}     *\*:\**                               Copy ``{action}`` permissions from ``Ref``
                                                           linked resource at ``{field}``.
user:{field}         *user:\**                             ``UserNeed(item.{field}.id)`` for ``REF`` 
no, nobody           *no*                                  Do not permit.
yes, everybody       *yes*                                 Always permit.
==================== ===================================== ===================================================


.. note::

    When protecting an :class:`itemroute`, read access permissions, and updates using the resource manager  are checked automatically;
    for other actions, permissions have to be checked manually from within the function.



Example API with permissions
============================

We're going to go ahead and create an example API using :class:`PrincipalMixin` with
`Flask-Login <https://flask-login.readthedocs.org>`_ for authentication. Since there are quite a few moving parts, this
example is split up into several sections.

Our example is a simple blog with *articles* and *comments*. First, let's create the database models:

.. code-block:: python

    from flask import Flask
    from flask_sqlalchemy import SQLAlchemy
    from flask_login import UserMixin
    from sqlalchemy.orm import relationship

    app = Flask(__name__)
    app.config['SECRET_KEY'] = 'secret'  # XXX replace with actual secret and don't keep it in source code

    db = SQLAlchemy(app)


    class User(UserMixin, db.Model):
        id = db.Column(db.Integer, primary_key=True)
        username = db.Column(db.String(), nullable=False)
        is_admin = db.Column(db.Boolean(), default=False)
        is_editor = db.Column(db.Boolean(), default=False)


    class Article(db.Model):
        id = db.Column(db.Integer, primary_key=True)
        author_id = db.Column(db.Integer, db.ForeignKey(User.id), nullable=False)
        author = relationship(User)
        content = db.Column(db.Text)


    class Comment(db.Model):
        id = db.Column(db.Integer, primary_key=True)
        article_id = db.Column(db.Integer, db.ForeignKey(Article.id), nullable=False)
        author_id = db.Column(db.Integer, db.ForeignKey(User.id), nullable=False)
        article = relationship(Article)
        author = relationship(User)
        message = db.Column(db.Text)


    db.create_all()

We're going to use *Flask-Login* to authenticate requests using *Basic Authentication*:

.. code-block:: python

    from flask_login import LoginManager, current_user

    login_manager = LoginManager(app)


    @login_manager.request_loader
    def load_user_from_request(request):
        if request.authorization:
            username, password = request.authorization.username, request.authorization.password

            # XXX replace this with an actual password check.
            if username == password:
                return User.query.filter_by(username=username).first()
        return None


This is where *Flask-Principal* comes in. With every request it adds the *needs* the identity should provide.
Authenticated users are given a *user need* and maybe some *role needs*. If this example had some top-level object based permissions
(think groups, projects, teams, etc.) they would also be added here.

.. code-block:: python

    from flask_principal import Principal, Identity, UserNeed, AnonymousIdentity, identity_loaded, RoleNeed

    principals = Principal(app)

    @principals.identity_loader
    def read_identity_from_flask_login():
        if current_user.is_authenticated():
            return Identity(current_user.id)
        return AnonymousIdentity()


    @identity_loaded.connect_via(app)
    def on_identity_loaded(sender, identity):
        if not isinstance(identity, AnonymousIdentity):
            identity.provides.add(UserNeed(identity.id))

            if current_user.is_editor:
                identity.provides.add(RoleNeed('editor'))

            if current_user.is_admin:
                identity.provides.add(RoleNeed('admin'))


Finally, we create our API with the ``login_required`` decorator from *Flask-Login*.


.. code-block:: python

    from flask_login import login_required
    from flask_restone import Api, ModelResource
    from flask_restone import SQLAlchemyManager
    from flask_restone import principals

    
    class UserResource(ModelResource):
        class Meta:
            model = User


    class ArticleResource(ModelResource):
        class Schema:
            author = Res('user')

        class Meta:
            model = Article
            read_only = ['author']
            permissions = {
                'create': 'editor',
                'update': ['user:author', 'admin']
            }


    class CommentResource(ModelResource):
        class Schema:
            article = Res('article')
            author = Res('user')

        class Meta:
            model = Comment
            read_only = ['author']
            permissions = {
                'create': 'anybody',
                'update': 'user:author',
                'delete': ['update:article', 'admin']
            }
        
        def on_before_create(self,item):
            item.author_id = current_user.id
            
    api = Api(app, decorators=[login_required],default_manager=principals(SQLAlchemyManager))
    api.add_resources(UserResource)
    api.add_resource(ArticleResource)
    api.add_resource(CommentResource)



We've implemented the following permissions:

- only editors can create articles
- articles can be updated or deleted by either their authors or by admins
- comments can be created by anyone who is authenticated
- comments can updated only by the person who wrote the comment, but deleted both by admins
  and the author of the article

Now we just need to start the app:

.. code-block:: python

    if __name__ == '__main__':
        # add some example users & run the application
        db.session.add(User(username='editorA', is_editor=True))
        db.session.add(User(username='editorB', is_editor=True))
        db.session.add(User(username='admin', is_admin=True))
        db.session.add(User(username='user'))
        db.session.commit()

        app.run()

You can find the complete example code on
GitHub under::

    examples/permissions_example.py



Object-based permissions
------------------------

The example above did already *sort of* touch on object-based permissions, with the ``'user:author'`` pattern that restricts
access to the user who has authored a *comment* or *article*. We've also used permissions options, with more than one *need* potentially providing access. Finally, you have seen a hint of cascading object-based permissions with the
``'update:article'`` pattern that conditions access to the permissions on a relation.

There is another permission layer, building on :class:`flask_principal.ItemNeed`, for object-specific permissions. You would want to use them on something important, such as this *project* resource:

.. code-block:: python


    class ProjectResource(ModelResource):
        class Meta:
            manager = principals(SQLAlchemyManager)
            model = Project
            permissions = {
                'create': 'anybody',
                'update': 'manage',
                'manage': 'manage'
            }

To update a project, your identity needs this *need*::

    Need('manage', PROJECT_ID, 'project')

The pair ``{'manage': 'manage'}`` makes manage a new virtual action, which is why the :class:`Need` wants
a ``'manage'`` permission. We could also have written ``{'update': 'update'}`` --- then the required *need* would have been::

    Need('update', PROJECT_ID, 'project')

With cascading permissions, role-based, user-based, and object-based permissions you should now have all the tools to
implement all sorts of complex permissions setups.


:class:`Need` class
===============================

.. autoclass:: Need
    :members:

Route-based permissions
------------------------

.. code-block:: python

    class BookResource(ModelResource):
        class Schema:
            author = Res("authors", io='r',attribute='author')
            title = Str
            year_published = Int
            author_id = Int(io='w')

        class Meta:
            model = Book

        @itemroute.get
        def year_published(self: Need[f'author',r'admin',u'1',b'token-like-bytes'],item) -> Int():
            return item.year_published

The :class:`Need` is used to annotate `self`:

    The `f` string like `f'author'` means :class:`FieldNeed`, equals to `item.author is current_user`;
    The `r` string means :class:`RoleNeed`, equals to `current_user.role == 'admin'`;
    The `u` string means :class:`UserNeed`, equals to `current_user.id == 1`;
    The `b` string(or byte) means :class:`ByteNeed`, equals to `current_user.identity.token == 'token-like-bytes'`


Efficiency
----------


Those who have worked with Flask-Principal know that it is on its own not well-suited for object-based permissions where large numbers of objects are involved, because each permission has
to be loaded into memory as ``Need`` at the start of the session.

The permission system built into Restone introduces the :class:`Need` and :class:`Permission` classes to solve this issue.
They can either be evaluated directly or be applied to SQLAlchemy queries, and are therefore efficient with any number of object-based permissions.


.. autoclass:: Need
    :members:


.. autoclass:: Permission
    :members:
