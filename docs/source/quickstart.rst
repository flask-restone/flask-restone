
Quick Start Guide
=================

This introductory guide describes how to set up an API using SQLAlchemy with Flask-Resone, query it, and attach routes
to resources.


A minimal Flask-Resone API looks like this:

.. module:: flask_restone

.. code-block:: python

    from flask import Flask
    from flask_sqlalchemy import SQLAlchemy
    from flask_restone import Api, ModelResource

    app = Flask(__name__)
    db = SQLAlchemy(app)

    class Book(db.Model):
        id = db.Column(db.Integer, primary_key=True)
        title = db.Column(db.Str(), nullable=False)
        year_published = db.Column(db.Integer)

    db.create_all()

    class BookResource(ModelResource):
        class Meta:
            model = Book

    api = Api(app)
    api.add_resources(BookResource)

    if __name__ == '__main__':
        app.run()

Save this as `server.py` and run it using your Python interpreter. The application will create an in-memory SQLite
database, so the state of the application will reset every time the server is restarted.

.. code-block:: bash

    $ python server.py
     * Running on http://127.0.0.1:5000/


What did we do here? We used a :class:`ModelResource` and defined a ``model`` in its :class:`Meta` property.
:class:`Meta` and :class:`Schema` are the two of the primary ways to describe resources (a third being :class:`route`,
which we'll go into later).


:class:`Meta` class attributes
------------------------------

The :class:`Meta` class is how the basic functions of a resource are defined. Besides ``model``, there
are a few other properties that control how the :class:`ModelResource` maps to the SQLAlchemy model:

=====================  ==============================  ==============================================================================
Attribute name         Default                         Description
=====================  ==============================  ==============================================================================
model                  ---                             The `Flask-SQLAlchemy` model
name                   ---                             Name of the resource; defaults to the lower-case of the `model's` table name
id_attribute           ``'id'``                        With SQLAlchemy models, defaults to the name of the primary key of `model`.
id_converter           –--                             Flask URL converter for resource routes. Typically this is inferred from `id_field_class`.
id_field_class         :class:`Int`                    Field class to use for ``"$id"``, also used to determine the URL route converter for resource routes.
include_id             ``False``                       Whether to include the id of the item as an ``"$id"`` attribute. The default is a ``"$uri"`` attribute with the URI of the item.

include_fields         ---                             A list of fields that should be imported from the `model`. By default, all
                                                       columns other than foreign key and primary key columns are imported.
                                                       :func:`sqlalchemy.orm.relationship` model attributes and hybrid properties
                                                       cannot be defined in this way and have to be specified explicitly in :class:`Schema`.
exclude_fields         ---                             A list of fields that should not be imported from the `model`.
required_fields        ---                             Fields that are automatically imported from the model are automatically
                                                       required if their columns are not `nullable` and do not have a `default`.
read_only_fields       ---                             A list of fields that are returned by the resource but are ignored in `POST`
                                                       and `PATCH` requests. Useful for e.g. timestamps.
filters                ``True``                        Used to configure what properties of an item can be filtered and what filters can be used.
write_only_fields      ---                             A list of fields that can be written to but are not returned. For secret stuff.
title                  ---                             JSON-schema title declaration
description            ---                             JSON-schema description declaration
manager                :class:`SQLAlchemyManager`      A :class:`Manager` class that takes care of reading from and writing to the data store
key_converters         ``(RefKey(), IDKey())``         A list of :class:`natural_keys.Key` instances. The first is used for formatting ``Res`` references.
natural_key            ``None``                        A string, or tuple of strings, corresponding to schema field names, for a natural key.
exclude_routes         ---                             A list of rel-strings for any previously defined routes that should not be published for this resource.
=====================  ==============================  ==============================================================================


:class:`Schema` class attributes
--------------------------------

:class:`Schema` is used to define a default schema for a resource. The :class:`Schema` class contains a set of fields
that inherit from :class:`Field`

Using `ModelResource` with a SQLAlchemy model, the schema is for the most part auto-generated for us. Yet it still on
occasion makes sense to manually describe a field. The reference field types, :class:`Res` and :class:`Many`, also
need to be set by hand.

For instance, our *book* resource only stores books produced by the printing press. Let's acknowledge this by setting a
sensible minimum for ``year_published``:

.. code-block:: python

    from flask_restone import fields

    class BookResource(ModelResource):
        class Meta:
            model = Book

        class Schema:
            year_published = Int[1400:]


.. _relationships:

Relationships
-------------

RESTful relationships create a variety of API client design and caching problems that Restone has been written to address.
To preface what you will see now, it needs to be said that Restone should be used with SPDY or the upcoming HTTP/2 as it generates more requests than some alternative
approaches.

We now have both an *author* and a *book* resource:

.. code-block:: python

    from flask import Flask
    from flask_sqlalchemy import SQLAlchemy
    from sqlalchemy.orm import backref
    from flask_restone.routes import Relation
    from flask_restone import ModelResource, fields, Api

    app = Flask(__name__)
    db = SQLAlchemy(app)

    class Author(db.Model):
        id = db.Column(db.Integer, primary_key=True)
        first_name = db.Column(db.String(), nullable=False)
        last_name = db.Column(db.Str(), nullable=False)


    class Book(db.Model):
        id = db.Column(db.Integer, primary_key=True)
        author_id = db.Column(db.Integer, db.ForeignKey(Author.id), nullable=False)

        title = db.Column(db.String(), nullable=False)
        year_published = db.Column(db.Integer)

        author = db.relationship(Author, backref=backref('books', lazy='dynamic'))

    db.create_all()

    class BookResource(ModelResource):
        class Meta:
            model = Book

        class Schema:
            author = Res('author')

    class AuthorResource(ModelResource):
        books = Relation('book')

        class Meta:
            model = Author

    api = Api(app)
    api.add_resources(BookResource,AuthorResource)

    if __name__ == '__main__':
        app.run()



We're going to add two authors and books:

.. code-block:: bash

    http :5000/author first_name=Charles last_name=Darwin

.. code-block:: http

    HTTP/1.0 200 OK
    Content-Length: 69
    Content-Type: application/json
    Date: Sat, 07 Feb 2015 12:11:33 GMT
    Server: Werkzeug/0.9.6 Python/3.3.2

    {
        "$uri": "/author/1",
        "first_name": "Charles",
        "last_name": "Darwin"
    }

.. note::

    At the moment, references always need to be declared as json-ref objects.
    This is tedious during command-line use, and an enhancement to Restone to support using ids and natural keys in requests is already in the works.

.. code-block:: bash


    http :5000/book title="On the Origin of Species" author:=1 year_published:=1859


.. code-block:: http

    HTTP/1.0 200 OK
    Content-Length: 113
    Content-Type: application/json
    Date: Sat, 07 Feb 2015 12:16:11 GMT
    Server: Werkzeug/0.9.6 Python/3.3.2

    {
        "$uri": "/book/1",
        "author": {
            "$ref": "/author/1"
        },
        "title": "On the Origin of Species",
        "year_published": 1859
    }

.. code-block:: bash

    http :5000/author first_name=James last_name=Watson > /dev/null
    http :5000/book title="The Double Helix" author:=2 year_published:=1968 > /dev/null

As you can see, references in Restone are `JSON Reference <https://tools.ietf.org/html/draft-pbryan-zyp-json-ref-03>`_ draft reference
objects. These objects always have the same format — ``{"$ref": 'target-uri'}`` — and can easily be recognized by an API client
when deserializing JSON. An API client can first check its cache for the target item and, if necessary, query it from the server.

Requests allow both plain ids and *json-ref* objects — it's all the same to the server.

There are now two ways available to us for querying the relationship between the resources. The first is the author's
``Relation('book')``, which created a new route on the *author* resource with references to the book resource. Let's query Charles' books:

.. code-block:: bash

    http :5000/author/1/books

.. code-block:: http

    HTTP/1.0 200 OK
    Content-Length: 21
    Content-Type: application/json
    Date: Sat, 07 Feb 2015 12:18:45 GMT
    Link: </author/1/books?page=1&per_page=20>; rel="self",</author/1/books?page=1&per_page=20>; rel="last"
    Server: Werkzeug/0.9.6 Python/3.3.2
    X-Total-Count: 1

    [
        {
            "$ref": "/book/1"
        }
    ]

This is not a particularly good example for using :class:`Relation`, and in fact there are few at all. There is a more
RESTful way for querying a *one-to-many* relation:

.. code-block:: bash

    http GET :5000/book where=='{"author": {"$ref": "/author/1"}}'

.. code-block:: http

    HTTP/1.0 200 OK
    Content-Length: 115
    Content-Type: application/json
    Date: Sat, 07 Feb 2015 12:34:18 GMT
    Link: </book?page=1&per_page=20>; rel="self",</book?page=1&per_page=20>; rel="last"
    Server: Werkzeug/0.9.6 Python/3.3.2
    X-Total-Count: 1

    [
        {
            "$uri": "/book/1",
            "author": {
                "$ref": "/author/1"
            },
            "title": "On the Origin of Species",
            "year_published": 1859
        }
    ]

So far, in our queries, we have used item ids and *json-ref* objects to refer to items. These *surrogate keys* can
be difficult to remember and tedious to work with on the command line — but Restone has a solution:

Natural Keys
^^^^^^^^^^^^

A *natural key* is a unique identifier that exists in the real world and is often more memorable than
a surrogate key. Restone ships with support for declaring natural keys.

The *author* model has both a first name and a last name. Together, these two names form a natural key for the *author* resource. We'll update both our database model and our resource to reflect this:

.. code-block:: python

    class Author(db.Model):
        id = db.Column(db.Integer, primary_key=True)
        first_name = db.Column(db.String(), nullable=False)
        last_name = db.Column(db.String(), nullable=False)

        __table_args__ = (
            UniqueConstraint('first_name', 'last_name'),  # unique constraint added here
        )


.. code-block:: python

    class AuthorResource(ModelResource):
        class Meta:
            model = Author
            natural_key = ('first_name', 'last_name')  # natural key declaration added here


Now our earlier query can be written using the full name of the author:


.. code-block:: bash

    http GET :5000/book where=='{"author": ["Charles", "Darwin"]}'

Natural keys can be declared as either a single unique field or a tuple of fields that are unique together.

Filtering & Sorting
-------------------

Instances of a :class:`ModelResource` can be filtered using the *where* query and sorted using *sort*.

We were interested in relations, so we filtered a :class:`Res` field for equality. Most other field types can also be filtered and support custom comparators. Here are some examples of *where* queries:

.. code-block:: bash

    http :5000/book where=='{"year_published": {"$gt": 1900}}'                # Book.year_published > 1900
    http :5000/author where=='{"first_name": {"$sw": "C"}}'           # Author.first_name starts with 'C'
    http :5000/author where=='{"first_name": {"$in": ["Charles", "James"]}}'  # Author.first_name in ['Charles', 'James']
    http :5000/book where=='{"title": "The Double Helix", "year_published": {"$lt": 2000}}'

Here are some examples of *sort* queries:

.. code-block:: bash

    http :5000/book sort=='{"year_published": false}'                # Book.year_published ascending
    http :5000/book sort=='{"year_published": false, "title": true}' # Book.year_published ascending, Book.title descending


Both *where* and *sort* need to be valid JSON, so use double quotes.

See :ref:`sec_filters` for a full list of possible filters.

.. _pagination:

Pagination
----------

Restone pagination is borrowed from the `GitHub API <http://developer.github.com/v3/#pagination>`_. Pages are requested
using the `page` and `per_page` query string arguments. The ``Link`` header lists links to the current, first, previous, next, and last page.
In addition, the ``X-Total-Count`` header contains a count of the total number of items.

.. code-block:: http

    HTTP/1.0 200 OK
    Content-Type: application/json
    Link: </book?page=1&per_page=20>; rel="self",
          </book?page=3&per_page=20>; rel="last",
          </book?page=2&per_page=20>; rel="next"
    X-Total-Count: 55


:class:`ModelResource` items are paginated automatically.

The default and maximum number of items per page can be configured using the
``'RESTONE_DEFAULT_PER_PAGE'`` and ``'RESTONE_MAX_PER_PAGE'`` configuration variables.

routes
------

routes are added using decorators named after the HTTP methods, declared either with or without arguments. The format
for the route decorators is:

.. code-block:: python

    route.method(rule = None,
                 rel=None,
                 attribute=None,
                 schema=None,
                 response_schema=None)


A :class:`route` instance itself also has decorators for each method, so that they can define different functions
for different HTTP methods on the same endpoint.

Each method has its own ``schema`` and ``response_schema`` used to decode, verify, and encode requests and responses.
If ``schema`` is a :class:`FieldSet`, its properties are
spread over the route function as keyword arguments.

:class:`itemroute` is a special route, used with :class:`ModelResource`, whose rule is prefixed ``'/<id_converter:id>'`` and
that passes the item as the first function argument.

Here is a slightly different :class:`Book` model (a rating has been added) and a *book* resource with some of the different
kinds of routes:

.. code-block:: python

    class Book(db.Model):
        id = db.Column(db.Integer, primary_key=True)
        title = db.Column(db.Str(), nullable=False)
        year_published = db.Column(db.Integer)
        rating = db.Column(db.Integer, default=5)

    class BookResource(ModelResource):
        class Meta:
            model = Book
            excluded_fields = ['rating']

        @itemroute.get('/rating')
        def rating(self, book) -> Int:
            return book.rating

        @rating.post
        def rate(self, book, value: Int[1:10]) -> Int:
            self.manager.update(book, {"rating": value})
            return value

        @itemroute.get
        def is_recent(self, book) -> Bool:
            return datetime.date.today().year <= book.year_published + 10

        @route.get
        def genres(self) -> List(Str, description="A list of genres"):
            return ['biography', 'history', 'essay', 'law', 'philosophy']


.. note::

    This example makes use of `function annotations <https://www.python.org/dev/peps/pep-3107/>`_, which appeared in Python 3.0.


After adding a book, we can give these routes a spin:

.. code-block:: bash

    http GET :5000/book/1/rating

.. code-block:: http


    HTTP/1.0 200 OK
    Content-Length: 3
    Content-Type: application/json
    Date: Sat, 07 Feb 2015 16:16:37 GMT
    Server: Werkzeug/0.9.6 Python/3.3.2

    5

.. code-block:: bash

    http POST :5000/book/1/rating value:=7

.. code-block:: http

    HTTP/1.0 200 OK
    Content-Length: 1
    Content-Type: application/json
    Date: Sat, 07 Feb 2015 16:17:59 GMT
    Server: Werkzeug/0.9.6 Python/3.3.2

    7

.. code-block:: bash

    http GET :5000/book/1/is-recent

.. code-block:: http

    HTTP/1.0 200 OK
    Content-Length: 5
    Content-Type: application/json
    Date: Sat, 07 Feb 2015 16:20:19 GMT
    Server: Werkzeug/0.9.6 Python/3.3.2

    false

.. code-block:: bash

    http GET :5000/book/genres

.. code-block:: http

    HTTP/1.0 200 OK
    Content-Length: 54
    Content-Type: application/json
    Date: Sat, 07 Feb 2015 16:20:44 GMT
    Server: Werkzeug/0.9.6 Python/3.3.2

    [
        "biography",
        "history",
        "essay",
        "law",
        "philosophy"
    ]


It is worth noting that :class:`ModelResource` is not much more than the empty :class:`Resource` type with a few custom
routes. :class:`route` and :class:`Resource` are the backbone of Restone.


route Sets & Mixins
-------------------

In the example above, we have one property --- rating --- which can be read and updated by accessing
a specific route. Restone provides a shortcut for this common pattern. Let's use :class:`AttrRoute` to rewrite the rating getter and setter:

.. code-block:: python

    class BookResource(ModelResource):
        rating = AttrRoute(Float)

        # ...

Done. Now, this isn't strictly a *set* of routes --- but it implements :class:`_RouteSet`, which can be used
to write reusable groups of routes. (:class:`Relation` is also a route set,:class:`TaskRoute` is also a route set).


A second pattern for reusability is the *mixin*. They can augment the :class:`Schema` and :class:`Meta` attributes and
add new routes and route sets to the resources. Here is an example mixin, adding two new fields to the schema:

.. code-block:: python

    class MetaMixin(object):
        class Schema:
            created_at = DateTime(io='r')
            updated_at = DateTime(io='r', nullable=True)


.. code-block:: python

    class BookResource(MetaMixin, ModelResource):
        # ...

Mixin and Resource base classes are evaluated left-to-right.

Self-documenting API
--------------------

It can be a huge hassle to write and maintain the documentation of an API---not with Restone!
In fact, every API you saw in this quick start guide was fully documented.

It uses flasgger to generate documentation automatically. You just need to set the autodoc parameter of the API to True.
Then you can read the doc and test your apis at `http://<ip>:<post>/apidocs`.

Next steps...
-------------

This guide has only skimmed the surface of what Restone can do for you.

In particular you may be interested in :ref:`permissions`, a guide to a fully-fledged permissions system for SQLAlchemy using Flask-Principal.
