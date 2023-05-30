
.. module:: flask_restone

.. _sec_filters:

=======
Filters
=======

Filter expressions
------------------


``Meta.filters`` may contain an expression used to specify which properties of items belonging to a resource can be filtered, and how.

The `filters` expression can be a :class:`bool` or a :class:`tuple` of field names.

For example, the following allows all filters:

::

    filters = True

The following allows filtering on the ``"name"`` field:

::

    filters = {
        "name": True
    }

The following allows filtering by equals and not equals on the ``"name"`` field:

::

    filters = ("name",)



Built-in default filters
------------------------

Filters are implemented for each contributed backend individually. The following filter classes are implemented for
most or all backends:


:class:`_BaseFilter`
---------------------------

.. autoclass:: _BaseFilter
   :members:

    _BaseFilter is used for registering sub-classes of filters, including:
        - lt: LessThan
        - gt: GreatThan
        - eq: Equal
        - ne: NotEqual
        - le: LessThanEqual
        - ge: GreatThanEqual
        - in: In
        - ni: NotIn
        - ha: Has
        - ct: Contain
        - ci: ContainIgnoreCase
        - sw: Startswith
        - si: StartswithIgnoreCase
        - ew: Endswith
        - ei: EndswithIgnoreCase
        - bt: Between

    These sub-classes are not intended to be called outside the module and are registered to the dictionary _BaseFilter.filters for internal usage.

    .. code-block:: python

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

:class:`_SQLAlchemyFilter`
---------------------------

.. autoclass:: _SQLAlchemyFilter
   :members:
    Similarly, _SQLAlchemyFilter inherits from _BaseFilter, and its sub-classes are also intended for internal usage within the module only.
    .. code-block:: python

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

.. note::

   you can write an equality comparison both ways:

   ::

      GET /user?where={"name": "foo"}
      GET /user?where={"name": {"$eq": "foo"}}
