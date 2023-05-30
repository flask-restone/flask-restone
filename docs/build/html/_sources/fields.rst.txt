
.. _field_types:

Field types
===========

.. module:: flask_restone

:class:`Field` field class
------------------------

.. autoclass:: Field
   :members:

Reference field types
---------------------
.. autoclass:: Res

.. autoclass:: Ref

.. autoclass:: Many


Basic field types
-----------------

.. autoclass:: Any
   :members:

.. autoclass:: Str
   :members:

.. autoclass:: Int
   :members:

.. autoclass:: Float
   :members:

.. autoclass:: Bool
   :members:

.. autoclass:: Date
   :members:

.. autoclass:: DateTime
   :members:

Composite field types
---------------------

.. autoclass:: List
   :members:

.. autoclass:: Dict
   :members:

.. autoclass:: Union
   :members:

.. autoclass:: Optional
   :members:

SQLAlchemy-specific field types
-------------------------------

.. class:: ModelDict

   For creating SQLAlchemy models without having to give them their own resource.

   Usage example:

   .. code-block:: python

      class FooResource(Resource):
         class Meta:
            model = Foo

         class Schema:
            # Here, Foo.bars is a collection of Bar items
            bars = List(ModelDict({"name": Str(description="Bar name"),
            "height": Int(description="Height of bar")}, model=Bar))

   :param dict properties: A dictionary of :class:`Field` objects
   :param model: An SQLAlchemy model


Internal types
--------------

Field types
^^^^^^^^^^^
.. autoclass:: ResUri
   :members:

Schema types
^^^^^^^^^^^^

.. module:: schema

.. autoclass:: _Schema
    :members:

.. autoclass:: _FieldSet
    :members:
