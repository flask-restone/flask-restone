.. module:: flask_restone

.. _api:


:class:`Api`
==================

There is not much to say about :class:`Api` except that it has an optional ``prefix`` and ``decorators``. Use::

    api.add_resources(YourResource)

To add a resource to the API. You can only add a single resource with a given name.


.. autoclass:: Api
    :members:

.. _schema:
