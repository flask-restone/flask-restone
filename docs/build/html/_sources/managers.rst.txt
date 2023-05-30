
========
Managers
========

Manager base class
^^^^^^^^^^^^^^^^^^

.. module:: flask_restone

:class:`Manager` is used by :class:`ModelResource` to implement a backend integration.

.. autoclass:: Manager
   :members:


Manager implementations
^^^^^^^^^^^^^^^^^^^^^^^

The following backend managers ship with *Flask-Restone*:


.. autoclass:: SQLAlchemyManager
   :members:


Additionally, :class:`SQLAlchemyManager` can be extended with
:class:`PrincipalsMixin` to form a new manager that implements a permissions system based on *Flask-Principals*.
