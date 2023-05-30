
=======
Signals
=======

Restone comes with several `Blinker <http://pythonhosted.org/blinker/>`_ signals. The signals can be used to
pre-process and post-process most parts of the read, create, update cycle.

Resources using the :class:`SQLAlchemyManager` hook into these signals.

Signal listeners can edit the item:

>>> @before_create.connect_via(ArticleResource)
... def on_before_create_article(sender, item):
...     item.author_id = current_user.id

Listeners may also raise exceptions:

>>> @before_create.connect_via(ArticleResource)
... def on_before_create_article(sender, item):
...     if not current_user.is_editor:
...         raise BadRequest()

The better way is:

>>> class ArticleResource:
...    def on_before_create(self,item):
...        if not current_user.is_editor:
...            raise BadRequest()

The complete list of signals:

.. module:: signals

.. class:: before_create

    :param sender: item resource
    :param item: instance of item

.. class:: after_create

    :param sender: item resource
    :param item: instance of item

.. class:: before_update

    :param sender: item resource
    :param item: instance of item
    :param dict changes: dictionary of changes, already parsed

.. class:: after_update

    :param sender: item resource
    :param item: instance of item
    :param dict changes: dictionary of changes, already parsed

.. class:: before_delete

    :param sender: item resource
    :param item: instance of item

.. class:: after_delete

    :param sender: item resource
    :param item: instance of item

.. class:: before_relate

    :param sender: parent resource
    :param item: instance of parent item
    :param attribute: name of relationship to child
    :param child: instance of child item

.. class:: after_relate

    :param sender: parent resource
    :param item: instance of parent item
    :param attribute: name of relationship to child
    :param child: instance of child item

.. class:: before_remove

    :param sender: parent resource
    :param item: instance of parent item
    :param attribute: name of relationship to child
    :param child: instance of child item

.. class:: after_remove

    :param sender: parent resource
    :param item: instance of parent item
    :param attribute: name of relationship to child
    :param child: instance of child item

.. note::

    Relation-related signals are only used by :class:`Relation`, They do not apply to relations created or removed by
    updating an item with :class:`Res` or :class:`Many` fields.
