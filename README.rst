SIP and Love
============

A SIP library


Installing
----------

Install and update using pip:

.. code-block:: text

    pip install -U snl


A Simple Example
----------------

.. code-block:: python

    import snl

    phoneA = snl.SIPPhoneClass()(
      ua=dict(proxy='1.2.3.4', aor='sip:+33123456789@sip.example.com')
    )
    phoneB = snl.SIPPhoneClass()(
      ua=dict(proxy='1.2.3.4', aor='sip:+33987654321@sip.example.com')
    )
    dialog = phoneA.invite(phoneB)
    if dialog:
      phoneB.bye(dialog)
