# API reference

## Reading traffic

```{eval-rst}
.. autofunction:: flowreassemble.conversations

.. autofunction:: flowreassemble.reassemble
```

## Conversations

```{eval-rst}
.. autoclass:: flowreassemble.Conversation

.. autoclass:: flowreassemble.Turn

.. autoclass:: flowreassemble.Anomaly
```

## Events

```{eval-rst}
.. autoclass:: flowreassemble.Opened

.. autoclass:: flowreassemble.Data

.. autoclass:: flowreassemble.Gap

.. autoclass:: flowreassemble.Closed

.. autoclass:: flowreassemble.Flow
```

## Enums

```{eval-rst}
.. autoclass:: flowreassemble.Direction

.. autoclass:: flowreassemble.CloseReason
```

## `flowreassemble.pcap`

```{eval-rst}
.. automodule:: flowreassemble.pcap
   :no-members:

.. autofunction:: flowreassemble.pcap.open_offline

.. autofunction:: flowreassemble.pcap.open_live

.. autofunction:: flowreassemble.pcap.create

.. autofunction:: flowreassemble.pcap.findalldevs

.. autoclass:: flowreassemble.pcap.Handle

.. autoexception:: flowreassemble.pcap.Error
```

## `flowreassemble.htp`

```{eval-rst}
.. automodule:: flowreassemble.htp
   :no-members:

.. autoclass:: flowreassemble.htp.Config

.. autoclass:: flowreassemble.htp.Tx()

.. autoclass:: flowreassemble.htp.Table
   :members: get

.. autoclass:: flowreassemble.htp.Uri

.. autoclass:: flowreassemble.htp.ServerPersonality

.. autoclass:: flowreassemble.htp.AuthType

.. autoclass:: flowreassemble.htp.RequestProgress

.. autoclass:: flowreassemble.htp.ResponseProgress
```
