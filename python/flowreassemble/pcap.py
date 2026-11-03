"""libpcap, exposed with its own model and names (without the ``pcap_`` prefix).

Open a handle, filter it, then pass it to ``reassemble()`` or ``conversations()``::

    h = pcap.open_offline("c2.pcap")
    h.setfilter("host 203.0.113.7")

Live capture, either in one call (``pcap_open_live``)::

    h = pcap.open_live("eth0", 65535, True, 100)

or with the create/activate sequence, which reaches every setting::

    h = pcap.create("eth0")
    h.set_immediate_mode(True)
    h.set_buffer_size(16 << 20)
    h.activate()

``h.breakloop()`` (safe from a signal handler) makes a running reassembly
close its open flows and end.
"""

from ._native import Handle, create, findalldevs, open_live, open_offline
from ._native import PcapError as Error

__all__ = ["Error", "Handle", "create", "findalldevs", "open_live", "open_offline"]
