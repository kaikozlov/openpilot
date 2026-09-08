from openpilot.cereal import log
from openpilot.selfdrive.pandad.pandad_api_impl import can_capnp_to_list, can_list_to_can_capnp


def test_can_fd_metadata():
  msgs = [
    (0x123, b"12345678", 0),
    (0x124, b"abcdefgh", 1, True),
    (0x125, bytes(range(32)), 2),
  ]
  raw = can_list_to_can_capnp(msgs, msgtype="sendcan")

  with log.Event.from_bytes(raw) as event:
    assert [m.fd for m in event.sendcan] == [False, True, True]

  # Keep the long-standing public three-tuple list API unchanged by default,
  # while allowing tooling to request the exact per-frame FDF explicitly.
  expected_three_tuple = [tuple(m[:3]) for m in msgs]
  assert can_capnp_to_list([raw], msgtype="sendcan")[0][1] == expected_three_tuple
  assert can_capnp_to_list([raw], msgtype="sendcan", include_fd=True)[0][1] == [
    (*msgs[0][:3], False),
    (*msgs[1][:3], True),
    (*msgs[2][:3], True),
  ]
