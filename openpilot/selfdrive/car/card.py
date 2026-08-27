#!/usr/bin/env python3
import os
import time
import threading

import openpilot.cereal.messaging as messaging

from openpilot.cereal import log
from opendbc.car.structs import car

from openpilot.common.params import Params
from openpilot.common.realtime import config_realtime_process, Priority, Ratekeeper
from openpilot.common.swaglog import cloudlog, ForwardingHandler

from opendbc.car import DT_CTRL, structs
from opendbc.car.can_definitions import CanData, CanRecvCallable, CanSendCallable
from opendbc.car.carlog import carlog
from opendbc.car.fw_versions import ObdCallback
from opendbc.car.car_helpers import get_car, interfaces
from opendbc.car.interfaces import CarInterfaceBase, RadarInterfaceBase
from openpilot.selfdrive.pandad import can_capnp_to_list, can_list_to_can_capnp
from openpilot.selfdrive.car.cruise import VCruiseHelper
from openpilot.selfdrive.car.toyota_tss3_dev import parse_toyota_tss3_development_config

REPLAY = "REPLAY" in os.environ

EventName = log.OnroadEvent.EventName

# forward
carlog.addHandler(ForwardingHandler(cloudlog))


def obd_callback(params: Params) -> ObdCallback:
  def set_obd_multiplexing(obd_multiplexing: bool):
    if params.get_bool("ObdMultiplexingEnabled") != obd_multiplexing:
      cloudlog.warning(f"Setting OBD multiplexing to {obd_multiplexing}")
      params.remove("ObdMultiplexingChanged")
      params.put_bool("ObdMultiplexingEnabled", obd_multiplexing, block=True)
      params.get_bool("ObdMultiplexingChanged", block=True)
      cloudlog.warning("OBD multiplexing set successfully")
  return set_obd_multiplexing


def configure_toyota_tss3_development_lateral(params: Params, is_release: bool, CI: CarInterfaceBase) -> bool:
  """Apply a fail-closed exact-F33 development config from persistent params.

  This is intentionally outside normal vehicle detection. Merely setting the
  enable bit is insufficient: the JSON must contain live-captured template/
  cadence plus explicit completed Gate-2 and relay-authority attestations, and
  the Toyota interface independently binds the current EPS F181/topology.
  """
  if not params.get_bool("ToyotaTSS3DevLateral"):
    return False
  if is_release:
    cloudlog.warning("Ignoring Toyota TSS3 development lateral on a release branch")
    return False
  if not hasattr(CI, "configure_tss3_gate2_development_lateral"):
    cloudlog.warning("Ignoring Toyota TSS3 development lateral on a non-Toyota interface")
    return False

  raw = params.get("ToyotaTSS3DevLateralConfig")
  try:
    cfg = parse_toyota_tss3_development_config(raw)
    CI.configure_tss3_gate2_development_lateral(
      expected_f181=cfg.f181,
      b6_template=cfg.b6_template,
      cadence_frames=cfg.cadence_frames,
      gate2_bypass_validated=cfg.gate2_bypass_validated,
      exclusive_b6_authority_validated=cfg.exclusive_b6_authority_validated,
    )
  except (KeyError, TypeError, ValueError) as e:
    cloudlog.warning(f"Ignoring Toyota TSS3 development lateral: {e}")
    return False

  cloudlog.warning("Enabled exact-F33 Gate-2 development lateral; production TSS3 output remains unsupported")
  return True


def can_comm_callbacks(logcan: messaging.SubSocket, sendcan: messaging.PubSocket) -> tuple[CanRecvCallable, CanSendCallable]:
  def can_recv(wait_for_one: bool = False) -> list[list[CanData]]:
    """
    wait_for_one: wait the normal logcan socket timeout for a CAN packet, may return empty list if nothing comes

    Returns: CAN packets comprised of CanData objects for easy access
    """
    ret = []
    for can in messaging.drain_sock(logcan, wait_for_one=wait_for_one):
      ret.append([CanData(msg.address, msg.dat, msg.src) for msg in can.can])
    return ret

  def can_send(msgs: list[CanData]) -> None:
    sendcan.send(can_list_to_can_capnp(msgs, msgtype='sendcan'))

  return can_recv, can_send


class Car:
  CI: CarInterfaceBase
  RI: RadarInterfaceBase
  CP: car.CarParams

  def __init__(self, CI=None, RI=None) -> None:
    self.can_sock = messaging.sub_sock('can', timeout=20)
    self.sm = messaging.SubMaster(['pandaStates', 'carControl', 'onroadEvents'])
    self.pm = messaging.PubMaster(['sendcan', 'carState', 'carParams', 'carOutput', 'radarTracks'])

    self.can_rcv_cum_timeout_counter = 0

    self.CC_prev = car.CarControl.new_message()
    self.CS_prev = car.CarState.new_message()
    self.initialized_prev = False

    self.last_actuators_output = structs.CarControl.Actuators()

    self.params = Params()

    self.can_callbacks = can_comm_callbacks(self.can_sock, self.pm.sock['sendcan'])

    is_release = self.params.get_bool("IsReleaseBranch")

    if CI is None:
      # wait for one pandaState and one CAN packet
      print("Waiting for CAN messages...")
      while True:
        can = messaging.recv_one_retry(self.can_sock)
        if len(can.can) > 0:
          break

      alpha_long_allowed = self.params.get_bool("AlphaLongitudinalEnabled")

      cached_params = None
      cached_params_raw = self.params.get("CarParamsCache")
      if cached_params_raw is not None:
        with car.CarParams.from_bytes(cached_params_raw) as _cached_params:
          cached_params = _cached_params

      self.CI = get_car(*self.can_callbacks, obd_callback(self.params), alpha_long_allowed, is_release, cached_params)
      self.RI = interfaces[self.CI.CP.carFingerprint].RadarInterface(self.CI.CP)
      self.CP = self.CI.CP

      # continue onto next fingerprinting step in pandad
      self.params.put_bool("FirmwareQueryDone", True, block=True)
    else:
      self.CI, self.CP = CI, CI.CP
      self.RI = RI

    self.CP.alternativeExperience = 0
    self.tss3_development_lateral = configure_toyota_tss3_development_lateral(self.params, is_release, self.CI)
    openpilot_enabled_toggle = self.params.get_bool("OpenpilotEnabledToggle")
    controller_available = self.CI.CC is not None and openpilot_enabled_toggle and not self.CP.dashcamOnly
    self.CP.passive = not controller_available or self.CP.dashcamOnly
    if self.CP.passive:
      safety_config = structs.CarParams.SafetyConfig()
      safety_config.safetyModel = structs.CarParams.SafetyModel.noOutput
      self.CP.safetyConfigs = [safety_config]

    if self.CP.secOcRequired:
      # Copy user key if available
      try:
        with open("/cache/params/SecOCKey") as f:
          user_key = f.readline().strip()
          if len(user_key) == 32:
            self.params.put("SecOCKey", user_key, block=True)
      except Exception:
        pass

      key_loaded = False
      secoc_key = self.params.get("SecOCKey")
      if secoc_key is not None:
        try:
          saved_secoc_key = bytes.fromhex(secoc_key.strip())
        except ValueError:
          saved_secoc_key = b""
        if len(saved_secoc_key) == 16:
          key_loaded = True
          self.CP.secOcKeyAvailable = True
          self.CI.CS.secoc_key = saved_secoc_key
          if controller_available:
            self.CI.CC.secoc_key = saved_secoc_key
        else:
          cloudlog.warning("Saved SecOC key is invalid")

      # A resident EPS bridge is a separate SecOC transport mechanism, not a key.
      # It is deliberately dormant unless a future evidence-gated deployment stores
      # both the bridge flag and the exact EPS F181 it was validated against. A real
      # SecOC key always takes priority, and the current bridge covers lateral only.
      bridge_requested = self.params.get_bool("ToyotaEphemeralSecOCBridge")
      bridge_f181_raw = self.params.get("ToyotaEphemeralSecOCBridgeF181")
      bridge_f181 = bridge_f181_raw.decode(errors="ignore").strip() if bridge_f181_raw is not None else ""
      # This parameter is an exact calibration binding, never a prefix/family selector.
      # Toyota EPS F181 software IDs tracked here are 13 ASCII alphanumerics beginning
      # with 8965 (for example 8965B4512000). Reject short prefixes before searching
      # the raw firmware-version response bytes.
      bridge_f181_valid = len(bridge_f181) == 13 and bridge_f181.startswith("8965") and bridge_f181.isalnum()
      eps_versions = [bytes(fw.fwVersion) for fw in self.CP.carFw if fw.ecu == structs.CarParams.Ecu.eps]
      bridge_target_matches = bool(bridge_f181_valid and any(bridge_f181.encode() in fw for fw in eps_versions))
      if bridge_requested and not key_loaded:
        if not bridge_f181_valid:
          cloudlog.warning("Ignoring Toyota ephemeral SecOC bridge: validated F181 must be one exact 13-character 8965... software ID")
        elif not bridge_target_matches:
          cloudlog.warning("Ignoring Toyota ephemeral SecOC bridge: validated F181 does not match current EPS")
        elif self.CP.openpilotLongitudinalControl:
          cloudlog.warning("Ignoring Toyota ephemeral SecOC bridge: resident bridge does not cover secured ACC 0x183")
        else:
          self.CP.secOcKeyAvailable = True
          if controller_available:
            self.CI.CC.ephemeral_secoc_bridge = True
          cloudlog.warning(f"Using target-bound Toyota ephemeral SecOC bridge for EPS {bridge_f181}")

    # Write previous route's CarParams
    prev_cp = self.params.get("CarParamsPersistent")
    if prev_cp is not None:
      self.params.put("CarParamsPrevRoute", prev_cp, block=True)

    # Write CarParams for controls and radard
    cp_bytes = self.CP.to_bytes()
    self.params.put("CarParams", cp_bytes, block=True)
    self.params.put("CarParamsCache", cp_bytes)
    self.params.put("CarParamsPersistent", cp_bytes)

    self.v_cruise_helper = VCruiseHelper(self.CP)

    self.is_metric = self.params.get_bool("IsMetric")
    self.experimental_mode = self.params.get_bool("ExperimentalMode")

    # card is driven by can recv, expected at 100Hz
    self.rk = Ratekeeper(100, print_delay_threshold=None)

  def state_update(self) -> tuple[car.CarState, structs.RadarDataT | None]:
    """carState update loop, driven by can"""

    can_strs = messaging.drain_sock_raw(self.can_sock, wait_for_one=True)
    can_list = can_capnp_to_list(can_strs)

    # Update carState from CAN
    CS = self.CI.update(can_list)

    # Update radar tracks from CAN
    RD: structs.RadarDataT | None = self.RI.update(can_list)

    self.sm.update(0)

    can_rcv_valid = len(can_strs) > 0

    # Check for CAN timeout
    if not can_rcv_valid:
      self.can_rcv_cum_timeout_counter += 1

    if can_rcv_valid and REPLAY:
      self.can_log_mono_time = messaging.log_from_bytes(can_strs[0]).logMonoTime

    self.v_cruise_helper.update_v_cruise(CS, self.sm['carControl'].enabled, self.is_metric)
    if self.sm['carControl'].enabled and not self.CC_prev.enabled:
      # Use CarState w/ buttons from the step selfdrived enables on
      self.v_cruise_helper.initialize_v_cruise(self.CS_prev, self.experimental_mode)

    # TODO: mirror the carState.cruiseState struct?
    CS.vCruise = float(self.v_cruise_helper.v_cruise_kph)
    CS.vCruiseCluster = float(self.v_cruise_helper.v_cruise_cluster_kph)

    return CS, RD

  def state_publish(self, CS: car.CarState, RD: structs.RadarDataT | None):
    """carState and carParams publish loop"""

    # carParams - logged every 50 seconds (> 1 per segment)
    if self.sm.frame % int(50. / DT_CTRL) == 0:
      cp_send = messaging.new_message('carParams')
      cp_send.valid = True
      cp_send.carParams = self.CP
      self.pm.send('carParams', cp_send)

    # publish new carOutput
    co_send = messaging.new_message('carOutput')
    co_send.valid = self.sm.all_checks(['carControl'])
    co_send.carOutput.actuatorsOutput = self.last_actuators_output
    self.pm.send('carOutput', co_send)

    # kick off controlsd step while we actuate the latest carControl packet
    cs_send = messaging.new_message('carState')
    cs_send.valid = CS.canValid
    cs_send.carState = CS
    cs_send.carState.canErrorCounter = self.can_rcv_cum_timeout_counter
    cs_send.carState.cumLagMs = -self.rk.remaining * 1000.
    self.pm.send('carState', cs_send)

    if RD is not None:
      tracks_msg = messaging.new_message('radarTracks')
      tracks_msg.valid = not any(RD.errors.to_dict().values())
      tracks_msg.radarTracks = RD
      self.pm.send('radarTracks', tracks_msg)

  def controls_update(self, CS: car.CarState, CC: car.CarControl):
    """control update loop, driven by carControl"""

    if not self.initialized_prev:
      # Initialize CarInterface, once controls are ready
      # TODO: this can make us miss at least a few cycles when doing an ECU knockout
      self.CI.init(self.CP, *self.can_callbacks)
      # signal pandad to switch to car safety mode
      self.params.put_bool("ControlsReady", True)

    if self.sm.all_alive(['carControl']):
      # send car controls over can
      now_nanos = self.can_log_mono_time if REPLAY else int(time.monotonic() * 1e9)
      self.last_actuators_output, can_sends = self.CI.apply(CC, now_nanos)
      self.pm.send('sendcan', can_list_to_can_capnp(can_sends, msgtype='sendcan', valid=CS.canValid))

      self.CC_prev = CC

  def step(self):
    CS, RD = self.state_update()

    self.state_publish(CS, RD)

    initialized = (not any(e.name == EventName.selfdriveInitializing for e in self.sm['onroadEvents']) and
                   self.sm.seen['onroadEvents'])
    if not self.CP.passive and initialized:
      self.controls_update(CS, self.sm['carControl'])

    self.initialized_prev = initialized
    self.CS_prev = CS

  def params_thread(self, evt):
    while not evt.is_set():
      self.is_metric = self.params.get_bool("IsMetric")
      self.experimental_mode = self.params.get_bool("ExperimentalMode") and self.CP.openpilotLongitudinalControl
      time.sleep(0.1)

  def card_thread(self):
    e = threading.Event()
    t = threading.Thread(target=self.params_thread, args=(e, ))
    try:
      t.start()
      while True:
        self.step()
        self.rk.monitor_time()
    finally:
      e.set()
      t.join()


def main():
  config_realtime_process(4, Priority.CTRL_HIGH)
  car = Car()
  car.card_thread()


if __name__ == "__main__":
  main()
