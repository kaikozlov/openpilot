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
from opendbc.car.toyota.values import CAR as TOYOTA_CAR, ToyotaFlags, ToyotaSafetyFlags
from openpilot.selfdrive.car.cruise import VCruiseHelper
from openpilot.selfdrive.car.toyota_tss3_oracle import configure_toyota_tss3_frc_oracle, elm327_diagnostic_ready

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
    openpilot_enabled_toggle = self.params.get_bool("OpenpilotEnabledToggle")
    controller_available = self.CI.CC is not None and openpilot_enabled_toggle and not self.CP.dashcamOnly
    self.CP.passive = not controller_available or self.CP.dashcamOnly
    if self.CP.passive:
      safety_config = structs.CarParams.SafetyConfig()
      safety_config.safetyModel = structs.CarParams.SafetyModel.noOutput
      self.CP.safetyConfigs = [safety_config]

    self.tss3_frc_oracle = configure_toyota_tss3_frc_oracle(
      self.params, is_release, self.CP,
    )
    if self.tss3_frc_oracle is not None:
      cloudlog.warning("Enabled exact-F33 read-only FRC LTA/ACC oracle capture; vehicle controls remain disabled")

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
      bridge_f181 = (bridge_f181_raw.decode(errors="ignore") if isinstance(bridge_f181_raw, bytes) else str(bridge_f181_raw)).strip() \
        if bridge_f181_raw is not None else ""
      # This parameter is an exact calibration binding, never a prefix/family selector.
      # Toyota EPS F181 software IDs tracked here are 13 ASCII alphanumerics beginning
      # with 8965 (for example 8965B4512000). Reject short prefixes before searching
      # the raw firmware-version response bytes.
      bridge_f181_valid = len(bridge_f181) == 13 and bridge_f181.startswith("8965") and bridge_f181.isalnum()
      eps_versions = [bytes(fw.fwVersion) for fw in self.CP.carFw if fw.ecu == structs.CarParams.Ecu.eps]
      bridge_target_matches = bool(bridge_f181_valid and any(bridge_f181.encode() in fw for fw in eps_versions))
      # The exact F33 EPS does not reliably answer F181 while the car is in READY,
      # but the normal comma CAN fingerprint now uniquely identifies this Camry.
      # For the maintainer-only non-release dev path, accept the persisted exact
      # calibration binding when that real CAN fingerprint selected the platform.
      bridge_target_matches |= bool(
        bridge_f181 == "8965F3307000"
        and self.CP.carFingerprint == TOYOTA_CAR.TOYOTA_CAMRY_TSS3
        and self.CP.fingerprintSource == structs.CarParams.FingerprintSource.can
        and self.params.get_bool("ToyotaTss3DevLateral")
        and not is_release
      )
      if bridge_requested and not key_loaded:
        if not bridge_f181_valid:
          cloudlog.warning("Ignoring Toyota ephemeral SecOC bridge: validated F181 must be one exact 13-character 8965... software ID")
        elif not bridge_target_matches:
          cloudlog.warning("Ignoring Toyota ephemeral SecOC bridge: validated F181 does not match current EPS")
        elif self.CP.openpilotLongitudinalControl:
          cloudlog.warning("Ignoring Toyota ephemeral SecOC bridge: resident bridge does not cover secured ACC 0x183")
        else:
          self.CP.secOcKeyAvailable = True

          # Development-only lateral actuation for the exact Camry F33
          # zero-MAC28 bridge: select the ALLOW_DEBUG toyota safety mode
          # with the TSS3 dev-lateral flag (B6-only TX whitelist) instead
          # of the observation-only noOutput config. Never in release, and
          # only for the one exact EPS calibration the bridge was built for.
          if (self.params.get_bool("ToyotaTss3DevLateral") and bridge_f181 == "8965F3307000"
              and self.CP.flags & ToyotaFlags.TSS3 and not is_release):
            self.CP.dashcamOnly = False
            safety_config = structs.CarParams.SafetyConfig()
            safety_config.safetyModel = structs.CarParams.SafetyModel.toyota
            safety_config.safetyParam = ToyotaSafetyFlags.TSS3_DEV_LATERAL.value
            self.CP.safetyConfigs = [safety_config]
            cloudlog.warning("Enabled exact-F33 TSS3 dev lateral (zero-MAC28 B6 via installed EPS bridge)")

          controller_available = self.CI.CC is not None and openpilot_enabled_toggle and not self.CP.dashcamOnly
          self.CP.passive = not controller_available
          if self.CP.passive:
            safety_config = structs.CarParams.SafetyConfig()
            safety_config.safetyModel = structs.CarParams.SafetyModel.noOutput
            self.CP.safetyConfigs = [safety_config]
          if controller_available:
            self.CI.CC.ephemeral_secoc_bridge = True

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

    if self.tss3_frc_oracle is not None:
      self.tss3_frc_oracle.observe(can_list, time.monotonic_ns())

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

  def tss3_frc_oracle_update(self, CS: car.CarState) -> None:
    if self.tss3_frc_oracle is None:
      return
    diagnostics_allowed = CS.canValid and elm327_diagnostic_ready(self.sm['pandaStates'])
    can_sends = self.tss3_frc_oracle.poll(time.monotonic_ns(), diagnostics_allowed=diagnostics_allowed)
    if can_sends:
      self.pm.send('sendcan', can_list_to_can_capnp(can_sends, msgtype='sendcan', valid=True))

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
    self.tss3_frc_oracle_update(CS)

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
