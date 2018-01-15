# Copyright 2014 ETH Zurich
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""
:mod:`local` --- Local beacon server
====================================
"""
# Stdlib
import logging
from collections import defaultdict

# SCION
from beacon_server.base import BeaconServer
from lib.defines import PATH_SERVICE, SIBRA_SERVICE
from lib.errors import SCIONServiceLookupError
from lib.packet.ctrl_pld import CtrlPayload
from lib.packet.hp_mgmt.base import HPMgmt
from lib.packet.hp_mgmt.seg import HPSegReg
from lib.packet.path_mgmt.base import PathMgmt
from lib.packet.path_mgmt.seg_recs import PathRecordsReg
from lib.packet.svc import SVCType
from lib.path_store import PathStore
from lib.types import PathSegmentType as PST
from lib.util import SCIONTime


class LocalBeaconServer(BeaconServer):
    """
    PathConstructionBeacon Server in a non-core AS.

    Receives, processes, and propagates beacons received by other beacon
    servers.
    """

    def __init__(self, server_id, conf_dir, prom_export=None):
        """
        :param str server_id: server identifier.
        :param str conf_dir: configuration directory.
        :param str prom_export: prometheus export address.
        """
        super().__init__(server_id, conf_dir, prom_export)
        # Sanity check that we should indeed be a local beacon server.
        assert not self.topology.is_core_as, "This shouldn't be a core BS!"
        self.beacons = PathStore(self.path_policy)
        self.up_segments = PathStore(self.path_policy)
        self.down_segments = PathStore(self.path_policy)
        self.hidden_segments = PathStore(self.path_policy)
        self.cert_chain = self.trust_store.get_cert(self.addr.isd_as)
        assert self.cert_chain

    def register_up_segment(self, pcb, svc_type):
        """
        Send up-segment to Local Path Servers and Sibra Servers

        :raises:
            SCIONServiceLookupError: service type lookup failure
        """
        records = PathRecordsReg.from_values({PST.UP: [pcb]})
        addr, port = self.dns_query_topo(svc_type)[0]
        meta = self._build_meta(host=addr, port=port)
        self.send_meta(CtrlPayload(PathMgmt(records)), meta)
        return meta

    def register_down_segment(self, pcb):
        """
        Send down-segment to Core Path Server
        """
        core_path = pcb.get_path(reverse_direction=True)
        records = PathRecordsReg.from_values({PST.DOWN: [pcb]})
        dst_ia = pcb.asm(0).isd_as()
        meta = self._build_meta(ia=dst_ia, host=SVCType.PS_A, path=core_path, reuse=True)
        self.send_meta(CtrlPayload(PathMgmt(records)), meta)
        return meta

    def register_hidden_segment(self, pcb, hps_ia, hpcfg_id):
        """
        Send hidden-segment to Hidden Path Server
        """
        dst_ia = pcb.asm(0).isd_as()
        records = HPSegReg.from_values({PST.HIDDEN: [pcb]}, hp_cfg_ids=[hpcfg_id])
        ts = int(SCIONTime.get_time())
        chain = self._get_my_cert()
        isd_as, cert_ver = chain.get_leaf_isd_as_ver()
        trc_ver = self._get_my_trc().version
        hmgt = HPMgmt(records, isd_as, trc_ver, cert_ver, ts)
        sig = hmgt.sign(self.signing_key)
        if not sig:
            logging.debug("Signing failed: %s" % hmgt)
            return None
        if hps_ia == self.addr.isd_as:
            # HPS is in the same AS
            try:
                addr, port = self.dsn_query_topo(PATH_SERVICE)[0]
            except SCIONServiceLookupError as e:
                logging.warning("Lookup for hidden path service failed: %s", e)
                return None
            meta = self._build_meta(host=addr, port=port)
        elif dst_ia == hps_ia:
            # HPS is in its' core AS (Currently core ASes do not support hidden path)
            core_path = pcb.get_path(reverse_direction=True)
            meta = self._build_meta(ia=dst_ia, host=SVCType.PS_A, path=core_path, reuse=True)
        else:
            path = self._get_path_via_sciond(hps_ia)
            if path:
                meta = self._build_meta(ia=hps_ia, host=SVCType.PS_A, path=path.fwd_path())
            else:
                logging.warning("Hidden path register (for %s) not sent: "
                                "no path found", hps_ia)
                return None

        self.send_meta(CtrlPayload(hmgt), meta)
        return meta

    def register_segments(self):
        """
        Register paths according to the received beacons.
        """
        self.register_up_segments()
        self.register_down_segments()
        self.register_hidden_segments()

    def _remove_revoked_pcbs(self, rev_info):
        with self._rev_seg_lock:
            candidates = (self.down_segments.candidates +
                          self.up_segments.candidates +
                          self.beacons.candidates)
            to_remove = self._pcb_list_to_remove(candidates, rev_info)
            # Remove the affected segments from the path stores.
            self.beacons.remove_segments(to_remove)
            self.up_segments.remove_segments(to_remove)
            self.down_segments.remove_segments(to_remove)

    def _handle_verified_beacon(self, pcb):
        """
        Once a beacon has been verified, place it into the right containers.
        """
        with self._rev_seg_lock:
            self.up_segments.add_segment(pcb)
            if pcb.p.ifID in self.hps_policy.if_ids:
                self.hidden_segments.add_segment(pcb)
            else:
                self.beacons.add_segment(pcb)
                self.down_segments.add_segment(pcb)

    def handle_pcbs_propagation(self):
        """
        Main loop to propagate received beacons.
        """
        # TODO: define function that dispatches the pcbs among the interfaces
        with self._rev_seg_lock:
            best_segments = self.beacons.get_best_segments()
        propagated_pcbs = defaultdict(list)
        for pcb in best_segments:
            propagated = self.propagate_downstream_pcb(pcb)
            for k, v in propagated.items():
                propagated_pcbs[k].extend(v)
        self._log_propagations(propagated_pcbs)

    def register_up_segments(self):
        """
        Register the paths to the core.
        """
        with self._rev_seg_lock:
            best_segments = self.up_segments.get_best_segments(sending=False)
        registered_paths = defaultdict(list)
        for pcb in best_segments:
            new_pcb = self._terminate_pcb(pcb)
            if not new_pcb:
                continue
            new_pcb.sign(self.signing_key)
            for svc_type in [PATH_SERVICE, SIBRA_SERVICE]:
                try:
                    dst_meta = self.register_up_segment(new_pcb, svc_type)
                except SCIONServiceLookupError as e:
                    logging.warning("Unable to send up-segment registration: %s", e)
                    continue
                # Keep the ID of the not-terminated PCB to relate to previously received ones.
                registered_paths[(str(dst_meta), svc_type)].append(pcb.short_id())
        self._log_registrations(registered_paths, "up")

    def register_down_segments(self):
        """
        Register the paths from the core.
        """
        with self._rev_seg_lock:
            best_segments = self.down_segments.get_best_segments(sending=False)
        registered_paths = defaultdict(list)
        for pcb in best_segments:
            new_pcb = self._terminate_pcb(pcb)
            if not new_pcb:
                continue
            new_pcb.sign(self.signing_key)
            dst_ps = self.register_down_segment(new_pcb)
            # Keep the ID of the not-terminated PCB to relate to previously received ones.
            registered_paths[(str(dst_ps), PATH_SERVICE)].append(pcb.short_id())
        self._log_registrations(registered_paths, "down")

    def register_hidden_segments(self):
        """
        Register the hidden paths from the core.
        """
        with self._rev_seg_lock:
            best_segments = self.hidden_segments.get_best_segments(sending=False)
        registered_paths = defaultdict(list)
        for pcb in best_segments:
            new_pcb = self._terminate_pcb(pcb)
            if not new_pcb:
                continue
            new_pcb.sign(self.signing_key)
            hpcfg_ids = self.hpcfg_store.get_intf_conf(pcb.p.ifID)
            for hpcfg_id in hpcfg_ids:
                hpcfg = self.hpcfg_store.get_hpcfg(hpcfg_id.__hash__())
                if not hpcfg:
                    continue
                for hps_ia in hpcfg.iter_hps_ias():
                    dst_ps = self.register_hidden_segment(new_pcb, hps_ia, hpcfg_id)
                    # Keep the ID of the not-terminated PCB to relate to previously received ones.
                    registered_paths[(str(dst_ps), PATH_SERVICE)].append(pcb.short_id())
        self._log_registrations(registered_paths, "hidden")
