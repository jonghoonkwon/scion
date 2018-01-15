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
:mod:`local` --- Local path server
==================================
"""
# Stdlib
import logging
import random

# SCION
from lib.crypto.certificate_chain import verify_sig_chain_trc
from lib.errors import SCIONVerificationError
from lib.hp_cfg_meta import HPCfgMeta
from lib.path_seg_meta import PathSegMeta
from lib.packet.svc import SVCType
from lib.packet.ctrl_pld import CtrlPayload
from lib.packet.hp_mgmt.base import HPMgmt
from lib.packet.hp_mgmt.cfg import HPCfgRecs, HPCfgReg, HPCfgReply, HPCfgReq
from lib.packet.hp_mgmt.seg import HPSegReply, HPSegReq
from lib.packet.path_mgmt.base import PathMgmt
from lib.packet.path_mgmt.seg_req import PathSegmentReq
from lib.packet.path_mgmt.seg_recs import PathSegmentRecords
from lib.path_db import PathSegmentDB
from lib.types import PathSegmentType as PST
from lib.util import SCIONTime
from path_server.base import PathServer, REQS_TOTAL


class LocalPathServer(PathServer):
    """
    SCION Path Server in a non-core AS. Stores up-segments to the core and
    registers down-segments with the CPS. Can cache segments learned from a CPS.
    """
    def __init__(self, server_id, conf_dir, prom_export=None):
        """
        :param str server_id: server identifier.
        :param str conf_dir: configuration directory.
        :param str prom_export: prometheus export address.
        """
        super().__init__(server_id, conf_dir, prom_export)
        # Sanity check that we should indeed be a local path server.
        assert not self.topology.is_core_as, "This shouldn't be a core PS!"
        # Database of up-segments to the core.
        up_labels = {**self._labels, "type": "up"} if self._labels else None
        hidden_labels = {**self._labels, "type": "hidden"} if self._labels else None
        self.up_segments = PathSegmentDB(max_res_no=self.MAX_SEG_NO, labels=up_labels)
        self.hidden_segments = PathSegmentDB(max_res_no=self.MAX_SEG_NO, labels=hidden_labels)

    def _handle_up_segment_record(self, pcb, from_zk=False):
        if not from_zk:
            self._segs_to_zk[pcb.get_hops_hash()] = (PST.UP, pcb)
        if self._add_segment(pcb, self.up_segments, "Up"):
            # Sending pending targets to the core using first registered
            # up-segment.
            self._handle_waiting_targets(pcb)
            return set([(pcb.first_ia(), pcb.is_sibra())])
        return set()

    def _handle_down_segment_record(self, pcb, from_zk=None):
        if self._add_segment(pcb, self.down_segments, "Down"):
            return set([(pcb.last_ia(), pcb.is_sibra())])
        return set()

    def _handle_core_segment_record(self, pcb, from_zk=None):
        if self._add_segment(pcb, self.core_segments, "Core"):
            return set([(pcb.first_ia(), pcb.is_sibra())])
        return set()

    def _handle_hidden_segment_record(self, pcb, from_zk=None):
        if self._add_segment(pcb, self.hidden_segments, "Hidden"):
            return set([(pcb.first_ia(), pcb.is_sibra())])
        return set()

    def handle_hpcfg_request(self, cpld, meta):
        hmgt = cpld.union
        hpcfg_reqs = hmgt.union
        assert isinstance(hpcfg_reqs, HPCfgReq), type(hpcfg_reqs)
        cfg_meta = HPCfgMeta(hmgt, self.continue_hpcfg_req_processing, meta)
        logging.debug("Handling HpCfgReq from %s: %s" % (str(cfg_meta.meta),
                                                         cfg_meta.hmgt.short_id()))
        self._process_hmgt(cfg_meta)

    def handle_hpcfg_record(self, cpld, meta):
        hmgt = cpld.union
        hpcfg_recs = hmgt.union
        assert isinstance(hpcfg_recs, HPCfgRecs), type(hpcfg_recs)
        cfg_meta = HPCfgMeta(hmgt, self.continue_hpcfg_processing, meta)
        logging.debug("Handling HpCfgReg from %s: %s" % (str(cfg_meta.meta),
                                                         cfg_meta.hmgt.short_id()))
        self._process_hmgt(cfg_meta)

    def handle_hpath_segment_request(self, cpld, meta):
        hmgt = cpld.union
        hseg_req = hmgt.union
        assert isinstance(hseg_req, PathSegmentReq), type(hseg_req)
        cfg_meta = HPCfgMeta(hmgt, self.continue_hseg_req_processing, meta)
        logging.debug("Handling HSecReq from %s: %s" % (str(cfg_meta.meta),
                                                        cfg_meta.hmgt.short_id()))
        self._process_hmgt(cfg_meta)

    def handle_hpath_segment_record(self, cpld, meta):
        hmgt = cpld.union
        hseg_recs = hmgt.union
        assert isinstance(hseg_recs, PathSegmentRecords), type(hseg_recs)
        cfg_meta = HPCfgMeta(hmgt, self.continue_hseg_rec_processing, meta)
        logging.debug("Handling HSecRecs from %s: %s" % (str(cfg_meta.meta),
                                                         cfg_meta.hmgt.short_id()))
        self._process_hmgt(cfg_meta)

    def _process_hmgt(self, cfg_meta):
        # Find missing TRCs and certificates
        missing_trcs = self._missing_trc_versions(cfg_meta.trc_vers)
        missing_certs = self._missing_cert_versions(cfg_meta.cert_vers)
        # Update missing TRCs/certs map
        cfg_meta.missing_trcs.update(missing_trcs)
        cfg_meta.missing_certs.update(missing_certs)
        if cfg_meta.verifiable():
            self._try_to_verify_hmgt(cfg_meta)
            return
        self._request_missing_trcs(cfg_meta)
        self._request_missing_certs(cfg_meta)
        if cfg_meta.meta:
            cfg_meta.meta.close()

    def _try_to_verify_hmgt(self, cfg_meta):
        try:
            self._verify_hmgt(cfg_meta)
        except SCIONVerificationError as e:
            logging.error("Signature verification failed for %s: %s" %
                          (cfg_meta.hmgt, e))
            return
        if cfg_meta.meta:
            cfg_meta.meta.close()
        cfg_meta.callback(cfg_meta)

    def _verify_hmgt(self, cfg_meta):
        hmgt = cfg_meta.hmgt
        ver_hmgt = hmgt.sig_pack()
        cert_ia = hmgt.isd_as()
        trc = self.trust_store.get_trc(cert_ia[0], hmgt.trc_ver())
        chain = self.trust_store.get_cert(cert_ia, hmgt.cert_ver())
        verify_sig_chain_trc(ver_hmgt, hmgt.signature, cert_ia, chain, trc)

    def continue_hpcfg_req_processing(self, cfg_meta):
        logging.debug("Successfully verified HpCfgReq %s" % cfg_meta.hmgt.short_id())
        hpcfg_req = cfg_meta.hmgt.union
        reader_ia = cfg_meta.meta.get_addr().isd_as
        hpcfgs = []
        for hpcfg_id in hpcfg_req.iter_hp_cfg_ids():
            hpcfg = self.hpcfg_store.is_approved(hpcfg_id, reader_ia=reader_ia)
            if hpcfg:
                hpcfgs.append(hpcfg)
            else:
                logging.warning("Unauthorized hpcfg request recieved from %s", reader_ia)
        records = HPCfgReply.from_values(hpcfgs)
        self._send_hpcfg_records(records, cfg_meta.meta)

    def continue_hpcfg_processing(self, cfg_meta):
        logging.debug("Successfully verified HpCfgReg %s" % cfg_meta.hmgt.short_id())
        hpcfg_recs = cfg_meta.hmgt.union
        for hpcfg in hpcfg_recs.iter_hp_cfgs():
            self.hpcfg_store.add_hpcfg(hpcfg)

    def continue_hseg_req_processing(self, cfg_meta):
        logging.debug("Successfully verified Hidden Path Request %s" % cfg_meta.hmgt.short_id())
        hseg_req = cfg_meta.hmgt.union
        hpcfg_id = hseg_req.hp_cfg_id(0)
        src_ia = cfg_meta.meta.get_addr().isd_as
        dst_ia = hseg_req.dst_ia()
        if self.hpcfg_store.is_approved(hpcfg_id, reader_ia=src_ia, writer_ia=dst_ia):
            self.hidden_path_resolution(cfg_meta.hmgt, cfg_meta.meta)
        else:
            logging.warning("Unauthorized hidden path request recieved from %s", src_ia)

    def continue_hseg_rec_processing(self, cfg_meta):
        logging.debug("Successfully verified Hidden PCB %s" % cfg_meta.hmgt.short_id())
        hseg_recs = cfg_meta.hmgt.union
        hpcfg_id = hseg_recs.hp_cfg_id(0)
        writer_ia = cfg_meta.meta.get_addr().isd_as
        if self.hpcfg_store.is_approved(hpcfg_id, writer_ia=writer_ia):
            params = self._dispatch_params(hseg_recs, cfg_meta.meta)
            for rev_info in hseg_recs.iter_rev_infos():
                self.revocations.add(rev_info)
            # Verify pcbs and process them
            for type_, pcb in hseg_recs.iter_pcbs():
                seg_meta = PathSegMeta(pcb, self.continue_seg_processing, cfg_meta.meta,
                                       type_, params)
                self._process_path_seg(seg_meta)
        else:
            logging.warning("Unauthorized hidden path registration recieved from %s", writer_ia)

    def hidden_path_resolution(self, hmgt, meta):
        req = hmgt.union
        assert isinstance(req, HPSegReq), type(req)
        # Random ID for a request.
        req_id = random.randint(0, 2**32 - 1)
        logger = self.get_request_logger(req, req_id, meta)
        logger.info("HIDDEN_PATH_REQ received")
        REQS_TOTAL.labels(**self._labels).inc()
        down_segs = set()
        self._resolve_hidden(req, down_segs)
        if down_segs:
            self._send_hpath_segments(req, meta, logger, down_segs)
            return True

    def _resolve_hidden(self, req, down_segs):
        for dseg in self.hidden_segments(last_ia=req.dst_ia(), sibra=req.p.flags.sibra):
            down_segs.add(dseg)

    def _send_hpath_segments(self, req, meta, logger, down=None):
        """
        Sends path-segments to requester (depending on Path Server's location).
        """
        if not down:
            logger.warning("No segments to send for request: %s from: %s" %
                           (req.short_desc(), meta))
            return
        revs_to_add = self._peer_revs_for_segs(down)
        records = HPSegReply.from_values(
            {PST.HIDDEN: down}, revs_to_add, list(req.iter_hp_cfg_ids()))
        ts = int(SCIONTime.get_time())
        chain = self._get_my_cert()
        isd_as, cert_ver = chain.get_leaf_isd_as_ver()
        trc_ver = self._get_my_trc().version
        hmgt = HPMgmt(records, isd_as, trc_ver, cert_ver, ts)
        sig = hmgt.sign(self.signing_key)
        if not sig:
            logging.debug("Signing failed: %s" % hmgt)
            return None
        self.send_meta(CtrlPayload(hmgt), meta)
        logger.info("Sending PATH_REPLY with %d hidden segment(s).", len(down))

    def handle_hpcfg_propagation(self):
        """
        Propagate hidden pass configuration. If it is a master AS, it sends registration packet
        to HPS. If it is a client AS, it sends request packet to HPS in order to get the newest
        hidden path configuration.
        """
        if self.hps_policy.is_master:
            for hpcfg in self.hpcfg_store.get_hpcfgs():
                id = hpcfg.id()
                if self.addr.isd_as == id.master_ia():
                    self._register_hpcfg(hpcfg)
        if self.hps_policy.is_reader:
            for hpcfg_id, hps_ias in self.hpcfg_store.get_hpcfg_ids():
                self._request_hpcfg(hpcfg_id, hps_ias)

    def _register_hpcfg(self, hpcfg):
        for hps_ia in hpcfg.iter_hps_ias():
            if self.addr.isd_as != hps_ia:
                records = HPCfgReg.from_values([hpcfg])
                path = self._get_path_via_sciond(hps_ia)
                if path:
                    meta = self._build_meta(ia=hps_ia, host=SVCType.PS_A, path=path.fwd_path())
                else:
                    logging.warning("Registration for hidden path configuration failed. "
                                    "no path found to path server: %s", hps_ia)
                    continue
                self._send_hpcfg_records(records, meta)

    def _request_hpcfg(self, hpcfg_id, hps_ias):
        for hps_ia in hps_ias:
            if self.addr.isd_as != hps_ia:
                records = HPCfgReq.from_values([hpcfg_id])
                path = self._get_path_via_sciond(hps_ia)
                if path:
                    meta = self._build_meta(ia=hps_ia, host=SVCType.PS_A, path=path.fwd_path())
                else:
                    logging.warning("Registration for hidden path configuration failed. "
                                    "no path found to path server: %s", hps_ia)
                    continue
                self._send_hpcfg_records(records, meta)

    def _send_hpcfg_records(self, records, meta):
        chain = self._get_my_cert()
        isd_as, cert_ver = chain.get_leaf_isd_as_ver()
        trc_ver = self._get_my_trc().version
        ts = int(SCIONTime.get_time())
        hmgt = HPMgmt(records, isd_as, trc_ver, cert_ver, ts)
        sig = hmgt.sign(self.signing_key)
        if not sig:
            logging.debug("Signing failed: %s" % hmgt)
            return
        self.send_meta(CtrlPayload(hmgt), meta)

    def path_resolution(self, cpld, meta, new_request=True, logger=None, req_id=None):
        """
        Handle generic type of a path request.
        """
        pmgt = cpld.union
        req = pmgt.union
        assert isinstance(req, PathSegmentReq), type(req)
        # Random ID for a request.
        req_id = req_id or random.randint(0, 2**32 - 1)
        if logger is None:
            logger = self.get_request_logger(req, req_id, meta)
        dst_ia = req.dst_ia()
        if new_request:
            logger.info("PATH_REQ received")
            REQS_TOTAL.labels(**self._labels).inc()
        if dst_ia == self.addr.isd_as:
            logger.warning("Dropping request: requested DST is local AS")
            return False
        up_segs = set()
        core_segs = set()
        down_segs = set()
        # dst as==0 means any core AS in the specified ISD
        if self.is_core_as(dst_ia) or dst_ia[1] == 0:
            self._resolve_core(req, up_segs, core_segs)
        else:
            self._resolve_not_core(req, up_segs, core_segs, down_segs)
        if up_segs | core_segs | down_segs:
            self._send_path_segments(req, meta, logger, up_segs, core_segs, down_segs)
            return True
        if new_request:
            if self.hpcfg_store.is_hidden_as(dst_ia):
                self._request_paths_from_hps(req, logger)
            else:
                self._request_paths_from_core(req, logger)
            self.pending_req[(dst_ia, req.p.flags.sibra)][req_id] = (req, meta, logger)
        elif self.hidden_segments(last_ia=dst_ia, sibra=req.p.flags.sibra):
            self._request_missing_paths_from_core(req, logger)
        return False

    def _resolve_core(self, req, up_segs, core_segs):
        """
        Dst is core AS.
        """
        dst_ia = req.dst_ia()
        params = dst_ia.params()
        params["sibra"] = req.p.flags.sibra
        if dst_ia[0] == self.addr.isd_as[0]:
            # Dst in local ISD. First check whether DST is a (super)-parent.
            up_segs.update(self.up_segments(**params))
        # Check whether dst is known core AS.
        for cseg in self.core_segments(**params):
            # Check do we have an up-seg that is connected to core_seg.
            tmp_up_segs = self.up_segments(first_ia=cseg.last_ia(),
                                           sibra=req.p.flags.sibra)
            if tmp_up_segs:
                up_segs.update(tmp_up_segs)
                core_segs.add(cseg)

    def _resolve_not_core(self, req, up_segs, core_segs, down_segs):
        """
        Dst is regular AS.
        """
        sibra = req.p.flags.sibra
        path_db = self.down_segments(last_ia=req.dst_ia(), sibra=sibra)
        if self.hpcfg_store.is_hidden_as(req.dst_ia()):
            path_db = self.hidden_segments(last_ia=req.dst_ia(), sibra=sibra)
        # Check if there exists down-seg to DST.
        for dseg in path_db:
            first_ia = dseg.first_ia()
            if req.dst_ia()[0] == self.addr.isd_as[0]:
                # Dst in local ISD. First try to find direct up-seg.
                dir_up_segs = self.up_segments(first_ia=first_ia, sibra=sibra)
                if dir_up_segs:
                    up_segs.update(dir_up_segs)
                    down_segs.add(dseg)
            # Now try core segments that connect to down segment.
            # PSz: it might make sense to start with up_segments instead.
            for cseg in self.core_segments(first_ia=first_ia, sibra=sibra):
                # And up segments that connect to core segment.
                up_core_segs = self.up_segments(first_ia=cseg.last_ia(),
                                                sibra=sibra)
                if up_core_segs:
                    up_segs.update(up_core_segs)
                    core_segs.add(cseg)
                    down_segs.add(dseg)

    def _request_paths_from_hps(self, req, logger):
        """
        Try to request HPS for given target.
        """
        src_ia = req.src_ia()
        dst_ia = req.dst_ia()
        flags = req.flags()
        hpcfg = self.hpcfg_store.get_hpcfg_from_data(src_ia, dst_ia)
        if hpcfg:
            new_req = HPSegReq.from_values(src_ia, dst_ia, flags, [hpcfg.id()])
            ts = int(SCIONTime.get_time())
            chain = self._get_my_cert()
            isd_as, cert_ver = chain.get_leaf_isd_as_ver()
            trc_ver = self._get_my_trc().version
            hmgt = HPMgmt(new_req, isd_as, trc_ver, cert_ver, ts)
            sig = hmgt.sign(self.signing_key)
            if not sig:
                logging.debug("Signing failed: %s" % hmgt)
                return
            for hps_ia in hpcfg.iter_hps_ias():
                path = self._get_path_via_sciond(hps_ia)
                if path:
                    meta = self._build_meta(ia=hps_ia, host=SVCType.PS_A, path=path.fwd_path())
                    self.send_meta(CtrlPayload(hmgt), meta)
                    logger.info("Hidden path request sent to %s via [%s]: %s",
                                meta, path.short_desc(), new_req.short_desc())
                else:
                    logger.warning("Hidden path request (for %s) not sent: "
                                   "no path found", new_req.short_desc())

    def _request_paths_from_core(self, req, logger):
        """
        Try to request core PS for given target.
        """
        up_segs = self.up_segments(sibra=req.p.flags.sibra)
        if not up_segs:
            logger.info('Pending target added.')
            # Wait for path to any local core AS
            self.waiting_targets[self.addr.isd_as[0]].append((req, logger))
            return

        # PSz: for multipath it makes sense to query with multiple core ASes
        pcb = up_segs[0]
        logger.info('Send request to core via %s', pcb.short_desc())
        path = pcb.get_path(reverse_direction=True)
        meta = self._build_meta(ia=pcb.first_ia(), path=path,
                                host=SVCType.PS_A, reuse=True)
        self.send_meta(CtrlPayload(PathMgmt(req.copy())), meta)

    def _request_missing_paths_from_core(self, req, logger):
        """
        """
        sibra = req.p.flags.sibra
        # Check if there exists down-seg to DST.
        dst_ias = []
        for dseg in self.hidden_segments(last_ia=req.dst_ia(), sibra=sibra):
            dst_ia = dseg.first_ia()
            if dst_ia not in dst_ias:
                dst_ias.append(dst_ia)
        for dst_ia in dst_ias:
            new_req = req.copy()
            new_req.p.dstIA = int(dst_ia)
            self._request_paths_from_core(new_req, logger)

    def _forward_revocation(self, rev_info, meta):
        # Inform core ASes if the revoked interface belongs to this AS or
        # the revocation originates from a different ISD.
        rev_isd_as = rev_info.isd_as()
        if (rev_isd_as == self.addr.isd_as or
                rev_isd_as[0] != self.addr.isd_as[0]):
            self._send_rev_to_core(rev_info)

    def _send_rev_to_core(self, rev_info):
        """
        Forwards a revocation to a core path service.

        :param rev_info: The RevocationInfo object
        """
        # Issue revocation to all core ASes excluding self.
        paths = self.up_segments()
        if not paths:
            logging.warning("No paths to core ASes available for forwarding"
                            "revocation: %s", rev_info.short_desc())
            return
        seg = paths[0]
        core_ia = seg.first_ia()
        path = seg.get_path(reverse_direction=True)
        logging.info("Forwarding Revocation to %s using path:\n%s" %
                     (core_ia, seg.short_desc()))
        meta = self._build_meta(ia=core_ia, path=path, host=SVCType.PS_A)
        self.send_meta(CtrlPayload(PathMgmt(rev_info.copy())), meta)
