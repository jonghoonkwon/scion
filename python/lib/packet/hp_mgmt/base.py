# Copyright 2017 ETH Zurich
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
:mod:`base` --- Container for hidden path packets
==================================================
"""
# Stdlib
from collections import defaultdict
# External
import capnp  # noqa
# SCION
import proto.hp_mgmt_capnp as P
from lib.errors import SCIONSigVerError
from lib.crypto.asymcrypto import sign
from lib.crypto.symcrypto import crypto_hash
from lib.packet.hp_mgmt.seg import HPSegReg, HPSegReply, HPSegReq
from lib.packet.hp_mgmt.cfg import HPCfgReg, HPCfgReply, HPCfgReq
from lib.packet.packet_base import CerealBox
from lib.packet.scion_addr import ISD_AS
from lib.types import HPMgmtType
from lib.util import proto_len


class HPMgmt(CerealBox):  # pragma: no cover
    NAME = "HPMgmt"
    P_CLS = P.HPMgmt
    VER = proto_len(P.HPMgmt.schema) - 1  # Highest number in the capnp schema.
    CLASS_FIELD_MAP = {
        HPCfgReq: HPMgmtType.CFG_REQ,
        HPCfgReply: HPMgmtType.CFG_REPLY,
        HPCfgReg: HPMgmtType.CFG_REG,
        HPSegReq: HPMgmtType.SEG_REQ,
        HPSegReply: HPMgmtType.SEG_REPLY,
        HPSegReg: HPMgmtType.SEG_REG,
    }

    def __init__(self, union, isdas, trcVer, certVer, timestamp, signature=None):
        super().__init__(union)
        self.isdas = int(isdas)
        self.trcVer = trcVer
        self.certVer = certVer
        self.timestamp = timestamp
        if signature:
            self.signature = signature
        else:
            self.signature = b""

    @classmethod
    def _from_union(cls, p, union):  # pragma: no cover
        """
        Internal constructor, overridden by sub-classes which have more fields than just a single
        unnamed union.

        p is passed in to be available to subclasses which override this.
        """
        return cls(union, p.isdas, p.trcVer, p.certVer, p.timestamp, p.signature)

    def proto(self):
        field = self.type()
        return self.P_CLS.new_message(**{"isdas": self.isdas,
                                         "trcVer": self.trcVer,
                                         "certVer": self.certVer,
                                         "timestamp": self.timestamp,
                                         "signature": self.signature,
                                         field: self.union.proto()})

    def isd_as(self):
        return ISD_AS(self.isdas)

    def trc_ver(self):
        return self.trcVer

    def cert_ver(self):
        return self.certVer

    def sig_pack(self):
        """Pack for signing version 10 (defined by highest field number)"""
        if self.VER != 10:
            raise SCIONSigVerError("HPMgmt.sig_pack cannot support version %s",
                                   self.VER)
        b = []
        b.append(self.isdas.to_bytes(4, 'big'))
        b.append(self.trcVer.to_bytes(4, 'big'))
        b.append(self.certVer.to_bytes(4, 'big'))
        b.append(self.timestamp.to_bytes(8, 'big'))
        b.append(self.union.sig_pack())
        return b"".join(b)

    def sign(self, key, set_=True):
        sig = sign(self.sig_pack(), key)
        if set_:
            self.signature = sig
        return sig

    def get_trcs_certs(self):
        trcs = defaultdict(set)
        certs = defaultdict(set)
        isd_as = self.isd_as()
        isd = isd_as[0]
        trcs[isd].add(self.trc_ver())
        certs[isd_as].add(self.cert_ver())
        return trcs, certs

    def short_id(self):
        return crypto_hash(self.sig_pack()).hex()[:12]

    def __str__(self):
        return "%s(%dB): timestamp=%s signature=%s %s" % (
            self.NAME, len(self), self.timestamp, self.signature, self.union)
