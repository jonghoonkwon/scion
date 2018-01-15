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
:mod:`missing_trc_cert_map` --- SCION map for missing trcs and certchains
=========================================================================
"""
# Stdlib
import threading


class HPCfgMeta(object):  # pragma: no cover
    """
    The HPCfgMeta class holds missing trcs and certificates and
    necessary metadata for a HMgmt.
    """

    def __init__(self, hmgt, callback, meta=None):
        self.trc_vers, self.cert_vers = hmgt.get_trcs_certs()
        self.missing_trcs = set()
        self.miss_trc_lock = threading.Lock()
        self.missing_certs = set()
        self.miss_cert_lock = threading.Lock()
        self.hmgt = hmgt
        self.callback = callback
        self.meta = meta

    def verifiable(self):
        with self.miss_cert_lock and self.miss_trc_lock:
            return not self.missing_trcs and not self.missing_certs
