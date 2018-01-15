@0xe8550b6088706947;

using Go = import "go.capnp";
$Go.package("proto");
$Go.import("github.com/netsec-ethz/scion/go/proto");

using PathMgmt = import "path_mgmt.capnp";
using HPCfg = import "hp_cfg.capnp";

struct HPCfgReq {
    hpCfgIds @0 :List(HPCfg.HPCfgId);
}

struct HPCfgRecs {
    hpCfgs @0 :List(HPCfg.HPCfg);
}

struct HPMgmt {
    isdas @0 :UInt32;  # Local ISD-AS
    trcVer @1 :UInt32;
    certVer @2 :UInt32;
    timestamp @3 :UInt64;
    signature @4 :Data;
    union {
        hpCfgReq @5 :HPCfgReq;
        hpCfgReply @6 :HPCfgRecs;
        hpCfgReg @7 :HPCfgRecs;
        hpSegReq @8 :PathMgmt.SegReq;
        hpSegReply @9 :PathMgmt.SegRecs;
        hpSegReg @10 :PathMgmt.SegRecs;
    }
}
