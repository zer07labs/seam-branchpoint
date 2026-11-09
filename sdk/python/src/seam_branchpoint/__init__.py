"""Seam Branchpoint SDK core: pure `branchpoint.v1` primitives (spec docs/spec/branchpoint-v1.md).

Local bpa1 assignment, the workload certificate, signed hash-chained receipts, the signed SDK document, the upload
batch and the SDK-key token. Nothing in this package does network I/O at import time or ever.
"""

from ._wire import (
    MAX_SAFE,
    ConfigError,
    InvalidUnit,
    JcsError,
    Refusal,
    UlidGenerator,
    bucket,
    from_micros,
    jcs_flat,
    jcs_tree,
    salt_kid,
    to_micros,
    unit_tag,
)
from .auth import DEFAULT_ROUTES, TOKEN_LIFETIME_S, SdkKey, TokenInputError
from .cert import Cert, CertRefused, build_wcert, check_pinned, key_id, parse_wcert, pin_keys, verify_cert, verify_cert_json
from .chain import (
    CHAIN_EXHAUSTED,
    ChainState,
    ReceiptRecord,
    SignedReceipt,
    admit_outcomes,
    batch_message,
    batch_nonempty,
    batch_shape_ok,
    build_batch,
    canonical_receipt,
    check_receipt,
    encode_batch,
    genesis,
    make_outcome,
    outcome_ok,
    receipt_hash,
    sign_batch,
    sign_receipt,
    verify_batch_sig,
    verify_receipt_sig,
)
from .document import (
    SUPPORTED_DOCUMENT_VERSION,
    CacheMark,
    Document,
    DocumentRefused,
    VerifiedDocument,
    is_stale,
    verify_document,
)
from .evaluate import Arm, Evaluation, ExperimentDef, evaluate

__version__ = "0.1.0.dev0"

__all__ = [
    "CHAIN_EXHAUSTED", "DEFAULT_ROUTES", "MAX_SAFE", "SUPPORTED_DOCUMENT_VERSION", "TOKEN_LIFETIME_S", "Arm",
    "CacheMark", "Cert", "ConfigError", "ReceiptRecord", "check_pinned", "sign_receipt", "CertRefused", "ChainState", "Document", "DocumentRefused", "Evaluation", "ExperimentDef",
    "InvalidUnit", "JcsError", "Refusal", "SdkKey", "SignedReceipt", "TokenInputError", "UlidGenerator", "VerifiedDocument",
    "__version__", "admit_outcomes", "batch_message", "batch_nonempty", "batch_shape_ok", "bucket", "build_batch", "build_wcert",
    "canonical_receipt", "check_receipt", "encode_batch", "evaluate", "from_micros", "genesis", "is_stale", "jcs_flat", "jcs_tree",
    "key_id", "make_outcome", "outcome_ok", "parse_wcert", "pin_keys", "receipt_hash",
    "salt_kid", "sign_batch", "to_micros", "unit_tag", "verify_batch_sig", "verify_cert", "verify_cert_json",
    "verify_document", "verify_receipt_sig",
]
