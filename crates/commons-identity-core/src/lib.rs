//! Portable cryptographic and protocol primitives for Commons Identity.
//!
//! This crate is an experimental, unaudited reference implementation of the
//! `commons-identity/1` CI-Core profile. It is not suitable for production
//! identity or access-control decisions until an independent security review.

pub mod audit;
pub mod credential;
pub mod crypto;
pub mod error;
pub mod migration;
pub mod presentation;
pub mod recovery;
pub mod status;
pub mod storage;
pub mod vault;

pub use audit::{AuditEntry, AuditLog, AuditOperation};
pub use credential::{
    CredentialKind, CredentialStatusReference, DataIntegrityProof, HolderBinding,
    UnsignedCredential, VerifiableCredential,
};
pub use crypto::{DeviceKeyMaterial, SigningKeyMaterial, sha256_multibase};
pub use error::{CommonsError, Result};
pub use migration::{CommunityMigrationBundle, MigrationPayload};
pub use presentation::{
    CiRequest, ConsentReceipt, Linkability, Presentation, PresentationPurpose, ReplayCache,
};
pub use recovery::{
    ArchivePayload, CommonsIdentityArchive, KdfParameters, RecoveryKit, RecoverySnapshot,
};
pub use status::{CredentialState, StatusList, StatusPurpose};
pub use storage::EncryptedRecordStore;
pub use vault::{
    CommunityPersona, CredentialInstance, DeviceRecord, DeviceRevocationReport, DeviceState,
    IdentityVault, RecoveryConfiguration,
};

/// Stable wire identifier for this protocol generation.
pub const PROTOCOL_ID: &str = "commons-identity/1";

/// Stable identifier for the first CI-Core interoperability profile.
pub const CI_CORE_PROFILE_ID: &str = "ci-core-1";

/// Context URL for Commons Identity extension terms.
pub const COMMONS_CONTEXT_V1: &str =
    "https://nishizukakoichi.github.io/commons-identity/contexts/v1.jsonld";

/// CI-Core uses the W3C EdDSA JCS 2022 Data Integrity cryptosuite.
pub const CI_CORE_CRYPTOSUITE: &str = "eddsa-jcs-2022";
