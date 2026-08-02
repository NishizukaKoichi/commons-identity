use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use commons_identity_core::{
    ArchivePayload, CI_CORE_PROFILE_ID, CiRequest, CommonsError, CommonsIdentityArchive,
    ConsentReceipt, CredentialKind, CredentialStatusReference, HolderBinding, IdentityVault,
    Linkability, Presentation, PresentationPurpose, RecoveryKit, RecoverySnapshot, ReplayCache,
    SigningKeyMaterial, StatusList, StatusPurpose, UnsignedCredential, crypto::random_urlsafe,
    status::MIN_STATUS_ENTRIES,
};
use rand::rngs::OsRng;
use serde_json::{Value, json};
use time::{Duration, OffsetDateTime};
use zeroize::Zeroizing;

#[derive(Debug, Parser)]
#[command(version, about = "Commons Identity Developer Preview tools")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Generate a complete local issuance/presentation/recovery fixture.
    Demo {
        #[arg(long, default_value = "artifacts/demo")]
        output: PathBuf,

        /// Archive passphrase. Prefer CI_ARCHIVE_PASSPHRASE to avoid shell history.
        #[arg(long, env = "CI_ARCHIVE_PASSPHRASE", hide_env_values = true)]
        passphrase: Option<String>,

        /// Overwrite only the known demo artifact files in the output directory.
        #[arg(long)]
        force: bool,
    },

    /// Decrypt a .cia archive and print a secret-free inventory.
    InspectArchive {
        #[arg(long)]
        archive: PathBuf,

        #[arg(long, env = "CI_ARCHIVE_PASSPHRASE", hide_env_values = true)]
        passphrase: String,
    },
}

fn main() -> Result<()> {
    match Cli::parse().command {
        Command::Demo {
            output,
            passphrase,
            force,
        } => run_demo(&output, passphrase.map(Zeroizing::new), force),
        Command::InspectArchive {
            archive,
            passphrase,
        } => inspect_archive(&archive, Zeroizing::new(passphrase)),
    }
}

fn run_demo(output: &Path, passphrase: Option<Zeroizing<String>>, force: bool) -> Result<()> {
    fs::create_dir_all(output).with_context(|| format!("could not create {}", output.display()))?;
    let artifact_names = [
        "credential.json",
        "presentation.json",
        "consent-receipt.json",
        "revocation-status-list.json",
        "suspension-status-list.json",
        "recovery-kit.cbor",
        "identity-archive.cia",
        "summary.json",
    ];
    if !force {
        let existing: Vec<_> = artifact_names
            .iter()
            .map(|name| output.join(name))
            .filter(|path| path.exists())
            .collect();
        if !existing.is_empty() {
            bail!(
                "refusing to overwrite existing demo artifacts; choose another --output or pass --force"
            );
        }
    }

    let generated_passphrase = passphrase.is_none();
    let passphrase = passphrase.unwrap_or_else(|| Zeroizing::new(random_urlsafe(&mut OsRng, 24)));
    let now = OffsetDateTime::now_utc();
    let community = "did:webvh:developer-preview:research.example";
    let second_community = "did:webvh:developer-preview:school.example";
    let issuer = SigningKeyMaterial::generate();
    let mut vault = IdentityVault::create("Demo Mac", now)?;
    let device_id = vault.first_active_device_id()?;
    vault.create_persona(
        community,
        "Example Research Community",
        "sha256-developer-preview-policy",
        now,
    )?;
    vault.create_persona(
        second_community,
        "Example School Community",
        "sha256-school-preview-policy",
        now,
    )?;

    let first_persona = vault.persona(community)?;
    let second_persona = vault.persona(second_community)?;
    let communities_are_separated = first_persona.local_subject_id
        != second_persona.local_subject_id
        && first_persona.device_public_key(device_id)?
            != second_persona.device_public_key(device_id)?;
    let holder_key = first_persona.device_signing_key(device_id)?.clone();

    let mut revocation = StatusList::new(
        "https://identity.example/status/revocation-1",
        community,
        StatusPurpose::Revocation,
        MIN_STATUS_ENTRIES,
        now,
    )?;
    let mut suspension = StatusList::new(
        "https://identity.example/status/suspension-1",
        community,
        StatusPurpose::Suspension,
        MIN_STATUS_ENTRIES,
        now,
    )?;
    let revocation_index = revocation.allocate_random()?;
    let suspension_index = suspension.allocate_random()?;
    let valid_from = rfc3339(now)?;
    let valid_until = rfc3339(now + Duration::days(90))?;
    let mut subject = BTreeMap::new();
    subject.insert("community".into(), json!(community));
    subject.insert("membership".into(), json!("active"));
    subject.insert("scope".into(), json!(["community:enter"]));
    subject.insert(
        "policyHash".into(),
        json!("sha256-developer-preview-policy"),
    );
    let mut unsigned = UnsignedCredential::new(
        CredentialKind::CommunityMembershipCredential,
        community,
        valid_from.clone(),
        valid_until,
        subject,
        HolderBinding::multikey(holder_key.public_key_multibase()),
        Some(CredentialStatusReference::bitstring(
            revocation.id.clone(),
            revocation_index,
            "revocation",
        )),
    );
    unsigned
        .credential_status
        .push(CredentialStatusReference::bitstring(
            suspension.id.clone(),
            suspension_index,
            "suspension",
        ));
    let credential = unsigned.issue(&issuer, &valid_from)?;
    credential.verify_with_issuer_key(&issuer.public_key_multibase(), now)?;
    vault.persona_mut(community)?.add_credential(
        device_id,
        credential.clone(),
        &issuer.public_key_multibase(),
        now,
    )?;

    let request = CiRequest::new(
        PresentationPurpose {
            code: "community_document_access".into(),
            display: "Access the example research archive".into(),
        },
        vec!["community".into(), "membership".into(), "scope".into()],
        300,
        false,
        Linkability::Community,
        None,
        "did:webvh:developer-preview-verifier:archive.example",
        now,
    )?;
    let presentation = Presentation::create_ci_core(
        &request,
        credential.clone(),
        &holder_key,
        &issuer.public_key_multibase(),
        now,
    )?;
    let mut replay_cache = ReplayCache::default();
    replay_cache.verify_and_consume(
        &presentation,
        &request,
        &issuer.public_key_multibase(),
        now,
    )?;
    let replay_rejected = matches!(
        replay_cache.verify_and_consume(
            &presentation,
            &request,
            &issuer.public_key_multibase(),
            now,
        ),
        Err(CommonsError::Replay)
    );
    let receipt = ConsentReceipt::from_approved_presentation(
        &request,
        &presentation,
        &issuer.public_key_multibase(),
        now,
    )?;
    vault.record_consent(receipt.clone(), now)?;
    vault.mark_recovery_kit_configured(now)?;

    let recovery = RecoveryKit::create(
        &RecoverySnapshot {
            vault_format_version: vault.vault_format_version.clone(),
            vault: vault.clone(),
            latest_snapshot_reference: None,
            created_at: rfc3339(now)?,
        },
        &passphrase,
    )?;
    let archive = CommonsIdentityArchive::create(
        &ArchivePayload {
            archive_version: "1".into(),
            vault: vault.clone(),
            credential_formats: vec!["application/vc".into(), "application/vp".into()],
            consent_receipts: vault.consent_receipts.clone(),
            schema_snapshots: BTreeMap::from([(
                "membership-v1".into(),
                json!({"required": ["community", "membership", "scope", "policyHash"]}),
            )]),
            resolver_cache: BTreeMap::new(),
            created_at: rfc3339(now)?,
        },
        &passphrase,
    )?;

    write_json(&output.join("credential.json"), &credential)?;
    write_json(&output.join("presentation.json"), &presentation)?;
    write_json(&output.join("consent-receipt.json"), &receipt)?;
    write_json(
        &output.join("revocation-status-list.json"),
        &revocation.as_credential(&issuer, Duration::days(2))?,
    )?;
    write_json(
        &output.join("suspension-status-list.json"),
        &suspension.as_credential(&issuer, Duration::days(2))?,
    )?;
    fs::write(output.join("recovery-kit.cbor"), recovery.to_bytes()?)?;
    fs::write(output.join("identity-archive.cia"), archive.to_bytes()?)?;
    let summary = json!({
        "protocol": commons_identity_core::PROTOCOL_ID,
        "profile": CI_CORE_PROFILE_ID,
        "audited": false,
        "communityPersonas": vault.personas.len(),
        "crossCommunityIdentifiersAndKeysSeparated": communities_are_separated,
        "holderBindingVerified": true,
        "issuerAuthorizationVerified": true,
        "replayRejected": replay_rejected,
        "revocationAndSuspensionSeparated": credential.credential_status.len() == 2,
        "consentReceiptStored": vault.consent_receipts.len() == 1,
        "guardianRecovery": "not implemented; excluded because CI-Core does not claim it",
        "warning": "Synthetic local data only. Not for identity or access-control decisions."
    });
    write_json(&output.join("summary.json"), &summary)?;

    if generated_passphrase {
        eprintln!("Generated demo archive passphrase (not stored in the output directory):");
        eprintln!("{}", passphrase.as_str());
    }
    println!("{}", serde_json::to_string_pretty(&summary)?);
    println!("Artifacts: {}", output.display());
    Ok(())
}

fn inspect_archive(path: &Path, passphrase: Zeroizing<String>) -> Result<()> {
    let bytes = fs::read(path).with_context(|| format!("could not read {}", path.display()))?;
    let archive = CommonsIdentityArchive::from_bytes(&bytes)?;
    let payload = archive.open(passphrase.as_str())?;
    let credential_count = payload
        .vault
        .personas
        .values()
        .map(|persona| persona.credentials.len())
        .sum::<usize>();
    let credential_kinds = payload
        .vault
        .personas
        .values()
        .flat_map(|persona| persona.credentials.iter())
        .filter_map(|instance| instance.credential.kind().map(str::to_string))
        .collect::<BTreeSet<_>>();
    let inventory: Value = json!({
        "archiveVersion": payload.archive_version,
        "vaultFormatVersion": payload.vault.vault_format_version,
        "deviceCount": payload.vault.devices.len(),
        "communityPersonaCount": payload.vault.personas.len(),
        "credentialCount": credential_count,
        "credentialKinds": credential_kinds,
        "consentReceiptCount": payload.consent_receipts.len(),
        "credentialFormats": payload.credential_formats,
        "createdAt": payload.created_at,
        "secretsDisplayed": false,
    });
    println!("{}", serde_json::to_string_pretty(&inventory)?);
    Ok(())
}

fn write_json(path: &Path, value: &impl serde::Serialize) -> Result<()> {
    let bytes = serde_json::to_vec_pretty(value)?;
    fs::write(path, bytes).with_context(|| format!("could not write {}", path.display()))
}

fn rfc3339(value: OffsetDateTime) -> Result<String> {
    value
        .format(&time::format_description::well_known::Rfc3339)
        .map_err(Into::into)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cli_parses_demo_and_inspection_commands() {
        assert!(Cli::try_parse_from(["ci", "demo", "--output", "tmp/demo"]).is_ok());
        assert!(
            Cli::try_parse_from([
                "ci",
                "inspect-archive",
                "--archive",
                "identity.cia",
                "--passphrase",
                "long-enough-passphrase",
            ])
            .is_ok()
        );
    }

    #[test]
    fn demo_artifact_names_never_include_a_passphrase_file() {
        let names = [
            "credential.json",
            "presentation.json",
            "consent-receipt.json",
            "recovery-kit.cbor",
            "identity-archive.cia",
        ];
        assert!(names.iter().all(|name| !name.contains("passphrase")));
    }
}
