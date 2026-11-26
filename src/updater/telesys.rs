//! Telesys: canal de atualização próprio do Suporte-Telesys (só Windows).
//!
//! Substitui, no cliente personalizado, a consulta a api.rustdesk.com:
//! 1. pergunta à API do servidor Telesys (`<api-server>/api/telesys/update`) se a
//!    linha deste build (`res/telesys/update.json`) tem build publicado maior;
//! 2. confere a assinatura ed25519 dos metadados com a chave pública abaixo (a privada
//!    fica só no secret TELESYS_UPDATE_ED25519_SEED do fork; o servidor apenas repassa);
//! 3. baixa o instalador da release do fork, confere tamanho e SHA-256 e instala com o
//!    mesmo caminho do atualizador oficial (`update_new_version`).
//!
//! Formato assinado (gerado por res/telesys/sign_update.py no workflow):
//! `{"schema_version":1,"app":"suporte-telesys","channel":"clientes","build":12,
//!   "version":"1.5.3","release_id":"build-<uid>","artifacts":[{"platform":"windows",
//!   "arch":"x86_64","format":"exe","url":"https://github.com/<repo>/releases/download/
//!   build-<uid>/<arquivo>","file_name":"<arquivo>","size":123,"sha256":"<hex>"}]}`
//! assinado sobre `SIGNATURE_CONTEXT + bytes do JSON`.

use super::{
    current_update_arch, current_update_format, current_update_platform,
    download::ensure_verified_update_artifact, has_no_active_conns, update_new_version,
};
use hbb_common::{
    anyhow::{anyhow, Context},
    base64::{engine::general_purpose::STANDARD, Engine as _},
    bail, config, log,
    sodiumoxide::crypto::sign::{verify_detached, PublicKey, Signature},
    ResultType,
};
use serde_derive::Deserialize;
use std::{io::Read, time::Duration};

const SIGNATURE_CONTEXT: &[u8] = b"Telesys update metadata v1\n";
const APP: &str = "suporte-telesys";
const SCHEMA_VERSION: u32 = 1;
/// Par gerado em 2026-11-26 (cópia da privada fora do git, em TelesysRemote/private).
const PUBLIC_KEY: [u8; 32] = [
    238, 169, 102, 121, 151, 19, 204, 188, 33, 153, 219, 236, 83, 98, 213, 133, 219, 97, 189,
    131, 26, 136, 64, 142, 67, 241, 107, 226, 22, 87, 82, 192,
];
const DEFAULT_REPO: &str = "fabiano3003/rustdesk";
const CHECK_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_RESPONSE_BYTES: u64 = 256 * 1024;

#[derive(Deserialize)]
struct CheckResponse {
    #[serde(default)]
    update: bool,
    #[serde(default)]
    metadata: String,
    #[serde(default)]
    signature: String,
}

#[derive(Deserialize)]
struct Metadata {
    schema_version: u32,
    app: String,
    channel: String,
    build: u64,
    #[serde(default)]
    version: String,
    artifacts: Vec<Artifact>,
}

#[derive(Deserialize)]
struct Artifact {
    platform: String,
    arch: String,
    format: String,
    url: String,
    file_name: String,
    size: u64,
    sha256: String,
}

#[derive(Debug)]
pub(crate) struct VerifiedArtifact {
    pub build: u64,
    pub version: String,
    pub url: String,
    pub file_name: String,
    pub size: u64,
    pub sha256: String,
}

fn repo() -> &'static str {
    // GITHUB_REPOSITORY existe no ambiente de compilação do GitHub Actions.
    option_env!("GITHUB_REPOSITORY")
        .filter(|r| !r.is_empty())
        .unwrap_or(DEFAULT_REPO)
}

/// Confere assinatura e conteúdo dos metadados e devolve o instalador desta máquina.
pub(crate) fn verify_metadata(
    metadata_bytes: &[u8],
    signature_b64: &str,
    public_key: &[u8; 32],
    channel: &str,
    current_build: u64,
    platform: &str,
    arch: &str,
    format: &str,
) -> ResultType<VerifiedArtifact> {
    let signature = STANDARD
        .decode(signature_b64.trim())
        .context("invalid update signature base64")?;
    let signature: [u8; 64] = signature
        .as_slice()
        .try_into()
        .map_err(|_| anyhow!("invalid update signature length"))?;
    let signature =
        Signature::from_bytes(&signature).map_err(|_| anyhow!("invalid update signature"))?;
    hbb_common::sodiumoxide::init().map_err(|_| anyhow!("failed to initialize sodiumoxide"))?;
    let mut signed = Vec::with_capacity(SIGNATURE_CONTEXT.len() + metadata_bytes.len());
    signed.extend_from_slice(SIGNATURE_CONTEXT);
    signed.extend_from_slice(metadata_bytes);
    if !verify_detached(&signature, &signed, &PublicKey(*public_key)) {
        bail!("invalid update metadata signature");
    }

    let metadata: Metadata =
        serde_json::from_slice(metadata_bytes).context("invalid update metadata JSON")?;
    if metadata.schema_version != SCHEMA_VERSION {
        bail!("unsupported update metadata schema version");
    }
    if metadata.app != APP {
        bail!("update metadata app mismatch");
    }
    if metadata.channel != channel {
        bail!("update is for another channel: {}", metadata.channel);
    }
    if metadata.build <= current_build {
        bail!(
            "update build {} is not newer than {}",
            metadata.build,
            current_build
        );
    }
    let mut matches = metadata
        .artifacts
        .iter()
        .filter(|a| a.platform == platform && a.arch == arch && a.format == format);
    let artifact = matches
        .next()
        .ok_or_else(|| anyhow!("no update artifact for {platform}/{arch}/{format}"))?;
    if matches.next().is_some() {
        bail!("multiple update artifacts for {platform}/{arch}/{format}");
    }
    validate_artifact(artifact, repo())?;
    Ok(VerifiedArtifact {
        build: metadata.build,
        version: metadata.version.clone(),
        url: artifact.url.clone(),
        file_name: artifact.file_name.clone(),
        size: artifact.size,
        sha256: artifact.sha256.to_ascii_lowercase(),
    })
}

fn is_safe_name(s: &str) -> bool {
    !s.is_empty()
        && s != "."
        && s != ".."
        && s.len() <= 128
        && s
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

fn validate_artifact(artifact: &Artifact, repo: &str) -> ResultType<()> {
    if !is_safe_name(&artifact.file_name) {
        bail!("invalid update artifact file name");
    }
    if artifact.size == 0 || artifact.size > 1024 * 1024 * 1024 {
        bail!("invalid update artifact size");
    }
    if artifact.sha256.len() != 64 || !artifact.sha256.bytes().all(|b| b.is_ascii_hexdigit()) {
        bail!("invalid update artifact sha256");
    }
    // Só da release do próprio fork: https://github.com/<repo>/releases/download/<tag>/<arquivo>
    let prefix = format!("https://github.com/{repo}/releases/download/");
    let Some(rest) = artifact.url.strip_prefix(&prefix) else {
        bail!("update artifact URL is outside the Telesys releases");
    };
    let Some((tag, file_name)) = rest.split_once('/') else {
        bail!("update artifact URL has no tag");
    };
    if !is_safe_name(tag) || file_name != artifact.file_name {
        bail!("update artifact URL does not match its file name");
    }
    Ok(())
}

fn fetch_check(url: &str) -> ResultType<CheckResponse> {
    // Os metadados são assinados: o servidor só repassa, não precisa ser confiável.
    let client = crate::hbbs_http::create_http_client_with_url(url);
    let response = client.get(url).timeout(CHECK_TIMEOUT).send()?;
    if !response.status().is_success() {
        bail!("Telesys update check failed: HTTP {}", response.status());
    }
    let mut bytes = Vec::new();
    response
        .take(MAX_RESPONSE_BYTES + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_RESPONSE_BYTES {
        bail!("Telesys update check response is too large");
    }
    Ok(serde_json::from_slice(&bytes)?)
}

/// Chamado por `updater::check_update` no lugar do atualizador oficial.
pub(super) fn check_update() -> ResultType<()> {
    let Some((channel, build)) = crate::common::telesys_update_build() else {
        log::debug!("Telesys update: build without update channel");
        return Ok(());
    };
    // Roda no processo de serviço: lê a configuração direto (como o heartbeat em hbbs_http/sync.rs).
    let api = crate::common::get_api_server(
        config::Config::get_option("api-server"),
        config::Config::get_option("custom-rendezvous-server"),
    );
    if api.is_empty() || crate::is_public(&api) {
        log::debug!("Telesys update: no API server");
        return Ok(());
    }
    let platform = current_update_platform();
    let arch = current_update_arch();
    let format = current_update_format(false);
    let url = url::Url::parse_with_params(
        &format!("{}/api/telesys/update", api.trim_end_matches('/')),
        &[
            ("channel", channel.to_owned()),
            ("build", build.to_string()),
            ("platform", platform.to_owned()),
            ("arch", arch.to_owned()),
            ("format", format.to_owned()),
            ("id", config::Config::get_id()),
        ],
    )?;
    let response = fetch_check(url.as_str())?;
    if !response.update {
        log::debug!("Telesys update: build {} ({}) is current", build, channel);
        return Ok(());
    }
    let metadata = STANDARD
        .decode(response.metadata.trim())
        .context("invalid update metadata base64")?;
    let artifact = verify_metadata(
        &metadata,
        &response.signature,
        &PUBLIC_KEY,
        channel,
        build,
        platform,
        arch,
        format,
    )?;
    log::info!(
        "Telesys update: build {} -> {} ({})",
        build,
        artifact.build,
        artifact.url
    );
    let file_path = std::env::temp_dir().join(format!(
        "telesys-update-{}-{}",
        artifact.build, artifact.file_name
    ));
    ensure_verified_update_artifact(
        &artifact.url,
        &file_path,
        artifact.size,
        &artifact.sha256,
    )?;
    // O download pode levar minutos: confere de novo se ninguém conectou.
    if has_no_active_conns() {
        let version = format!("{} build {}", artifact.version, artifact.build);
        update_new_version(false, &version, &file_path, &artifact.sha256);
    } else {
        log::info!("Telesys update: connection started during download, deferring");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use hbb_common::sodiumoxide::crypto::sign;

    fn signed(json: &str) -> (Vec<u8>, String, [u8; 32]) {
        let _ = hbb_common::sodiumoxide::init();
        let (pk, sk) = sign::gen_keypair();
        let mut data = SIGNATURE_CONTEXT.to_vec();
        data.extend_from_slice(json.as_bytes());
        let sig = sign::sign_detached(&data, &sk);
        (json.as_bytes().to_vec(), STANDARD.encode(sig.to_bytes()), pk.0)
    }

    fn metadata(channel: &str, build: u64, url: &str) -> String {
        format!(
            r#"{{"schema_version":1,"app":"suporte-telesys","channel":"{channel}","build":{build},"version":"1.5.3","release_id":"build-x","artifacts":[{{"platform":"windows","arch":"x86_64","format":"exe","url":"{url}","file_name":"rustdesk-1.5.3-x86_64.exe","size":10,"sha256":"{}"}}]}}"#,
            "a".repeat(64)
        )
    }

    fn url() -> String {
        format!(
            "https://github.com/{}/releases/download/build-20261126-ab12/rustdesk-1.5.3-x86_64.exe",
            repo()
        )
    }

    #[test]
    fn accepts_newer_build_of_same_channel() {
        let (m, s, k) = signed(&metadata("clientes", 5, &url()));
        let a = verify_metadata(&m, &s, &k, "clientes", 4, "windows", "x86_64", "exe").unwrap();
        assert_eq!(a.build, 5);
        assert_eq!(a.file_name, "rustdesk-1.5.3-x86_64.exe");
    }

    #[test]
    fn rejects_wrong_key_channel_build_and_url() {
        let (m, s, _) = signed(&metadata("clientes", 5, &url()));
        let (_, _, other) = signed("{}");
        assert!(verify_metadata(&m, &s, &other, "clientes", 4, "windows", "x86_64", "exe").is_err());

        let (m, s, k) = signed(&metadata("tecnicos", 5, &url()));
        assert!(verify_metadata(&m, &s, &k, "clientes", 4, "windows", "x86_64", "exe").is_err());

        let (m, s, k) = signed(&metadata("clientes", 4, &url()));
        assert!(verify_metadata(&m, &s, &k, "clientes", 4, "windows", "x86_64", "exe").is_err());

        let evil = "https://github.com/rustdesk/rustdesk/releases/download/1.5.4/rustdesk-1.5.3-x86_64.exe";
        let (m, s, k) = signed(&metadata("clientes", 5, evil));
        assert!(verify_metadata(&m, &s, &k, "clientes", 4, "windows", "x86_64", "exe").is_err());

        let (m, s, k) = signed(&metadata("clientes", 5, &url()));
        assert!(verify_metadata(&m, &s, &k, "clientes", 4, "windows", "aarch64", "exe").is_err());
    }

    #[test]
    fn rejects_tampered_metadata() {
        let (mut m, s, k) = signed(&metadata("clientes", 5, &url()));
        let pos = m.iter().position(|b| *b == b'5').unwrap();
        m[pos] = b'9';
        assert!(verify_metadata(&m, &s, &k, "clientes", 4, "windows", "x86_64", "exe").is_err());
    }
}
