//! ACME account handling and certificate orders (HTTP-01), via instant-acme.
use super::pem::{certified, not_after_unix};
use super::{CertResolver, ChallengeStore, TlsError};
use crate::config::{AcmeDirectory, GatewayCfg};
use crate::storage::{Db, certs::CertRecord, now_unix};
use instant_acme::{
    Account, AccountCredentials, AuthorizationStatus, ChallengeType, Identifier, LetsEncrypt, NewAccount,
    NewOrder, OrderStatus, RetryPolicy,
};
use std::sync::Arc;
use std::time::Duration;

pub fn directory_url(d: &AcmeDirectory) -> String {
    match d {
        AcmeDirectory::Production => LetsEncrypt::Production.url().to_string(),
        AcmeDirectory::Staging => LetsEncrypt::Staging.url().to_string(),
        AcmeDirectory::Custom(u) => u.clone(),
    }
}

/// Loads the stored account for the directory, or registers a new one.
pub async fn account(gw: &GatewayCfg, db: &Db, email: &str) -> Result<Account, TlsError> {
    let dir = directory_url(&gw.acme_directory);
    let builder = match &gw.acme_ca_root {
        Some(p) => Account::builder_with_root(p)?,
        None => Account::builder()?,
    };
    if let Some(json) = db.get_account(&dir).await? {
        let creds: AccountCredentials = serde_json::from_str(&json)?;
        return Ok(builder.from_credentials(creds).await?);
    }
    let contact = format!("mailto:{email}");
    let new = NewAccount {
        contact: &[&contact],
        terms_of_service_agreed: true,
        only_return_existing: false,
    };
    let (acct, creds) = builder.create(&new, dir.clone(), None).await?;
    db.put_account(&dir, &serde_json::to_string(&creds)?).await?;
    Ok(acct)
}

/// Orders one certificate covering all `hosts`, stores it under each host and installs it in the resolver.
pub async fn issue(
    account: &Account,
    hosts: &[String],
    db: &Db,
    resolver: &CertResolver,
    challenges: &ChallengeStore,
) -> Result<(), TlsError> {
    let ids: Vec<Identifier> = hosts.iter().map(|h| Identifier::Dns(h.clone())).collect();
    let mut order = account.new_order(&NewOrder::new(&ids)).await?;
    let mut tokens = Vec::new();
    let prepared: Result<(), TlsError> = async {
        let mut auths = order.authorizations();
        while let Some(a) = auths.next().await {
            let mut a = a?;
            if a.status == AuthorizationStatus::Valid {
                continue;
            }
            let mut ch = a
                .challenge(ChallengeType::Http01)
                .ok_or_else(|| TlsError::Order("no http-01 challenge".into()))?;
            challenges.put(ch.token.clone(), ch.key_authorization().as_str().to_owned());
            tokens.push(ch.token.clone());
            ch.set_ready().await?;
        }
        Ok(())
    }
    .await;
    let retry = RetryPolicy::new()
        .initial_delay(Duration::from_secs(1))
        .backoff(2.0)
        .timeout(Duration::from_secs(120));
    let status = match prepared {
        Ok(()) => order.poll_ready(&retry).await.map_err(TlsError::from),
        Err(e) => Err(e),
    };
    tokens.iter().for_each(|t| challenges.remove(t));
    let status = status?;
    if status != OrderStatus::Ready {
        return Err(TlsError::Order(format!("order status {status:?}")));
    }
    let key_pem = order.finalize().await?;
    let chain_pem = order.poll_certificate(&retry).await?;
    let key = Arc::new(certified(&chain_pem, &key_pem)?);
    let not_after = not_after_unix(&chain_pem)?;
    for h in hosts {
        let rec = CertRecord {
            domain: h.clone(),
            cert_pem: chain_pem.clone(),
            key_pem: key_pem.clone(),
            not_after,
            issued_at: now_unix(),
        };
        db.put_cert(rec).await?;
        resolver.set(h, key.clone());
    }
    tracing::info!(hosts = ?hosts, not_after, "certificate issued");
    Ok(())
}
