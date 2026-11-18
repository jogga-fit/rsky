//! A PDS whose tokens come from an external authorization server
//! (`PDS_OAUTH_ISSUER`). Its own binary, because the setting is process-wide.
use rocket::http::{ContentType, Header, Status};
use rocket::local::asynchronous::Client;
use rsky_oauth::jwk::{EcCurve, Jwk};
use rsky_oauth::jwt::{JwtClaims, JwtHeader};
use serde_json::{json, Value};

mod common;
use common::oauth::*;

const ISSUER: &str = "https://auth.example.com";
const DID: &str = "did:plc:khvyd3oiw46vif5gm7hijslk";

fn issuer_key() -> Jwk {
    Jwk::from_private_key_bytes(EcCurve::P256, &[0x42u8; 32]).unwrap()
}

/// An access token as the external issuer mints it; `edit` makes it wrong.
fn token(client: &Client, key: &Jwk, scope: &str, edit: impl Fn(&mut JwtClaims)) -> String {
    let audience = &client
        .rocket()
        .state::<rsky_pds::config::ServerConfig>()
        .unwrap()
        .service
        .did;
    let mut header = JwtHeader::new("ES256");
    header.typ = Some("at+jwt".to_string());
    let mut claims = JwtClaims {
        iss: Some(ISSUER.to_string()),
        sub: Some(DID.to_string()),
        aud: Some(json!(audience)),
        exp: Some(now_secs() + 300),
        iat: Some(now_secs()),
        jti: Some(format!("tok-{}", "0".repeat(32))),
        ..Default::default()
    };
    claims.extra.insert(
        "cnf".into(),
        json!({"jkt": dpop_key().to_public().thumbprint()}),
    );
    claims.extra.insert("scope".into(), json!(scope));
    edit(&mut claims);
    rsky_oauth::jwt::sign(&header, &claims, key).unwrap()
}

async fn status(client: &Client, path: &str) -> Status {
    client.get(path).dispatch().await.status()
}

#[tokio::test]
async fn an_external_issuer_replaces_the_authorization_server() {
    std::env::set_var("PDS_OAUTH_ISSUER", ISSUER);
    std::env::set_var(
        "PDS_OAUTH_ISSUER_JWK",
        serde_json::to_string(&issuer_key().to_public()).unwrap(),
    );
    let (_dir, client) = get_oauth_client().await;
    create_active_account(&client).await;

    let meta: Value = client
        .get("/.well-known/oauth-protected-resource")
        .dispatch()
        .await
        .into_json()
        .await
        .unwrap();
    assert_eq!(meta["authorization_servers"], json!([ISSUER]));
    assert_eq!(meta["resource"], json!(public_url(&client)));
    assert_eq!(
        status(&client, "/.well-known/oauth-authorization-server").await,
        Status::NotFound
    );
    assert_eq!(status(&client, "/oauth/jwks").await, Status::NotFound);
    let par = client
        .post("/oauth/par")
        .header(ContentType::Form)
        .dispatch()
        .await;
    assert_eq!(par.status(), Status::NotFound);

    let key = dpop_key();
    let session = "/xrpc/com.atproto.server.getSession";
    let good = token(&client, &issuer_key(), "atproto transition:generic", |_| {});
    assert_eq!(dpop_get(&client, &key, &good, session).await.0, Status::Ok);

    let other = Jwk::from_private_key_bytes(EcCurve::P256, &[0x43u8; 32]).unwrap();
    let refused = [
        token(&client, &other, "atproto", |_| {}),
        token(&client, &issuer_key(), "atproto", |c| {
            c.iss = Some("https://evil.example.com".into())
        }),
        token(&client, &issuer_key(), "atproto", |c| {
            c.aud = Some(json!("did:web:other.example"))
        }),
        token(&client, &issuer_key(), "atproto", |c| {
            c.exp = Some(now_secs() - 120)
        }),
        token(&client, &issuer_key(), "atproto", |c| {
            c.extra.remove("scope");
        }),
    ];
    for bad in refused {
        assert_eq!(
            dpop_get(&client, &key, &bad, session).await.0,
            Status::Unauthorized
        );
    }

    // A proof from a different key, and one proof two times.
    assert_eq!(
        dpop_get(&client, &other, &good, session).await.0,
        Status::Unauthorized
    );
    let htu = format!("{}{session}", public_url(&client));
    let send = |proof: String| {
        client
            .get(session)
            .header(Header::new("Authorization", format!("DPoP {good}")))
            .header(Header::new("DPoP", proof))
            .dispatch()
    };
    let challenge = send(dpop_proof(&key, "GET", &htu, None, Some(&good))).await;
    let nonce = challenge.headers().get_one("DPoP-Nonce").unwrap();
    let proof = dpop_proof(&key, "GET", &htu, Some(nonce), Some(&good));
    assert_eq!(send(proof.clone()).await.status(), Status::Ok);
    assert_eq!(send(proof).await.status(), Status::Unauthorized);

    // The most dangerous changes stay refused to each OAuth token.
    let (status, body) = dpop_post(
        &client,
        &key,
        &good,
        "/xrpc/com.atproto.server.requestAccountDelete",
        json!({}),
    )
    .await;
    assert!(status.code >= 400, "{status} {body}");
    // A collection outside the scope is refused, inside it is written.
    let narrow = token(
        &client,
        &issuer_key(),
        "atproto repo:fit.jogga.graph.follow",
        |_| {},
    );
    let record = |collection: &str| {
        json!({"repo": DID, "collection": collection, "record": {"$type": collection,
               "subject": DID, "createdAt": "2026-01-01T00:00:00Z"}})
    };
    let create = "/xrpc/com.atproto.repo.createRecord";
    let (status, _) = dpop_post(
        &client,
        &key,
        &narrow,
        create,
        record("app.bsky.graph.follow"),
    )
    .await;
    assert_eq!(status, Status::Forbidden);
    let (status, body) = dpop_post(
        &client,
        &key,
        &narrow,
        create,
        record("fit.jogga.graph.follow"),
    )
    .await;
    assert_eq!(status, Status::Ok, "{body}");

    // The handle needs `identity:handle`. With it, the request gets past the scope: the PLC
    // directory of the tests cannot do the change itself.
    let handle = "/xrpc/com.atproto.identity.updateHandle";
    let new_handle = json!({"handle": "bar.test"});
    let (status, _) = dpop_post(&client, &key, &narrow, handle, new_handle.clone()).await;
    assert_eq!(status, Status::Forbidden);
    let wide = token(&client, &issuer_key(), "atproto identity:handle", |_| {});
    let (status, body) = dpop_post(&client, &key, &wide, handle, new_handle).await;
    assert_ne!(status, Status::Forbidden, "{body}");
    // No scope lets an OAuth token change the email.
    let wide = token(
        &client,
        &issuer_key(),
        "atproto account:email?action=manage transition:email",
        |_| {},
    );
    let email = "/xrpc/com.atproto.server.updateEmail";
    let (status, _) = dpop_post(&client, &key, &wide, email, json!({"email": "a@b.example"})).await;
    assert_eq!(status, Status::Forbidden);

    // A new password ends the password sessions, but not the OAuth sessions of the PDS. Thus a
    // token of the external issuer also stays good.
    let accounts = client
        .rocket()
        .state::<rsky_pds::account_manager::AccountManager>()
        .unwrap();
    accounts
        .update_account_password(rsky_pds::account_manager::UpdateAccountPasswordOpts {
            did: DID.into(),
            password: "a-new-password".into(),
        })
        .await
        .unwrap();
    assert_eq!(dpop_get(&client, &key, &good, session).await.0, Status::Ok);

    // A deactivated account: the token is good, and the write is refused.
    accounts.deactivate_account(DID, None).await.unwrap();
    let (status, body) = dpop_post(
        &client,
        &key,
        &narrow,
        create,
        record("fit.jogga.graph.follow"),
    )
    .await;
    assert_eq!(status, Status::BadRequest);
    assert!(
        body["message"]
            .as_str()
            .is_some_and(|m| m.starts_with("AccountDeactivated")),
        "{body}"
    );
}
