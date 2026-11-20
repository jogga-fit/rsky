//! `com.atproto.temp.checkHandleAvailability` answers available exactly when
//! `createAccount` would accept the handle.

mod common;

use common::{create_account, get_client};
use rocket::http::Status;
use serde_json::{json, Value};

const AVAILABLE: &str = "com.atproto.temp.checkHandleAvailability#resultAvailable";
const UNAVAILABLE: &str = "com.atproto.temp.checkHandleAvailability#resultUnavailable";

#[tokio::test]
async fn availability_follows_the_create_account_rules() {
    let (_dir, client) = get_client().await;
    // foo.rsky.com, deactivated: an imported account starts deactivated
    create_account(&client).await;

    for (handle, expected) in [
        ("newcomer.rsky.com", AVAILABLE),
        ("NewComer.rsky.com", AVAILABLE), // normalized to lowercase
        ("foo.rsky.com", UNAVAILABLE),    // held by a deactivated account
        ("help.rsky.com", UNAVAILABLE),   // reserved
        ("ab.rsky.com", UNAVAILABLE),     // too short
        ("abcdefghijklmnopqrs.rsky.com", UNAVAILABLE), // too long
        ("a.b.rsky.com", UNAVAILABLE),    // more than one label
        ("alice.example.com", UNAVAILABLE), // not a service handle domain
    ] {
        let response = client
            .get(format!(
                "/xrpc/com.atproto.temp.checkHandleAvailability?handle={handle}"
            ))
            .dispatch()
            .await;
        assert_eq!(response.status(), Status::Ok, "{handle}");
        let body: Value = response.into_json().await.unwrap();
        assert_eq!(body["handle"], handle.to_lowercase(), "{handle}");
        assert_eq!(body["result"]["$type"], expected, "{handle}");
        if expected == UNAVAILABLE {
            assert_eq!(body["result"]["suggestions"], json!([]), "{handle}");
        }
    }
}

#[tokio::test]
async fn an_invalid_handle_is_a_bad_request() {
    let (_dir, client) = get_client().await;
    let response = client
        .get("/xrpc/com.atproto.temp.checkHandleAvailability?handle=bad_handle")
        .dispatch()
        .await;
    assert_eq!(response.status(), Status::BadRequest);
    let body: Value = response.into_json().await.unwrap();
    assert_eq!(body["error"], "InvalidRequest", "{body}");
}
