use crate::account_manager::helpers::account::AvailabilityFlags;
use crate::account_manager::AccountManager;
use crate::apis::com::atproto::server::validate_handle;
use crate::apis::ApiError;
use crate::config::ServerConfig;
use crate::handle::{normalize_and_validate_handle, HandleValidationContext, HandleValidationOpts};
use crate::SharedIdResolver;
use rocket::serde::json::Json;
use rocket::State;
use rsky_lexicon::com::atproto::temp::{
    CheckHandleAvailabilityOutput, CheckHandleAvailabilityResult,
};
use rsky_syntax::handle::normalize_and_ensure_valid_handle;

/// Checks whether `createAccount` would accept this handle. A handle that is
/// syntactically valid but taken, reserved, the wrong length, or outside the
/// service handle domains is unavailable. This PDS makes no suggestions, so
/// the optional `email` and `birthDate` inputs are ignored.
#[tracing::instrument(skip_all)]
#[rocket::get("/xrpc/com.atproto.temp.checkHandleAvailability?<handle>")]
pub async fn check_handle_availability(
    handle: String,
    cfg: &State<ServerConfig>,
    id_resolver: &State<SharedIdResolver>,
    account_manager: AccountManager,
) -> Result<Json<CheckHandleAvailabilityOutput>, ApiError> {
    let handle = normalize_and_ensure_valid_handle(handle)
        .map_err(|_| ApiError::InvalidRequest("handle must be a valid handle".to_string()))?;
    let opts = HandleValidationOpts {
        handle: handle.clone(),
        did: None,
        allow_reserved: None,
    };
    let validation_ctx = HandleValidationContext {
        server_config: cfg,
        id_resolver,
    };
    // The same checks as createAccount. A deactivated or taken-down account
    // still holds its handle.
    let holders = AvailabilityFlags {
        include_taken_down: Some(true),
        include_deactivated: Some(true),
    };
    let available = match normalize_and_validate_handle(opts, validation_ctx).await {
        Ok(valid) => {
            validate_handle(&valid, &cfg.identity.service_handle_domains)
                && account_manager
                    .get_account(&valid, Some(holders))
                    .await?
                    .is_none()
        }
        Err(_) => false,
    };
    let result = if available {
        CheckHandleAvailabilityResult::Available
    } else {
        CheckHandleAvailabilityResult::Unavailable {
            suggestions: vec![],
        }
    };
    Ok(Json(CheckHandleAvailabilityOutput { handle, result }))
}
