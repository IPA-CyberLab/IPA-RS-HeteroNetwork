//! Local wire data only. Receivers must authenticate kernel peer credentials,
//! enforce framing/version bounds, and validate the live invocation separately.
use super::{SudoChallenge, SudoLocalInvocation, SudoToken};
use serde::{Deserialize, Serialize};

pub const PROTOCOL_VERSION: u32 = 2;
pub const MAX_FRAME_BYTES: usize = 16 * 1024;
pub const SUBMIT_SOCKET: &str = "/run/ipars-sudo-v2/submit.sock";

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub version: u32,
    pub nonce: [u8; 32],
    pub operation: Operation,
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum Operation {
    BindRequester { requester_public_key: [u8; 32] },
    SubmitToken { token: Box<SudoToken> },
    Redeem { requester_proof: Vec<u8> },
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Reply {
    pub version: u32,
    pub response: Response,
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum Response {
    Challenge {
        challenge: SudoChallenge,
    },
    Redemption {
        invocation: SudoLocalInvocation,
    },
    /// Durable submission, not evidence that the sudo command actually executed.
    Submitted,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn local_wire_is_typed_and_rejects_identity_overrides() -> Result<(), serde_json::Error> {
        let request = Request {
            version: PROTOCOL_VERSION,
            nonce: [7; 32],
            operation: Operation::BindRequester {
                requester_public_key: [8; 32],
            },
        };
        let value = serde_json::to_value(&request)?;
        assert_eq!(value["operation"]["type"], "bind_requester");
        let roundtrip: Request = serde_json::from_value(value.clone())?;
        assert_eq!(roundtrip.nonce, request.nonce);
        let mut identity_override = value.clone();
        identity_override["operation"]["caller_uid"] = serde_json::json!(0);
        assert!(serde_json::from_value::<Request>(identity_override).is_err());
        let mut execution = value;
        execution["operation"] = serde_json::json!({"type": "execute", "command": "ignored"});
        assert!(serde_json::from_value::<Request>(execution).is_err());
        let reply = Reply {
            version: PROTOCOL_VERSION,
            response: Response::Submitted,
        };
        assert_eq!(
            serde_json::to_value(reply)?["response"]["type"],
            "submitted"
        );
        Ok(())
    }
}
