use crate::aead::{self, CiphertextEnvelope};
use crate::kdf::hkdf_sha256_32;
use crate::pq_sig::{HybridSignature, PqSignatureProvider};
use crate::tlv::{critical_type, decode_strict, encode, require, TlvRecord};
use crate::CoreError;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand_core::{CryptoRng, OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

const GROUP_ID_BYTES: usize = 16;
const ROOT_SECRET_BYTES: usize = 32;
const MEMBER_CREDENTIAL_SECRET_BYTES: usize = 32;
const SNAPSHOT_AAD_LABEL: &str = "pqmsg-private-group-snapshot-v1";
const MEMBER_CREDENTIAL_HANDLE_LABEL: &str = "pqmsg-private-group-member-handle-v1";
const MEMBER_CREDENTIAL_COMMITMENT_LABEL: &str = "pqmsg-private-group-member-commitment-v1";
const MEMBER_CREDENTIAL_FETCH_KEY_LABEL: &str = "pqmsg-private-group-member-fetch-key-v1";
const MEMBER_CREDENTIAL_PUBLISH_KEY_LABEL: &str = "pqmsg-private-group-member-publish-key-v1";
const GROUP_MESSAGE_KEY_LABEL: &str = "pqmsg-private-group-message-key-v1";
const GROUP_INVITE_LINK_KEY_LABEL: &str = "pqmsg-private-group-link-invite-v1";
const GROUP_MESSAGE_AAD_LABEL: &str = "pqmsg-private-group-message-aad-v1";
const GROUP_MESSAGE_SIGNATURE_LABEL: &str = "pqmsg-private-group-message-signature-v1";

const TLV_OWNER_USER_ID: u16 = critical_type(0x3001);
const TLV_GROUP_TITLE: u16 = critical_type(0x3002);
const TLV_GROUP_DESCRIPTION: u16 = 0x3003;
const TLV_GROUP_AVATAR_HASH: u16 = 0x3004;
const TLV_GROUP_TIMER_SECONDS: u16 = 0x3005;
const TLV_GROUP_CREATED_AT: u16 = critical_type(0x3006);
const TLV_GROUP_UPDATED_AT: u16 = critical_type(0x3007);
const TLV_GROUP_MEMBERS: u16 = critical_type(0x3008);
const TLV_GROUP_MESSAGE_LABEL: u16 = critical_type(0x3010);
const TLV_GROUP_MESSAGE_GROUP_ID: u16 = critical_type(0x3011);
const TLV_GROUP_MESSAGE_EPOCH: u16 = critical_type(0x3012);
const TLV_GROUP_MESSAGE_SENDER_USER_ID: u16 = critical_type(0x3013);
const TLV_GROUP_MESSAGE_SENT_AT: u16 = critical_type(0x3014);
const TLV_GROUP_MESSAGE_NONCE: u16 = critical_type(0x3015);
const TLV_GROUP_MESSAGE_CIPHERTEXT: u16 = critical_type(0x3016);
const TLV_GROUP_MESSAGE_AAD: u16 = critical_type(0x3017);

const KNOWN_GROUP_PAYLOAD_TYPES: &[u16] = &[
    TLV_OWNER_USER_ID,
    TLV_GROUP_TITLE,
    TLV_GROUP_DESCRIPTION,
    TLV_GROUP_AVATAR_HASH,
    TLV_GROUP_TIMER_SECONDS,
    TLV_GROUP_CREATED_AT,
    TLV_GROUP_UPDATED_AT,
    TLV_GROUP_MEMBERS,
];

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PrivateGroupAttributes {
    pub title: String,
    pub description: Option<String>,
    pub avatar_hash_sha256: Option<String>,
    pub disappearing_message_timer_seconds: Option<u32>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, Ord, PartialOrd)]
pub enum PrivateGroupRole {
    Owner,
    Admin,
    Member,
}

impl PrivateGroupRole {
    fn to_byte(self) -> u8 {
        match self {
            Self::Owner => 1,
            Self::Admin => 2,
            Self::Member => 3,
        }
    }

    fn from_byte(value: u8) -> Result<Self, CoreError> {
        match value {
            1 => Ok(Self::Owner),
            2 => Ok(Self::Admin),
            3 => Ok(Self::Member),
            _ => Err(CoreError::MessageParsing("invalid private group role")),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PrivateGroupMember {
    pub user_id: String,
    pub role: PrivateGroupRole,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PrivateGroupEncryptedSnapshot {
    pub group_id: String,
    pub epoch: u64,
    pub state_commitment_sha256: [u8; 32],
    pub ciphertext: CiphertextEnvelope,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PrivateGroupInvitePackage {
    pub group_id: String,
    pub epoch: u64,
    pub root_secret: [u8; 32],
    pub snapshot: PrivateGroupEncryptedSnapshot,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PrivateGroupJoinPackage {
    pub invite: PrivateGroupInvitePackage,
    pub member_credential: PrivateGroupMemberCredential,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PrivateGroupLinkInviteEnvelope {
    pub group_id: String,
    pub epoch: u64,
    pub invite_commitment_sha256: [u8; 32],
    pub ciphertext: CiphertextEnvelope,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PrivateGroupLinkInviteMaterial {
    pub invite_secret: [u8; 32],
    pub envelope: PrivateGroupLinkInviteEnvelope,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PrivateGroupEncryptedMessage {
    pub group_id: String,
    pub epoch: u64,
    pub sender_user_id: String,
    pub sent_at_unix_ms: u64,
    pub ciphertext: CiphertextEnvelope,
    pub sender_hybrid_signature: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PrivateGroupDecryptedMessage {
    pub group_id: String,
    pub epoch: u64,
    pub sender_user_id: String,
    pub sent_at_unix_ms: u64,
    pub body: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PrivateGroupEpochTransition {
    pub next_state: PrivateGroupState,
    pub member_credentials: Vec<PrivateGroupMemberCredential>,
    pub added_member_join_package: Option<PrivateGroupJoinPackage>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PrivateGroupState {
    pub group_id: String,
    pub epoch: u64,
    pub root_secret: [u8; 32],
    pub attributes: PrivateGroupAttributes,
    pub members: Vec<PrivateGroupMember>,
    pub created_at_unix_seconds: u64,
    pub updated_at_unix_seconds: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PrivateGroupMemberCredential {
    pub group_id: String,
    pub epoch: u64,
    pub member_user_id: String,
    pub role: PrivateGroupRole,
    pub credential_secret: [u8; MEMBER_CREDENTIAL_SECRET_BYTES],
}

impl PrivateGroupState {
    pub fn new(
        owner_user_id: String,
        attributes: PrivateGroupAttributes,
        initial_members: Vec<PrivateGroupMember>,
        created_at_unix_seconds: u64,
    ) -> Result<Self, CoreError> {
        Self::new_with_rng(
            owner_user_id,
            attributes,
            initial_members,
            created_at_unix_seconds,
            &mut OsRng,
        )
    }

    pub fn new_with_rng<R: RngCore + CryptoRng>(
        owner_user_id: String,
        attributes: PrivateGroupAttributes,
        initial_members: Vec<PrivateGroupMember>,
        created_at_unix_seconds: u64,
        rng: &mut R,
    ) -> Result<Self, CoreError> {
        validate_group_attributes(&attributes)?;
        let normalized_members = normalize_members(&owner_user_id, initial_members)?;

        let mut group_id_bytes = [0u8; GROUP_ID_BYTES];
        rng.fill_bytes(&mut group_id_bytes);
        let mut root_secret = [0u8; ROOT_SECRET_BYTES];
        rng.fill_bytes(&mut root_secret);

        Ok(Self {
            group_id: hex_encode(&group_id_bytes),
            epoch: 1,
            root_secret,
            attributes,
            members: normalized_members,
            created_at_unix_seconds,
            updated_at_unix_seconds: created_at_unix_seconds,
        })
    }

    pub fn member_count(&self) -> usize {
        self.members.len()
    }

    pub fn encrypted_snapshot(&self) -> Result<PrivateGroupEncryptedSnapshot, CoreError> {
        self.encrypted_snapshot_with_rng(&mut OsRng)
    }

    pub fn encrypt_message<P: PqSignatureProvider>(
        &self,
        sender_user_id: &str,
        sender_identity_sig_secret: &[u8],
        sender_identity_pq_sig_secret: &[u8],
        body: &str,
        sent_at_unix_ms: u64,
        pq_provider: &P,
    ) -> Result<PrivateGroupEncryptedMessage, CoreError> {
        self.encrypt_message_with_rng(
            sender_user_id,
            sender_identity_sig_secret,
            sender_identity_pq_sig_secret,
            body,
            sent_at_unix_ms,
            pq_provider,
            &mut OsRng,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn encrypt_message_with_rng<P: PqSignatureProvider, R: RngCore + CryptoRng>(
        &self,
        sender_user_id: &str,
        sender_identity_sig_secret: &[u8],
        sender_identity_pq_sig_secret: &[u8],
        body: &str,
        sent_at_unix_ms: u64,
        pq_provider: &P,
        rng: &mut R,
    ) -> Result<PrivateGroupEncryptedMessage, CoreError> {
        validate_user_id(sender_user_id)?;
        if body.trim().is_empty() {
            return Err(CoreError::PolicyViolation(
                "private group message body cannot be blank",
            ));
        }
        if !self
            .members
            .iter()
            .any(|member| member.user_id == sender_user_id)
        {
            return Err(CoreError::PolicyViolation(
                "private group sender is not a member of the current epoch",
            ));
        }

        let signing_key = decode_ed25519_signing_key(
            "private_group.sender_identity_sig_secret",
            sender_identity_sig_secret,
        )?;
        let message_key = derive_message_key(&self.root_secret, &self.group_id, self.epoch)?;
        let aad = message_aad(&self.group_id, self.epoch, sender_user_id, sent_at_unix_ms);
        let padded_body = aead::pad_plaintext(body.as_bytes(), aead::PADDING_BLOCK_SIZE);
        let ciphertext = aead::encrypt_with_rng(&message_key, &padded_body, &aad, rng)?;

        let mut message = PrivateGroupEncryptedMessage {
            group_id: self.group_id.clone(),
            epoch: self.epoch,
            sender_user_id: sender_user_id.to_string(),
            sent_at_unix_ms,
            ciphertext,
            sender_hybrid_signature: Vec::new(),
        };
        let transcript = encode_message_signature_payload(&message)?;
        let ed25519_sig = signing_key.sign(&transcript).to_bytes().to_vec();
        let pq_sig = pq_provider.sign(sender_identity_pq_sig_secret, &transcript)?;
        message.sender_hybrid_signature = HybridSignature {
            ed25519_sig,
            pq_sig,
        }
        .encode();
        Ok(message)
    }

    pub fn decrypt_message<P: PqSignatureProvider>(
        &self,
        message: &PrivateGroupEncryptedMessage,
        sender_identity_sig_pub: &[u8],
        sender_identity_pq_sig_pub: &[u8],
        pq_provider: &P,
    ) -> Result<PrivateGroupDecryptedMessage, CoreError> {
        validate_private_group_message_membership(self, message)?;
        let expected_aad = message_aad(
            &message.group_id,
            message.epoch,
            &message.sender_user_id,
            message.sent_at_unix_ms,
        );
        if message.ciphertext.aad != expected_aad {
            return Err(CoreError::PolicyViolation(
                "private group message aad mismatch",
            ));
        }
        let transcript = encode_message_signature_payload(message)?;
        let hybrid_signature = HybridSignature::decode(&message.sender_hybrid_signature)?;
        let verifying_key = decode_ed25519_verifying_key(
            "private_group.sender_identity_sig_pub",
            sender_identity_sig_pub,
        )?;
        let ed25519_sig = Signature::from_slice(&hybrid_signature.ed25519_sig).map_err(|_| {
            CoreError::InvalidLength {
                field: "private_group.sender_identity_sig",
                expected: 64,
                actual: hybrid_signature.ed25519_sig.len(),
            }
        })?;
        verifying_key
            .verify(&transcript, &ed25519_sig)
            .map_err(|_| CoreError::SignatureVerificationFailed)?;
        pq_provider.verify(
            sender_identity_pq_sig_pub,
            &transcript,
            &hybrid_signature.pq_sig,
        )?;
        let message_key = derive_message_key(&self.root_secret, &self.group_id, self.epoch)?;
        let decrypted = aead::decrypt(&message_key, &message.ciphertext)?;
        let body = String::from_utf8(aead::unpad_plaintext(&decrypted)?.to_vec())
            .map_err(|_| CoreError::InvalidUtf8("private_group.message.body"))?;
        if body.trim().is_empty() {
            return Err(CoreError::PolicyViolation(
                "private group message body cannot be blank",
            ));
        }
        Ok(PrivateGroupDecryptedMessage {
            group_id: message.group_id.clone(),
            epoch: message.epoch,
            sender_user_id: message.sender_user_id.clone(),
            sent_at_unix_ms: message.sent_at_unix_ms,
            body,
        })
    }

    pub fn encrypted_snapshot_with_rng<R: RngCore + CryptoRng>(
        &self,
        rng: &mut R,
    ) -> Result<PrivateGroupEncryptedSnapshot, CoreError> {
        let payload = encode_group_payload(self)?;
        let padded_payload = aead::pad_plaintext(&payload, aead::PADDING_BLOCK_SIZE);
        let snapshot_key = derive_snapshot_key(&self.root_secret, &self.group_id, self.epoch)?;
        let aad = snapshot_aad(&self.group_id, self.epoch);
        let ciphertext = aead::encrypt_with_rng(&snapshot_key, &padded_payload, &aad, rng)?;
        Ok(PrivateGroupEncryptedSnapshot {
            group_id: self.group_id.clone(),
            epoch: self.epoch,
            state_commitment_sha256: sha256_bytes(&payload),
            ciphertext,
        })
    }

    pub fn export_invite_package(&self) -> Result<PrivateGroupInvitePackage, CoreError> {
        self.export_invite_package_with_rng(&mut OsRng)
    }

    pub fn export_invite_package_with_rng<R: RngCore + CryptoRng>(
        &self,
        rng: &mut R,
    ) -> Result<PrivateGroupInvitePackage, CoreError> {
        let snapshot = self.encrypted_snapshot_with_rng(rng)?;
        Ok(PrivateGroupInvitePackage {
            group_id: self.group_id.clone(),
            epoch: self.epoch,
            root_secret: self.root_secret,
            snapshot,
        })
    }

    pub fn export_join_package_for_member(
        &self,
        member_user_id: &str,
    ) -> Result<PrivateGroupJoinPackage, CoreError> {
        self.export_join_package_for_member_with_rng(member_user_id, &mut OsRng)
    }

    pub fn export_join_package_for_member_with_rng<R: RngCore + CryptoRng>(
        &self,
        member_user_id: &str,
        rng: &mut R,
    ) -> Result<PrivateGroupJoinPackage, CoreError> {
        let role = self
            .members
            .iter()
            .find(|member| member.user_id == member_user_id)
            .map(|member| member.role)
            .ok_or(CoreError::PolicyViolation(
                "private group join package member missing from state",
            ))?;
        let member_credential =
            self.issue_member_credential_with_rng(member_user_id.to_string(), role, rng)?;
        self.export_join_package_for_member_credential_with_rng(member_credential, rng)
    }

    pub fn export_join_package_for_member_credential(
        &self,
        member_credential: PrivateGroupMemberCredential,
    ) -> Result<PrivateGroupJoinPackage, CoreError> {
        self.export_join_package_for_member_credential_with_rng(member_credential, &mut OsRng)
    }

    pub fn export_join_package_for_member_credential_with_rng<R: RngCore + CryptoRng>(
        &self,
        member_credential: PrivateGroupMemberCredential,
        rng: &mut R,
    ) -> Result<PrivateGroupJoinPackage, CoreError> {
        if member_credential.group_id != self.group_id {
            return Err(CoreError::PolicyViolation(
                "private group join package credential group_id mismatch",
            ));
        }
        if member_credential.epoch != self.epoch {
            return Err(CoreError::PolicyViolation(
                "private group join package credential epoch mismatch",
            ));
        }
        let member = self
            .members
            .iter()
            .find(|member| member.user_id == member_credential.member_user_id)
            .ok_or(CoreError::PolicyViolation(
                "private group join package member missing from state",
            ))?;
        if member.role != member_credential.role {
            return Err(CoreError::PolicyViolation(
                "private group join package credential role mismatch",
            ));
        }
        let invite = self.export_invite_package_with_rng(rng)?;
        Ok(PrivateGroupJoinPackage {
            invite,
            member_credential,
        })
    }

    pub fn prepare_add_member_transition(
        &self,
        user_id: String,
        role: PrivateGroupRole,
        updated_at_unix_seconds: u64,
    ) -> Result<PrivateGroupEpochTransition, CoreError> {
        self.prepare_add_member_transition_with_rng(
            user_id,
            role,
            updated_at_unix_seconds,
            &mut OsRng,
        )
    }

    pub fn prepare_add_member_transition_with_rng<R: RngCore + CryptoRng>(
        &self,
        user_id: String,
        role: PrivateGroupRole,
        updated_at_unix_seconds: u64,
        rng: &mut R,
    ) -> Result<PrivateGroupEpochTransition, CoreError> {
        let mut next_state = self.clone();
        let changed = next_state.add_member(user_id.clone(), role, updated_at_unix_seconds)?;
        if !changed {
            return Err(CoreError::PolicyViolation(
                "private group member already has requested role",
            ));
        }
        let member_credentials =
            next_state.issue_member_credentials_for_all_members_with_rng(rng)?;
        let added_member_credential = member_credentials
            .iter()
            .find(|credential| credential.member_user_id == user_id)
            .cloned()
            .ok_or(CoreError::PolicyViolation(
                "private group added member credential missing from transition",
            ))?;
        let added_member_join_package = Some(
            next_state
                .export_join_package_for_member_credential_with_rng(added_member_credential, rng)?,
        );
        Ok(PrivateGroupEpochTransition {
            next_state,
            member_credentials,
            added_member_join_package,
        })
    }

    pub fn prepare_remove_member_transition(
        &self,
        user_id: &str,
        updated_at_unix_seconds: u64,
    ) -> Result<PrivateGroupEpochTransition, CoreError> {
        self.prepare_remove_member_transition_with_rng(user_id, updated_at_unix_seconds, &mut OsRng)
    }

    pub fn prepare_remove_member_transition_with_rng<R: RngCore + CryptoRng>(
        &self,
        user_id: &str,
        updated_at_unix_seconds: u64,
        rng: &mut R,
    ) -> Result<PrivateGroupEpochTransition, CoreError> {
        let mut next_state = self.clone();
        let removed = next_state.remove_member(user_id, updated_at_unix_seconds)?;
        if !removed {
            return Err(CoreError::PolicyViolation(
                "private group member is not present",
            ));
        }
        let member_credentials =
            next_state.issue_member_credentials_for_all_members_with_rng(rng)?;
        Ok(PrivateGroupEpochTransition {
            next_state,
            member_credentials,
            added_member_join_package: None,
        })
    }

    pub fn restore_from_invite_package(
        package: &PrivateGroupInvitePackage,
    ) -> Result<Self, CoreError> {
        if package.snapshot.group_id != package.group_id {
            return Err(CoreError::PolicyViolation(
                "private group invite package group_id mismatch",
            ));
        }
        if package.snapshot.epoch != package.epoch {
            return Err(CoreError::PolicyViolation(
                "private group invite package epoch mismatch",
            ));
        }
        let snapshot_key =
            derive_snapshot_key(&package.root_secret, &package.group_id, package.epoch)?;
        let aad = snapshot_aad(&package.group_id, package.epoch);
        if package.snapshot.ciphertext.aad != aad {
            return Err(CoreError::PolicyViolation(
                "private group snapshot aad mismatch",
            ));
        }
        let decrypted = aead::decrypt(&snapshot_key, &package.snapshot.ciphertext)?;
        let payload = aead::unpad_plaintext(&decrypted)?;
        let commitment = sha256_bytes(payload);
        if commitment != package.snapshot.state_commitment_sha256 {
            return Err(CoreError::PolicyViolation(
                "private group snapshot commitment mismatch",
            ));
        }
        decode_group_payload(
            &package.group_id,
            package.epoch,
            package.root_secret,
            payload,
        )
    }

    pub fn add_member(
        &mut self,
        user_id: String,
        role: PrivateGroupRole,
        updated_at_unix_seconds: u64,
    ) -> Result<bool, CoreError> {
        validate_user_id(&user_id)?;
        let next_role = if user_id == self.owner_user_id() {
            PrivateGroupRole::Owner
        } else {
            role
        };
        match self
            .members
            .iter_mut()
            .find(|member| member.user_id == user_id)
        {
            Some(existing) if existing.role == next_role => Ok(false),
            Some(existing) => {
                existing.role = next_role;
                self.bump_epoch(updated_at_unix_seconds);
                Ok(true)
            }
            None => {
                self.members.push(PrivateGroupMember {
                    user_id,
                    role: next_role,
                });
                self.members
                    .sort_by(|left, right| left.user_id.cmp(&right.user_id));
                self.bump_epoch(updated_at_unix_seconds);
                Ok(true)
            }
        }
    }

    pub fn remove_member(
        &mut self,
        user_id: &str,
        updated_at_unix_seconds: u64,
    ) -> Result<bool, CoreError> {
        if user_id == self.owner_user_id() {
            return Err(CoreError::PolicyViolation(
                "private group owner cannot be removed",
            ));
        }
        let previous_len = self.members.len();
        self.members.retain(|member| member.user_id != user_id);
        if self.members.len() == previous_len {
            return Ok(false);
        }
        self.bump_epoch(updated_at_unix_seconds);
        Ok(true)
    }

    pub fn update_attributes(
        &mut self,
        attributes: PrivateGroupAttributes,
        updated_at_unix_seconds: u64,
    ) -> Result<bool, CoreError> {
        validate_group_attributes(&attributes)?;
        if self.attributes == attributes {
            return Ok(false);
        }
        self.attributes = attributes;
        self.bump_epoch(updated_at_unix_seconds);
        Ok(true)
    }

    pub fn issue_member_credential(
        &self,
        member_user_id: String,
        role: PrivateGroupRole,
    ) -> Result<PrivateGroupMemberCredential, CoreError> {
        self.issue_member_credential_with_rng(member_user_id, role, &mut OsRng)
    }

    pub fn issue_member_credentials_for_all_members(
        &self,
    ) -> Result<Vec<PrivateGroupMemberCredential>, CoreError> {
        self.issue_member_credentials_for_all_members_with_rng(&mut OsRng)
    }

    pub fn issue_member_credential_with_rng<R: RngCore + CryptoRng>(
        &self,
        member_user_id: String,
        role: PrivateGroupRole,
        rng: &mut R,
    ) -> Result<PrivateGroupMemberCredential, CoreError> {
        validate_user_id(&member_user_id)?;
        let normalized_role = if member_user_id == self.owner_user_id() {
            PrivateGroupRole::Owner
        } else {
            role
        };
        let mut credential_secret = [0u8; MEMBER_CREDENTIAL_SECRET_BYTES];
        rng.fill_bytes(&mut credential_secret);
        Ok(PrivateGroupMemberCredential {
            group_id: self.group_id.clone(),
            epoch: self.epoch,
            member_user_id,
            role: normalized_role,
            credential_secret,
        })
    }

    fn issue_member_credentials_for_all_members_with_rng<R: RngCore + CryptoRng>(
        &self,
        rng: &mut R,
    ) -> Result<Vec<PrivateGroupMemberCredential>, CoreError> {
        self.members
            .iter()
            .map(|member| {
                self.issue_member_credential_with_rng(member.user_id.clone(), member.role, rng)
            })
            .collect()
    }

    fn owner_user_id(&self) -> &str {
        self.members
            .iter()
            .find(|member| member.role == PrivateGroupRole::Owner)
            .map(|member| member.user_id.as_str())
            .unwrap_or("")
    }

    fn bump_epoch(&mut self, updated_at_unix_seconds: u64) {
        self.epoch = self.epoch.saturating_add(1);
        self.updated_at_unix_seconds = updated_at_unix_seconds;
    }
}

impl PrivateGroupMemberCredential {
    pub fn membership_handle_sha256(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(MEMBER_CREDENTIAL_HANDLE_LABEL.as_bytes());
        hasher.update(self.group_id.as_bytes());
        hasher.update(self.epoch.to_be_bytes());
        hasher.update([self.role.to_byte()]);
        hasher.update(self.credential_secret);
        let mut output = [0u8; 32];
        output.copy_from_slice(&hasher.finalize());
        output
    }

    pub fn member_commitment_sha256(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(MEMBER_CREDENTIAL_COMMITMENT_LABEL.as_bytes());
        hasher.update(self.group_id.as_bytes());
        hasher.update(self.epoch.to_be_bytes());
        hasher.update(self.member_user_id.as_bytes());
        hasher.update([self.role.to_byte()]);
        hasher.update(self.credential_secret);
        let mut output = [0u8; 32];
        output.copy_from_slice(&hasher.finalize());
        output
    }

    pub fn state_fetch_key(&self) -> Result<[u8; 32], CoreError> {
        let info = format!(
            "{MEMBER_CREDENTIAL_FETCH_KEY_LABEL}:{}:{}:{}",
            self.group_id, self.epoch, self.member_user_id
        );
        hkdf_sha256_32(&self.credential_secret, None, info.as_bytes())
    }

    pub fn state_publish_key(&self) -> Result<Option<[u8; 32]>, CoreError> {
        if matches!(self.role, PrivateGroupRole::Member) {
            return Ok(None);
        }
        let info = format!(
            "{MEMBER_CREDENTIAL_PUBLISH_KEY_LABEL}:{}:{}:{}",
            self.group_id, self.epoch, self.member_user_id
        );
        Ok(Some(hkdf_sha256_32(
            &self.credential_secret,
            None,
            info.as_bytes(),
        )?))
    }
}

impl PrivateGroupJoinPackage {
    pub fn restore_state_and_credential(
        &self,
    ) -> Result<(PrivateGroupState, PrivateGroupMemberCredential), CoreError> {
        if self.invite.group_id != self.member_credential.group_id {
            return Err(CoreError::PolicyViolation(
                "private group join package group_id mismatch",
            ));
        }
        if self.invite.epoch != self.member_credential.epoch {
            return Err(CoreError::PolicyViolation(
                "private group join package epoch mismatch",
            ));
        }
        let state = PrivateGroupState::restore_from_invite_package(&self.invite)?;
        let member = state
            .members
            .iter()
            .find(|member| member.user_id == self.member_credential.member_user_id)
            .ok_or(CoreError::PolicyViolation(
                "private group join package member missing from state",
            ))?;
        if member.role != self.member_credential.role {
            return Err(CoreError::PolicyViolation(
                "private group join package role mismatch",
            ));
        }
        Ok((state, self.member_credential.clone()))
    }

    pub fn encrypt_for_share_link(&self) -> Result<PrivateGroupLinkInviteMaterial, CoreError> {
        self.encrypt_for_share_link_with_rng(&mut OsRng)
    }

    pub fn encrypt_for_share_link_with_rng<R: RngCore + CryptoRng>(
        &self,
        rng: &mut R,
    ) -> Result<PrivateGroupLinkInviteMaterial, CoreError> {
        let plaintext = serde_json::to_vec(self).map_err(|_| {
            CoreError::MessageParsing("failed to serialize private group join package")
        })?;
        let mut invite_secret = [0u8; ROOT_SECRET_BYTES];
        rng.fill_bytes(&mut invite_secret);
        let invite_key =
            derive_link_invite_key(&invite_secret, &self.invite.group_id, self.invite.epoch)?;
        let aad = link_invite_aad(&self.invite.group_id, self.invite.epoch);
        let ciphertext = aead::encrypt_with_rng(&invite_key, &plaintext, &aad, rng)?;
        Ok(PrivateGroupLinkInviteMaterial {
            invite_secret,
            envelope: PrivateGroupLinkInviteEnvelope {
                group_id: self.invite.group_id.clone(),
                epoch: self.invite.epoch,
                invite_commitment_sha256: sha256_bytes(&invite_secret),
                ciphertext,
            },
        })
    }
}

impl PrivateGroupLinkInviteEnvelope {
    pub fn open_join_package(
        &self,
        invite_secret: &[u8; ROOT_SECRET_BYTES],
    ) -> Result<PrivateGroupJoinPackage, CoreError> {
        if sha256_bytes(invite_secret) != self.invite_commitment_sha256 {
            return Err(CoreError::PolicyViolation(
                "private group invite secret commitment mismatch",
            ));
        }
        let invite_key = derive_link_invite_key(invite_secret, &self.group_id, self.epoch)?;
        let aad = link_invite_aad(&self.group_id, self.epoch);
        if self.ciphertext.aad != aad {
            return Err(CoreError::PolicyViolation(
                "private group invite envelope aad mismatch",
            ));
        }
        let plaintext = aead::decrypt(&invite_key, &self.ciphertext)?;
        let join_package: PrivateGroupJoinPackage =
            serde_json::from_slice(&plaintext).map_err(|_| {
                CoreError::MessageParsing("failed to decode private group join package")
            })?;
        if join_package.invite.group_id != self.group_id {
            return Err(CoreError::PolicyViolation(
                "private group link invite group_id mismatch",
            ));
        }
        if join_package.invite.epoch != self.epoch {
            return Err(CoreError::PolicyViolation(
                "private group link invite epoch mismatch",
            ));
        }
        let _ = join_package.restore_state_and_credential()?;
        Ok(join_package)
    }
}

fn validate_group_attributes(attributes: &PrivateGroupAttributes) -> Result<(), CoreError> {
    if attributes.title.trim().is_empty() {
        return Err(CoreError::PolicyViolation(
            "private group title cannot be blank",
        ));
    }
    if let Some(hash) = &attributes.avatar_hash_sha256 {
        let normalized = hash.trim();
        let is_hex =
            normalized.len() == 64 && normalized.bytes().all(|byte| byte.is_ascii_hexdigit());
        if !is_hex {
            return Err(CoreError::PolicyViolation(
                "private group avatar hash must be a 64-character hex SHA-256",
            ));
        }
    }
    Ok(())
}

fn validate_user_id(user_id: &str) -> Result<(), CoreError> {
    if user_id.trim().is_empty() {
        return Err(CoreError::PolicyViolation(
            "private group member user_id cannot be blank",
        ));
    }
    Ok(())
}

fn derive_link_invite_key(
    invite_secret: &[u8; ROOT_SECRET_BYTES],
    group_id: &str,
    epoch: u64,
) -> Result<[u8; 32], CoreError> {
    let info = format!("{GROUP_INVITE_LINK_KEY_LABEL}:{group_id}:{epoch}");
    hkdf_sha256_32(invite_secret, None, info.as_bytes())
}

fn derive_message_key(
    root_secret: &[u8; ROOT_SECRET_BYTES],
    group_id: &str,
    epoch: u64,
) -> Result<[u8; 32], CoreError> {
    let info = format!("{GROUP_MESSAGE_KEY_LABEL}:{group_id}:{epoch}");
    hkdf_sha256_32(root_secret, None, info.as_bytes())
}

fn link_invite_aad(group_id: &str, epoch: u64) -> Vec<u8> {
    let mut aad = Vec::with_capacity(GROUP_INVITE_LINK_KEY_LABEL.len() + group_id.len() + 16);
    aad.extend_from_slice(GROUP_INVITE_LINK_KEY_LABEL.as_bytes());
    aad.extend_from_slice(group_id.as_bytes());
    aad.extend_from_slice(&epoch.to_be_bytes());
    aad
}

fn message_aad(group_id: &str, epoch: u64, sender_user_id: &str, sent_at_unix_ms: u64) -> Vec<u8> {
    let mut aad = Vec::with_capacity(
        GROUP_MESSAGE_AAD_LABEL.len() + group_id.len() + sender_user_id.len() + 24,
    );
    aad.extend_from_slice(GROUP_MESSAGE_AAD_LABEL.as_bytes());
    aad.extend_from_slice(group_id.as_bytes());
    aad.extend_from_slice(&epoch.to_be_bytes());
    aad.extend_from_slice(sender_user_id.as_bytes());
    aad.extend_from_slice(&sent_at_unix_ms.to_be_bytes());
    aad
}

fn encode_message_signature_payload(
    message: &PrivateGroupEncryptedMessage,
) -> Result<Vec<u8>, CoreError> {
    encode(&[
        TlvRecord {
            ty: TLV_GROUP_MESSAGE_LABEL,
            value: GROUP_MESSAGE_SIGNATURE_LABEL.as_bytes().to_vec(),
        },
        TlvRecord {
            ty: TLV_GROUP_MESSAGE_GROUP_ID,
            value: message.group_id.as_bytes().to_vec(),
        },
        TlvRecord {
            ty: TLV_GROUP_MESSAGE_EPOCH,
            value: message.epoch.to_be_bytes().to_vec(),
        },
        TlvRecord {
            ty: TLV_GROUP_MESSAGE_SENDER_USER_ID,
            value: message.sender_user_id.as_bytes().to_vec(),
        },
        TlvRecord {
            ty: TLV_GROUP_MESSAGE_SENT_AT,
            value: message.sent_at_unix_ms.to_be_bytes().to_vec(),
        },
        TlvRecord {
            ty: TLV_GROUP_MESSAGE_NONCE,
            value: message.ciphertext.nonce.to_vec(),
        },
        TlvRecord {
            ty: TLV_GROUP_MESSAGE_CIPHERTEXT,
            value: message.ciphertext.ciphertext.clone(),
        },
        TlvRecord {
            ty: TLV_GROUP_MESSAGE_AAD,
            value: message.ciphertext.aad.clone(),
        },
    ])
}

fn validate_private_group_message_membership(
    state: &PrivateGroupState,
    message: &PrivateGroupEncryptedMessage,
) -> Result<(), CoreError> {
    if message.group_id != state.group_id {
        return Err(CoreError::PolicyViolation(
            "private group message group_id mismatch",
        ));
    }
    if message.epoch != state.epoch {
        return Err(CoreError::PolicyViolation(
            "private group message epoch mismatch",
        ));
    }
    if !state
        .members
        .iter()
        .any(|member| member.user_id == message.sender_user_id)
    {
        return Err(CoreError::PolicyViolation(
            "private group message sender is not a member of the current epoch",
        ));
    }
    Ok(())
}

fn decode_ed25519_signing_key(
    field: &'static str,
    secret_key: &[u8],
) -> Result<SigningKey, CoreError> {
    let secret_key: [u8; 32] = secret_key
        .try_into()
        .map_err(|_| CoreError::InvalidLength {
            field,
            expected: 32,
            actual: secret_key.len(),
        })?;
    Ok(SigningKey::from_bytes(&secret_key))
}

fn decode_ed25519_verifying_key(
    field: &'static str,
    public_key: &[u8],
) -> Result<VerifyingKey, CoreError> {
    let public_key: [u8; 32] = public_key
        .try_into()
        .map_err(|_| CoreError::InvalidLength {
            field,
            expected: 32,
            actual: public_key.len(),
        })?;
    VerifyingKey::from_bytes(&public_key).map_err(|_| CoreError::SignatureVerificationFailed)
}

fn normalize_members(
    owner_user_id: &str,
    initial_members: Vec<PrivateGroupMember>,
) -> Result<Vec<PrivateGroupMember>, CoreError> {
    validate_user_id(owner_user_id)?;
    let mut members_by_user = BTreeMap::new();
    members_by_user.insert(owner_user_id.to_string(), PrivateGroupRole::Owner);
    for member in initial_members {
        validate_user_id(&member.user_id)?;
        let next_role = if member.user_id == owner_user_id {
            PrivateGroupRole::Owner
        } else {
            member.role
        };
        members_by_user
            .entry(member.user_id)
            .and_modify(|existing| {
                if role_rank(next_role) < role_rank(*existing) {
                    *existing = next_role;
                }
            })
            .or_insert(next_role);
    }
    Ok(members_by_user
        .into_iter()
        .map(|(user_id, role)| PrivateGroupMember { user_id, role })
        .collect())
}

fn role_rank(role: PrivateGroupRole) -> u8 {
    match role {
        PrivateGroupRole::Owner => 0,
        PrivateGroupRole::Admin => 1,
        PrivateGroupRole::Member => 2,
    }
}

fn encode_group_payload(state: &PrivateGroupState) -> Result<Vec<u8>, CoreError> {
    let mut records = vec![
        TlvRecord {
            ty: TLV_OWNER_USER_ID,
            value: state.owner_user_id().as_bytes().to_vec(),
        },
        TlvRecord {
            ty: TLV_GROUP_TITLE,
            value: state.attributes.title.as_bytes().to_vec(),
        },
        TlvRecord {
            ty: TLV_GROUP_CREATED_AT,
            value: state.created_at_unix_seconds.to_be_bytes().to_vec(),
        },
        TlvRecord {
            ty: TLV_GROUP_UPDATED_AT,
            value: state.updated_at_unix_seconds.to_be_bytes().to_vec(),
        },
        TlvRecord {
            ty: TLV_GROUP_MEMBERS,
            value: encode_members(&state.members)?,
        },
    ];
    if let Some(description) = &state.attributes.description {
        records.push(TlvRecord {
            ty: TLV_GROUP_DESCRIPTION,
            value: description.as_bytes().to_vec(),
        });
    }
    if let Some(avatar_hash) = &state.attributes.avatar_hash_sha256 {
        records.push(TlvRecord {
            ty: TLV_GROUP_AVATAR_HASH,
            value: avatar_hash.as_bytes().to_vec(),
        });
    }
    if let Some(timer) = state.attributes.disappearing_message_timer_seconds {
        records.push(TlvRecord {
            ty: TLV_GROUP_TIMER_SECONDS,
            value: timer.to_be_bytes().to_vec(),
        });
    }
    encode(&records)
}

fn decode_group_payload(
    group_id: &str,
    epoch: u64,
    root_secret: [u8; 32],
    payload: &[u8],
) -> Result<PrivateGroupState, CoreError> {
    let records = decode_strict(payload, KNOWN_GROUP_PAYLOAD_TYPES)?;
    let owner_user_id =
        decode_utf8_field(require(&records, TLV_OWNER_USER_ID, "group.owner_user_id")?)?;
    let title = decode_utf8_field(require(&records, TLV_GROUP_TITLE, "group.title")?)?;
    let created_at_unix_seconds = decode_u64_field(require(
        &records,
        TLV_GROUP_CREATED_AT,
        "group.created_at_unix_seconds",
    )?)?;
    let updated_at_unix_seconds = decode_u64_field(require(
        &records,
        TLV_GROUP_UPDATED_AT,
        "group.updated_at_unix_seconds",
    )?)?;
    let description = records
        .iter()
        .find(|record| record.ty == TLV_GROUP_DESCRIPTION)
        .map(|record| decode_utf8_field(&record.value))
        .transpose()?;
    let avatar_hash_sha256 = records
        .iter()
        .find(|record| record.ty == TLV_GROUP_AVATAR_HASH)
        .map(|record| decode_utf8_field(&record.value))
        .transpose()?;
    let disappearing_message_timer_seconds = records
        .iter()
        .find(|record| record.ty == TLV_GROUP_TIMER_SECONDS)
        .map(|record| decode_u32_field(&record.value))
        .transpose()?;
    let members = decode_members(require(&records, TLV_GROUP_MEMBERS, "group.members")?)?;
    let normalized_members = normalize_members(&owner_user_id, members)?;
    let attributes = PrivateGroupAttributes {
        title,
        description,
        avatar_hash_sha256,
        disappearing_message_timer_seconds,
    };
    validate_group_attributes(&attributes)?;
    Ok(PrivateGroupState {
        group_id: group_id.to_string(),
        epoch,
        root_secret,
        attributes,
        members: normalized_members,
        created_at_unix_seconds,
        updated_at_unix_seconds,
    })
}

fn encode_members(members: &[PrivateGroupMember]) -> Result<Vec<u8>, CoreError> {
    if members.len() > u16::MAX as usize {
        return Err(CoreError::InvalidLength {
            field: "private_group.members",
            expected: u16::MAX as usize,
            actual: members.len(),
        });
    }
    let mut encoded = Vec::new();
    encoded.extend_from_slice(&(members.len() as u16).to_be_bytes());
    for member in members {
        validate_user_id(&member.user_id)?;
        let user_id_bytes = member.user_id.as_bytes();
        if user_id_bytes.len() > u16::MAX as usize {
            return Err(CoreError::InvalidLength {
                field: "private_group.member.user_id",
                expected: u16::MAX as usize,
                actual: user_id_bytes.len(),
            });
        }
        encoded.extend_from_slice(&(user_id_bytes.len() as u16).to_be_bytes());
        encoded.extend_from_slice(user_id_bytes);
        encoded.push(member.role.to_byte());
    }
    Ok(encoded)
}

fn decode_members(input: &[u8]) -> Result<Vec<PrivateGroupMember>, CoreError> {
    if input.len() < 2 {
        return Err(CoreError::MessageParsing(
            "private group members payload truncated",
        ));
    }
    let count = u16::from_be_bytes([input[0], input[1]]) as usize;
    let mut cursor = 2usize;
    let mut members = Vec::with_capacity(count);
    for _ in 0..count {
        if input.len().saturating_sub(cursor) < 3 {
            return Err(CoreError::MessageParsing(
                "private group member entry truncated",
            ));
        }
        let user_id_len = u16::from_be_bytes([input[cursor], input[cursor + 1]]) as usize;
        cursor += 2;
        if input.len().saturating_sub(cursor) < user_id_len + 1 {
            return Err(CoreError::MessageParsing(
                "private group member user_id truncated",
            ));
        }
        let user_id = decode_utf8_field(&input[cursor..cursor + user_id_len])?;
        cursor += user_id_len;
        let role = PrivateGroupRole::from_byte(input[cursor])?;
        cursor += 1;
        members.push(PrivateGroupMember { user_id, role });
    }
    if cursor != input.len() {
        return Err(CoreError::MessageParsing(
            "private group members payload has trailing bytes",
        ));
    }
    Ok(members)
}

fn decode_utf8_field(value: &[u8]) -> Result<String, CoreError> {
    String::from_utf8(value.to_vec()).map_err(|_| CoreError::InvalidUtf8("private_group_field"))
}

fn decode_u64_field(value: &[u8]) -> Result<u64, CoreError> {
    let array: [u8; 8] = value.try_into().map_err(|_| CoreError::InvalidLength {
        field: "private_group_u64",
        expected: 8,
        actual: value.len(),
    })?;
    Ok(u64::from_be_bytes(array))
}

fn decode_u32_field(value: &[u8]) -> Result<u32, CoreError> {
    let array: [u8; 4] = value.try_into().map_err(|_| CoreError::InvalidLength {
        field: "private_group_u32",
        expected: 4,
        actual: value.len(),
    })?;
    Ok(u32::from_be_bytes(array))
}

fn derive_snapshot_key(
    root_secret: &[u8; 32],
    group_id: &str,
    epoch: u64,
) -> Result<[u8; 32], CoreError> {
    let info = format!("{SNAPSHOT_AAD_LABEL}:key:{group_id}:{epoch}");
    hkdf_sha256_32(root_secret, None, info.as_bytes())
}

fn snapshot_aad(group_id: &str, epoch: u64) -> Vec<u8> {
    format!("{SNAPSHOT_AAD_LABEL}:{group_id}:{epoch}").into_bytes()
}

fn sha256_bytes(input: &[u8]) -> [u8; 32] {
    let mut output = [0u8; 32];
    output.copy_from_slice(&Sha256::digest(input));
    output
}

fn hex_encode(input: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(input.len() * 2);
    for byte in input {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pq_sig::MlDsa65;
    use ed25519_dalek::SigningKey;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    fn sample_attributes() -> PrivateGroupAttributes {
        PrivateGroupAttributes {
            title: "Project Mercury".to_string(),
            description: Some("Launch planning".to_string()),
            avatar_hash_sha256: Some("aa".repeat(32)),
            disappearing_message_timer_seconds: Some(3600),
        }
    }

    #[test]
    fn new_group_normalizes_members_and_owner_role() {
        let mut rng = ChaCha20Rng::from_seed([7u8; 32]);
        let state = PrivateGroupState::new_with_rng(
            "alice".to_string(),
            sample_attributes(),
            vec![
                PrivateGroupMember {
                    user_id: "bob".to_string(),
                    role: PrivateGroupRole::Member,
                },
                PrivateGroupMember {
                    user_id: "alice".to_string(),
                    role: PrivateGroupRole::Member,
                },
                PrivateGroupMember {
                    user_id: "bob".to_string(),
                    role: PrivateGroupRole::Admin,
                },
            ],
            1_700_000_000,
            &mut rng,
        )
        .expect("create group");
        assert_eq!(state.epoch, 1);
        assert_eq!(state.members.len(), 2);
        assert_eq!(state.members[0].user_id, "alice");
        assert_eq!(state.members[0].role, PrivateGroupRole::Owner);
        assert_eq!(state.members[1].user_id, "bob");
        assert_eq!(state.members[1].role, PrivateGroupRole::Admin);
        assert_eq!(state.group_id.len(), GROUP_ID_BYTES * 2);
    }

    #[test]
    fn invite_package_roundtrip_restores_state() {
        let mut rng = ChaCha20Rng::from_seed([9u8; 32]);
        let state = PrivateGroupState::new_with_rng(
            "alice".to_string(),
            sample_attributes(),
            vec![PrivateGroupMember {
                user_id: "bob".to_string(),
                role: PrivateGroupRole::Member,
            }],
            1_700_000_001,
            &mut rng,
        )
        .expect("create group");
        let invite = state
            .export_invite_package_with_rng(&mut rng)
            .expect("export invite");
        let restored =
            PrivateGroupState::restore_from_invite_package(&invite).expect("restore invite");
        assert_eq!(restored.group_id, state.group_id);
        assert_eq!(restored.epoch, state.epoch);
        assert_eq!(restored.root_secret, state.root_secret);
        assert_eq!(restored.attributes, state.attributes);
        assert_eq!(restored.members, state.members);
        assert_eq!(
            restored.created_at_unix_seconds,
            state.created_at_unix_seconds
        );
        assert_eq!(
            restored.updated_at_unix_seconds,
            state.updated_at_unix_seconds
        );
    }

    #[test]
    fn membership_changes_advance_epoch() {
        let mut rng = ChaCha20Rng::from_seed([11u8; 32]);
        let mut state = PrivateGroupState::new_with_rng(
            "alice".to_string(),
            sample_attributes(),
            vec![],
            1_700_000_010,
            &mut rng,
        )
        .expect("create group");
        assert!(state
            .add_member("bob".to_string(), PrivateGroupRole::Member, 1_700_000_011)
            .expect("add member"));
        assert_eq!(state.epoch, 2);
        assert!(state
            .remove_member("bob", 1_700_000_012)
            .expect("remove member"));
        assert_eq!(state.epoch, 3);
    }

    #[test]
    fn owner_removal_is_rejected() {
        let mut rng = ChaCha20Rng::from_seed([13u8; 32]);
        let mut state = PrivateGroupState::new_with_rng(
            "alice".to_string(),
            sample_attributes(),
            vec![],
            1_700_000_020,
            &mut rng,
        )
        .expect("create group");
        let error = state
            .remove_member("alice", 1_700_000_021)
            .expect_err("owner removal should fail");
        assert!(error.to_string().contains("owner"));
    }

    #[test]
    fn tampered_snapshot_commitment_is_rejected() {
        let mut rng = ChaCha20Rng::from_seed([15u8; 32]);
        let state = PrivateGroupState::new_with_rng(
            "alice".to_string(),
            sample_attributes(),
            vec![PrivateGroupMember {
                user_id: "bob".to_string(),
                role: PrivateGroupRole::Member,
            }],
            1_700_000_030,
            &mut rng,
        )
        .expect("create group");
        let mut invite = state
            .export_invite_package_with_rng(&mut rng)
            .expect("export invite");
        invite.snapshot.state_commitment_sha256[0] ^= 0x01;
        let error = PrivateGroupState::restore_from_invite_package(&invite)
            .expect_err("tampered commitment should fail");
        assert!(error.to_string().contains("commitment"));
    }

    #[test]
    fn issued_member_credentials_are_bound_to_group_epoch_and_role() {
        let mut rng = ChaCha20Rng::from_seed([17u8; 32]);
        let state = PrivateGroupState::new_with_rng(
            "alice".to_string(),
            sample_attributes(),
            vec![PrivateGroupMember {
                user_id: "bob".to_string(),
                role: PrivateGroupRole::Admin,
            }],
            1_700_000_040,
            &mut rng,
        )
        .expect("create group");
        let admin_credential = state
            .issue_member_credential_with_rng("bob".to_string(), PrivateGroupRole::Admin, &mut rng)
            .expect("issue admin credential");
        let member_credential = state
            .issue_member_credential_with_rng(
                "carol".to_string(),
                PrivateGroupRole::Member,
                &mut rng,
            )
            .expect("issue member credential");

        assert_ne!(
            admin_credential.membership_handle_sha256(),
            member_credential.membership_handle_sha256()
        );
        assert!(admin_credential
            .state_publish_key()
            .expect("admin publish key")
            .is_some());
        assert!(member_credential
            .state_publish_key()
            .expect("member publish key")
            .is_none());
        assert_ne!(
            admin_credential.state_fetch_key().expect("admin fetch key"),
            member_credential
                .state_fetch_key()
                .expect("member fetch key")
        );
    }

    #[test]
    fn join_package_roundtrip_restores_state_and_member_credential() {
        let mut rng = ChaCha20Rng::from_seed([19u8; 32]);
        let state = PrivateGroupState::new_with_rng(
            "alice".to_string(),
            sample_attributes(),
            vec![PrivateGroupMember {
                user_id: "bob".to_string(),
                role: PrivateGroupRole::Admin,
            }],
            1_700_000_050,
            &mut rng,
        )
        .expect("create group");

        let join = state
            .export_join_package_for_member_with_rng("bob", &mut rng)
            .expect("export join package");
        let (restored_state, restored_credential) = join
            .restore_state_and_credential()
            .expect("restore join package");

        assert_eq!(restored_state.group_id, state.group_id);
        assert_eq!(restored_state.epoch, state.epoch);
        assert_eq!(restored_state.members, state.members);
        assert_eq!(restored_credential.group_id, state.group_id);
        assert_eq!(restored_credential.epoch, state.epoch);
        assert_eq!(restored_credential.member_user_id, "bob");
        assert_eq!(restored_credential.role, PrivateGroupRole::Admin);
    }

    #[test]
    fn join_package_rejects_member_role_mismatch() {
        let mut rng = ChaCha20Rng::from_seed([21u8; 32]);
        let state = PrivateGroupState::new_with_rng(
            "alice".to_string(),
            sample_attributes(),
            vec![PrivateGroupMember {
                user_id: "bob".to_string(),
                role: PrivateGroupRole::Member,
            }],
            1_700_000_060,
            &mut rng,
        )
        .expect("create group");

        let mut join = state
            .export_join_package_for_member_with_rng("bob", &mut rng)
            .expect("export join package");
        join.member_credential.role = PrivateGroupRole::Admin;

        let error = join
            .restore_state_and_credential()
            .expect_err("role mismatch should fail");
        assert!(error.to_string().contains("role mismatch"));
    }

    #[test]
    fn share_link_invite_roundtrip_restores_join_package() {
        let mut rng = ChaCha20Rng::from_seed([22u8; 32]);
        let state = PrivateGroupState::new_with_rng(
            "alice".to_string(),
            sample_attributes(),
            vec![PrivateGroupMember {
                user_id: "bob".to_string(),
                role: PrivateGroupRole::Member,
            }],
            1_700_000_065,
            &mut rng,
        )
        .expect("create group");

        let join_package = state
            .export_join_package_for_member_with_rng("bob", &mut rng)
            .expect("export join package");
        let link_material = join_package
            .encrypt_for_share_link_with_rng(&mut rng)
            .expect("encrypt share link invite");
        let restored = link_material
            .envelope
            .open_join_package(&link_material.invite_secret)
            .expect("open share link invite");

        assert_eq!(restored.invite.group_id, join_package.invite.group_id);
        assert_eq!(restored.invite.epoch, join_package.invite.epoch);
        assert_eq!(
            restored.member_credential.member_user_id,
            join_package.member_credential.member_user_id
        );
    }

    #[test]
    fn share_link_invite_rejects_wrong_secret() {
        let mut rng = ChaCha20Rng::from_seed([24u8; 32]);
        let state = PrivateGroupState::new_with_rng(
            "alice".to_string(),
            sample_attributes(),
            vec![PrivateGroupMember {
                user_id: "bob".to_string(),
                role: PrivateGroupRole::Member,
            }],
            1_700_000_066,
            &mut rng,
        )
        .expect("create group");

        let join_package = state
            .export_join_package_for_member_with_rng("bob", &mut rng)
            .expect("export join package");
        let link_material = join_package
            .encrypt_for_share_link_with_rng(&mut rng)
            .expect("encrypt share link invite");
        let mut wrong_secret = link_material.invite_secret;
        wrong_secret[0] ^= 0x01;

        let error = link_material
            .envelope
            .open_join_package(&wrong_secret)
            .expect_err("wrong secret should fail");
        assert!(error.to_string().contains("commitment"));
    }

    #[test]
    fn add_member_transition_advances_epoch_and_returns_join_package() {
        let mut rng = ChaCha20Rng::from_seed([23u8; 32]);
        let state = PrivateGroupState::new_with_rng(
            "alice".to_string(),
            sample_attributes(),
            vec![],
            1_700_000_070,
            &mut rng,
        )
        .expect("create group");

        let transition = state
            .prepare_add_member_transition_with_rng(
                "bob".to_string(),
                PrivateGroupRole::Member,
                1_700_000_071,
                &mut rng,
            )
            .expect("prepare add transition");

        assert_eq!(transition.next_state.epoch, 2);
        assert_eq!(transition.next_state.members.len(), 2);
        assert_eq!(transition.member_credentials.len(), 2);
        let join = transition
            .added_member_join_package
            .expect("join package for added member");
        let (restored_state, restored_credential) = join
            .restore_state_and_credential()
            .expect("restore added join package");
        assert_eq!(restored_state.group_id, transition.next_state.group_id);
        assert_eq!(restored_state.epoch, transition.next_state.epoch);
        assert_eq!(restored_credential.member_user_id, "bob");
        assert_eq!(restored_credential.role, PrivateGroupRole::Member);
        let transition_credential = transition
            .member_credentials
            .iter()
            .find(|credential| credential.member_user_id == "bob")
            .expect("transition member credential");
        assert_eq!(&restored_credential, transition_credential);
    }

    #[test]
    fn remove_member_transition_advances_epoch_and_drops_removed_member() {
        let mut rng = ChaCha20Rng::from_seed([25u8; 32]);
        let state = PrivateGroupState::new_with_rng(
            "alice".to_string(),
            sample_attributes(),
            vec![PrivateGroupMember {
                user_id: "bob".to_string(),
                role: PrivateGroupRole::Member,
            }],
            1_700_000_080,
            &mut rng,
        )
        .expect("create group");

        let transition = state
            .prepare_remove_member_transition_with_rng("bob", 1_700_000_081, &mut rng)
            .expect("prepare remove transition");

        assert_eq!(transition.next_state.epoch, 2);
        assert_eq!(transition.next_state.members.len(), 1);
        assert_eq!(transition.next_state.members[0].user_id, "alice");
        assert!(transition
            .member_credentials
            .iter()
            .all(|credential| credential.member_user_id != "bob"));
        assert!(transition.added_member_join_package.is_none());
    }

    #[test]
    #[cfg(any(feature = "pq-oqs", feature = "pq-rust"))]
    fn private_group_message_roundtrip_verifies_hybrid_sender_signature() {
        let mut rng = ChaCha20Rng::from_seed([26u8; 32]);
        let state = PrivateGroupState::new_with_rng(
            "alice".to_string(),
            sample_attributes(),
            vec![PrivateGroupMember {
                user_id: "bob".to_string(),
                role: PrivateGroupRole::Member,
            }],
            1_700_000_090,
            &mut rng,
        )
        .expect("create group");
        let provider = MlDsa65::new().expect("pq provider");
        let alice_identity_sig = SigningKey::from_bytes(&[7u8; 32]);
        let alice_identity_pq_sig = provider.keypair().expect("alice pq keypair");

        let encrypted = state
            .encrypt_message_with_rng(
                "alice",
                &alice_identity_sig.to_bytes(),
                alice_identity_pq_sig.secret_key.as_slice(),
                "Launch window moved to 09:30 UTC",
                1_700_000_090_123,
                &provider,
                &mut rng,
            )
            .expect("encrypt");
        let opened = state
            .decrypt_message(
                &encrypted,
                alice_identity_sig.verifying_key().as_bytes(),
                &alice_identity_pq_sig.public_key,
                &provider,
            )
            .expect("decrypt");

        assert_eq!(opened.group_id, state.group_id);
        assert_eq!(opened.epoch, state.epoch);
        assert_eq!(opened.sender_user_id, "alice");
        assert_eq!(opened.body, "Launch window moved to 09:30 UTC");
    }

    #[test]
    #[cfg(any(feature = "pq-oqs", feature = "pq-rust"))]
    fn private_group_message_rejects_sender_signature_spoof() {
        let mut rng = ChaCha20Rng::from_seed([27u8; 32]);
        let state = PrivateGroupState::new_with_rng(
            "alice".to_string(),
            sample_attributes(),
            vec![PrivateGroupMember {
                user_id: "bob".to_string(),
                role: PrivateGroupRole::Member,
            }],
            1_700_000_100,
            &mut rng,
        )
        .expect("create group");
        let provider = MlDsa65::new().expect("pq provider");
        let alice_identity_sig = SigningKey::from_bytes(&[8u8; 32]);
        let alice_identity_pq_sig = provider.keypair().expect("alice pq keypair");
        let bob_identity_sig = SigningKey::from_bytes(&[9u8; 32]);
        let bob_identity_pq_sig = provider.keypair().expect("bob pq keypair");

        let encrypted = state
            .encrypt_message_with_rng(
                "alice",
                &alice_identity_sig.to_bytes(),
                alice_identity_pq_sig.secret_key.as_slice(),
                "Spoof check",
                1_700_000_100_456,
                &provider,
                &mut rng,
            )
            .expect("encrypt");
        let error = state
            .decrypt_message(
                &encrypted,
                bob_identity_sig.verifying_key().as_bytes(),
                &bob_identity_pq_sig.public_key,
                &provider,
            )
            .expect_err("wrong sender keys should fail");
        assert!(error.to_string().contains("signature"));
    }
}
