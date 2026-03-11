import { ed25519, x25519 } from "@noble/curves/ed25519";
import { sha256 } from "@noble/hashes/sha2";
import {
  base64ToBytes,
  bytesToBase64,
  bytesToHex,
  bytesToUtf8,
  concatBytes,
  randomBytes,
  utf8ToBytes
} from "./base64";
import { criticalType, encodeTlv, i64ToBeBytes, u16ToBeBytes } from "./tlv";
import * as wasmCrypto from "./crypto-wasm";
import type { BundleResponse } from "./server";

const AUTH_TAG_ENDPOINT = criticalType(0x3201);
const AUTH_TAG_USER_ID = criticalType(0x3202);
const AUTH_TAG_DEVICE_ID = criticalType(0x3203);
const AUTH_TAG_TIMESTAMP = criticalType(0x3204);
const AUTH_TAG_NONCE = criticalType(0x3205);
const AUTH_TAG_RECIPIENT_ID = criticalType(0x3206);
const AUTH_TAG_SINCE = criticalType(0x3207);
const AUTH_TAG_MESSAGE_BLOB = criticalType(0x3208);
const AUTH_TAG_PREKEY_SPK_HASH = criticalType(0x3209);
const AUTH_TAG_PREKEY_PQSPK_HASH = criticalType(0x320a);
const AUTH_TAG_LINK_DEVICE_ID = criticalType(0x3212);
const AUTH_TAG_REVOKE_DEVICE_ID = criticalType(0x3213);
const AUTH_TAG_DISCOVERY_PHONE_HASHES_HASH = criticalType(0x3216);
const AUTH_TAG_DISCOVERY_EMAIL_HASHES_HASH = criticalType(0x3217);
const AUTH_TAG_DISCOVERY_QUERY_HASHES_HASH = criticalType(0x3218);
const AUTH_TAG_CONTACT_USER_ID = criticalType(0x3219);
const AUTH_TAG_CONTACT_ALIAS_HASH = criticalType(0x321a);
const AUTH_TAG_CONTACT_VERIFIED_FLAG = criticalType(0x321b);
const AUTH_TAG_CONTACT_FINGERPRINT = criticalType(0x321c);
const AUTH_TAG_PROFILE_DISPLAY_NAME_HASH = criticalType(0x3226);
const AUTH_TAG_PROFILE_AVATAR_HASH = criticalType(0x3227);
const AUTH_TAG_PROFILE_AVATAR_MIME_HASH = criticalType(0x3228);
const AUTH_TAG_PRESENCE_STATUS = criticalType(0x3229);
const AUTH_TAG_TYPING_PEER_ID = criticalType(0x322a);
const AUTH_TAG_TYPING_STATE_FLAG = criticalType(0x322b);
const AUTH_TAG_DELETE_IDS_HASH = criticalType(0x3214);
const AUTH_TAG_DELETE_BEFORE_ID = criticalType(0x3215);
const AUTH_TAG_GROUP_ID = criticalType(0x321d);
const AUTH_TAG_GROUP_MEMBER_USER_ID = criticalType(0x321e);
const AUTH_TAG_GROUP_MEMBERS_HASH = criticalType(0x321f);
const AUTH_TAG_GROUP_SENDER_USER_ID = criticalType(0x3220);
const AUTH_TAG_GROUP_MESSAGE_BLOB_HASH = criticalType(0x3221);
const AUTH_TAG_FILE_ID = criticalType(0x3222);
const AUTH_TAG_FILE_RECIPIENT_ID = criticalType(0x3223);
const AUTH_TAG_FILE_BLOB_HASH = criticalType(0x3224);
const AUTH_TAG_FILE_MIME_HASH = criticalType(0x3225);
const AUTH_TAG_PUSH_DEVICE_ID = criticalType(0x3210);
const AUTH_TAG_PUSH_TOKEN_HASH = criticalType(0x3211);
const AUTH_TAG_ROTATE_NEW_X25519_HASH = criticalType(0x320b);
const AUTH_TAG_ROTATE_NEW_SIG_HASH = criticalType(0x320c);
const AUTH_TAG_ROTATE_CHALLENGE_ID = criticalType(0x320d);
const AUTH_TAG_ROTATE_SIG_CURRENT_HASH = criticalType(0x320e);
const AUTH_TAG_ROTATE_SIG_NEW_HASH = criticalType(0x320f);

const SIG_TAG_PROTOCOL_VERSION = criticalType(0x0201);
const SIG_TAG_LABEL = criticalType(0x0202);
const SIG_TAG_KEY_MATERIAL = criticalType(0x0203);

const PBKDF2_ITERATIONS = 200_000;

export type GeneratedKeys = {
  userId: string;
  deviceId: string;
  suite: "ml-kem-768" | "kyber768";
  identityX25519Pub: string;
  identityX25519Secret: string;
  identitySigPub: string;
  identitySigSecret: string;
  signedPrekeyX25519Pub: string;
  signedPrekeyX25519Secret: string;
  pqSignedPrekeyPubMlkem768: string;
  pqSignedPrekeySecretMlkem768: string;
  oneTimePrekeysX25519: string[];
  oneTimePrekeysX25519Secret: string[];
  oneTimePrekeysMlkem768: string[];
  oneTimePrekeysMlkem768Secret: string[];
};

export type RequestAuthHeaders = {
  "x-pqmsg-auth-user": string;
  "x-pqmsg-auth-device": string;
  "x-pqmsg-auth-timestamp": string;
  "x-pqmsg-auth-nonce": string;
  "x-pqmsg-auth-signature": string;
};

export type PublishPrekeysPayload = {
  signed_prekey_x25519_pub: string;
  sig_over_spk: string;
  pq_signed_prekey_pub_mlkem768: string;
  sig_over_pqspk: string;
  one_time_prekeys_x25519: string[];
  one_time_prekeys_mlkem768: string[];
};

export type WireEnvelope = {
  v: 1;
  mode: "webcrypto-fallback-v1" | "pqmsg-classical-v1";
  sender: string;
  recipient: string;
  salt_b64: string;
  iv_b64: string;
  ct_b64: string;
};

type SealedPayload = {
  salt_b64: string;
  iv_b64: string;
  ct_b64: string;
};

export type DirectMessageSessionSendResult = {
  messageBytesBase64: string;
  sessionJson: string;
  usedHandshake: boolean;
};

export type DirectMessageSessionDecryptResult = {
  plaintextUtf8: string;
  plaintextBase64: string;
  sessionJson: string;
  usedHandshake: boolean;
  updatedKeys: GeneratedKeys;
};

export function generateIdentityKeys(
  userId: string,
  deviceId: string,
  suite: "ml-kem-768" | "kyber768",
  oneTimeCount: number
): GeneratedKeys {
  if (oneTimeCount < 1 || oneTimeCount > 64) {
    throw new Error("one-time prekey count must be in 1..64");
  }
  if (suite === "ml-kem-768" && !wasmCrypto.kemAvailable()) {
    throw new Error("Web post-quantum runtime unavailable in this build.");
  }
  const identityXSecret = x25519.utils.randomPrivateKey();
  const identityXPub = x25519.getPublicKey(identityXSecret);
  const identitySigSecret = ed25519.utils.randomPrivateKey();
  const identitySigPub = ed25519.getPublicKey(identitySigSecret);
  const signedPrekeySecret = x25519.utils.randomPrivateKey();
  const signedPrekeyPub = x25519.getPublicKey(signedPrekeySecret);

  const pqSignedPrekey = wasmCrypto.kemKeypair();

  const oneTimePrekeysX25519: string[] = [];
  const oneTimePrekeysX25519Secret: string[] = [];
  const oneTimePrekeysMlkem768: string[] = [];
  const oneTimePrekeysMlkem768Secret: string[] = [];

  for (let idx = 0; idx < oneTimeCount; idx += 1) {
    const xSecret = x25519.utils.randomPrivateKey();
    const xPub = x25519.getPublicKey(xSecret);
    oneTimePrekeysX25519.push(bytesToBase64(xPub));
    oneTimePrekeysX25519Secret.push(bytesToBase64(xSecret));
    const pqOtpk = wasmCrypto.kemKeypair();
    oneTimePrekeysMlkem768.push(bytesToBase64(pqOtpk.public_key));
    oneTimePrekeysMlkem768Secret.push(bytesToBase64(pqOtpk.secret_key));
  }

  return {
    userId,
    deviceId,
    suite,
    identityX25519Pub: bytesToBase64(identityXPub),
    identityX25519Secret: bytesToBase64(identityXSecret),
    identitySigPub: bytesToBase64(identitySigPub),
    identitySigSecret: bytesToBase64(identitySigSecret),
    signedPrekeyX25519Pub: bytesToBase64(signedPrekeyPub),
    signedPrekeyX25519Secret: bytesToBase64(signedPrekeySecret),
    pqSignedPrekeyPubMlkem768: bytesToBase64(pqSignedPrekey.public_key),
    pqSignedPrekeySecretMlkem768: bytesToBase64(pqSignedPrekey.secret_key),
    oneTimePrekeysX25519,
    oneTimePrekeysX25519Secret,
    oneTimePrekeysMlkem768,
    oneTimePrekeysMlkem768Secret
  };
}

export function buildPublishPrekeysPayload(keys: GeneratedKeys): PublishPrekeysPayload {
  const spkPub = base64ToBytes(keys.signedPrekeyX25519Pub);
  const pqSpkPub = base64ToBytes(keys.pqSignedPrekeyPubMlkem768);
  const identitySigSecret = base64ToBytes(keys.identitySigSecret);
  const spkMsg = signatureMessage(1, utf8ToBytes("SPK"), spkPub);
  const pqMsg = signatureMessage(1, utf8ToBytes("PQSPK"), pqSpkPub);
  const sigOverSpk = ed25519.sign(spkMsg, identitySigSecret);
  const sigOverPq = ed25519.sign(pqMsg, identitySigSecret);
  return {
    signed_prekey_x25519_pub: keys.signedPrekeyX25519Pub,
    sig_over_spk: bytesToBase64(sigOverSpk),
    pq_signed_prekey_pub_mlkem768: keys.pqSignedPrekeyPubMlkem768,
    sig_over_pqspk: bytesToBase64(sigOverPq),
    one_time_prekeys_x25519: keys.oneTimePrekeysX25519,
    one_time_prekeys_mlkem768: keys.oneTimePrekeysMlkem768
  };
}

export function buildPrekeysAuthHeaders(
  keys: GeneratedKeys,
  payload: PublishPrekeysPayload
): RequestAuthHeaders {
  const timestamp = unixTimestampSeconds();
  const nonce = bytesToBase64(randomBytes(16));
  const records = authCommonRecords("prekeys", keys.userId, keys.deviceId, timestamp, nonce);
  records.push({
    ty: AUTH_TAG_PREKEY_SPK_HASH,
    value: sha256(utf8ToBytes(payload.signed_prekey_x25519_pub))
  });
  records.push({
    ty: AUTH_TAG_PREKEY_PQSPK_HASH,
    value: sha256(utf8ToBytes(payload.pq_signed_prekey_pub_mlkem768))
  });
  return signAuthHeaders(keys, timestamp, nonce, records);
}

export function buildRelayAuthHeaders(
  keys: GeneratedKeys,
  recipientUserId: string,
  messageBytesBase64: string
): RequestAuthHeaders {
  const timestamp = unixTimestampSeconds();
  const nonce = bytesToBase64(randomBytes(16));
  const records = authCommonRecords("relay", keys.userId, keys.deviceId, timestamp, nonce);
  records.push({
    ty: AUTH_TAG_RECIPIENT_ID,
    value: utf8ToBytes(recipientUserId)
  });
  records.push({
    ty: AUTH_TAG_MESSAGE_BLOB,
    value: base64ToBytes(messageBytesBase64)
  });
  return signAuthHeaders(keys, timestamp, nonce, records);
}

export function buildInboxAuthHeaders(keys: GeneratedKeys, since: number): RequestAuthHeaders {
  const timestamp = unixTimestampSeconds();
  const nonce = bytesToBase64(randomBytes(16));
  const records = authCommonRecords("inbox", keys.userId, keys.deviceId, timestamp, nonce);
  records.push({
    ty: AUTH_TAG_RECIPIENT_ID,
    value: utf8ToBytes(keys.userId)
  });
  records.push({
    ty: AUTH_TAG_SINCE,
    value: i64ToBeBytes(since)
  });
  return signAuthHeaders(keys, timestamp, nonce, records);
}

export function buildListDevicesAuthHeaders(keys: GeneratedKeys): RequestAuthHeaders {
  const timestamp = unixTimestampSeconds();
  const nonce = bytesToBase64(randomBytes(16));
  const records = authCommonRecords("devices-list", keys.userId, keys.deviceId, timestamp, nonce);
  records.push({
    ty: AUTH_TAG_RECIPIENT_ID,
    value: utf8ToBytes(keys.userId)
  });
  return signAuthHeaders(keys, timestamp, nonce, records);
}

export function buildLinkDeviceAuthHeaders(
  keys: GeneratedKeys,
  newDeviceId: string
): RequestAuthHeaders {
  const timestamp = unixTimestampSeconds();
  const nonce = bytesToBase64(randomBytes(16));
  const records = authCommonRecords("devices-link", keys.userId, keys.deviceId, timestamp, nonce);
  records.push({
    ty: AUTH_TAG_RECIPIENT_ID,
    value: utf8ToBytes(keys.userId)
  });
  records.push({
    ty: AUTH_TAG_LINK_DEVICE_ID,
    value: utf8ToBytes(newDeviceId)
  });
  return signAuthHeaders(keys, timestamp, nonce, records);
}

export function buildRevokeDeviceAuthHeaders(
  keys: GeneratedKeys,
  targetDeviceId: string
): RequestAuthHeaders {
  const timestamp = unixTimestampSeconds();
  const nonce = bytesToBase64(randomBytes(16));
  const records = authCommonRecords("devices-revoke", keys.userId, keys.deviceId, timestamp, nonce);
  records.push({
    ty: AUTH_TAG_RECIPIENT_ID,
    value: utf8ToBytes(keys.userId)
  });
  records.push({
    ty: AUTH_TAG_REVOKE_DEVICE_ID,
    value: utf8ToBytes(targetDeviceId)
  });
  return signAuthHeaders(keys, timestamp, nonce, records);
}

export function buildRetireDeviceAuthHeaders(keys: GeneratedKeys): RequestAuthHeaders {
  const timestamp = unixTimestampSeconds();
  const nonce = bytesToBase64(randomBytes(16));
  const records = authCommonRecords("devices-retire", keys.userId, keys.deviceId, timestamp, nonce);
  records.push({
    ty: AUTH_TAG_RECIPIENT_ID,
    value: utf8ToBytes(keys.userId)
  });
  records.push({
    ty: AUTH_TAG_REVOKE_DEVICE_ID,
    value: utf8ToBytes(keys.deviceId)
  });
  return signAuthHeaders(keys, timestamp, nonce, records);
}

// --- Phase 2: Profile auth ---

export function buildProfileGetAuthHeaders(
  keys: GeneratedKeys,
  targetUserId: string
): RequestAuthHeaders {
  const timestamp = unixTimestampSeconds();
  const nonce = bytesToBase64(randomBytes(16));
  const records = authCommonRecords("profile-get", keys.userId, keys.deviceId, timestamp, nonce);
  records.push({ ty: AUTH_TAG_RECIPIENT_ID, value: utf8ToBytes(targetUserId) });
  return signAuthHeaders(keys, timestamp, nonce, records);
}

export function buildProfileUpsertAuthHeaders(
  keys: GeneratedKeys,
  displayName: string,
  avatarMime: string,
  avatarBlob: string
): RequestAuthHeaders {
  const timestamp = unixTimestampSeconds();
  const nonce = bytesToBase64(randomBytes(16));
  const records = authCommonRecords("profile-upsert", keys.userId, keys.deviceId, timestamp, nonce);
  records.push({ ty: AUTH_TAG_RECIPIENT_ID, value: utf8ToBytes(keys.userId) });
  records.push({ ty: AUTH_TAG_PROFILE_DISPLAY_NAME_HASH, value: sha256(utf8ToBytes(displayName)) });
  records.push({ ty: AUTH_TAG_PROFILE_AVATAR_HASH, value: sha256(utf8ToBytes(avatarBlob)) });
  records.push({ ty: AUTH_TAG_PROFILE_AVATAR_MIME_HASH, value: sha256(utf8ToBytes(avatarMime)) });
  return signAuthHeaders(keys, timestamp, nonce, records);
}

// --- Phase 2: Presence auth ---

export function buildPresenceGetAuthHeaders(keys: GeneratedKeys): RequestAuthHeaders {
  const timestamp = unixTimestampSeconds();
  const nonce = bytesToBase64(randomBytes(16));
  const records = authCommonRecords("presence-get", keys.userId, keys.deviceId, timestamp, nonce);
  records.push({ ty: AUTH_TAG_RECIPIENT_ID, value: utf8ToBytes(keys.userId) });
  return signAuthHeaders(keys, timestamp, nonce, records);
}

export function buildPresenceUpdateAuthHeaders(keys: GeneratedKeys, status: string): RequestAuthHeaders {
  const timestamp = unixTimestampSeconds();
  const nonce = bytesToBase64(randomBytes(16));
  const records = authCommonRecords("presence-update", keys.userId, keys.deviceId, timestamp, nonce);
  records.push({ ty: AUTH_TAG_RECIPIENT_ID, value: utf8ToBytes(keys.userId) });
  records.push({ ty: AUTH_TAG_PRESENCE_STATUS, value: utf8ToBytes(status) });
  return signAuthHeaders(keys, timestamp, nonce, records);
}

// --- Phase 2: Typing auth ---

export function buildTypingGetAuthHeaders(keys: GeneratedKeys): RequestAuthHeaders {
  const timestamp = unixTimestampSeconds();
  const nonce = bytesToBase64(randomBytes(16));
  const records = authCommonRecords("typing-get", keys.userId, keys.deviceId, timestamp, nonce);
  records.push({ ty: AUTH_TAG_RECIPIENT_ID, value: utf8ToBytes(keys.userId) });
  return signAuthHeaders(keys, timestamp, nonce, records);
}

export function buildTypingUpdateAuthHeaders(
  keys: GeneratedKeys,
  peerUserId: string,
  isTyping: boolean
): RequestAuthHeaders {
  const timestamp = unixTimestampSeconds();
  const nonce = bytesToBase64(randomBytes(16));
  const records = authCommonRecords("typing-update", keys.userId, keys.deviceId, timestamp, nonce);
  records.push({ ty: AUTH_TAG_TYPING_PEER_ID, value: utf8ToBytes(peerUserId) });
  records.push({ ty: AUTH_TAG_TYPING_STATE_FLAG, value: new Uint8Array([isTyping ? 1 : 0]) });
  return signAuthHeaders(keys, timestamp, nonce, records);
}

// --- Phase 2: Receipt auth (plain string format, not TLV) ---

export function buildSendReceiptAuthHeaders(
  keys: GeneratedKeys,
  messageId: number,
  receiptType: string
): RequestAuthHeaders {
  const authMsg = `receipt:${keys.userId}:${keys.deviceId}:${messageId}:${receiptType}`;
  const timestamp = unixTimestampSeconds();
  const nonce = bytesToBase64(randomBytes(16));
  const signingKey = base64ToBytes(keys.identitySigSecret);
  const signature = ed25519.sign(utf8ToBytes(authMsg), signingKey);
  return {
    "x-pqmsg-auth-user": keys.userId,
    "x-pqmsg-auth-device": keys.deviceId,
    "x-pqmsg-auth-timestamp": String(timestamp),
    "x-pqmsg-auth-nonce": nonce,
    "x-pqmsg-auth-signature": bytesToBase64(signature),
  };
}

export function buildGetReceiptsAuthHeaders(
  keys: GeneratedKeys,
  sinceId: number
): RequestAuthHeaders {
  const authMsg = `get-receipts:${keys.userId}:${keys.deviceId}:${sinceId}`;
  const timestamp = unixTimestampSeconds();
  const nonce = bytesToBase64(randomBytes(16));
  const signingKey = base64ToBytes(keys.identitySigSecret);
  const signature = ed25519.sign(utf8ToBytes(authMsg), signingKey);
  return {
    "x-pqmsg-auth-user": keys.userId,
    "x-pqmsg-auth-device": keys.deviceId,
    "x-pqmsg-auth-timestamp": String(timestamp),
    "x-pqmsg-auth-nonce": nonce,
    "x-pqmsg-auth-signature": bytesToBase64(signature),
  };
}

// --- Phase 2: Contacts auth ---

export function buildContactsListAuthHeaders(keys: GeneratedKeys): RequestAuthHeaders {
  const timestamp = unixTimestampSeconds();
  const nonce = bytesToBase64(randomBytes(16));
  const records = authCommonRecords("contacts-list", keys.userId, keys.deviceId, timestamp, nonce);
  records.push({ ty: AUTH_TAG_RECIPIENT_ID, value: utf8ToBytes(keys.userId) });
  return signAuthHeaders(keys, timestamp, nonce, records);
}

export function buildContactsUpsertAuthHeaders(
  keys: GeneratedKeys,
  contactUserId: string,
  alias: string,
  verifiedByQr: boolean,
  fingerprint: string
): RequestAuthHeaders {
  const timestamp = unixTimestampSeconds();
  const nonce = bytesToBase64(randomBytes(16));
  const records = authCommonRecords("contacts-upsert", keys.userId, keys.deviceId, timestamp, nonce);
  records.push({ ty: AUTH_TAG_RECIPIENT_ID, value: utf8ToBytes(keys.userId) });
  records.push({ ty: AUTH_TAG_CONTACT_USER_ID, value: utf8ToBytes(contactUserId) });
  records.push({ ty: AUTH_TAG_CONTACT_ALIAS_HASH, value: sha256(utf8ToBytes(alias)) });
  records.push({ ty: AUTH_TAG_CONTACT_VERIFIED_FLAG, value: new Uint8Array([verifiedByQr ? 1 : 0]) });
  if (fingerprint) {
    records.push({ ty: AUTH_TAG_CONTACT_FINGERPRINT, value: utf8ToBytes(fingerprint) });
  }
  return signAuthHeaders(keys, timestamp, nonce, records);
}

export function buildContactsRemoveAuthHeaders(
  keys: GeneratedKeys,
  contactUserId: string
): RequestAuthHeaders {
  const timestamp = unixTimestampSeconds();
  const nonce = bytesToBase64(randomBytes(16));
  const records = authCommonRecords("contacts-remove", keys.userId, keys.deviceId, timestamp, nonce);
  records.push({ ty: AUTH_TAG_RECIPIENT_ID, value: utf8ToBytes(keys.userId) });
  records.push({ ty: AUTH_TAG_CONTACT_USER_ID, value: utf8ToBytes(contactUserId) });
  return signAuthHeaders(keys, timestamp, nonce, records);
}

// --- Phase 3: Group auth ---

function hashStringListSha256(items: string[]): Uint8Array {
  const sorted = [...new Set(items)].sort();
  return sha256(utf8ToBytes(sorted.join(",")));
}

export function buildGroupCreateAuthHeaders(
  keys: GeneratedKeys,
  groupId: string,
  memberUserIds: string[]
): RequestAuthHeaders {
  const timestamp = unixTimestampSeconds();
  const nonce = bytesToBase64(randomBytes(16));
  const records = authCommonRecords("groups-create", keys.userId, keys.deviceId, timestamp, nonce);
  records.push({ ty: AUTH_TAG_GROUP_ID, value: utf8ToBytes(groupId) });
  records.push({ ty: AUTH_TAG_GROUP_MEMBERS_HASH, value: hashStringListSha256(memberUserIds) });
  return signAuthHeaders(keys, timestamp, nonce, records);
}

export function buildUserGroupsListAuthHeaders(
  keys: GeneratedKeys,
  userId: string
): RequestAuthHeaders {
  const timestamp = unixTimestampSeconds();
  const nonce = bytesToBase64(randomBytes(16));
  const records = authCommonRecords("groups-list", keys.userId, keys.deviceId, timestamp, nonce);
  records.push({ ty: AUTH_TAG_RECIPIENT_ID, value: utf8ToBytes(userId) });
  return signAuthHeaders(keys, timestamp, nonce, records);
}

export function buildGroupMembersListAuthHeaders(
  keys: GeneratedKeys,
  groupId: string
): RequestAuthHeaders {
  const timestamp = unixTimestampSeconds();
  const nonce = bytesToBase64(randomBytes(16));
  const records = authCommonRecords("groups-members-list", keys.userId, keys.deviceId, timestamp, nonce);
  records.push({ ty: AUTH_TAG_GROUP_ID, value: utf8ToBytes(groupId) });
  return signAuthHeaders(keys, timestamp, nonce, records);
}

export function buildGroupMembersAddAuthHeaders(
  keys: GeneratedKeys,
  groupId: string,
  memberUserId: string
): RequestAuthHeaders {
  const timestamp = unixTimestampSeconds();
  const nonce = bytesToBase64(randomBytes(16));
  const records = authCommonRecords("groups-members-add", keys.userId, keys.deviceId, timestamp, nonce);
  records.push({ ty: AUTH_TAG_GROUP_ID, value: utf8ToBytes(groupId) });
  records.push({ ty: AUTH_TAG_GROUP_MEMBER_USER_ID, value: utf8ToBytes(memberUserId) });
  return signAuthHeaders(keys, timestamp, nonce, records);
}

export function buildGroupMembersRemoveAuthHeaders(
  keys: GeneratedKeys,
  groupId: string,
  memberUserId: string
): RequestAuthHeaders {
  const timestamp = unixTimestampSeconds();
  const nonce = bytesToBase64(randomBytes(16));
  const records = authCommonRecords("groups-members-remove", keys.userId, keys.deviceId, timestamp, nonce);
  records.push({ ty: AUTH_TAG_GROUP_ID, value: utf8ToBytes(groupId) });
  records.push({ ty: AUTH_TAG_GROUP_MEMBER_USER_ID, value: utf8ToBytes(memberUserId) });
  return signAuthHeaders(keys, timestamp, nonce, records);
}

export function buildGroupRelayAuthHeaders(
  keys: GeneratedKeys,
  groupId: string,
  messageBytesBase64: string
): RequestAuthHeaders {
  const timestamp = unixTimestampSeconds();
  const nonce = bytesToBase64(randomBytes(16));
  const records = authCommonRecords("groups-relay", keys.userId, keys.deviceId, timestamp, nonce);
  records.push({ ty: AUTH_TAG_GROUP_ID, value: utf8ToBytes(groupId) });
  records.push({ ty: AUTH_TAG_GROUP_SENDER_USER_ID, value: utf8ToBytes(keys.userId) });
  records.push({ ty: AUTH_TAG_GROUP_MESSAGE_BLOB_HASH, value: sha256(base64ToBytes(messageBytesBase64)) });
  return signAuthHeaders(keys, timestamp, nonce, records);
}

// --- Phase 3: File auth ---

export function buildFileUploadAuthHeaders(
  keys: GeneratedKeys,
  recipientUserId: string,
  mimeType: string,
  fileBytesBase64: string
): RequestAuthHeaders {
  const timestamp = unixTimestampSeconds();
  const nonce = bytesToBase64(randomBytes(16));
  const records = authCommonRecords("files-upload", keys.userId, keys.deviceId, timestamp, nonce);
  records.push({ ty: AUTH_TAG_FILE_RECIPIENT_ID, value: utf8ToBytes(recipientUserId) });
  records.push({ ty: AUTH_TAG_FILE_BLOB_HASH, value: sha256(base64ToBytes(fileBytesBase64)) });
  records.push({ ty: AUTH_TAG_FILE_MIME_HASH, value: sha256(utf8ToBytes(mimeType)) });
  return signAuthHeaders(keys, timestamp, nonce, records);
}

export function buildFileDownloadAuthHeaders(
  keys: GeneratedKeys,
  fileId: string
): RequestAuthHeaders {
  const timestamp = unixTimestampSeconds();
  const nonce = bytesToBase64(randomBytes(16));
  const records = authCommonRecords("files-download", keys.userId, keys.deviceId, timestamp, nonce);
  records.push({ ty: AUTH_TAG_FILE_ID, value: utf8ToBytes(fileId) });
  return signAuthHeaders(keys, timestamp, nonce, records);
}

// --- Phase 3: Inbox delete auth ---

export function buildInboxDeleteAuthHeaders(
  keys: GeneratedKeys,
  messageIds: number[],
  deleteBeforeId?: number
): RequestAuthHeaders {
  const timestamp = unixTimestampSeconds();
  const nonce = bytesToBase64(randomBytes(16));
  const records = authCommonRecords("inbox-delete", keys.userId, keys.deviceId, timestamp, nonce);
  records.push({ ty: AUTH_TAG_RECIPIENT_ID, value: utf8ToBytes(keys.userId) });
  // Hash sorted deduplicated message IDs as concatenated big-endian i64
  const sorted = [...new Set(messageIds)].sort((a, b) => a - b);
  const idBytes = concatBytes(sorted.map(id => i64ToBeBytes(id)));
  records.push({ ty: AUTH_TAG_DELETE_IDS_HASH, value: sha256(idBytes) });
  if (deleteBeforeId !== undefined) {
    records.push({ ty: AUTH_TAG_DELETE_BEFORE_ID, value: i64ToBeBytes(deleteBeforeId) });
  }
  return signAuthHeaders(keys, timestamp, nonce, records);
}

// --- Phase 3: Prekey status auth ---

export function buildPrekeysStatusAuthHeaders(keys: GeneratedKeys): RequestAuthHeaders {
  const timestamp = unixTimestampSeconds();
  const nonce = bytesToBase64(randomBytes(16));
  const records = authCommonRecords("prekeys-status", keys.userId, keys.deviceId, timestamp, nonce);
  records.push({ ty: AUTH_TAG_RECIPIENT_ID, value: utf8ToBytes(keys.userId) });
  return signAuthHeaders(keys, timestamp, nonce, records);
}

// --- Phase 4: Identity key rotation auth ---

export function buildRotateInitAuthHeaders(
  keys: GeneratedKeys,
  newIdentityX25519Pub: string,
  newIdentitySigPub: string
): RequestAuthHeaders {
  const timestamp = unixTimestampSeconds();
  const nonce = bytesToBase64(randomBytes(16));
  const records = authCommonRecords("rotate-init", keys.userId, keys.deviceId, timestamp, nonce);
  records.push({ ty: AUTH_TAG_ROTATE_NEW_X25519_HASH, value: sha256(utf8ToBytes(newIdentityX25519Pub)) });
  records.push({ ty: AUTH_TAG_ROTATE_NEW_SIG_HASH, value: sha256(utf8ToBytes(newIdentitySigPub)) });
  return signAuthHeaders(keys, timestamp, nonce, records);
}

export function buildRotateConfirmAuthHeaders(
  keys: GeneratedKeys,
  challengeId: string,
  sigByCurrentIdentity: string,
  sigByNewIdentity: string
): RequestAuthHeaders {
  const timestamp = unixTimestampSeconds();
  const nonce = bytesToBase64(randomBytes(16));
  const records = authCommonRecords("rotate-confirm", keys.userId, keys.deviceId, timestamp, nonce);
  records.push({ ty: AUTH_TAG_ROTATE_CHALLENGE_ID, value: utf8ToBytes(challengeId) });
  records.push({ ty: AUTH_TAG_ROTATE_SIG_CURRENT_HASH, value: sha256(utf8ToBytes(sigByCurrentIdentity)) });
  records.push({ ty: AUTH_TAG_ROTATE_SIG_NEW_HASH, value: sha256(utf8ToBytes(sigByNewIdentity)) });
  return signAuthHeaders(keys, timestamp, nonce, records);
}

export function buildIdentityLogAuthHeaders(keys: GeneratedKeys): RequestAuthHeaders {
  const timestamp = unixTimestampSeconds();
  const nonce = bytesToBase64(randomBytes(16));
  const records = authCommonRecords("identity-log", keys.userId, keys.deviceId, timestamp, nonce);
  records.push({ ty: AUTH_TAG_RECIPIENT_ID, value: utf8ToBytes(keys.userId) });
  return signAuthHeaders(keys, timestamp, nonce, records);
}

// --- Phase 4: Sealed sender auth ---

export function buildSealedInboxAuthHeaders(keys: GeneratedKeys, since: number): RequestAuthHeaders {
  const timestamp = unixTimestampSeconds();
  const nonce = bytesToBase64(randomBytes(16));
  const records = authCommonRecords("sealed-inbox", keys.userId, keys.deviceId, timestamp, nonce);
  records.push({ ty: AUTH_TAG_RECIPIENT_ID, value: utf8ToBytes(keys.userId) });
  records.push({ ty: AUTH_TAG_SINCE, value: i64ToBeBytes(since) });
  return signAuthHeaders(keys, timestamp, nonce, records);
}

// --- Phase 4: Ephemeral relay auth (format-string, not TLV) ---

export function buildEphemeralRelayAuthHeaders(
  keys: GeneratedKeys,
  recipientUserId: string,
  ttlSeconds: number
): RequestAuthHeaders {
  const timestamp = unixTimestampSeconds();
  const nonce = bytesToBase64(randomBytes(16));
  const message = `ephemeral-relay:${keys.userId}:${keys.deviceId}:${recipientUserId}:${ttlSeconds}`;
  const signingKey = base64ToBytes(keys.identitySigSecret);
  const signature = ed25519.sign(utf8ToBytes(message), signingKey);
  return {
    "x-pqmsg-auth-user": keys.userId,
    "x-pqmsg-auth-device": keys.deviceId,
    "x-pqmsg-auth-timestamp": String(timestamp),
    "x-pqmsg-auth-nonce": nonce,
    "x-pqmsg-auth-signature": bytesToBase64(signature)
  };
}

export function buildDiscoveryHandlesAuthHeaders(
  keys: GeneratedKeys,
  phoneHashes: string[],
  emailHashes: string[]
): RequestAuthHeaders {
  const sortedPhones = [...phoneHashes].sort().join(",");
  const sortedEmails = [...emailHashes].sort().join(",");
  const timestamp = unixTimestampSeconds();
  const nonce = bytesToBase64(randomBytes(16));
  const records = authCommonRecords("discovery-handles", keys.userId, keys.deviceId, timestamp, nonce);
  records.push({ ty: AUTH_TAG_RECIPIENT_ID, value: utf8ToBytes(keys.userId) });
  records.push({ ty: AUTH_TAG_DISCOVERY_PHONE_HASHES_HASH, value: sha256(utf8ToBytes(sortedPhones)) });
  records.push({ ty: AUTH_TAG_DISCOVERY_EMAIL_HASHES_HASH, value: sha256(utf8ToBytes(sortedEmails)) });
  return signAuthHeaders(keys, timestamp, nonce, records);
}

export function buildDiscoveryMatchAuthHeaders(
  keys: GeneratedKeys,
  queryHashes: string[]
): RequestAuthHeaders {
  const sorted = [...queryHashes].sort().join(",");
  const timestamp = unixTimestampSeconds();
  const nonce = bytesToBase64(randomBytes(16));
  const records = authCommonRecords("discovery-match", keys.userId, keys.deviceId, timestamp, nonce);
  records.push({ ty: AUTH_TAG_RECIPIENT_ID, value: utf8ToBytes(keys.userId) });
  records.push({ ty: AUTH_TAG_DISCOVERY_QUERY_HASHES_HASH, value: sha256(utf8ToBytes(sorted)) });
  return signAuthHeaders(keys, timestamp, nonce, records);
}

export function buildPushTokenAuthHeaders(
  keys: GeneratedKeys,
  token: string
): RequestAuthHeaders {
  const timestamp = unixTimestampSeconds();
  const nonce = bytesToBase64(randomBytes(16));
  const records = authCommonRecords("push-token", keys.userId, keys.deviceId, timestamp, nonce);
  records.push({ ty: AUTH_TAG_RECIPIENT_ID, value: utf8ToBytes(keys.userId) });
  records.push({ ty: AUTH_TAG_PUSH_DEVICE_ID, value: utf8ToBytes(keys.deviceId) });
  records.push({ ty: AUTH_TAG_PUSH_TOKEN_HASH, value: sha256(utf8ToBytes(token)) });
  return signAuthHeaders(keys, timestamp, nonce, records);
}

export async function sealJsonWithPassphrase<T>(value: T, passphrase: string): Promise<string> {
  const plaintext = utf8ToBytes(JSON.stringify(value));
  const salt = randomBytes(16);
  const iv = randomBytes(12);
  const key = await deriveAesGcmKey(passphrase, salt);
  const aad = utf8ToBytes("pqmsg-web-fallback-sealed-state-v1");
  const ciphertext = new Uint8Array(
    await crypto.subtle.encrypt(
      {
        name: "AES-GCM",
        iv: iv.buffer as ArrayBuffer,
        additionalData: aad.buffer as ArrayBuffer
      },
      key,
      plaintext.buffer as ArrayBuffer
    )
  );
  const payload: SealedPayload = {
    salt_b64: bytesToBase64(salt),
    iv_b64: bytesToBase64(iv),
    ct_b64: bytesToBase64(ciphertext)
  };
  return JSON.stringify(payload);
}

export async function openJsonWithPassphrase<T>(
  sealed: string,
  passphrase: string
): Promise<T> {
  const parsed = JSON.parse(sealed) as SealedPayload;
  const salt = base64ToBytes(parsed.salt_b64);
  const iv = base64ToBytes(parsed.iv_b64);
  const ciphertext = base64ToBytes(parsed.ct_b64);
  const key = await deriveAesGcmKey(passphrase, salt);
  const aad = utf8ToBytes("pqmsg-web-fallback-sealed-state-v1");
  const plaintext = new Uint8Array(
    await crypto.subtle.decrypt(
      {
        name: "AES-GCM",
        iv: iv.buffer as ArrayBuffer,
        additionalData: aad.buffer as ArrayBuffer
      },
      key,
      ciphertext.buffer as ArrayBuffer
    )
  );
  return JSON.parse(bytesToUtf8(plaintext)) as T;
}

export async function encryptFallbackMessage(
  passphrase: string,
  sender: string,
  recipient: string,
  plaintext: string
): Promise<WireEnvelope> {
  const salt = randomBytes(16);
  const iv = randomBytes(12);
  const key = await deriveAesGcmKey(passphrase, salt);
  const aad = utf8ToBytes(`pqmsg-webcrypto-fallback:${sender}:${recipient}:v1`);
  const ciphertext = new Uint8Array(
    await crypto.subtle.encrypt(
      {
        name: "AES-GCM",
        iv: iv.buffer as ArrayBuffer,
        additionalData: aad.buffer as ArrayBuffer
      },
      key,
      utf8ToBytes(plaintext).buffer as ArrayBuffer
    )
  );
  return {
    v: 1,
    mode: "webcrypto-fallback-v1",
    sender,
    recipient,
    salt_b64: bytesToBase64(salt),
    iv_b64: bytesToBase64(iv),
    ct_b64: bytesToBase64(ciphertext)
  };
}

export async function decryptFallbackMessage(
  passphrase: string,
  wire: WireEnvelope
): Promise<string> {
  const salt = base64ToBytes(wire.salt_b64);
  const iv = base64ToBytes(wire.iv_b64);
  const ciphertext = base64ToBytes(wire.ct_b64);
  const key = await deriveAesGcmKey(passphrase, salt);
  const aad = utf8ToBytes(`pqmsg-webcrypto-fallback:${wire.sender}:${wire.recipient}:v1`);
  const plaintext = new Uint8Array(
    await crypto.subtle.decrypt(
      {
        name: "AES-GCM",
        iv: iv.buffer as ArrayBuffer,
        additionalData: aad.buffer as ArrayBuffer
      },
      key,
      ciphertext.buffer as ArrayBuffer
    )
  );
  return bytesToUtf8(plaintext);
}

export function encodeWireEnvelopeBase64(envelope: WireEnvelope): string {
  return bytesToBase64(utf8ToBytes(JSON.stringify(envelope)));
}

export function decodeWireEnvelopeBase64(wireBase64: string): WireEnvelope {
  const wire = JSON.parse(bytesToUtf8(base64ToBytes(wireBase64))) as WireEnvelope;
  if (wire.v !== 1 || (wire.mode !== "webcrypto-fallback-v1" && wire.mode !== "pqmsg-classical-v1")) {
    throw new Error("unsupported wire mode");
  }
  return wire;
}

/** Try to initialize WASM crypto. Returns true if WASM is available. */
export async function initWasmCrypto(): Promise<boolean> {
  return wasmCrypto.initWasm();
}

/** Whether WASM crypto is loaded and available for message encryption. */
export function isWasmCryptoAvailable(): boolean {
  return wasmCrypto.wasmAvailable();
}

/** Whether real session-based PQ direct messaging is available. */
export function isPqSessionMessagingAvailable(): boolean {
  return wasmCrypto.sessionMessagingAvailable();
}

/**
 * Regenerate server-published prekeys while preserving the user's long-term
 * identity and signed X25519 prekey material.
 */
export function regeneratePublishedPrekeys(
  keys: GeneratedKeys,
  oneTimeCount = Math.max(keys.oneTimePrekeysX25519.length, 16)
): GeneratedKeys {
  if (!wasmCrypto.kemAvailable()) {
    throw new Error("Web post-quantum runtime unavailable in this build.");
  }
  if (oneTimeCount < 1 || oneTimeCount > 64) {
    throw new Error("one-time prekey count must be in 1..64");
  }

  const oneTimePrekeysX25519: string[] = [];
  const oneTimePrekeysX25519Secret: string[] = [];
  const oneTimePrekeysMlkem768: string[] = [];
  const oneTimePrekeysMlkem768Secret: string[] = [];

  for (let idx = 0; idx < oneTimeCount; idx += 1) {
    const xSecret = x25519.utils.randomPrivateKey();
    const xPub = x25519.getPublicKey(xSecret);
    const pqOtpk = wasmCrypto.kemKeypair();
    oneTimePrekeysX25519.push(bytesToBase64(xPub));
    oneTimePrekeysX25519Secret.push(bytesToBase64(xSecret));
    oneTimePrekeysMlkem768.push(bytesToBase64(pqOtpk.public_key));
    oneTimePrekeysMlkem768Secret.push(bytesToBase64(pqOtpk.secret_key));
  }

  const pqSignedPrekey = wasmCrypto.kemKeypair();
  return {
    ...keys,
    pqSignedPrekeyPubMlkem768: bytesToBase64(pqSignedPrekey.public_key),
    pqSignedPrekeySecretMlkem768: bytesToBase64(pqSignedPrekey.secret_key),
    oneTimePrekeysX25519,
    oneTimePrekeysX25519Secret,
    oneTimePrekeysMlkem768,
    oneTimePrekeysMlkem768Secret,
  };
}

/**
 * Encrypt a message using WASM (ChaCha20-Poly1305 via pqmsg-core).
 * Falls back to WebCrypto AES-GCM if WASM is unavailable.
 */
export async function encryptMessage(
  passphrase: string,
  sender: string,
  recipient: string,
  plaintext: string
): Promise<WireEnvelope> {
  if (wasmCrypto.wasmAvailable()) {
    const ad = wasmCrypto.conversationAd(sender, recipient);
    const salt = randomBytes(16);
    const key = wasmCrypto.hkdfSha256(utf8ToBytes(passphrase), salt, ad, 32);
    const ct = wasmCrypto.encrypt(key, utf8ToBytes(plaintext), ad);
    // ct = nonce(12) || ciphertext+tag
    const nonce = ct.slice(0, 12);
    const ciphertextBytes = ct.slice(12);
    return {
      v: 1,
      mode: "pqmsg-classical-v1",
      sender,
      recipient,
      salt_b64: bytesToBase64(salt),
      iv_b64: bytesToBase64(nonce),
      ct_b64: bytesToBase64(ciphertextBytes)
    };
  }
  return encryptFallbackMessage(passphrase, sender, recipient, plaintext);
}

/**
 * Decrypt a message — auto-detects mode from wire envelope.
 */
export async function decryptMessage(
  passphrase: string,
  wire: WireEnvelope
): Promise<string> {
  if (wire.mode === "pqmsg-classical-v1") {
    if (!wasmCrypto.wasmAvailable()) {
      throw new Error("WASM crypto required to decrypt pqmsg-classical-v1 messages");
    }
    const salt = base64ToBytes(wire.salt_b64);
    const nonce = base64ToBytes(wire.iv_b64);
    const ciphertext = base64ToBytes(wire.ct_b64);
    const ad = wasmCrypto.conversationAd(wire.sender, wire.recipient);
    const key = wasmCrypto.hkdfSha256(utf8ToBytes(passphrase), salt, ad, 32);
    // Reconstruct nonce || ciphertext for WASM decrypt
    const combined = concatBytes([nonce, ciphertext]);
    const pt = wasmCrypto.decrypt(key, combined, ad);
    return bytesToUtf8(pt);
  }
  return decryptFallbackMessage(passphrase, wire);
}

export function initiateDirectMessageSession(
  keys: GeneratedKeys,
  peerBundle: BundleResponse,
  plaintext: string
): DirectMessageSessionSendResult {
  const result = wasmCrypto.initiateSessionAndEncrypt(
    keys,
    keys.userId,
    peerBundle.user_id,
    peerBundle,
    plaintext
  );
  return {
    messageBytesBase64: result.message_bytes_base64,
    sessionJson: result.session_json,
    usedHandshake: result.used_handshake,
  };
}

export function encryptDirectMessageWithSession(
  sessionJson: string,
  senderUserId: string,
  peerUserId: string,
  plaintext: string
): DirectMessageSessionSendResult {
  const result = wasmCrypto.encryptWithSession(sessionJson, senderUserId, peerUserId, plaintext);
  return {
    messageBytesBase64: result.message_bytes_base64,
    sessionJson: result.session_json,
    usedHandshake: result.used_handshake,
  };
}

export function decryptDirectMessage(
  keys: GeneratedKeys,
  senderUserId: string,
  messageBytesBase64: string,
  existingSessionJson?: string | null
): DirectMessageSessionDecryptResult {
  const result = wasmCrypto.decryptDirectMessage(
    keys,
    keys.userId,
    senderUserId,
    messageBytesBase64,
    existingSessionJson
  );
  return {
    plaintextUtf8: result.plaintext_utf8,
    plaintextBase64: result.plaintext_base64,
    sessionJson: result.session_json,
    usedHandshake: result.used_handshake,
    updatedKeys: result.updated_keys as GeneratedKeys,
  };
}

export function identityFingerprint(identityX25519PubB64: string): string {
  return bytesToHex(sha256(base64ToBytes(identityX25519PubB64)));
}

function signatureMessage(
  protocolVersion: number,
  label: Uint8Array,
  keyMaterial: Uint8Array
): Uint8Array {
  return encodeTlv([
    { ty: SIG_TAG_PROTOCOL_VERSION, value: u16ToBeBytes(protocolVersion) },
    { ty: SIG_TAG_LABEL, value: label },
    { ty: SIG_TAG_KEY_MATERIAL, value: keyMaterial }
  ]);
}

function authCommonRecords(
  endpoint: string,
  userId: string,
  deviceId: string,
  timestamp: number,
  nonce: string
): { ty: number; value: Uint8Array }[] {
  return [
    { ty: AUTH_TAG_ENDPOINT, value: utf8ToBytes(endpoint) },
    { ty: AUTH_TAG_USER_ID, value: utf8ToBytes(userId) },
    { ty: AUTH_TAG_DEVICE_ID, value: utf8ToBytes(deviceId) },
    { ty: AUTH_TAG_TIMESTAMP, value: i64ToBeBytes(timestamp) },
    { ty: AUTH_TAG_NONCE, value: utf8ToBytes(nonce) }
  ];
}

function signAuthHeaders(
  keys: GeneratedKeys,
  timestamp: number,
  nonce: string,
  records: { ty: number; value: Uint8Array }[]
): RequestAuthHeaders {
  const transcript = encodeTlv(records);
  const signingKey = base64ToBytes(keys.identitySigSecret);
  const signature = ed25519.sign(transcript, signingKey);
  return {
    "x-pqmsg-auth-user": keys.userId,
    "x-pqmsg-auth-device": keys.deviceId,
    "x-pqmsg-auth-timestamp": String(timestamp),
    "x-pqmsg-auth-nonce": nonce,
    "x-pqmsg-auth-signature": bytesToBase64(signature)
  };
}

async function deriveAesGcmKey(passphrase: string, salt: Uint8Array): Promise<CryptoKey> {
  if (!passphrase.trim()) {
    throw new Error("passphrase is empty");
  }
  const keyMaterial = await crypto.subtle.importKey(
    "raw",
    utf8ToBytes(passphrase).buffer as ArrayBuffer,
    "PBKDF2",
    false,
    ["deriveKey"]
  );
  return crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      salt: salt.buffer as ArrayBuffer,
      iterations: PBKDF2_ITERATIONS,
      hash: "SHA-256"
    },
    keyMaterial,
    {
      name: "AES-GCM",
      length: 256
    },
    false,
    ["encrypt", "decrypt"]
  );
}

function unixTimestampSeconds(): number {
  return Math.floor(Date.now() / 1000);
}
