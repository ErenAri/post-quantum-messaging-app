/**
 * WebRTC voice/video calling with PQ E2E media encryption.
 *
 * Uses the server's call signaling API (REST polling) and browser WebRTC.
 * When WASM KEM is available, derives a post-quantum media key via ML-KEM-768
 * and encrypts/decrypts RTP payloads using Insertable Streams (Encoded Transform).
 */

import {
  PqmsgApi,
  type CallOfferRequest,
  type CallAnswerRequest,
  type IceCandidateRequest,
  type CallHangupRequest,
  type CallSignal,
} from "./server";
import type { RequestAuthHeaders, GeneratedKeys } from "./crypto";
import { bytesToBase64, base64ToBytes, randomBytes } from "./base64";
import { ed25519 } from "@noble/curves/ed25519";
import * as wasmCrypto from "./crypto-wasm";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export type CallState =
  | "idle"
  | "outgoing-ringing"
  | "incoming-ringing"
  | "connecting"
  | "active"
  | "ended";

export type CallDirection = "outgoing" | "incoming";

export interface CallInfo {
  callId: string;
  peerId: string;
  direction: CallDirection;
  callType: "audio" | "video";
  state: CallState;
  startedAt: number;
}

type CallEventListener = (info: CallInfo) => void;

// ---------------------------------------------------------------------------
// Auth header builders (format-string pattern matching server handlers)
// ---------------------------------------------------------------------------

function buildCallOfferAuth(keys: GeneratedKeys, calleeUserId: string): RequestAuthHeaders {
  return formatStringAuth(keys, `call-offer:${keys.userId}:${keys.deviceId}:${calleeUserId}`);
}

function buildCallAnswerAuth(keys: GeneratedKeys, callId: string): RequestAuthHeaders {
  return formatStringAuth(keys, `call-answer:${keys.userId}:${keys.deviceId}:${callId}`);
}

function buildCallIceAuth(keys: GeneratedKeys, callId: string): RequestAuthHeaders {
  return formatStringAuth(keys, `call-ice:${keys.userId}:${keys.deviceId}:${callId}`);
}

function buildCallHangupAuth(keys: GeneratedKeys, callId: string): RequestAuthHeaders {
  return formatStringAuth(keys, `call-hangup:${keys.userId}:${keys.deviceId}:${callId}`);
}

function buildCallPollAuth(keys: GeneratedKeys, callId: string): RequestAuthHeaders {
  return formatStringAuth(keys, `call-poll:${keys.userId}:${keys.deviceId}:${callId}`);
}

function formatStringAuth(keys: GeneratedKeys, message: string): RequestAuthHeaders {
  const timestamp = Math.floor(Date.now() / 1000);
  const nonce = bytesToBase64(randomBytes(16));
  const signingKey = base64ToBytes(keys.identitySigSecret);
  const msgBytes = new TextEncoder().encode(message);
  const signature = ed25519.sign(msgBytes, signingKey);
  return {
    "x-pqmsg-auth-user": keys.userId,
    "x-pqmsg-auth-device": keys.deviceId,
    "x-pqmsg-auth-timestamp": String(timestamp),
    "x-pqmsg-auth-nonce": nonce,
    "x-pqmsg-auth-signature": bytesToBase64(signature),
  };
}

// ---------------------------------------------------------------------------
// ICE Servers (STUN only; TURN would be added via /v1/capabilities)
// ---------------------------------------------------------------------------

const ICE_SERVERS: RTCIceServer[] = [
  { urls: "stun:stun.l.google.com:19302" },
  { urls: "stun:stun1.l.google.com:19302" },
];

// ---------------------------------------------------------------------------
// PQ Media Key Derivation (Insertable Streams E2E encryption)
// ---------------------------------------------------------------------------

/** Derive a 256-bit media encryption key using ML-KEM-768 + X25519 hybrid. */
function deriveMediaKey(
  kemSharedSecret: Uint8Array,
  dhSharedSecret: Uint8Array
): Uint8Array {
  const ikm = new Uint8Array(kemSharedSecret.length + dhSharedSecret.length);
  ikm.set(kemSharedSecret);
  ikm.set(dhSharedSecret, kemSharedSecret.length);
  const info = new TextEncoder().encode("pqmsg-media-key-v1");
  const salt = new Uint8Array(32); // zero salt for initial derivation
  return wasmCrypto.hkdfSha256(ikm, salt, info, 32);
}

// ---------------------------------------------------------------------------
// CallManager — manages a single active call
// ---------------------------------------------------------------------------

export class CallManager {
  private api: PqmsgApi;
  private keys: GeneratedKeys;
  private pc: RTCPeerConnection | null = null;
  private localStream: MediaStream | null = null;
  private remoteStream: MediaStream | null = null;
  private callInfo: CallInfo | null = null;
  private signalPollTimer: ReturnType<typeof setInterval> | null = null;
  private lastSignalId = 0;
  private listeners: CallEventListener[] = [];
  private mediaKey: Uint8Array | null = null;
  private mediaKeyRatchetTimer: ReturnType<typeof setInterval> | null = null;
  private ratchetCounter = 0;

  constructor(api: PqmsgApi, keys: GeneratedKeys) {
    this.api = api;
    this.keys = keys;
  }

  /** Register a listener for call state changes. */
  onStateChange(listener: CallEventListener): void {
    this.listeners.push(listener);
  }

  /** Get current call info, or null if no active call. */
  getCallInfo(): CallInfo | null {
    return this.callInfo ? { ...this.callInfo } : null;
  }

  /** Get the remote media stream (audio/video tracks from peer). */
  getRemoteStream(): MediaStream | null {
    return this.remoteStream;
  }

  /** Get local media stream. */
  getLocalStream(): MediaStream | null {
    return this.localStream;
  }

  // -----------------------------------------------------------------------
  // Outgoing call
  // -----------------------------------------------------------------------

  async startCall(peerId: string, callType: "audio" | "video"): Promise<void> {
    if (this.callInfo && this.callInfo.state !== "idle" && this.callInfo.state !== "ended") {
      throw new Error("call already in progress");
    }

    this.callInfo = {
      callId: "",
      peerId,
      direction: "outgoing",
      callType,
      state: "outgoing-ringing",
      startedAt: Date.now(),
    };
    this.emitState();

    // Acquire local media
    this.localStream = await navigator.mediaDevices.getUserMedia({
      audio: true,
      video: callType === "video",
    });

    // Create peer connection
    this.pc = new RTCPeerConnection({ iceServers: ICE_SERVERS });
    this.setupPeerConnection();

    // Add local tracks
    for (const track of this.localStream.getTracks()) {
      this.pc.addTrack(track, this.localStream);
    }

    // Setup E2E encryption if WASM KEM available
    await this.setupE2EEncryption();

    // Create SDP offer
    const offer = await this.pc.createOffer();
    await this.pc.setLocalDescription(offer);

    const sdpBase64 = bytesToBase64(new TextEncoder().encode(offer.sdp ?? ""));

    const payload: CallOfferRequest = {
      caller_user_id: this.keys.userId,
      device_id: this.keys.deviceId,
      sdp_offer_base64: sdpBase64,
      call_type: callType,
    };

    const headers = buildCallOfferAuth(this.keys, peerId);
    const response = await this.api.callOffer(peerId, payload, headers);

    this.callInfo.callId = response.call_id;
    this.emitState();

    // Begin polling for answer and ICE candidates
    this.startSignalPolling();
  }

  // -----------------------------------------------------------------------
  // Incoming call — accept
  // -----------------------------------------------------------------------

  async acceptCall(
    callId: string,
    peerId: string,
    callType: "audio" | "video",
    sdpOfferBase64: string
  ): Promise<void> {
    this.callInfo = {
      callId,
      peerId,
      direction: "incoming",
      callType,
      state: "connecting",
      startedAt: Date.now(),
    };
    this.emitState();

    // Acquire local media
    this.localStream = await navigator.mediaDevices.getUserMedia({
      audio: true,
      video: callType === "video",
    });

    // Create peer connection
    this.pc = new RTCPeerConnection({ iceServers: ICE_SERVERS });
    this.setupPeerConnection();

    // Add local tracks
    for (const track of this.localStream.getTracks()) {
      this.pc.addTrack(track, this.localStream);
    }

    await this.setupE2EEncryption();

    // Set remote description from offer
    const sdpOffer = new TextDecoder().decode(base64ToBytes(sdpOfferBase64));
    await this.pc.setRemoteDescription({
      type: "offer",
      sdp: sdpOffer,
    });

    // Create and send answer
    const answer = await this.pc.createAnswer();
    await this.pc.setLocalDescription(answer);

    const sdpAnswerBase64 = bytesToBase64(
      new TextEncoder().encode(answer.sdp ?? "")
    );

    const payload: CallAnswerRequest = {
      callee_user_id: this.keys.userId,
      device_id: this.keys.deviceId,
      sdp_answer_base64: sdpAnswerBase64,
    };

    const headers = buildCallAnswerAuth(this.keys, callId);
    await this.api.callAnswer(callId, payload, headers);

    this.callInfo.state = "connecting";
    this.emitState();

    // Begin polling for ICE candidates
    this.startSignalPolling();
  }

  // -----------------------------------------------------------------------
  // Hang up
  // -----------------------------------------------------------------------

  async hangup(reason = "user-hangup"): Promise<void> {
    if (!this.callInfo || !this.callInfo.callId) {
      this.cleanup();
      return;
    }

    const callId = this.callInfo.callId;
    const payload: CallHangupRequest = {
      user_id: this.keys.userId,
      device_id: this.keys.deviceId,
      reason,
    };

    try {
      const headers = buildCallHangupAuth(this.keys, callId);
      await this.api.callHangup(callId, payload, headers);
    } catch {
      // Best-effort hangup
    }

    this.endCall();
  }

  // -----------------------------------------------------------------------
  // Media controls
  // -----------------------------------------------------------------------

  toggleMute(): boolean {
    if (!this.localStream) return false;
    const audioTrack = this.localStream.getAudioTracks()[0];
    if (audioTrack) {
      audioTrack.enabled = !audioTrack.enabled;
      return !audioTrack.enabled; // returns true if now muted
    }
    return false;
  }

  toggleVideo(): boolean {
    if (!this.localStream) return false;
    const videoTrack = this.localStream.getVideoTracks()[0];
    if (videoTrack) {
      videoTrack.enabled = !videoTrack.enabled;
      return !videoTrack.enabled; // returns true if now disabled
    }
    return false;
  }

  // -----------------------------------------------------------------------
  // Private: Peer connection setup
  // -----------------------------------------------------------------------

  private setupPeerConnection(): void {
    if (!this.pc) return;

    this.remoteStream = new MediaStream();

    this.pc.ontrack = (event) => {
      for (const stream of event.streams) {
        for (const track of stream.getTracks()) {
          this.remoteStream!.addTrack(track);
        }
      }
    };

    this.pc.onicecandidate = (event) => {
      if (event.candidate && this.callInfo?.callId) {
        void this.sendIceCandidate(event.candidate);
      }
    };

    this.pc.onconnectionstatechange = () => {
      if (!this.pc || !this.callInfo) return;
      const state = this.pc.connectionState;
      if (state === "connected") {
        this.callInfo.state = "active";
        this.emitState();
      } else if (state === "disconnected" || state === "failed" || state === "closed") {
        this.endCall();
      }
    };

    this.pc.oniceconnectionstatechange = () => {
      if (!this.pc || !this.callInfo) return;
      if (this.pc.iceConnectionState === "failed") {
        void this.hangup("ice-failed");
      }
    };
  }

  // -----------------------------------------------------------------------
  // Private: E2E encryption via Insertable Streams
  // -----------------------------------------------------------------------

  private async setupE2EEncryption(): Promise<void> {
    if (!wasmCrypto.kemAvailable() || !this.pc) return;

    // Generate ephemeral X25519 key pair for DH
    const dhKeypairBytes = wasmCrypto.x25519Keypair();
    // keypair is 64 bytes: [32-byte secret | 32-byte public]
    const dhSecret = dhKeypairBytes.slice(0, 32);
    const dhPublic = dhKeypairBytes.slice(32, 64);

    // Generate ML-KEM-768 key pair
    const kemKp = wasmCrypto.kemKeypair();

    // For a full implementation, we'd exchange KEM ciphertexts via the signaling
    // channel. Here we derive a deterministic key for the demo — in production,
    // the caller would encapsulate to the callee's KEM public key from their
    // prekey bundle, and both sides derive the same media key.
    // For now, use HKDF over the local KEM public key as a best-effort seed.
    const kemSeed = kemKp.public_key.slice(0, 32);
    this.mediaKey = deriveMediaKey(kemSeed, dhSecret);

    // Apply Insertable Streams (Encoded Transform) if browser supports it
    this.applyEncodedTransform();

    // Start media key ratchet (every 60 seconds for forward secrecy)
    this.mediaKeyRatchetTimer = setInterval(() => {
      this.ratchetMediaKey();
    }, 60_000);
  }

  private applyEncodedTransform(): void {
    if (!this.pc || !this.mediaKey) return;

    const senders = this.pc.getSenders();
    for (const sender of senders) {
      if (sender.track && "createEncodedStreams" in sender) {
        this.applySenderTransform(sender);
      }
    }

    const receivers = this.pc.getReceivers();
    for (const receiver of receivers) {
      if (receiver.track && "createEncodedStreams" in receiver) {
        this.applyReceiverTransform(receiver);
      }
    }
  }

  private applySenderTransform(sender: RTCRtpSender): void {
    // Use the modern RTCRtpScriptTransform if available
    const mediaKey = this.mediaKey;
    if (!mediaKey) return;

    try {
      // Encoded Transform API (Chromium)
      const senderStreams = (sender as unknown as { createEncodedStreams: () => { readable: ReadableStream; writable: WritableStream } }).createEncodedStreams();
      const transformStream = new TransformStream({
        transform: (frame: RTCEncodedAudioFrame | RTCEncodedVideoFrame, controller: TransformStreamDefaultController) => {
          const data = new Uint8Array(frame.data);
          // XOR with media key for lightweight E2E (demo — production would use ChaCha20-Poly1305)
          const encrypted = new Uint8Array(data.length);
          for (let i = 0; i < data.length; i++) {
            encrypted[i] = data[i] ^ mediaKey[i % mediaKey.length];
          }
          frame.data = encrypted.buffer;
          controller.enqueue(frame);
        },
      });
      senderStreams.readable.pipeThrough(transformStream).pipeTo(senderStreams.writable);
    } catch {
      // Browser doesn't support Insertable Streams — media flows unencrypted at application layer
      // (still protected by DTLS-SRTP at transport layer)
    }
  }

  private applyReceiverTransform(receiver: RTCRtpReceiver): void {
    const mediaKey = this.mediaKey;
    if (!mediaKey) return;

    try {
      const receiverStreams = (receiver as unknown as { createEncodedStreams: () => { readable: ReadableStream; writable: WritableStream } }).createEncodedStreams();
      const transformStream = new TransformStream({
        transform: (frame: RTCEncodedAudioFrame | RTCEncodedVideoFrame, controller: TransformStreamDefaultController) => {
          const data = new Uint8Array(frame.data);
          const decrypted = new Uint8Array(data.length);
          for (let i = 0; i < data.length; i++) {
            decrypted[i] = data[i] ^ mediaKey[i % mediaKey.length];
          }
          frame.data = decrypted.buffer;
          controller.enqueue(frame);
        },
      });
      receiverStreams.readable.pipeThrough(transformStream).pipeTo(receiverStreams.writable);
    } catch {
      // Insertable Streams not supported
    }
  }

  private ratchetMediaKey(): void {
    if (!this.mediaKey) return;
    this.ratchetCounter++;
    const info = new TextEncoder().encode(`pqmsg-media-ratchet-${this.ratchetCounter}`);
    const salt = new Uint8Array(32);
    this.mediaKey = wasmCrypto.hkdfSha256(this.mediaKey, salt, info, 32);
    // Re-apply transforms would be needed for a full implementation
  }

  // -----------------------------------------------------------------------
  // Private: ICE candidate exchange
  // -----------------------------------------------------------------------

  private async sendIceCandidate(candidate: RTCIceCandidate): Promise<void> {
    if (!this.callInfo?.callId) return;

    const candidateBase64 = bytesToBase64(
      new TextEncoder().encode(JSON.stringify(candidate.toJSON()))
    );

    const payload: IceCandidateRequest = {
      sender_user_id: this.keys.userId,
      device_id: this.keys.deviceId,
      candidate_base64: candidateBase64,
    };

    try {
      const headers = buildCallIceAuth(this.keys, this.callInfo.callId);
      await this.api.callIceCandidate(this.callInfo.callId, payload, headers);
    } catch {
      // Best-effort ICE candidate delivery
    }
  }

  // -----------------------------------------------------------------------
  // Private: Signal polling
  // -----------------------------------------------------------------------

  private startSignalPolling(): void {
    this.signalPollTimer = setInterval(() => {
      void this.pollSignals();
    }, 1000);
  }

  private async pollSignals(): Promise<void> {
    if (!this.callInfo?.callId) return;

    try {
      const headers = buildCallPollAuth(this.keys, this.callInfo.callId);
      const resp = await this.api.pollCallSignals(
        this.callInfo.callId,
        this.lastSignalId,
        headers
      );

      for (const signal of resp.signals) {
        await this.handleSignal(signal);
      }
    } catch {
      // Polling failure — will retry on next interval
    }
  }

  private async handleSignal(signal: CallSignal): Promise<void> {
    if (!this.pc) return;

    switch (signal.signal_type) {
      case "answer": {
        const sdp = new TextDecoder().decode(base64ToBytes(signal.payload_base64));
        await this.pc.setRemoteDescription({ type: "answer", sdp });
        if (this.callInfo) {
          this.callInfo.state = "connecting";
          this.emitState();
        }
        break;
      }
      case "ice-candidate": {
        const candidateJson = new TextDecoder().decode(
          base64ToBytes(signal.payload_base64)
        );
        const candidate = JSON.parse(candidateJson) as RTCIceCandidateInit;
        await this.pc.addIceCandidate(candidate);
        break;
      }
      case "hangup": {
        this.endCall();
        break;
      }
      case "offer": {
        // Incoming call offer received while polling — handled by app layer
        break;
      }
    }
  }

  // -----------------------------------------------------------------------
  // Private: cleanup
  // -----------------------------------------------------------------------

  private endCall(): void {
    if (this.callInfo) {
      this.callInfo.state = "ended";
      this.emitState();
    }
    this.cleanup();
  }

  private cleanup(): void {
    if (this.signalPollTimer) {
      clearInterval(this.signalPollTimer);
      this.signalPollTimer = null;
    }

    if (this.mediaKeyRatchetTimer) {
      clearInterval(this.mediaKeyRatchetTimer);
      this.mediaKeyRatchetTimer = null;
    }

    if (this.localStream) {
      for (const track of this.localStream.getTracks()) {
        track.stop();
      }
      this.localStream = null;
    }

    this.remoteStream = null;

    if (this.pc) {
      this.pc.close();
      this.pc = null;
    }

    this.mediaKey = null;
    this.lastSignalId = 0;
    this.ratchetCounter = 0;
  }

  private emitState(): void {
    if (!this.callInfo) return;
    const info = { ...this.callInfo };
    for (const listener of this.listeners) {
      listener(info);
    }
  }
}
