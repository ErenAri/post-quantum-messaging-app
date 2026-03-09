import type { ServerCapabilitiesResponse } from "./server";

export const WEB_BETA_SCOPE_SUMMARY =
  "Android messaging is the supported beta path. Web stays outside this beta, and calling is unavailable.";

export type WebBetaHoldback = {
  messagingAllowed: boolean;
  title: string;
  detail: string;
  tone: "info" | "warning";
};

export function getWebBetaHoldback(
  caps: ServerCapabilitiesResponse | null
): WebBetaHoldback {
  if (!caps) {
    return {
      messagingAllowed: false,
      title: "Web demo-only holdback",
      detail:
        "Server capabilities could not be verified, so outbound web messaging stays disabled. Use Android, iOS, or CLI for interoperable chat. Calling is not part of this beta.",
      tone: "warning",
    };
  }

  if (caps.web_client_policy === "demo_only") {
    return {
      messagingAllowed: false,
      title: "Web demo-only holdback",
      detail:
        "Outbound web messaging is disabled because the server policy is demo_only. Use Android, iOS, or CLI for interoperable chat. Calling is not part of this beta.",
      tone: "warning",
    };
  }

  return {
    messagingAllowed: true,
    title: "Web remains outside the supported beta scope",
    detail:
      "This server does not block web messaging by policy, but Android is still the supported beta client and calling remains unavailable.",
    tone: "info",
  };
}
