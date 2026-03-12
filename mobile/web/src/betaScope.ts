import type { ServerCapabilitiesResponse } from "./server";

export const WEB_BETA_SCOPE_SUMMARY =
  "Web direct messages use the local post-quantum runtime when available. Web group messaging and calling are unavailable in the supported beta path.";

export type WebBetaHoldback = {
  messagingAllowed: boolean;
  title: string;
  detail: string;
  tone: "info" | "warning";
};

export function getWebBetaHoldback(
  caps: ServerCapabilitiesResponse | null
): WebBetaHoldback {
  const policySuffix = caps
    ? `Server policy is ${caps.web_client_policy}.`
    : "Server capabilities could not be verified.";

  if (!caps) {
    return {
      messagingAllowed: false,
      title: "Web group messaging unavailable",
      detail:
        `${policySuffix} Direct web messaging still requires the local PQ runtime. Group messaging and calling are not part of the supported web beta.`,
      tone: "warning",
    };
  }

  return {
    messagingAllowed: false,
    title: "Web group messaging unavailable",
    detail:
      `${policySuffix} Direct web messaging still uses the local PQ runtime. Group messaging is disabled pending a private group design, and calling stays out of scope for the supported web beta.`,
    tone: "warning",
  };
}
