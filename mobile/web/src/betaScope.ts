import type { ServerCapabilitiesResponse } from "./server";

export const WEB_BETA_SCOPE_SUMMARY =
  "Web remains a demo surface until the server promotes the hardened web policy. Private groups require their own capability, and calling stays unavailable on web.";

export type WebBetaHoldback = {
  directMessagingAllowed: boolean;
  groupMessagingAllowed: boolean;
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
      directMessagingAllowed: false,
      groupMessagingAllowed: false,
      title: "Web messaging unavailable",
      detail:
        `${policySuffix} Direct web messaging still requires the local PQ runtime. Private groups and calling are not part of the supported web beta until the server advertises the hardened web policy.`,
      tone: "warning",
    };
  }

  if (caps.web_client_policy === "demo_only") {
    return {
      directMessagingAllowed: false,
      groupMessagingAllowed: false,
      title: "Web messaging unavailable",
      detail:
        `${policySuffix} Direct web messaging and private groups stay disabled while the server remains in demo-only web mode. Calling stays out of scope for the supported web beta.`,
      tone: "warning",
    };
  }

  if (!caps.private_group_messaging_supported) {
    return {
      directMessagingAllowed: true,
      groupMessagingAllowed: false,
      title: "Web private groups unavailable",
      detail:
        `${policySuffix} Direct web messaging can use the hardened PQ path, but private groups stay unavailable until the server advertises the private-group messaging capability. Calling stays out of scope for the supported web beta.`,
      tone: "warning",
    };
  }

  return {
    directMessagingAllowed: true,
    groupMessagingAllowed: true,
    title: "Hardened web messaging enabled",
    detail:
      `${policySuffix} Direct web messaging and private groups are enabled on the hardened web path when the local PQ runtime is available. Calling stays out of scope for the supported web beta.`,
    tone: "info",
  };
}
