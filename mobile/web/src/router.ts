/**
 * Application state and view router.
 */

export type AppView =
  | { screen: "onboarding" }
  | { screen: "create-account" }
  | { screen: "sign-in" }
  | { screen: "import-device" }
  | { screen: "conversations" }
  | { screen: "chat"; peerId: string }
  | { screen: "settings" }
  | { screen: "new-chat" }
  | { screen: "group-chat"; groupId: string }
  | { screen: "group-info"; groupId: string }
  | { screen: "create-group" }
  | { screen: "identity-log" }
  | { screen: "discovery" }
  | { screen: "server-info" }
  | { screen: "search" }
  | { screen: "devices" }
  | { screen: "link-device" }
  | { screen: "call"; peerId: string; callType: "audio" | "video" }
  | { screen: "incoming-call"; callId: string; peerId: string; callType: "audio" | "video"; sdpOfferBase64: string };

export type AppNotification = {
  id: number;
  text: string;
  type: "info" | "error" | "success";
  actionLabel?: string;
  action?: () => void;
};

let currentView: AppView = { screen: "onboarding" };
let viewChangeListeners: Array<(view: AppView) => void> = [];
let notificationListeners: Array<(n: AppNotification) => void> = [];
let nextNotificationId = 1;

export function getCurrentView(): AppView {
  return currentView;
}

export function navigateTo(view: AppView): void {
  currentView = view;
  for (const listener of viewChangeListeners) {
    listener(view);
  }
}

export function onViewChange(listener: (view: AppView) => void): void {
  viewChangeListeners.push(listener);
}

export function notify(
  text: string,
  type: AppNotification["type"] = "info",
  options?: Pick<AppNotification, "actionLabel" | "action">
): void {
  const notification: AppNotification = { id: nextNotificationId++, text, type, ...options };
  for (const listener of notificationListeners) {
    listener(notification);
  }
}

export function onNotification(listener: (n: AppNotification) => void): void {
  notificationListeners.push(listener);
}
