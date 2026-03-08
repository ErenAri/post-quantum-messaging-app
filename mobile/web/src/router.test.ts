import { describe, it, expect, beforeEach } from "vitest";

// Router uses module-level state, so we need fresh imports.
// We'll test the exported functions directly.

let routerModule: typeof import("./router");

beforeEach(async () => {
  // Re-import to reset module state
  routerModule = await import("./router");
});

describe("getCurrentView", () => {
  it("defaults to onboarding", () => {
    // On first load the default view is "onboarding"
    const view = routerModule.getCurrentView();
    expect(view.screen).toBe("onboarding");
  });
});

describe("navigateTo", () => {
  it("updates current view", () => {
    routerModule.navigateTo({ screen: "conversations" });
    expect(routerModule.getCurrentView()).toEqual({ screen: "conversations" });
  });

  it("updates to chat with peerId", () => {
    routerModule.navigateTo({ screen: "chat", peerId: "alice" });
    expect(routerModule.getCurrentView()).toEqual({ screen: "chat", peerId: "alice" });
  });

  it("updates to group-chat with groupId", () => {
    routerModule.navigateTo({ screen: "group-chat", groupId: "g1" });
    expect(routerModule.getCurrentView()).toEqual({ screen: "group-chat", groupId: "g1" });
  });
});

describe("onViewChange", () => {
  it("listener receives navigation events", () => {
    const events: Array<import("./router").AppView> = [];
    routerModule.onViewChange((view) => events.push(view));
    routerModule.navigateTo({ screen: "settings" });
    routerModule.navigateTo({ screen: "search" });
    expect(events).toHaveLength(2);
    expect(events[0]).toEqual({ screen: "settings" });
    expect(events[1]).toEqual({ screen: "search" });
  });

  it("multiple listeners all fire", () => {
    let count = 0;
    routerModule.onViewChange(() => count++);
    routerModule.onViewChange(() => count++);
    routerModule.navigateTo({ screen: "discovery" });
    expect(count).toBe(2);
  });
});

describe("notify / onNotification", () => {
  it("fires notification listeners with incrementing IDs", () => {
    const notifications: Array<import("./router").AppNotification> = [];
    routerModule.onNotification((n) => notifications.push(n));
    routerModule.notify("test message", "info");
    routerModule.notify("error!", "error");
    expect(notifications).toHaveLength(2);
    expect(notifications[0].text).toBe("test message");
    expect(notifications[0].type).toBe("info");
    expect(notifications[1].text).toBe("error!");
    expect(notifications[1].type).toBe("error");
    // IDs should be sequential
    expect(notifications[1].id).toBeGreaterThan(notifications[0].id);
  });

  it("defaults type to info", () => {
    const notifications: Array<import("./router").AppNotification> = [];
    routerModule.onNotification((n) => notifications.push(n));
    routerModule.notify("hello");
    expect(notifications[0].type).toBe("info");
  });

  it("supports success type", () => {
    const notifications: Array<import("./router").AppNotification> = [];
    routerModule.onNotification((n) => notifications.push(n));
    routerModule.notify("done", "success");
    expect(notifications[0].type).toBe("success");
  });
});
