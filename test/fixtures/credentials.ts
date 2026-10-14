// Synthetic, non-functional values for detector and live end-to-end checks.
export const credentialFixtures = [
  { name: "SendGrid", value: "SG." + "a".repeat(22) + "." + "b".repeat(43) },
  { name: "Twilio", value: "SK" + "a1".repeat(16) },
  { name: "PyPI", value: "pypi-" + "a".repeat(80) + "_-" },
  { name: "GitLab runner", value: "glrt-" + "b".repeat(24) + "_-" },
  { name: "Google OAuth", value: "ya29." + "c".repeat(45) + "_-" },
  { name: "Slack webhook", value: "https://hooks.slack.com/services/T" + "A".repeat(8) + "/B" + "B".repeat(8) + "/" + "c".repeat(24) },
  { name: "Discord webhook", value: "https://discord.com/api/webhooks/123456789/" + "d".repeat(68) + "_-" },
  { name: "Redis password-only URI", value: "redis://:synthetic-redis-canary@localhost:6379/0" },
  { name: "Plain token assignment", value: "token=synthetic-assignment-canary" },
] as const;
