import axios from "axios";

const ALLOWED_HOSTS = ["hooks.slack.com"];

export async function sendSlackWebhook(webhookUrl, payload) {
  try {
    const url = new URL(webhookUrl);
    if (!ALLOWED_HOSTS.includes(url.hostname)) {
      throw new Error("Webhook host not allowed");
    }
    const res = await axios.post(webhookUrl, payload, {
      timeout: 5000,
      headers: { "Content-Type": "application/json" },
      validateStatus: (s) => s >= 200 && s < 300,
    });
    return { success: true, status: res.status };
  } catch (e) {
    return { success: false, error: e.message };
  }
}
