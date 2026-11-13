/**
 * Cloudflare Email Routing Worker for ft97.com
 *
 * Forwards all incoming emails for *@ft97.com over HTTPS to your Throwaway backend
 * endpoint `POST /api/v1/inbound/email` when inbound TCP port 25 is not reachable.
 *
 * Required Cloudflare Worker Secret:
 *   - INBOUND_WEBHOOK_SECRET (must match your backend .env INBOUND_WEBHOOK_SECRET)
 * Optional Cloudflare Worker Variable:
 *   - BACKEND_INBOUND_URL (defaults to https://ft97.com/api/v1/inbound/email)
 */
export default {
  async email(message, env) {
    const endpoint = env.BACKEND_INBOUND_URL || 'https://ft97.com/api/v1/inbound/email';
    const raw = await new Response(message.raw).text();

    const response = await fetch(endpoint, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Webhook-Secret': env.INBOUND_WEBHOOK_SECRET || '',
      },
      body: JSON.stringify({
        to: message.to,
        from: message.from,
        raw,
      }),
    });

    if (response.status === 404) {
      message.setReject('550 5.1.1 Mailbox not found');
    } else if (!response.ok) {
      message.setReject('451 4.3.0 Temporary local delivery error');
    }
  },
};
