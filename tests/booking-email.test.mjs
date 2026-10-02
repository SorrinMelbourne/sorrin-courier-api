import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { test } from "node:test";

const source = await readFile(new URL("../worker.js", import.meta.url), "utf8");
const exported = `${source}\nexport { sendEmail, sendOwnerBookingEmail, notifySorrinbotBookingSubmission };`;
const { sendEmail, sendOwnerBookingEmail, notifySorrinbotBookingSubmission } = await import(
  `data:text/javascript;base64,${Buffer.from(exported).toString("base64")}`
);

function environment() {
  const events = [];
  return {
    events,
    env: {
      RESEND_API_KEY: "re_test_key",
      DB: {
        prepare(query) {
          assert.match(query, /INSERT INTO job_events/);
          return {
            bind(...values) {
              return { async run() { events.push({ jobId: values[1], ...JSON.parse(values[2]) }); } };
            },
          };
        },
      },
    },
  };
}

test("missing Resend key fails before a booking email can be reported as sent", async () => {
  const original = globalThis.fetch;
  globalThis.fetch = () => { throw new Error("Must not call the network"); };
  try {
    await assert.rejects(sendEmail({}, { to: "courier@sorrin.com.au" }), /RESEND_API_KEY missing/);
  } finally { globalThis.fetch = original; }
});

test("owner alert uses a separate sender, records provider acceptance and retries safely", async () => {
  const { env, events } = environment();
  const original = globalThis.fetch;
  const requests = [];
  globalThis.fetch = async (_url, options) => {
    requests.push(options);
    return requests.length === 1
      ? Response.json({ message: "Temporary failure" }, { status: 503 })
      : Response.json({ id: "mail-owner-123" });
  };
  try {
    const result = await sendOwnerBookingEmail(env, {
      id: "booking-1", reference: "SORRIN-1", bookingType: "guest",
      requesterDetails: "Name: Test", details: "Quote", idempotencyKey: "booking-owner-booking-1",
    });
    assert.deepEqual(result, { accepted: true, providerId: "mail-owner-123" });
    assert.equal(requests.length, 2);
    assert.equal(requests[0].headers["Idempotency-Key"], requests[1].headers["Idempotency-Key"]);
    assert.equal(JSON.parse(requests[0].body).from, "Sorrin Booking Alerts <notifications@sorrin.com.au>");
    assert.deepEqual(JSON.parse(requests[0].body).to, ["courier@sorrin.com.au"]);
    assert.deepEqual(events, [{ jobId: "job:booking-1", channel: "owner", status: "accepted", providerId: "mail-owner-123", error: null }]);
  } finally { globalThis.fetch = original; }
});

test("owner rejection is recorded and does not prevent customer confirmation", async () => {
  const { env, events } = environment();
  const original = globalThis.fetch;
  const originalError = console.error;
  const recipients = [];
  globalThis.fetch = async (_url, options) => {
    const recipient = JSON.parse(options.body).to[0];
    recipients.push(recipient);
    return recipient === "courier@sorrin.com.au"
      ? Response.json({ message: "Domain not verified" }, { status: 403 })
      : Response.json({ id: "mail-customer-123" });
  };
  console.error = () => {};
  try {
    const warning = await notifySorrinbotBookingSubmission(
      env,
      { usc: "TEST-001", business_name: "Test Business" },
      "SORRIN-2",
      { requester: { requesterName: "Test", requesterEmail: "test@example.com", requesterPhone: "0400000000" }, quote: {} },
      "booking-2",
    );
    assert.match(warning, /Owner email:.*403/);
    assert.deepEqual(recipients, ["courier@sorrin.com.au", "test@example.com"]);
    assert.deepEqual(events.map(({ channel, status }) => [channel, status]), [["owner", "failed"], ["customer", "accepted"]]);
  } finally { globalThis.fetch = original; console.error = originalError; }
});
