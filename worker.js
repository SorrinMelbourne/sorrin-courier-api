const ALLOWED_ORIGINS = new Set([
  "https://sorrin.com.au",
  "https://www.sorrin.com.au",
]);

function corsHeaders(request) {
  const origin = request.headers.get("Origin");

  return {
    "Access-Control-Allow-Origin": ALLOWED_ORIGINS.has(origin)
      ? origin
      : "https://sorrin.com.au",
    "Access-Control-Allow-Methods": "GET, POST, PATCH, DELETE, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization",
    Vary: "Origin",
  };
}

const OPS_COOKIE_NAME = "sorrin_ops_session";
const OPS_SESSION_SECONDS = 60 * 60 * 12;
const OPS_BUILD = "FINAL-V21-SUMMARY-FINANCE-NAV+A022-SORRINBOT-FINANCE+A027-BUSINESS-PROFILE+A035-MEMBERSHIP-LIST+A037-CONSULTATION-REQUEST+A039-SESSION-RESUME+PATCH30-USC-ONLY-BOOKING+V22-MANDATORY-DELIVERY-PHOTO+PATCH31-FIRST-TWO-JOBS-FREE";
const SORRINBOT_USC_SESSION_VERSION = "1.0.0";
const SORRINBOT_USC_REGISTRATION_VERSION = "A017-1.0.0";
const SORRINBOT_REPEAT_JOB_VERSION = "A018-1.0.0";
const SORRINBOT_FINANCE_ASSISTANT_VERSION = "A022-1.0.0";
const SORRINBOT_ROLLING_BUSINESS_PROFILE_VERSION = "A027-1.0.0";
const SORRINBOT_MEMBERSHIP_MAILING_LIST_VERSION = "A035-1.0.0";
const SORRINBOT_CONSULTATION_REQUEST_VERSION = "A037-1.0.0";
const SORRINBOT_SESSION_RESUME_VERSION = "A039-1.0.0";
const SORRINBOT_SESSION_RESUME_SECONDS_DEFAULT = 8 * 60 * 60;
const SORRINBOT_ROLLING_BUSINESS_PROFILE_SECONDS_DEFAULT = 8 * 60 * 60;
const SORRINBOT_USC_SESSION_IDLE_SECONDS_DEFAULT = 30 * 60;
const SORRINBOT_USC_SESSION_MAX_SECONDS_DEFAULT = 8 * 60 * 60;
const STRIPE_API_BASE = "https://api.stripe.com/v1";
const STRIPE_SIGNATURE_TOLERANCE_SECONDS = 300;
const MAX_DELIVERY_PHOTO_BYTES = 10 * 1024 * 1024;
const DELIVERY_PHOTO_TYPES = new Map([
  ["image/jpeg", "jpg"],
  ["image/png", "png"],
  ["image/webp", "webp"],
]);
const OPERATIONS_STATUSES = new Set([
  "pending",
  "approved",
  "active",
  "delivered",
  "declined",
  "cancelled",
]);
const FINANCE_COLLECTION_TYPES = new Set(["prepayment", "invoice"]);
const FINANCE_PAYMENT_STATUSES = new Set([
  "not_started",
  "awaiting_payment",
  "partially_paid",
  "paid",
  "waived",
  "refunded",
]);
const FINANCE_INVOICE_STATUSES = new Set([
  "not_required",
  "draft",
  "issued",
  "paid",
  "void",
]);
const OPERATIONS_NOTIFICATION_TYPES = new Set([
  "approved",
  "pickup_en_route",
  "delivered",
  "invoice_issued",
  "payment_reminder",
]);

function textResponse(body, status = 200, headers = {}) {
  return new Response(body, {
    status,
    headers: {
      "Content-Type": "text/html; charset=utf-8",
      "Cache-Control": "no-store",
      "X-Content-Type-Options": "nosniff",
      "Referrer-Policy": "no-referrer",
      "Content-Security-Policy": [
        "default-src 'self'",
        "style-src 'unsafe-inline'",
        "script-src 'unsafe-inline'",
        "img-src 'self' data:",
        "connect-src 'self'",
        "base-uri 'none'",
        "form-action 'self'",
        "frame-ancestors 'none'",
      ].join("; "),
      "X-Sorrin-Operations-Build": OPS_BUILD,
      ...headers,
    },
  });
}

function getCookie(request, name) {
  const cookieHeader = request.headers.get("Cookie") || "";
  for (const part of cookieHeader.split(";")) {
    const [key, ...valueParts] = part.trim().split("=");
    if (key === name) return valueParts.join("=");
  }
  return null;
}

function base64UrlEncodeBytes(bytes) {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
}

function base64UrlEncodeText(value) {
  return base64UrlEncodeBytes(new TextEncoder().encode(value));
}

function base64UrlDecodeText(value) {
  const padded =
    value.replace(/-/g, "+").replace(/_/g, "/") +
    "=".repeat((4 - (value.length % 4)) % 4);
  const binary = atob(padded);
  return new TextDecoder().decode(
    Uint8Array.from(binary, (character) => character.charCodeAt(0)),
  );
}

async function hmacSignature(secret, value) {
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const signature = await crypto.subtle.sign(
    "HMAC",
    key,
    new TextEncoder().encode(value),
  );
  return base64UrlEncodeBytes(new Uint8Array(signature));
}

function constantTimeEqual(left, right) {
  const a = new TextEncoder().encode(String(left || ""));
  const b = new TextEncoder().encode(String(right || ""));
  const length = Math.max(a.length, b.length);
  let mismatch = a.length ^ b.length;
  for (let index = 0; index < length; index += 1) {
    mismatch |= (a[index] || 0) ^ (b[index] || 0);
  }
  return mismatch === 0;
}

async function createOperationsSession(env, email) {
  const expiresAt = Math.floor(Date.now() / 1000) + OPS_SESSION_SECONDS;
  const payload = base64UrlEncodeText(JSON.stringify({ email, expiresAt }));
  const signature = await hmacSignature(env.OPS_SESSION_SECRET, payload);
  return `${payload}.${signature}`;
}

async function operationsSession(request, env) {
  if (!env.OPS_SESSION_SECRET) return null;
  const token = getCookie(request, OPS_COOKIE_NAME);
  if (!token) return null;
  const [payload, signature, ...extra] = token.split(".");
  if (!payload || !signature || extra.length) return null;
  const expected = await hmacSignature(env.OPS_SESSION_SECRET, payload);
  if (!constantTimeEqual(signature, expected)) return null;

  try {
    const session = JSON.parse(base64UrlDecodeText(payload));
    if (
      !session.email ||
      Number(session.expiresAt) <= Math.floor(Date.now() / 1000)
    ) {
      return null;
    }
    return session;
  } catch {
    return null;
  }
}

function operationsCookie(token) {
  return `${OPS_COOKIE_NAME}=${token}; Max-Age=${OPS_SESSION_SECONDS}; Path=/operations; HttpOnly; Secure; SameSite=Strict`;
}

function expiredOperationsCookie() {
  return `${OPS_COOKIE_NAME}=; Max-Age=0; Path=/operations; HttpOnly; Secure; SameSite=Strict`;
}

function parseJson(value, fallback = {}) {
  if (value && typeof value === "object") return value;
  try {
    return JSON.parse(value || "");
  } catch {
    return fallback;
  }
}

function dateKeyInSydney(value = new Date()) {
  const parts = new Intl.DateTimeFormat("en-AU", {
    timeZone: "Australia/Sydney",
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
  })
    .formatToParts(value)
    .reduce(
      (result, part) => ({ ...result, [part.type]: part.value }),
      /** @type {Record<string, string>} */ ({}),
    );
  return `${parts.year}-${parts.month}-${parts.day}`;
}

function addDaysToDateKey(value, days) {
  const match = String(value || "").match(/^(\d{4})-(\d{2})-(\d{2})$/);
  if (!match) return null;
  const date = new Date(
    Date.UTC(Number(match[1]), Number(match[2]) - 1, Number(match[3])),
  );
  date.setUTCDate(date.getUTCDate() + Math.max(0, Number(days || 0)));
  return date.toISOString().slice(0, 10);
}

function financeEffectiveStatus(finance, today = dateKeyInSydney()) {
  const stored = String(finance?.payment_status || "not_started");
  if (["waived", "refunded"].includes(stored)) return stored;
  const due = Math.max(0, Number(finance?.amount_due_cents || 0));
  const paid = Math.max(0, Number(finance?.amount_paid_cents || 0));
  if ((due === 0 && stored === "paid") || (due > 0 && paid >= due)) return "paid";
  if (paid > 0) return "partially_paid";
  if (
    finance?.collection_type === "invoice" &&
    finance?.invoice_status === "issued" &&
    finance?.due_date &&
    finance.due_date < today
  ) {
    return "overdue";
  }
  return stored;
}

function financeSummary(row) {
  if (!row || !row.finance_id) return null;
  const finance = {
    id: row.finance_id,
    bookingId: row.booking_id,
    businessId: row.finance_business_id || row.business_id || null,
    collectionType: row.collection_type || "prepayment",
    paymentStatus: row.finance_payment_status || "not_started",
    paymentMethod: row.finance_payment_method || null,
    amountDueCents: Math.max(0, Number(row.amount_due_cents || 0)),
    amountPaidCents: Math.max(0, Number(row.amount_paid_cents || 0)),
    invoiceStatus: row.invoice_status || "not_required",
    invoiceNumber: row.invoice_number || null,
    invoiceIssuedAt: row.invoice_issued_at || null,
    dueDate: row.due_date || null,
    paidAt: row.paid_at || null,
    notes: row.finance_notes || null,
    stripeCheckoutSessionId: row.stripe_checkout_session_id || null,
    stripeCheckoutUrl: row.stripe_checkout_url || null,
    stripeCheckoutAmountCents: Math.max(
      0,
      Number(row.stripe_checkout_amount_cents || 0),
    ),
    stripePaymentIntentId: row.stripe_payment_intent_id || null,
    stripeCustomerId: row.stripe_customer_id || null,
    stripePaymentStatus: row.stripe_payment_status || null,
    stripeCheckoutExpiresAt: row.stripe_checkout_expires_at || null,
    createdAt: row.finance_created_at || null,
    updatedAt: row.finance_updated_at || null,
  };
  finance.effectiveStatus = financeEffectiveStatus({
    payment_status: finance.paymentStatus,
    collection_type: finance.collectionType,
    invoice_status: finance.invoiceStatus,
    amount_due_cents: finance.amountDueCents,
    amount_paid_cents: finance.amountPaidCents,
    due_date: finance.dueDate,
  });
  finance.outstandingCents = Math.max(
    0,
    finance.amountDueCents - finance.amountPaidCents,
  );
  return finance;
}

function paymentDispatchGate(job) {
  const finance = job?.finance || null;
  if (!finance) {
    return {
      required: true,
      blocked: true,
      code: "finance_missing",
      label: "FINANCE RECORD REQUIRED BEFORE STARTING",
      outstandingCents: 0,
      collectionType: null,
    };
  }
  const collectionType = finance.collectionType || "prepayment";
  const amountDueCents = Math.max(0, Number(finance.amountDueCents || 0));
  const amountPaidCents = Math.max(0, Number(finance.amountPaidCents || 0));
  const outstandingCents = Math.max(0, amountDueCents - amountPaidCents);
  const waived =
    finance.paymentStatus === "waived" || finance.effectiveStatus === "waived";
  const required = collectionType === "prepayment" && amountDueCents > 0 && !waived;
  const blocked = required && outstandingCents > 0;
  return {
    required,
    blocked,
    code: blocked ? "prepayment_required" : "dispatch_clear",
    label: blocked
      ? "PAYMENT REQUIRED BEFORE STARTING"
      : collectionType === "invoice"
        ? "INVOICE ACCOUNT — DISPATCH CLEAR"
        : "PAYMENT CLEAR",
    outstandingCents,
    collectionType,
  };
}

function executionNextAction(job) {
  const stops = Array.isArray(job?.stops) ? job.stops : [];
  const stop = stops.find(
    (item) =>
      !["completed", "skipped", "cancelled"].includes(
        String(item.stop_status || "pending"),
      ),
  );
  if (!stop) {
    return {
      code: "complete",
      label: "JOB COMPLETE",
      enabled: false,
      stopId: null,
    };
  }
  if (!String(job?.status || "").match(/^(approved|active)$/)) {
    return {
      code: "approve_first",
      label: "APPROVE BEFORE STARTING",
      enabled: false,
      stopId: stop.id,
    };
  }
  const paymentGate = paymentDispatchGate(job);
  if (job.status === "approved" && paymentGate.blocked) {
    return {
      code: "payment_required",
      label: paymentGate.label,
      enabled: false,
      stopId: stop.id,
      paymentGate,
    };
  }
  const stopStatus = String(stop.stop_status || "pending");
  if (stopStatus === "en_route") {
    return {
      code: "arrive",
      label: "MARK ARRIVED",
      enabled: true,
      stopId: stop.id,
    };
  }
  if (stopStatus === "arrived") {
    const remaining = stops.filter(
      (item) =>
        item.id !== stop.id &&
        !["completed", "skipped", "cancelled"].includes(
          String(item.stop_status || "pending"),
        ),
    );
    if (!remaining.length && !job?.deliveryPhoto) {
      return {
        code: "delivery_photo_required",
        label: "DELIVERY PHOTO REQUIRED",
        enabled: false,
        stopId: stop.id,
        requiresDeliveryPhoto: true,
      };
    }
    return {
      code: remaining.length ? "complete_stop" : "complete_job",
      label: remaining.length ? "COMPLETE & NEXT" : "MARK AS DELIVERED",
      enabled: true,
      stopId: stop.id,
    };
  }
  return {
    code: job.status === "approved" ? "start_job" : "start_leg",
    label: job.status === "approved" ? "START JOB" : "START NEXT LEG",
    enabled: true,
    stopId: stop.id,
  };
}

function servicePriority(value) {
  const service = String(value || "").toLowerCase();
  if (service.includes("priority") || service.includes("asap"))
    return "priority";
  if (service.includes("express")) return "express";
  return "flexible";
}

function safeDateTime(day, time) {
  const date = cleanText(day, 30);
  const clock = cleanText(time, 30);
  return [date, clock].filter(Boolean).join(" ") || null;
}

function canonicalJobStatus(row) {
  const requestStatus = String(row.status || row.request_status || "pending");
  const bookingStatus = String(row.booking_status || "");
  const jobStatus = String(row.job_status || "");

  if (requestStatus === "declined" || bookingStatus === "rejected")
    return "declined";
  if (
    requestStatus === "cancelled" ||
    bookingStatus === "cancelled" ||
    jobStatus === "cancelled"
  )
    return "cancelled";
  if (
    requestStatus === "completed" ||
    bookingStatus === "delivered" ||
    jobStatus === "completed"
  )
    return "delivered";
  if (jobStatus === "active" || bookingStatus === "collected") return "active";
  if (
    ["approved", "confirmed"].includes(bookingStatus) ||
    requestStatus === "approved"
  )
    return "approved";
  return "pending";
}

function statusDatabaseValues(status) {
  const values = {
    pending: { request: "pending", booking: "submitted", job: "unscheduled" },
    approved: { request: "approved", booking: "approved", job: "scheduled" },
    active: { request: "approved", booking: "collected", job: "active" },
    delivered: { request: "completed", booking: "delivered", job: "completed" },
    declined: { request: "declined", booking: "rejected", job: "cancelled" },
    cancelled: { request: "cancelled", booking: "cancelled", job: "cancelled" },
  };
  return values[status];
}

function jobRecordsFromRequest(requestRow) {
  const payload = parseJson(requestRow.payload_json, {});
  const requester = payload.requester || {};
  const quote = payload.quote || {};
  const bookingId = `booking:${requestRow.id}`;
  const jobId = `job:${requestRow.id}`;
  const dropoffs = Array.isArray(quote.dropoffs) ? quote.dropoffs : [];
  const pickup = quote.pickup || {};
  const stops = [
    {
      id: `${jobId}:stop:1`,
      type: "pickup",
      sequence: 1,
      address: requestRow.pickup_address,
      contactName: cleanText(pickup.contact, 200) || requestRow.requester_name,
      contactPhone: cleanText(pickup.contactPhone, 60) || requestRow.requester_phone,
      earliest: safeDateTime(pickup.jobDate, pickup.earliestPickupTime),
      latest: safeDateTime(
        pickup.latestCollectionDay || pickup.jobDate,
        pickup.latestPickupTime,
      ),
      strict: booleanInteger(pickup.strictWindow),
      notes: cleanText(pickup.notes, 2000) || null,
    },
    ...dropoffs.map((dropoff, index) => ({
      id: `${jobId}:stop:${index + 2}`,
      type: "dropoff",
      sequence: index + 2,
      address: cleanText(dropoff.address, 500),
      contactName: cleanText(dropoff.contact, 200) || null,
      contactPhone: cleanText(dropoff.contactPhone, 60) || null,
      earliest: safeDateTime(
        dropoff.earliestDropoffDay || dropoff.jobDate,
        dropoff.earliestDropoffTime,
      ),
      latest: safeDateTime(dropoff.jobDate, dropoff.latestDropoffTime),
      strict: booleanInteger(dropoff.strictWindow),
      notes: cleanText(dropoff.notes, 2000) || null,
    })),
  ].filter((stop) => stop.address);

  return {
    payload,
    requester,
    quote,
    bookingId,
    jobId,
    stops,
  };
}

async function syncRequestToOrganisedJob(env, requestRow) {
  const records = jobRecordsFromRequest(requestRow);
  const total = numberOrNull(records.quote.total);
  const quotedPriceCents =
    requestRow.indicative_total_cents ??
    (total == null ? null : Math.max(0, Math.round(total * 100)));
  let uscUsed = cleanText(requestRow.usc_used, 40) || null;
  if (!uscUsed && requestRow.usc_verified) {
    uscUsed = cleanText(requestRow.business_name_or_usc, 40) || null;
  }
  if (!uscUsed && requestRow.business_id) {
    const linkedBusiness = await env.DB.prepare(
      `SELECT usc FROM businesses WHERE id = ? LIMIT 1`,
    )
      .bind(requestRow.business_id)
      .first();
    uscUsed = cleanText(linkedBusiness?.usc, 40) || null;
  }
  const statements = [
    env.DB.prepare(
      `
      INSERT OR IGNORE INTO bookings (
        id, booking_reference, checkout_mode, business_id, usc_used,
        customer_name, customer_email, customer_phone, request_data,
        quoted_price_cents, booking_status, payment_status
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'submitted', 'not_started')
    `,
    ).bind(
      records.bookingId,
      requestRow.reference,
      requestRow.booking_type === "business" ? "account" : "guest",
      requestRow.business_id,
      uscUsed,
      requestRow.requester_name,
      requestRow.requester_email,
      requestRow.requester_phone,
      requestRow.payload_json,
      quotedPriceCents,
    ),
    env.DB.prepare(
      `
      INSERT OR IGNORE INTO jobs (
        id, booking_id, job_reference, service_priority, job_status
      ) VALUES (?, ?, ?, ?, 'unscheduled')
    `,
    ).bind(
      records.jobId,
      records.bookingId,
      requestRow.reference,
      servicePriority(requestRow.service_level),
    ),
    env.DB.prepare(
      `
      INSERT OR IGNORE INTO operations_finance (
        id, booking_id, business_id, collection_type,
        payment_status, payment_method, amount_due_cents, invoice_status
      ) VALUES (
        ?, ?, ?,
        CASE WHEN EXISTS (
          SELECT 1 FROM businesses
          WHERE id = ? AND invoice_eligible = 1
        ) THEN 'invoice' ELSE 'prepayment' END,
        'not_started', ?, ?,
        CASE WHEN EXISTS (
          SELECT 1 FROM businesses
          WHERE id = ? AND invoice_eligible = 1
        ) THEN 'draft' ELSE 'not_required' END
      )
    `,
    ).bind(
      `finance:${records.bookingId}`,
      records.bookingId,
      requestRow.business_id,
      requestRow.business_id,
      requestRow.payment_method || null,
      Math.max(0, Number(quotedPriceCents || 0)),
      requestRow.business_id,
    ),
  ];

  for (const stop of records.stops) {
    statements.push(
      env.DB.prepare(
        `
      INSERT OR IGNORE INTO job_stops (
        id, job_id, stop_type, stop_sequence, address,
        contact_name, contact_phone, earliest_time, latest_time,
        strict_window, stop_notes, route_sequence
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `,
      ).bind(
        stop.id,
        records.jobId,
        stop.type,
        stop.sequence,
        stop.address,
        stop.contactName,
        stop.contactPhone,
        stop.earliest,
        stop.latest,
        stop.strict,
        stop.notes,
        stop.sequence,
      ),
    );
  }

  statements.push(
    env.DB.prepare(
      `
    INSERT INTO job_events (id, job_id, event_type, event_data)
    SELECT ?, ?, 'route_updated', ?
    WHERE NOT EXISTS (
      SELECT 1 FROM job_events
      WHERE job_id = ?
        AND (
          event_type = 'scheduled'
          OR (
            event_type = 'route_updated'
            AND json_extract(event_data, '$.source') = 'booking_request'
          )
        )
    )
  `,
    ).bind(
      crypto.randomUUID(),
      records.jobId,
      JSON.stringify({
        source: "booking_request",
        reference: requestRow.reference,
      }),
      records.jobId,
    ),
  );

  await env.DB.batch(statements);
  if (records.quote?.firstTwoJobsFreeApplied) {
    await env.DB.batch([
      env.DB.prepare(
        `UPDATE bookings SET quoted_price_cents = 0, payment_status = 'waived',
          updated_at = datetime('now') WHERE id = ?`,
      ).bind(records.bookingId),
      env.DB.prepare(
        `UPDATE operations_finance SET payment_status = 'waived', amount_due_cents = 0,
          amount_paid_cents = 0, invoice_status = 'not_required', invoice_number = NULL,
          invoice_issued_at = NULL, due_date = NULL, paid_at = NULL,
          updated_at = datetime('now') WHERE booking_id = ?`,
      ).bind(records.bookingId),
    ]);
  }
  return records;
}

function jsonResponse(request, data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      ...corsHeaders(request),
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": "no-store",
      "X-Content-Type-Options": "nosniff",
    },
  });
}

function normalizePhone(value) {
  return String(value || "")
    .replace(/\D/g, "")
    .replace(/^61/, "0");
}

function normalizeEmail(value) {
  return String(value || "")
    .trim()
    .toLowerCase();
}

function validEmail(value) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value) && value.length <= 254;
}

function cleanText(value, maxLength = 500) {
  return String(value || "")
    .trim()
    .slice(0, maxLength);
}

function escapeHtml(value) {
  return String(value || "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

function csvCell(value) {
  const text = String(value ?? "");
  const safe = /^[=+\-@\t\r]/.test(text) ? `'${text}` : text;
  return /[",\r\n]/.test(safe) ? `"${safe.replace(/"/g, '""')}"` : safe;
}

function csvResponse(filename, rows) {
  const body = rows.map((row) => row.map(csvCell).join(",")).join("\r\n");
  return new Response(`\uFEFF${body}\r\n`, {
    status: 200,
    headers: {
      "Content-Type": "text/csv; charset=utf-8",
      "Content-Disposition": `attachment; filename="${filename}"`,
      "Cache-Control": "no-store",
      "X-Content-Type-Options": "nosniff",
      "X-Sorrin-Operations-Build": OPS_BUILD,
    },
  });
}

function validDateKey(value) {
  const text = cleanText(value, 10);
  return /^\d{4}-\d{2}-\d{2}$/.test(text) ? text : null;
}

function validTimeText(value, fallback = "") {
  const text = cleanText(value, 5);
  return /^\d{2}:\d{2}$/.test(text) ? text : fallback;
}

function localDateTime(date, time) {
  const day = validDateKey(date);
  const clock = validTimeText(time);
  return day && clock ? `${day} ${clock}` : null;
}

function dateOnlyFromDateTime(value) {
  const match = String(value || "").match(/^(\d{4}-\d{2}-\d{2})/);
  return match ? match[1] : "";
}

function timeOnlyFromDateTime(value) {
  const match = String(value || "").match(/(?:T|\s)(\d{2}:\d{2})/);
  return match ? match[1] : "";
}

function validPhone(value) {
  const phone = normalizePhone(value);
  return /^0\d{8,10}$/.test(phone);
}

function numberOrNull(value) {
  if (value === "" || value == null) return null;
  const number = Number(value);
  return Number.isFinite(number) ? number : null;
}

function booleanInteger(value) {
  return value === true || value === 1 || value === "1" ? 1 : 0;
}

function referenceDateCode(value) {
  const supplied = cleanText(value, 40);
  const australian = supplied.match(/^(\d{1,2})\/(\d{1,2})\/(\d{4})$/);
  if (australian) {
    return `${australian[3].slice(-2)}${australian[2].padStart(2, "0")}${australian[1].padStart(2, "0")}`;
  }

  const iso = supplied.match(/^(\d{4})-(\d{2})-(\d{2})/);
  if (iso) return `${iso[1].slice(-2)}${iso[2]}${iso[3]}`;

  const sydneyParts = new Intl.DateTimeFormat("en-AU", {
    timeZone: "Australia/Sydney",
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
  })
    .formatToParts(new Date())
    .reduce(
      (parts, item) => ({ ...parts, [item.type]: item.value }),
      /** @type {Record<string, string>} */ ({}),
    );
  return `${sydneyParts.year.slice(-2)}${sydneyParts.month}${sydneyParts.day}`;
}

function suburbFromAddress(address) {
  const parts = cleanText(address, 500)
    .split(",")
    .map((part) => part.trim())
    .filter(Boolean);
  const statePattern = /\b(?:VIC|VICTORIA|NSW|NEW SOUTH WALES|QLD|QUEENSLAND|SA|SOUTH AUSTRALIA|WA|WESTERN AUSTRALIA|TAS|TASMANIA|NT|NORTHERN TERRITORY|ACT|AUSTRALIAN CAPITAL TERRITORY)\b/i;
  const postcodePattern = /\b\d{4}\b/;
  const localityPart =
    [...parts].reverse().find((part) => statePattern.test(part) || postcodePattern.test(part)) ||
    (parts.length > 1 ? parts[parts.length - 2] : parts[0] || "");
  return cleanText(localityPart, 120)
    .replace(statePattern, "")
    .replace(postcodePattern, "")
    .replace(/\bAustralia\b/gi, "")
    .trim();
}

function referenceSuburbToken(explicitSuburb, address, fallback) {
  const supplied = cleanText(explicitSuburb, 100);
  const suburb =
    supplied && !/^(?:pick-?up|drop-?off) location$/i.test(supplied)
      ? supplied
      : suburbFromAddress(address);
  const words = cleanText(suburb || fallback, 120)
    .normalize("NFKD")
    .replace(/[\u0300-\u036f]/g, "")
    .replace(/['’]/g, "")
    .replace(/&/g, " AND ")
    .toUpperCase()
    .match(/[A-Z0-9]+/g) || [];
  const token = words.map((word) => word.slice(0, 5)).filter(Boolean).join(".");
  return token || String(fallback || "STOP").toUpperCase().slice(0, 5);
}

async function nextJobNumbers(env, businessId = null) {
  const globalRow = await env.DB.prepare(
    `SELECT COALESCE(MAX(global_job_number), 0) + 1 AS next_number
     FROM booking_requests`,
  ).first();
  const globalJobNumber = Math.max(1, Number(globalRow?.next_number || 1));
  let uscJobNumber = null;
  if (businessId) {
    const uscRow = await env.DB.prepare(
      `SELECT COALESCE(MAX(usc_job_number), 0) + 1 AS next_number
       FROM booking_requests
       WHERE business_id = ?`,
    )
      .bind(businessId)
      .first();
    uscJobNumber = Math.max(1, Number(uscRow?.next_number || 1));
  }
  return { globalJobNumber, uscJobNumber };
}

async function firstTwoJobsFreeAdjustment(
  env,
  businessId,
  uscJobNumber,
  originalTotalCents,
) {
  const jobNumber = Number(uscJobNumber);
  const original =
    originalTotalCents == null
      ? null
      : Math.max(0, Math.round(Number(originalTotalCents || 0)));
  if (!businessId || !Number.isFinite(jobNumber) || jobNumber < 1 || jobNumber > 2) {
    return {
      applied: false,
      uscJobNumber: Number.isFinite(jobNumber) ? jobNumber : null,
      originalTotalCents: original,
      effectiveTotalCents: original,
    };
  }
  const business = await env.DB.prepare(
    `SELECT first_two_jobs_free FROM businesses WHERE id = ? LIMIT 1`,
  )
    .bind(businessId)
    .first();
  const applied = Boolean(business?.first_two_jobs_free);
  return {
    applied,
    uscJobNumber: jobNumber,
    originalTotalCents: original,
    effectiveTotalCents: applied ? 0 : original,
  };
}

function applyFirstTwoJobsFreeToQuote(quote, adjustment) {
  if (!adjustment?.applied || !quote || typeof quote !== "object") return quote;
  const originalTotal = numberOrNull(quote.total);
  quote.originalTotal = originalTotal;
  quote.total = 0;
  quote.firstTwoJobsFreeApplied = true;
  quote.firstTwoJobsFreeJobNumber = adjustment.uscJobNumber;
  return quote;
}

/**
 * @param {any} quote
 * @param {string} pickupAddress
 * @param {string} primaryDropoffAddress
 * @param {{usc?: string|null, globalJobNumber: number, uscJobNumber?: number|null}} options
 */
function bookingReference(
  quote,
  pickupAddress,
  primaryDropoffAddress,
  options,
) {
  const { usc = null, globalJobNumber, uscJobNumber = null } = options;
  const dropoffs = Array.isArray(quote?.dropoffs) ? quote.dropoffs : [];
  const pickupSuburb = referenceSuburbToken(
    quote?.pickup?.suburb,
    pickupAddress,
    "PICKU",
  );
  const routeDropoffs = dropoffs.length
    ? dropoffs
    : [{ address: primaryDropoffAddress, suburb: "" }];
  const dropoffTokens = routeDropoffs.map((dropoff, index) =>
    referenceSuburbToken(
      dropoff?.suburb,
      dropoff?.address || (index === 0 ? primaryDropoffAddress : ""),
      "DROPO",
    ),
  );
  const prefix = normaliseUsc(usc) || "S";
  const route = [prefix, pickupSuburb, ...dropoffTokens];
  if (usc && Number.isFinite(Number(uscJobNumber))) {
    route.push(String(Math.max(1, Number(uscJobNumber))));
  }
  route.push(String(Math.max(1, Number(globalJobNumber || 1))));
  return route.join("-");
}

function quoteText(quote) {
  const dropoffs = Array.isArray(quote.dropoffs) ? quote.dropoffs : [];
  const surcharges = Array.isArray(quote.surcharges) ? quote.surcharges : [];
  const requirements = Array.isArray(quote.freeRequirements)
    ? quote.freeRequirements
    : [];

  const dropoffText = dropoffs
    .map((dropoff, index) =>
      [
        `DROP-OFF ${index + 1}`,
        `Address: ${cleanText(dropoff?.address, 500) || "Not supplied"}`,
        `Earliest: ${cleanText(dropoff?.earliestDropoffTime, 100) || "ASAP"}`,
        `Latest: ${cleanText(dropoff?.latestDropoffTime, 100) || "Not supplied"}`,
        `Contact: ${cleanText(dropoff?.contact, 300) || "Not supplied"}`,
        `Notes: ${cleanText(dropoff?.notes, 1000) || "None"}`,
        `Leave safe possible: ${dropoff?.leaveSafePossible ? "Yes" : "No"}`,
        `Fragile item: ${dropoff?.fragileItem ? "Yes" : "No"}`,
        `Additional fragile items: ${numberOrNull(dropoff?.additionalFragileCount) || 0}`,
        `Overnight hold: ${dropoff?.overnightHold ? "Yes" : "No"}`,
      ].join("\n"),
    )
    .join("\n\n");

  const surchargeText = surcharges.length
    ? surcharges
        .map(
          (item) =>
            `- ${cleanText(item?.label, 200)}: $${Number(item?.price || 0).toFixed(2)}`,
        )
        .join("\n")
    : "- None";

  const requirementsText = requirements.length
    ? requirements.map((item) => `- ${cleanText(item, 300)}`).join("\n")
    : "- None";

  const total = numberOrNull(quote.total);
  const routeKm = numberOrNull(quote.routeKm);

  return [
    "QUOTE",
    `Indicative quote: ${quote.manualQuote ? "Manual quote required" : total == null ? "Not calculated" : `$${total.toFixed(2)}`}`,
    `Estimated route distance: ${routeKm == null ? "Not calculated" : `${routeKm.toFixed(1)} km`}`,
    `Distance bracket: ${cleanText(quote.bracket, 100) || "Not supplied"}`,
    `Service: ${cleanText(quote.service, 150) || "Not supplied"}`,
    `Base price: ${quote.manualQuote ? "Manual" : `$${Number(quote.basePrice || 0).toFixed(2)}`}`,
    quote.firstTwoJobsFreeApplied
      ? `Promotion: FIRST TWO JOBS FREE — job ${Number(quote.firstTwoJobsFreeJobNumber || 0)} of 2 (100% discount)`
      : null,
    "Surcharges:",
    surchargeText,
    "Free special requirements:",
    requirementsText,
    "",
    "CARGO",
    `Required space: ${cleanText(quote.packageLabel, 200) || "Not supplied"}`,
    `Item count: ${cleanText(quote.itemCount, 50) || "Not supplied"}`,
    `Largest item: ${cleanText(quote.dimensions, 200) || "Not supplied"}`,
    `Notes: ${cleanText(quote.cargoNotes, 1000) || "None"}`,
    `Perishable: ${cleanText(quote.perishable, 30) || "No"}`,
    "",
    "PICK-UP",
    `Address: ${cleanText(quote.pickup?.address, 500) || "Not supplied"}`,
    `Earliest: ${cleanText(quote.pickup?.earliestPickupTime, 100) || "ASAP"}`,
    `Latest: ${cleanText(quote.pickup?.latestPickupTime, 100) || "Not supplied"}`,
    `Contact: ${cleanText(quote.pickup?.contact, 300) || "Not supplied"}`,
    `Notes: ${cleanText(quote.pickup?.notes, 1000) || "None"}`,
    "",
    dropoffText || "DROP-OFF\nNot supplied",
  ].filter((line) => line !== null).join("\n");
}

async function verifiedEmailRecord(env, email, verificationId, token) {
  if (!verificationId || !token) return null;

  const tokenHash = await hashValue(token);

  return env.DB.prepare(
    `
    SELECT id
    FROM email_verifications
    WHERE id = ?
      AND email = ? COLLATE NOCASE
      AND status = 'verified'
      AND token_hash = ?
      AND token_expires_at > datetime('now')
    LIMIT 1
  `,
  )
    .bind(verificationId, email, tokenHash)
    .first();
}

function generateCode() {
  const values = new Uint32Array(1);
  crypto.getRandomValues(values);
  return String(100000 + (values[0] % 900000));
}

function generateToken(byteLength = 32) {
  const bytes = new Uint8Array(byteLength);
  crypto.getRandomValues(bytes);

  let binary = "";

  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }

  return btoa(binary)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

async function hashValue(value) {
  const bytes = new TextEncoder().encode(value);
  const digest = await crypto.subtle.digest("SHA-256", bytes);

  return Array.from(new Uint8Array(digest))
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");
}

/**
 * @param {any} env
 * @param {{ to: string, subject: string, text: string, html: string, from?: string, replyTo?: string }} message
 */
async function sendEmail(env, { to, subject, text, html, from, replyTo }) {
  const response = await fetch("https://api.resend.com/emails", {
    method: "POST",
    headers: {
      Authorization: `Bearer ${env.RESEND_API_KEY}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      from: from || "Sorrin Courier <courier@sorrin.com.au>",
      to: [to],
      reply_to: replyTo || "courier@sorrin.com.au",
      subject,
      text,
      html,
    }),
  });

  const result = await response.json();

  if (!response.ok) {
    throw new Error(result.message || "Email could not be sent");
  }

  return result;
}

function stripeMode(env) {
  const key = String(env.STRIPE_SECRET_KEY || "");
  if (key.startsWith("sk_live_")) return "live";
  if (key.startsWith("sk_test_")) return "test";
  return "unconfigured";
}

function stripeSessionMode(sessionId) {
  const id = String(sessionId || "");
  if (id.startsWith("cs_live_")) return "live";
  if (id.startsWith("cs_test_")) return "test";
  return "unknown";
}

function stripeConfigured(env) {
  return Boolean(
    stripeMode(env) !== "unconfigured" &&
      String(env.STRIPE_WEBHOOK_SECRET || "").startsWith("whsec_"),
  );
}

function stripeConfigurationProblem(env) {
  const mode = stripeMode(env);
  if (mode === "unconfigured") {
    return "Add STRIPE_SECRET_KEY as a Cloudflare secret using a Stripe sk_test_ or sk_live_ key";
  }
  const requestedMode = String(env.STRIPE_MODE || "").trim().toLowerCase();
  if (requestedMode && !["test", "live"].includes(requestedMode)) {
    return "STRIPE_MODE must be either test or live when it is set";
  }
  if (requestedMode && requestedMode !== mode) {
    return `STRIPE_MODE is ${requestedMode} but STRIPE_SECRET_KEY is a ${mode} key`;
  }
  if (!String(env.STRIPE_WEBHOOK_SECRET || "").startsWith("whsec_")) {
    return "Add STRIPE_WEBHOOK_SECRET as a Cloudflare secret using the webhook whsec_ value";
  }
  return null;
}

async function stripeApiRequest(env, path, values, idempotencyKey = null) {
  const problem = stripeConfigurationProblem(env);
  if (problem) throw new Error(problem);
  const body = new URLSearchParams();
  for (const [key, value] of Object.entries(values || {})) {
    if (value !== null && value !== undefined && value !== "") {
      body.append(key, String(value));
    }
  }
  const headers = {
    Authorization: `Bearer ${env.STRIPE_SECRET_KEY}`,
    "Content-Type": "application/x-www-form-urlencoded",
  };
  if (idempotencyKey) headers["Idempotency-Key"] = idempotencyKey;
  const response = await fetch(`${STRIPE_API_BASE}${path}`, {
    method: "POST",
    headers,
    body,
  });
  const result = await response.json().catch(() => ({}));
  if (!response.ok) {
    throw new Error(
      result?.error?.message || `Stripe request failed with status ${response.status}`,
    );
  }
  return result;
}

async function stripeApiGet(env, path) {
  const problem = stripeConfigurationProblem(env);
  if (problem) throw new Error(problem);
  const response = await fetch(`${STRIPE_API_BASE}${path}`, {
    method: "GET",
    headers: { Authorization: `Bearer ${env.STRIPE_SECRET_KEY}` },
  });
  const result = await response.json().catch(() => ({}));
  if (!response.ok) {
    throw new Error(
      result?.error?.message || `Stripe request failed with status ${response.status}`,
    );
  }
  return result;
}

function hexEncode(bytes) {
  return Array.from(bytes)
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");
}

async function stripeWebhookSignature(secret, payload) {
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const signature = await crypto.subtle.sign(
    "HMAC",
    key,
    new TextEncoder().encode(payload),
  );
  return hexEncode(new Uint8Array(signature));
}

async function verifyStripeWebhook(request, rawBody, env) {
  const secret = String(env.STRIPE_WEBHOOK_SECRET || "");
  if (!secret.startsWith("whsec_")) {
    return { ok: false, error: "Stripe webhook secret is not configured" };
  }
  const header = request.headers.get("Stripe-Signature") || "";
  const parts = header.split(",").reduce(
    (result, part) => {
      const separator = part.indexOf("=");
      if (separator < 1) return result;
      const key = part.slice(0, separator).trim();
      const value = part.slice(separator + 1).trim();
      if (key === "t") result.timestamp = value;
      if (key === "v1") result.signatures.push(value);
      return result;
    },
    { timestamp: "", signatures: [] },
  );
  const timestamp = Number(parts.timestamp);
  if (!Number.isFinite(timestamp) || !parts.signatures.length) {
    return { ok: false, error: "Stripe signature header is invalid" };
  }
  const age = Math.abs(Math.floor(Date.now() / 1000) - timestamp);
  if (age > STRIPE_SIGNATURE_TOLERANCE_SECONDS) {
    return { ok: false, error: "Stripe signature is outside the five-minute window" };
  }
  const expected = await stripeWebhookSignature(
    secret,
    `${parts.timestamp}.${rawBody}`,
  );
  const matched = parts.signatures.some((signature) =>
    constantTimeEqual(signature, expected),
  );
  return matched
    ? { ok: true }
    : { ok: false, error: "Stripe signature did not match" };
}

function d1Changes(result) {
  return Number(result?.meta?.changes ?? result?.changes ?? 0);
}

async function findStripeFinance(env, object) {
  const metadata = object?.metadata || {};
  if (metadata.finance_id) {
    const byId = await env.DB.prepare(
      `SELECT * FROM operations_finance WHERE id = ? LIMIT 1`,
    )
      .bind(metadata.finance_id)
      .first();
    if (byId) return byId;
  }
  const sessionId = object?.object === "checkout.session" ? object.id : null;
  const paymentIntentId =
    object?.object === "payment_intent"
      ? object.id
      : typeof object?.payment_intent === "string"
        ? object.payment_intent
        : null;
  if (!sessionId && !paymentIntentId) return null;
  return env.DB.prepare(
    `SELECT * FROM operations_finance
     WHERE stripe_checkout_session_id = ? OR stripe_payment_intent_id = ?
     LIMIT 1`,
  )
    .bind(sessionId, paymentIntentId)
    .first();
}

async function processStripeWebhook(request, env) {
  const rawBody = await request.text();
  const verification = await verifyStripeWebhook(request, rawBody, env);
  if (!verification.ok) {
    return operationsJson({ received: false, error: verification.error }, 400);
  }
  let event;
  try {
    event = JSON.parse(rawBody);
  } catch {
    return operationsJson({ received: false, error: "Webhook body is not JSON" }, 400);
  }
  if (!event?.id || !event?.type || !event?.data?.object) {
    return operationsJson({ received: false, error: "Webhook event is incomplete" }, 400);
  }
  const configuredMode = stripeMode(env);
  if (configuredMode === "unconfigured") {
    return operationsJson(
      { received: false, error: "Stripe secret key is not configured" },
      503,
    );
  }
  const expectedLivemode = configuredMode === "live";
  if (Boolean(event.livemode) !== expectedLivemode) {
    return operationsJson(
      {
        received: false,
        error: `Stripe event mode does not match the configured ${configuredMode} key`,
      },
      400,
    );
  }
  const claim = await env.DB.prepare(
    `INSERT OR IGNORE INTO stripe_webhook_events
      (event_id, event_type, livemode, status)
     VALUES (?, ?, ?, 'processing')`,
  )
    .bind(event.id, event.type, event.livemode ? 1 : 0)
    .run();
  if (d1Changes(claim) === 0) {
    return operationsJson({ received: true, duplicate: true });
  }

  try {
  const object = event.data.object;
  const finance = await findStripeFinance(env, object);
  if (!finance) {
    await env.DB.prepare(
      `UPDATE stripe_webhook_events
       SET status = 'ignored', processed_at = datetime('now'),
         error_message = 'No matching finance record'
       WHERE event_id = ?`,
    )
      .bind(event.id)
      .run();
    return operationsJson({ received: true, ignored: true });
  }

  let paymentStatus = finance.payment_status;
  let amountPaidCents = Math.max(0, Number(finance.amount_paid_cents || 0));
  let paidAt = finance.paid_at || null;
  let stripeStatus = object.payment_status || object.status || event.type;
  const amountDueCents = Math.max(0, Number(finance.amount_due_cents || 0));
  const eventAmount = Math.max(
    0,
    Number(object.amount_total ?? object.amount_received ?? object.amount ?? 0),
  );

  if (
    event.type === "checkout.session.async_payment_succeeded" ||
    event.type === "payment_intent.succeeded" ||
    (event.type === "checkout.session.completed" && object.payment_status === "paid")
  ) {
    amountPaidCents = Math.max(amountPaidCents, eventAmount || amountDueCents);
    paymentStatus = amountDueCents > 0 && amountPaidCents < amountDueCents
      ? "partially_paid"
      : "paid";
    paidAt = new Date().toISOString();
  } else if (
    event.type === "checkout.session.completed" ||
    event.type === "checkout.session.async_payment_failed" ||
    event.type === "checkout.session.expired" ||
    event.type === "payment_intent.payment_failed"
  ) {
    if (paymentStatus !== "paid") paymentStatus = "awaiting_payment";
  } else if (event.type === "charge.refunded") {
    const charged = Math.max(0, Number(object.amount || amountDueCents));
    const refunded = Math.max(0, Number(object.amount_refunded || 0));
    amountPaidCents = Math.max(0, charged - refunded);
    paymentStatus = refunded >= charged ? "refunded" : "partially_paid";
    paidAt = paymentStatus === "refunded" ? null : paidAt;
  }

  const paymentIntentId =
    object.object === "payment_intent"
      ? object.id
      : typeof object.payment_intent === "string"
        ? object.payment_intent
        : finance.stripe_payment_intent_id;
  const customerId =
    typeof object.customer === "string"
      ? object.customer
      : finance.stripe_customer_id;
  const eventData = JSON.stringify({
    action: "stripe_webhook",
    stripeEventId: event.id,
    stripeEventType: event.type,
    paymentStatus,
    amountPaidCents,
  });
  await env.DB.batch([
    env.DB.prepare(
      `UPDATE operations_finance SET
        payment_status = ?, amount_paid_cents = ?, paid_at = ?,
        invoice_status = CASE
          WHEN ? = 'paid' AND collection_type = 'invoice' THEN 'paid'
          WHEN ? = 'refunded' AND collection_type = 'invoice' THEN 'void'
          WHEN ? = 'partially_paid' AND collection_type = 'invoice'
            AND invoice_status = 'paid' THEN 'issued'
          ELSE invoice_status END,
        payment_method = CASE WHEN ? IN ('paid', 'partially_paid', 'refunded')
          THEN 'Stripe' ELSE payment_method END,
        stripe_payment_intent_id = ?, stripe_customer_id = ?,
        stripe_payment_status = ?, updated_at = datetime('now')
       WHERE id = ?`,
    ).bind(
      paymentStatus,
      amountPaidCents,
      paidAt,
      paymentStatus,
      paymentStatus,
      paymentStatus,
      paymentStatus,
      paymentIntentId || null,
      customerId || null,
      stripeStatus || event.type,
      finance.id,
    ),
    env.DB.prepare(
      `UPDATE bookings SET payment_status = ?, updated_at = datetime('now')
       WHERE id = ?`,
    ).bind(paymentStatus, finance.booking_id),
    env.DB.prepare(
      `INSERT INTO operations_finance_events
        (id, finance_id, booking_id, event_type, event_data)
       VALUES (?, ?, ?, 'stripe_webhook', ?)`,
    ).bind(
      crypto.randomUUID(),
      finance.id,
      finance.booking_id,
      eventData,
    ),
    env.DB.prepare(
      `UPDATE stripe_webhook_events SET
        finance_id = ?, booking_id = ?, status = 'processed',
        processed_at = datetime('now')
       WHERE event_id = ?`,
    ).bind(finance.id, finance.booking_id, event.id),
  ]);
  return operationsJson({ received: true, processed: true });
  } catch (error) {
    await env.DB.prepare(
      `DELETE FROM stripe_webhook_events WHERE event_id = ? AND status = 'processing'`,
    )
      .bind(event.id)
      .run();
    throw error;
  }
}

function stripeReturnUrl(template, fallback, reference) {
  const value = String(template || fallback);
  return value.replaceAll("{REFERENCE}", encodeURIComponent(reference));
}

async function emailStripeCheckout(env, job, checkoutUrl) {
  const amount = operationsMoney(job.finance?.outstandingCents || 0);
  const mode = stripeMode(env);
  const isTest = mode === "test";
  const modeNote = isTest
    ? "\n\nTEST MODE: This payment link will not collect real money."
    : "";
  const htmlModeNote = isTest
    ? '<p><strong>TEST MODE:</strong> This payment link will not collect real money.</p>'
    : "";
  const message = `Hi ${job.requesterName || "there"},

Your secure Stripe checkout for Sorrin courier booking ${job.reference} is ready.

Amount: ${amount}
Payment link: ${checkoutUrl}${modeNote}

Sorrin Courier
0452 200 359
courier@sorrin.com.au`;
  return sendEmail(env, {
    to: job.requesterEmail,
    subject: `${isTest ? "TEST - " : ""}Payment link for Sorrin booking ${job.reference}`,
    text: message,
    html: `<div style="font-family:Arial,sans-serif;max-width:680px;margin:auto;padding:32px;color:#111;line-height:1.55"><p>Hi ${escapeHtml(job.requesterName || "there")},</p><p>Your secure Stripe checkout for Sorrin courier booking <strong>${escapeHtml(job.reference)}</strong> is ready.</p><p style="font-size:22px"><strong>${escapeHtml(amount)}</strong></p><p><a href="${escapeHtml(checkoutUrl)}" style="display:inline-block;background:#111;color:#fff;padding:14px 20px;text-decoration:none;font-weight:800">OPEN SECURE CHECKOUT</a></p>${htmlModeNote}<p>Sorrin Courier<br>0452 200 359<br>courier@sorrin.com.au</p></div>`,
  });
}

async function createStripeCheckoutForJob(env, job, createdBy) {
  const problem = stripeConfigurationProblem(env);
  if (problem) throw new Error(problem);
  if (!job?.finance) throw new Error("Finance record is missing");
  if (!validEmail(job.requesterEmail)) {
    throw new Error("Customer email is not valid");
  }
  const outstandingCents = Math.max(
    0,
    Number(job.finance.amountDueCents || 0) -
      Number(job.finance.amountPaidCents || 0),
  );
  if (!outstandingCents) throw new Error("There is no outstanding balance");
  if (job.finance.effectiveStatus === "waived") {
    throw new Error("This payment record has been waived");
  }

  const existingExpiry = Date.parse(job.finance.stripeCheckoutExpiresAt || "");
  const configuredStripeMode = stripeMode(env);
  const existingSessionMode = stripeSessionMode(
    job.finance.stripeCheckoutSessionId,
  );
  const existingSessionMatchesMode =
    existingSessionMode === "unknown" || existingSessionMode === configuredStripeMode;
  let session = null;
  let reused = false;
  if (
    existingSessionMatchesMode &&
    job.finance.stripeCheckoutUrl &&
    job.finance.stripeCheckoutAmountCents === outstandingCents &&
    Number.isFinite(existingExpiry) &&
    existingExpiry > Date.now() + 60_000
  ) {
    session = {
      id: job.finance.stripeCheckoutSessionId,
      url: job.finance.stripeCheckoutUrl,
      expires_at: Math.floor(existingExpiry / 1000),
      payment_status: job.finance.stripePaymentStatus || "unpaid",
    };
    reused = true;
  } else {
    let replacedSessionId = null;
    if (
      existingSessionMatchesMode &&
      job.finance.stripeCheckoutSessionId &&
      job.finance.stripeCheckoutUrl &&
      Number.isFinite(existingExpiry) &&
      existingExpiry > Date.now() + 60_000
    ) {
      replacedSessionId = job.finance.stripeCheckoutSessionId;
      try {
        await stripeApiRequest(
          env,
          `/checkout/sessions/${encodeURIComponent(replacedSessionId)}/expire`,
          {},
          `sorrin-expire-${replacedSessionId}`,
        );
      } catch (error) {
        let prior = null;
        try {
          prior = await stripeApiGet(
            env,
            `/checkout/sessions/${encodeURIComponent(replacedSessionId)}`,
          );
        } catch {
          prior = null;
        }
        if (!prior || !["complete", "expired"].includes(prior.status)) {
          throw new Error(
            `The previous Stripe checkout could not be retired safely: ${error.message}`,
          );
        }
      }
    }
    const successUrl = stripeReturnUrl(
      "https://sorrin.com.au/courier-payment-success.html?reference={REFERENCE}&session_id={CHECKOUT_SESSION_ID}",
      "https://sorrin.com.au/courier-payment-success.html?reference={REFERENCE}&session_id={CHECKOUT_SESSION_ID}",
      job.reference,
    );
    const cancelUrl = stripeReturnUrl(
      env.STRIPE_CANCEL_URL,
      "https://sorrin.com.au/courier-get-a-quote.html?stripe=cancelled&reference={REFERENCE}",
      job.reference,
    );
    const expiresAt = Math.floor(Date.now() / 1000) + 24 * 60 * 60;
    session = await stripeApiRequest(
      env,
      "/checkout/sessions",
      {
        mode: "payment",
        submit_type: "pay",
        success_url: successUrl,
        cancel_url: cancelUrl,
        customer_email: job.requesterEmail,
        client_reference_id: job.reference,
        "line_items[0][price_data][currency]": "aud",
        "line_items[0][price_data][product_data][name]":
          `Sorrin courier booking ${job.reference}`,
        "line_items[0][price_data][unit_amount]": outstandingCents,
        "line_items[0][quantity]": 1,
        "metadata[booking_id]": job.bookingId,
        "metadata[finance_id]": job.finance.id,
        "metadata[reference]": job.reference,
        "payment_intent_data[metadata][booking_id]": job.bookingId,
        "payment_intent_data[metadata][finance_id]": job.finance.id,
        "payment_intent_data[metadata][reference]": job.reference,
        expires_at: expiresAt,
      },
      `sorrin-checkout-${job.finance.id}-${outstandingCents}-${crypto.randomUUID()}`,
    );
    const expectedLivemode = stripeMode(env) === "live";
    if (Boolean(session.livemode) !== expectedLivemode) {
      throw new Error(
        `Stripe Checkout mode does not match the configured ${stripeMode(env)} key`,
      );
    }
    if (!session.id || !session.url) {
      throw new Error("Stripe did not return a Checkout link");
    }
    const sessionExpiry = new Date(
      Number(session.expires_at || expiresAt) * 1000,
    ).toISOString();
    const eventData = JSON.stringify({
      action: "stripe_checkout_created",
      reference: job.reference,
      stripeCheckoutSessionId: session.id,
      outstandingCents,
      expiresAt: sessionExpiry,
      replacedSessionId,
      createdBy,
    });
    await env.DB.batch([
      env.DB.prepare(
        `UPDATE operations_finance SET
          payment_status = CASE
            WHEN amount_paid_cents > 0 THEN 'partially_paid'
            ELSE 'awaiting_payment' END,
          stripe_checkout_session_id = ?, stripe_checkout_url = ?,
          stripe_checkout_amount_cents = ?, stripe_payment_status = ?,
          stripe_checkout_expires_at = ?, updated_at = datetime('now')
         WHERE id = ?`,
      ).bind(
        session.id,
        session.url,
        outstandingCents,
        session.payment_status || "unpaid",
        sessionExpiry,
        job.finance.id,
      ),
      env.DB.prepare(
        `UPDATE bookings SET
          payment_status = CASE
            WHEN ? > 0 THEN 'partially_paid'
            ELSE 'awaiting_payment' END,
          updated_at = datetime('now')
         WHERE id = ?`,
      ).bind(Number(job.finance.amountPaidCents || 0), job.bookingId),
      env.DB.prepare(
        `INSERT INTO operations_finance_events
          (id, finance_id, booking_id, event_type, event_data)
         VALUES (?, ?, ?, 'stripe_checkout_created', ?)`,
      ).bind(
        crypto.randomUUID(),
        job.finance.id,
        job.bookingId,
        eventData,
      ),
    ]);
  }

  let emailSent = false;
  let emailError = null;
  try {
    await emailStripeCheckout(env, job, session.url);
    emailSent = true;
  } catch (error) {
    emailError = error.message || "Customer email could not be sent";
  }
  if (emailSent) {
    const notificationData = JSON.stringify({
      action: "customer_notified",
      reference: job.reference,
      notificationType: "stripe_payment_link",
      recipient: job.requesterEmail,
      subject: `${stripeMode(env) === "test" ? "TEST - " : ""}Payment link for Sorrin booking ${job.reference}`,
      stripeCheckoutSessionId: session.id,
      sentBy: createdBy,
    });
    await env.DB.batch([
      env.DB.prepare(
        `INSERT INTO job_events (id, job_id, event_type, event_data)
         VALUES (?, ?, 'note_added', ?)`,
      ).bind(crypto.randomUUID(), job.jobId, notificationData),
      env.DB.prepare(
        `INSERT INTO operations_finance_events
          (id, finance_id, booking_id, event_type, event_data)
         VALUES (?, ?, ?, 'stripe_checkout_emailed', ?)`,
      ).bind(
        crypto.randomUUID(),
        job.finance.id,
        job.bookingId,
        notificationData,
      ),
    ]);
  }
  return {
    id: session.id,
    url: session.url,
    expiresAt: new Date(Number(session.expires_at) * 1000).toISOString(),
    reused,
    emailSent,
    emailError,
  };
}

async function autoCheckoutForApprovedPrepayment(env, job, createdBy) {
  const gate = paymentDispatchGate(job);
  if (job?.status !== "approved" || !gate.blocked) {
    return { attempted: false, required: gate.required, blocked: gate.blocked };
  }
  if (job.finance?.collectionType !== "prepayment") {
    return { attempted: false, required: false, blocked: false };
  }
  try {
    const checkout = await createStripeCheckoutForJob(env, job, createdBy);
    return {
      attempted: true,
      required: true,
      blocked: true,
      checkout,
    };
  } catch (error) {
    return {
      attempted: true,
      required: true,
      blocked: true,
      error: error.message || "Stripe checkout could not be created",
    };
  }
}

function operationsJson(data, status = 200, headers = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": "no-store",
      "X-Content-Type-Options": "nosniff",
      "X-Sorrin-Operations-Build": OPS_BUILD,
      ...headers,
    },
  });
}

async function requestBody(request) {
  try {
    return await request.json();
  } catch {
    return null;
  }
}

function deliveryPhotoSummary(row, reference) {
  if (!row?.id) return null;
  return {
    id: row.id,
    contentType: row.content_type,
    sizeBytes: Number(row.size_bytes || 0),
    sha256: row.sha256,
    uploadedBy: row.uploaded_by,
    uploadedAt: row.updated_at || row.created_at,
    createdAt: row.created_at,
    url: `/operations/api/jobs/${encodeURIComponent(reference)}/delivery-photo`,
  };
}

function validDeliveryPhotoSignature(contentType, bytes) {
  if (contentType === "image/jpeg") {
    return bytes.length >= 3 && bytes[0] === 0xff && bytes[1] === 0xd8 && bytes[2] === 0xff;
  }
  if (contentType === "image/png") {
    const signature = [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a];
    return bytes.length >= signature.length && signature.every((value, index) => bytes[index] === value);
  }
  if (contentType === "image/webp") {
    return (
      bytes.length >= 12 &&
      String.fromCharCode(...bytes.slice(0, 4)) === "RIFF" &&
      String.fromCharCode(...bytes.slice(8, 12)) === "WEBP"
    );
  }
  return false;
}

async function deliveryPhotoUpload(request) {
  const declaredLength = Number(request.headers.get("Content-Length") || 0);
  if (declaredLength > MAX_DELIVERY_PHOTO_BYTES + 512 * 1024) {
    throw Object.assign(new Error("Delivery photo must be 10 MB or smaller"), { status: 413 });
  }
  let form;
  try {
    form = await request.formData();
  } catch {
    throw Object.assign(new Error("Choose a delivery photo to upload"), { status: 400 });
  }
  const file = form.get("photo");
  if (!file || typeof file.arrayBuffer !== "function") {
    throw Object.assign(new Error("Choose a delivery photo to upload"), { status: 400 });
  }
  const contentType = String(file.type || "").toLowerCase();
  const extension = DELIVERY_PHOTO_TYPES.get(contentType);
  if (!extension) {
    throw Object.assign(new Error("Delivery photo must be a JPEG, PNG or WebP image"), { status: 415 });
  }
  if (!Number(file.size) || Number(file.size) > MAX_DELIVERY_PHOTO_BYTES) {
    throw Object.assign(new Error("Delivery photo must be between 1 byte and 10 MB"), { status: 413 });
  }
  const buffer = await file.arrayBuffer();
  const bytes = new Uint8Array(buffer);
  if (!validDeliveryPhotoSignature(contentType, bytes.slice(0, 16))) {
    throw Object.assign(new Error("The selected file is not a valid supported image"), { status: 415 });
  }
  const digest = await crypto.subtle.digest("SHA-256", buffer);
  const sha256 = Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, "0")).join("");
  return { buffer, contentType, extension, sizeBytes: bytes.byteLength, sha256 };
}

async function syncLegacyRequests(env, limit = 100) {
  const missing = await env.DB.prepare(
    `
    SELECT br.*
    FROM booking_requests br
    LEFT JOIN jobs j ON j.job_reference = br.reference COLLATE NOCASE
    WHERE j.id IS NULL
    ORDER BY br.created_at ASC
    LIMIT ?
  `,
  )
    .bind(limit)
    .all();

  let synced = 0;
  for (const requestRow of missing.results || []) {
    await syncRequestToOrganisedJob(env, requestRow);
    synced += 1;
  }
  return synced;
}

function jobSummary(row) {
  const payload = parseJson(row.payload_json, {});
  const quote = payload.quote || {};
  const requester = payload.requester || {};
  const totalCents =
    row.final_price_cents ??
    row.quoted_price_cents ??
    row.indicative_total_cents;
  const finance = financeSummary(row);
  const status = canonicalJobStatus(row);
  const paymentGate = paymentDispatchGate({
    status,
    bookingType: row.booking_type,
    finance,
  });
  return {
    reference: row.reference,
    status,
    bookingType: row.booking_type,
    businessId: row.business_id,
    businessName:
      row.registered_business_name || requester.businessName || null,
    usc:
      row.registered_usc ||
      row.usc_used ||
      (row.usc_verified ? row.business_name_or_usc : null),
    requesterName: row.requester_name,
    requesterEmail: row.requester_email,
    requesterPhone: row.requester_phone,
    serviceLevel: row.service_level,
    servicePriority: row.service_priority || servicePriority(row.service_level),
    pickupAddress: row.pickup_address,
    primaryDropoffAddress: row.primary_dropoff_address,
    jobDate: quote.pickup?.jobDate || null,
    earliestPickupTime: quote.pickup?.earliestPickupTime || "ASAP",
    latestDropoffTime: quote.dropoffs?.[0]?.latestDropoffTime || null,
    totalCents: totalCents == null ? null : Number(totalCents),
    manualQuote: Boolean(row.manual_quote),
    paymentStatus:
      finance?.effectiveStatus || row.payment_status || "not_started",
    finance,
    paymentGate,
    stopCount: Number(
      row.stop_count ||
        (Array.isArray(quote.dropoffs) ? quote.dropoffs.length + 1 : 2),
    ),
    currentStopSequence: Number(row.current_stop_sequence || 1),
    globalJobNumber: row.global_job_number == null ? null : Number(row.global_job_number),
    uscJobNumber: row.usc_job_number == null ? null : Number(row.usc_job_number),
    archivedAt: row.operations_archived_at || null,
    archivedBy: row.operations_archived_by || null,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

async function listOperationsJobs(env, view, search, includeArchived = false, limit = 500) {
  const query = await env.DB.prepare(
    `
    SELECT
      br.*,
      b.id AS booking_id,
      b.booking_status,
      b.payment_status,
      b.quoted_price_cents,
      b.final_price_cents,
      f.id AS finance_id,
      f.business_id AS finance_business_id,
      f.collection_type,
      f.payment_status AS finance_payment_status,
      f.payment_method AS finance_payment_method,
      f.amount_due_cents,
      f.amount_paid_cents,
      f.invoice_status,
      f.invoice_number,
      f.invoice_issued_at,
      f.due_date,
      f.paid_at,
      f.finance_notes,
      f.stripe_checkout_session_id,
      f.stripe_checkout_url,
      f.stripe_checkout_amount_cents,
      f.stripe_payment_intent_id,
      f.stripe_customer_id,
      f.stripe_payment_status,
      f.stripe_checkout_expires_at,
      f.created_at AS finance_created_at,
      f.updated_at AS finance_updated_at,
      j.job_status,
      j.service_priority,
      j.current_stop_sequence,
      j.driver_notes,
      businesses.business_name AS registered_business_name,
      businesses.usc AS registered_usc,
      COUNT(js.id) AS stop_count
    FROM booking_requests br
    LEFT JOIN bookings b ON b.booking_reference = br.reference COLLATE NOCASE
    LEFT JOIN operations_finance f ON f.booking_id = b.id
    LEFT JOIN jobs j ON j.job_reference = br.reference COLLATE NOCASE
    LEFT JOIN job_stops js ON js.job_id = j.id
    LEFT JOIN businesses ON businesses.id = br.business_id
    ${includeArchived ? "" : "WHERE br.operations_archived_at IS NULL"}
    GROUP BY br.id
    ORDER BY br.created_at DESC
    LIMIT ?
  `,
  )
    .bind(Math.max(1, Math.min(10000, Number(limit || 500))))
    .all();

  const needle = String(search || "")
    .trim()
    .toLowerCase();
  return (query.results || []).map(jobSummary).filter((job) => {
    if (view === "pending" && !["pending", "approved"].includes(job.status))
      return false;
    if (view === "current" && job.status !== "active") return false;
    if (
      view === "completed" &&
      !["delivered", "declined", "cancelled"].includes(job.status)
    )
      return false;
    if (!needle) return true;
    return [
      job.reference,
      job.requesterName,
      job.requesterEmail,
      job.requesterPhone,
      job.businessName,
      job.usc,
      job.pickupAddress,
      job.primaryDropoffAddress,
    ].some((value) =>
      String(value || "")
        .toLowerCase()
        .includes(needle),
    );
    });
}

const PROCESSOR_TIME_ZONE = "Australia/Sydney";
const PROCESSOR_DEFAULT_ORIGIN =
  "Myer Ballarat, 18 Armstrong Street South, Ballarat Central VIC 3350, Australia";
const PROCESSOR_DEFAULT_ORIGIN_COORDINATES = Object.freeze({
  latitude: -37.56262,
  longitude: 143.85685,
});
const PROCESSOR_ROUTE_LIMIT = 9;
const PROCESSOR_STOP_BUFFER_MINUTES = 5;

function processorDateParts(value = new Date()) {
  return new Intl.DateTimeFormat("en-AU", {
    timeZone: PROCESSOR_TIME_ZONE,
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    hourCycle: "h23",
  })
    .formatToParts(value)
    .reduce(
      (parts, part) => ({ ...parts, [part.type]: part.value }),
      /** @type {Record<string, string>} */ ({}),
    );
}

function processorDateKey(parts) {
  return `${parts.year}-${parts.month}-${parts.day}`;
}

function processorDateTextKey(value, fallbackValue = "") {
  const date = processorDateFromText(value, fallbackValue);
  if (!date) return null;
  return `${String(date.year).padStart(4, "0")}-${String(date.month).padStart(2, "0")}-${String(date.day).padStart(2, "0")}`;
}

function processorZonedEpoch(year, month, day, hour, minute) {
  const wanted = Date.UTC(year, month - 1, day, hour, minute, 0, 0);
  let candidate = wanted;
  for (let pass = 0; pass < 3; pass += 1) {
    const local = processorDateParts(new Date(candidate));
    const rendered = Date.UTC(
      Number(local.year),
      Number(local.month) - 1,
      Number(local.day),
      Number(local.hour),
      Number(local.minute),
      0,
      0,
    );
    candidate += wanted - rendered;
  }
  return candidate;
}

function processorDateFromText(value, fallbackValue) {
  const supplied = cleanText(value, 100);
  const fallback = cleanText(fallbackValue, 40);
  const australian = supplied.match(/\b(\d{1,2})\/(\d{1,2})\/(\d{4})\b/);
  if (australian) {
    return {
      year: Number(australian[3]),
      month: Number(australian[2]),
      day: Number(australian[1]),
    };
  }
  const iso = supplied.match(/\b(\d{4})-(\d{2})-(\d{2})\b/);
  if (iso) {
    return { year: Number(iso[1]), month: Number(iso[2]), day: Number(iso[3]) };
  }
  if (fallback && fallback !== supplied) {
    return processorDateFromText(fallback, "");
  }
  return null;
}

function processorMoment(value, fallbackDate, asapEpoch = null) {
  const supplied = cleanText(value, 100);
  if (!supplied) return null;
  const date = processorDateFromText(supplied, fallbackDate);
  if (!date) return null;
  if (/\bASAP\b/i.test(supplied)) {
    const startOfDay = processorZonedEpoch(
      date.year,
      date.month,
      date.day,
      0,
      0,
    );
    return asapEpoch == null ? startOfDay : Math.max(asapEpoch, startOfDay);
  }

  const clock = supplied.match(/\b(\d{1,2}):(\d{2})\s*(AM|PM)?\b/i);
  if (!clock) return null;
  let hour = Number(clock[1]);
  const minute = Number(clock[2]);
  const period = String(clock[3] || "").toUpperCase();
  if (period === "AM") hour = hour === 12 ? 0 : hour;
  if (period === "PM") hour = hour === 12 ? 12 : hour + 12;
  if (hour > 23 || minute > 59) return null;
  return processorZonedEpoch(date.year, date.month, date.day, hour, minute);
}

function processorServiceRank(value) {
  return value === "priority" ? 0 : value === "express" ? 1 : 2;
}

function processorPressure(candidate, nowEpoch) {
  const stopState = String(candidate.stopStatus || "pending");
  const minutesToReady =
    candidate.earliestEpoch == null
      ? null
      : Math.ceil((candidate.earliestEpoch - nowEpoch) / 60000);
  const minutesToDeadline =
    candidate.latestEpoch == null
      ? null
      : Math.floor((candidate.latestEpoch - nowEpoch) / 60000);
  const isInProgress = ["en_route", "arrived"].includes(stopState);
  let bucket = 6;
  let level = "normal";
  let label = "Queued";
  let explanation = "No fixed deadline; service level controls its position.";

  if (isInProgress || candidate.status === "active") {
    bucket = 0;
    level = "critical";
    label = stopState === "arrived" ? "At stop" : "In progress";
    explanation = "This job is already active, so its next incomplete stop stays first.";
  } else if (minutesToReady != null && minutesToReady > 0) {
    bucket = 7;
    level = "future";
    label = "Not ready";
    explanation = `Ready in about ${minutesToReady} minutes.`;
  } else if (minutesToDeadline != null && minutesToDeadline < 0) {
    bucket = 1;
    level = "critical";
    label = "Overdue";
    explanation = `${Math.abs(minutesToDeadline)} minutes past its latest time.`;
  } else if (minutesToDeadline != null && minutesToDeadline <= 45) {
    bucket = 2;
    level = "critical";
    label = "Due now";
    explanation = `${Math.max(0, minutesToDeadline)} minutes remain before its latest time.`;
  } else if (
    minutesToDeadline != null &&
    (minutesToDeadline <= 120 || candidate.strictWindow)
  ) {
    bucket = 3;
    level = "warning";
    label = candidate.strictWindow ? "Strict window" : "Time pressure";
    explanation = `${minutesToDeadline} minutes remain${candidate.strictWindow ? "; this is a strict window" : ""}.`;
  } else if (minutesToDeadline != null) {
    bucket = 4;
    level = candidate.strictWindow ? "warning" : "normal";
    label = candidate.strictWindow ? "Strict window" : "Timed";
    explanation = `Latest acceptable time is ${candidate.latestTime}.`;
  } else if (candidate.servicePriority === "priority") {
    bucket = 5;
    level = "warning";
    label = "Priority";
    explanation = "Priority / ASAP job with no fixed latest time.";
  } else if (candidate.servicePriority === "express") {
    bucket = 5;
    label = "Express";
    explanation = "Express job with no fixed latest time.";
  }

  return {
    bucket,
    level,
    label,
    explanation,
    minutesToReady,
    minutesToDeadline,
  };
}

function processorCandidateSort(left, right) {
  const leftSlack = Number.isFinite(left.routeSlackMinutes)
    ? left.routeSlackMinutes
    : Number.MAX_SAFE_INTEGER;
  const rightSlack = Number.isFinite(right.routeSlackMinutes)
    ? right.routeSlackMinutes
    : Number.MAX_SAFE_INTEGER;
  return (
    left.pressure.bucket - right.pressure.bucket ||
    leftSlack - rightSlack ||
    (left.latestEpoch ?? Number.MAX_SAFE_INTEGER) -
      (right.latestEpoch ?? Number.MAX_SAFE_INTEGER) ||
    processorServiceRank(left.servicePriority) -
      processorServiceRank(right.servicePriority) ||
    Number(right.strictWindow) - Number(left.strictWindow) ||
    String(left.createdAt).localeCompare(String(right.createdAt))
  );
}

function processorConflicts(candidates) {
  const conflicts = candidates
    .filter(
      (candidate) =>
        Number.isFinite(candidate.routeSlackMinutes) &&
        candidate.routeSlackMinutes < 0,
    )
    .map((candidate) => ({
      id: `route|${candidate.reference}`,
      level: "critical",
      jobs: [candidate.reference],
      message: `${candidate.reference} is projected about ${Math.abs(candidate.routeSlackMinutes)} minutes late if started now.`,
    }))
    .slice(0, 10);
  if (conflicts.length >= 10) return conflicts;
  const timed = candidates.filter(
    (candidate) =>
      candidate.latestEpoch != null && candidate.pressure.level !== "future",
  );
  for (let index = 0; index < timed.length; index += 1) {
    for (let nextIndex = index + 1; nextIndex < timed.length; nextIndex += 1) {
      const left = timed[index];
      const right = timed[nextIndex];
      const gapMinutes = Math.round(
        Math.abs(left.latestEpoch - right.latestEpoch) / 60000,
      );
      if (gapMinutes > 45) continue;
      conflicts.push({
        id: `${left.reference}|${right.reference}`,
        level: "potential",
        jobs: [left.reference, right.reference],
        message: `${left.reference} and ${right.reference} have latest times only ${gapMinutes} minutes apart.`,
      });
      if (conflicts.length >= 10) return conflicts;
    }
  }
  return conflicts;
}

function processorMapboxToken(env) {
  return cleanText(env.MAPBOX_ACCESS_TOKEN, 2048);
}

function processorValidCoordinates(latitude, longitude) {
  const lat = numberOrNull(latitude);
  const lng = numberOrNull(longitude);
  if (
    lat == null ||
    lng == null ||
    lat < -90 ||
    lat > 90 ||
    lng < -180 ||
    lng > 180
  ) {
    return null;
  }
  return { latitude: lat, longitude: lng };
}

async function processorGeocode(env, address) {
  const supplied = cleanText(address, 500);
  if (!supplied) throw new Error("A routing address is required");
  const token = processorMapboxToken(env);
  if (!token) throw new Error("Routing access is not configured");
  const url = new URL(
    `https://api.mapbox.com/geocoding/v5/mapbox.places/${encodeURIComponent(supplied)}.json`,
  );
  url.searchParams.set("access_token", token);
  url.searchParams.set("country", "au");
  url.searchParams.set("limit", "5");
  url.searchParams.set("types", "address,poi,postcode,place,locality");
  url.searchParams.set(
    "proximity",
    `${PROCESSOR_DEFAULT_ORIGIN_COORDINATES.longitude},${PROCESSOR_DEFAULT_ORIGIN_COORDINATES.latitude}`,
  );
  const response = await fetch(url.toString());
  const result = await response.json().catch(() => ({}));
  const suppliedWantsVictoria = /\b(?:VIC|VICTORIA|3350)\b/i.test(supplied);
  const features = Array.isArray(result.features) ? result.features : [];
  const feature =
    features.find((item) => {
      const label = cleanText(item?.place_name || item?.text, 500);
      if (!suppliedWantsVictoria) return true;
      return /\b(?:VIC|VICTORIA)\b/i.test(label) && !/\bNSW\b|NEW SOUTH WALES/i.test(label);
    }) || null;
  const coordinates = processorValidCoordinates(
    feature?.center?.[1],
    feature?.center?.[0],
  );
  if (!response.ok || !coordinates) {
    throw new Error(result.message || `Could not locate ${supplied}`);
  }
  return {
    ...coordinates,
    label: cleanText(feature.place_name || feature.text || supplied, 500),
  };
}

async function processorResolveOrigin(env, originInput = {}) {
  const coordinates = processorValidCoordinates(
    originInput.latitude,
    originInput.longitude,
  );
  if (coordinates) {
    return {
      ...coordinates,
      label: cleanText(originInput.label, 200) || "Current device location",
      source: "device",
    };
  }
  const address =
    cleanText(originInput.address, 500) || PROCESSOR_DEFAULT_ORIGIN;
  if (
    address === PROCESSOR_DEFAULT_ORIGIN ||
    /^(?:3350|Ballarat Central(?: Victoria)? 3350(?:, Australia)?)$/i.test(
      address,
    )
  ) {
    return {
      ...PROCESSOR_DEFAULT_ORIGIN_COORDINATES,
      label: PROCESSOR_DEFAULT_ORIGIN,
      source: "default",
    };
  }
  return {
    ...(await processorGeocode(env, address)),
    source: "address",
  };
}

async function processorTrafficMatrix(env, origin, candidates) {
  const token = processorMapboxToken(env);
  if (!token) throw new Error("Routing access is not configured");
  const coordinates = [origin, ...candidates].map(
    (point) => `${point.longitude},${point.latitude}`,
  );
  const requestMatrix = async (profile) => {
    const url = new URL(
      `https://api.mapbox.com/directions-matrix/v1/mapbox/${profile}/${coordinates.join(";")}`,
    );
    url.searchParams.set("access_token", token);
    url.searchParams.set("sources", "all");
    url.searchParams.set("destinations", "all");
    url.searchParams.set("annotations", "duration,distance");
    const response = await fetch(url.toString());
    const result = await response.json().catch(() => ({}));
    if (!response.ok || result.code !== "Ok") {
      const status = response.status || "unknown";
      const code = cleanText(result.code, 80) || "NoCode";
      const message =
        cleanText(result.message, 180) || "Road-time calculation failed";
      throw new Error(
        `Mapbox Matrix ${profile} failed (HTTP ${status}, ${code}): ${message}`,
      );
    }
    return result;
  };

  try {
    return {
      trafficAware: true,
      ...(await requestMatrix("driving-traffic")),
    };
  } catch (trafficError) {
    try {
      return {
        trafficAware: false,
        ...(await requestMatrix("driving")),
      };
    } catch (roadError) {
      throw new Error(
        `${trafficError.message} Fallback also failed: ${roadError.message}`,
      );
    }
  }
}

function processorDownstreamMinutes(candidate) {
  return candidate.deadlineStopSequence > candidate.stopSequence &&
    Number.isFinite(candidate.routeMinutes)
    ? Math.max(0, Math.ceil(candidate.routeMinutes)) +
        PROCESSOR_STOP_BUFFER_MINUTES
    : 0;
}

function processorRouteProjection(candidate, travelMinutes, cursorEpoch, nowEpoch) {
  const arrivalEpoch = cursorEpoch + travelMinutes * 60000;
  const serviceEpoch = Math.max(
    arrivalEpoch,
    candidate.earliestEpoch == null ? arrivalEpoch : candidate.earliestEpoch,
  );
  const waitMinutes = Math.max(
    0,
    Math.ceil((serviceEpoch - arrivalEpoch) / 60000),
  );
  const downstreamMinutes = processorDownstreamMinutes(candidate);
  const routeSlackMinutes =
    candidate.latestEpoch == null
      ? null
      : Math.floor(
          (candidate.latestEpoch - serviceEpoch) / 60000 - downstreamMinutes,
        );
  const inProgress =
    candidate.status === "active" ||
    ["en_route", "arrived"].includes(String(candidate.stopStatus || ""));
  const expired =
    !inProgress &&
    candidate.latestEpoch != null &&
    candidate.latestEpoch < nowEpoch;
  let bucket = 6;
  if (inProgress) bucket = 0;
  else if (expired) bucket = 1;
  else if (Number.isFinite(routeSlackMinutes) && routeSlackMinutes < 0)
    bucket = 2;
  else if (
    Number.isFinite(routeSlackMinutes) &&
    (routeSlackMinutes <= 30 ||
      (candidate.strictWindow && routeSlackMinutes <= 60))
  )
    bucket = 3;
  else if (waitMinutes > 120) bucket = 7;
  else if (candidate.latestEpoch != null) bucket = 4;
  else if (candidate.servicePriority !== "flexible") bucket = 5;
  return {
    arrivalEpoch,
    serviceEpoch,
    waitMinutes,
    downstreamMinutes,
    routeSlackMinutes,
    bucket,
    expired,
  };
}

function processorProjectionSort(left, right) {
  const leftSlack = Number.isFinite(left.projection.routeSlackMinutes)
    ? left.projection.routeSlackMinutes
    : Number.MAX_SAFE_INTEGER;
  const rightSlack = Number.isFinite(right.projection.routeSlackMinutes)
    ? right.projection.routeSlackMinutes
    : Number.MAX_SAFE_INTEGER;
  return (
    left.projection.bucket - right.projection.bucket ||
    leftSlack - rightSlack ||
    (left.candidate.latestEpoch ?? Number.MAX_SAFE_INTEGER) -
      (right.candidate.latestEpoch ?? Number.MAX_SAFE_INTEGER) ||
    processorServiceRank(left.candidate.servicePriority) -
      processorServiceRank(right.candidate.servicePriority) ||
    left.travelMinutes - right.travelMinutes ||
    String(left.candidate.createdAt).localeCompare(
      String(right.candidate.createdAt),
    )
  );
}

function processorApplyPlannedAssessment(
  candidate,
  projection,
  travelMinutes,
  travelKm,
  travelFrom,
) {
  candidate.travelMinutes = travelMinutes;
  candidate.travelKm = travelKm;
  candidate.travelFrom = travelFrom;
  candidate.waitMinutes = projection.waitMinutes;
  candidate.downstreamMinutes = projection.downstreamMinutes;
  candidate.etaEpoch = projection.serviceEpoch;
  candidate.etaAt = new Date(projection.serviceEpoch).toISOString();
  candidate.routeSlackMinutes = projection.routeSlackMinutes;
  const roadSummary = `${travelMinutes} min / ${travelKm.toFixed(1)} km from ${travelFrom}`;
  const waiting = projection.waitMinutes
    ? ` Includes about ${projection.waitMinutes} minutes waiting until the stop is ready.`
    : "";
  const inProgress =
    candidate.status === "active" ||
    ["en_route", "arrived"].includes(String(candidate.stopStatus || ""));
  if (inProgress) {
    candidate.processorCode = "IN_PROGRESS";
    candidate.pressure = {
      ...candidate.pressure,
      bucket: 0,
      level: "critical",
      label: "In progress",
      explanation: `${roadSummary}. This job is already active.${waiting}`,
    };
  } else if (projection.expired) {
    candidate.processorCode = "EXPIRED_COMMITMENT";
    candidate.pressure = {
      ...candidate.pressure,
      bucket: 1,
      level: "critical",
      label: "Expired commitment",
      explanation: `Its latest commitment has already passed. ${roadSummary}.`,
    };
  } else if (
    Number.isFinite(projection.routeSlackMinutes) &&
    projection.routeSlackMinutes < 0
  ) {
    candidate.processorCode = "ROUTE_CONFLICT";
    candidate.pressure = {
      ...candidate.pressure,
      bucket: 2,
      level: "critical",
      label: "Route conflict",
      explanation: `${roadSummary}. This planned sequence projects about ${Math.abs(projection.routeSlackMinutes)} minutes late.${waiting}`,
    };
  } else if (
    Number.isFinite(projection.routeSlackMinutes) &&
    (projection.routeSlackMinutes <= 30 ||
      (candidate.strictWindow && projection.routeSlackMinutes <= 60))
  ) {
    candidate.processorCode = "AT_RISK";
    candidate.pressure = {
      ...candidate.pressure,
      bucket: 3,
      level: "warning",
      label: "At risk",
      explanation: `${roadSummary}. About ${projection.routeSlackMinutes} minutes of route margin remain.${waiting}`,
    };
  } else if (projection.waitMinutes > 30) {
    candidate.processorCode = "SCHEDULED_LATER";
    candidate.pressure = {
      ...candidate.pressure,
      bucket: projection.bucket,
      level: "future",
      label: "Scheduled later",
      explanation: `${roadSummary}.${waiting} Hold this position in the plan; navigation is not yet recommended.`,
    };
  } else {
    candidate.processorCode = "ON_TRACK";
    const margin = Number.isFinite(projection.routeSlackMinutes)
      ? ` About ${projection.routeSlackMinutes} minutes of route margin remain.`
      : " No fixed latest commitment is recorded.";
    candidate.pressure = {
      ...candidate.pressure,
      bucket: projection.bucket,
      level: "normal",
      label: "On track",
      explanation: `${roadSummary}.${margin}${waiting}`,
    };
  }
  return candidate;
}

function processorApplyRoadPressure(candidate, nowEpoch) {
  if (!Number.isFinite(candidate.travelMinutes)) return candidate;
  const projection = processorRouteProjection(
    candidate,
    candidate.travelMinutes,
    nowEpoch,
    nowEpoch,
  );
  return processorApplyPlannedAssessment(
    candidate,
    projection,
    candidate.travelMinutes,
    Number(candidate.travelKm || 0),
    "the selected start",
  );
}

async function processorApplyRoadTimes(
  env,
  candidates,
  now,
  originInput = {},
) {
  if (!candidates.length) {
    return {
      mode: "empty",
      origin: null,
      trafficAware: false,
      assessedCandidates: 0,
      unassessedCandidates: 0,
      message: "No live jobs need road-time assessment.",
    };
  }

  try {
    const origin = await processorResolveOrigin(env, originInput);
    const selected = candidates.slice(0, PROCESSOR_ROUTE_LIMIT);
    const resolved = await Promise.allSettled(
      selected.map(async (candidate) => {
        const existing = processorValidCoordinates(
          candidate.latitude,
          candidate.longitude,
        );
        return {
          candidate,
          ...(existing || (await processorGeocode(env, candidate.address))),
        };
      }),
    );
    const routeable = resolved
      .filter((item) => item.status === "fulfilled")
      .map((item) => item.value);
    if (!routeable.length) throw new Error("No live job stops could be located");
    const matrix = await processorTrafficMatrix(env, origin, routeable);
    const remaining = routeable.map((item, index) => ({
      ...item,
      matrixIndex: index + 1,
    }));
    let currentMatrixIndex = 0;
    let cursorEpoch = now.getTime();
    let travelFrom = "Myer Ballarat";
    let position = 1;
    while (remaining.length) {
      const choices = remaining
        .map((item) => {
          const durationSeconds = numberOrNull(
            matrix.durations?.[currentMatrixIndex]?.[item.matrixIndex],
          );
          const distanceMetres = numberOrNull(
            matrix.distances?.[currentMatrixIndex]?.[item.matrixIndex],
          );
          if (durationSeconds == null || distanceMetres == null) return null;
          const travelMinutes = Math.max(1, Math.ceil(durationSeconds / 60));
          return {
            ...item,
            travelMinutes,
            travelKm: Math.max(0, distanceMetres / 1000),
            projection: processorRouteProjection(
              item.candidate,
              travelMinutes,
              cursorEpoch,
              now.getTime(),
            ),
          };
        })
        .filter(Boolean)
        .sort(processorProjectionSort);
      if (!choices.length) break;
      const chosen = choices[0];
      chosen.candidate.position = position;
      processorApplyPlannedAssessment(
        chosen.candidate,
        chosen.projection,
        chosen.travelMinutes,
        chosen.travelKm,
        travelFrom,
      );
      cursorEpoch =
        chosen.projection.serviceEpoch + PROCESSOR_STOP_BUFFER_MINUTES * 60000;
      currentMatrixIndex = chosen.matrixIndex;
      travelFrom = chosen.candidate.suburb || chosen.candidate.address;
      position += 1;
      remaining.splice(
        remaining.findIndex(
          (item) => item.matrixIndex === chosen.matrixIndex,
        ),
        1,
      );
    }
    const assessedCandidates = candidates.filter((candidate) =>
      Number.isFinite(candidate.position),
    ).length;
    return {
      mode: matrix.trafficAware ? "traffic_aware" : "road_time",
      origin: {
        label: origin.label,
        latitude: origin.latitude,
        longitude: origin.longitude,
        source: origin.source,
      },
      trafficAware: matrix.trafficAware,
      assessedCandidates,
      unassessedCandidates: candidates.length - assessedCandidates,
      message: matrix.trafficAware
        ? "Live traffic is included and each stop is measured from the stop before it."
        : "Current road times are included and each stop is measured from the stop before it; live traffic was unavailable.",
    };
  } catch (error) {
    return {
      mode: "commitment_only",
      origin: null,
      trafficAware: false,
      assessedCandidates: 0,
      unassessedCandidates: candidates.length,
      message: `Road times are temporarily unavailable. Commitment-first ranking remains active. ${cleanText(error.message, 180)}`,
    };
  }
}

async function buildConsciousProcessor(
  env,
  now = new Date(),
  originInput = {},
) {
  await syncLegacyRequests(env, 500);
  const result = await env.DB.prepare(
    `
    SELECT
      br.*,
      b.booking_status,
      b.payment_status,
      b.quoted_price_cents,
      b.final_price_cents,
      f.id AS finance_id,
      f.business_id AS finance_business_id,
      f.collection_type,
      f.payment_status AS finance_payment_status,
      f.payment_method AS finance_payment_method,
      f.amount_due_cents,
      f.amount_paid_cents,
      f.invoice_status,
      f.invoice_number,
      f.invoice_issued_at,
      f.due_date,
      f.paid_at,
      f.finance_notes,
      f.created_at AS finance_created_at,
      f.updated_at AS finance_updated_at,
      j.id AS job_id,
      j.job_status,
      j.service_priority,
      j.current_stop_sequence,
      j.driver_notes,
      EXISTS(
        SELECT 1 FROM delivery_proof_photos dpp
        WHERE dpp.job_id = j.id
      ) AS delivery_photo_present,
      js.id AS stop_id,
      js.stop_type,
      js.stop_sequence,
      js.route_sequence,
      js.stop_status,
      js.address AS stop_address,
      js.latitude AS stop_latitude,
      js.longitude AS stop_longitude,
      js.earliest_time,
      js.latest_time,
      js.strict_window,
      js.contact_name AS stop_contact_name,
      js.contact_phone AS stop_contact_phone
    FROM booking_requests br
    JOIN bookings b ON b.booking_reference = br.reference COLLATE NOCASE
    LEFT JOIN operations_finance f ON f.booking_id = b.id
    JOIN jobs j ON j.job_reference = br.reference COLLATE NOCASE
    JOIN job_stops js ON js.job_id = j.id
    WHERE br.operations_archived_at IS NULL
      AND js.stop_status NOT IN ('completed', 'skipped', 'cancelled')
    ORDER BY br.created_at ASC,
      COALESCE(js.route_sequence, js.stop_sequence) ASC,
      js.stop_sequence ASC
    LIMIT 2000
  `,
  ).all();

  const nowEpoch = now.getTime();
  const nowParts = processorDateParts(now);
  const today = processorDateKey(nowParts);
  const grouped = new Map();
  for (const row of result.results || []) {
    const status = canonicalJobStatus(row);
    if (!["approved", "active"].includes(status)) continue;
    if (!grouped.has(row.reference)) grouped.set(row.reference, []);
    grouped.get(row.reference).push(row);
  }

  const candidates = [];
  for (const rows of grouped.values()) {
    const row = rows[0];
    const summary = jobSummary(row);
    if (summary.status === "approved" && summary.paymentGate?.blocked) continue;
    const payload = parseJson(row.payload_json, {});
    const quote = payload.quote || {};
    const jobDate = quote.pickup?.jobDate || summary.jobDate || null;
    const earliestEpoch = processorMoment(
      row.earliest_time,
      jobDate,
      nowEpoch,
    );
    const deadlines = rows
      .map((stopRow) => ({
        row: stopRow,
        epoch: processorMoment(stopRow.latest_time, jobDate),
      }))
      .filter((deadline) => deadline.epoch != null)
      .sort((left, right) => left.epoch - right.epoch);
    const commitment = deadlines[0] || null;
    const latestEpoch = commitment?.epoch ?? null;
    const deadlineRow = commitment?.row || row;
    const candidate = {
      reference: summary.reference,
      status: summary.status,
      serviceLevel: summary.serviceLevel,
      servicePriority: summary.servicePriority,
      requesterName: summary.requesterName,
      requesterPhone: summary.requesterPhone,
      stopId: row.stop_id,
      stopType: row.stop_type,
      stopSequence: Number(row.stop_sequence || 1),
      stopStatus: row.stop_status,
      address: row.stop_address,
      suburb: suburbFromAddress(row.stop_address) || row.stop_address,
      latitude: numberOrNull(row.stop_latitude),
      longitude: numberOrNull(row.stop_longitude),
      earliestTime: row.earliest_time,
      latestTime: deadlineRow.latest_time,
      deadlineStopType: deadlineRow.stop_type,
      deadlineStopSequence: Number(deadlineRow.stop_sequence || 1),
      deadlineAddress: deadlineRow.stop_address,
      strictWindow: Boolean(row.strict_window || deadlineRow.strict_window),
      jobDate,
      serviceDateKey:
        processorDateTextKey(row.earliest_time, jobDate) ||
        processorDateTextKey(jobDate),
      earliestEpoch,
      latestEpoch,
      routeMinutes: numberOrNull(quote.routeMinutes),
      createdAt: summary.createdAt,
      totalCents: summary.totalCents,
    };
    candidate.execution = executionNextAction({
      status: summary.status,
      finance: summary.finance,
      deliveryPhoto: Boolean(row.delivery_photo_present),
      stops: rows.map((stopRow) => ({
        id: stopRow.stop_id,
        stop_status: stopRow.stop_status,
      })),
    });
    candidate.pressure = processorPressure(candidate, nowEpoch);
    candidates.push(candidate);
  }

  const liveCandidates = [];
  const attention = [];
  const upcoming = [];
  for (const candidate of candidates) {
    const isActive =
      candidate.status === "active" ||
      ["en_route", "arrived"].includes(String(candidate.stopStatus || ""));
    const expiredByDeadline =
      !isActive &&
      candidate.latestEpoch != null &&
      candidate.latestEpoch < nowEpoch;
    const expiredByDate =
      !isActive &&
      candidate.serviceDateKey &&
      candidate.serviceDateKey < today;
    if (expiredByDeadline || expiredByDate) {
      candidate.processorCode = "EXPIRED_COMMITMENT";
      candidate.pressure = {
        ...candidate.pressure,
        bucket: 1,
        level: "critical",
        label: "Expired commitment",
        explanation: candidate.latestEpoch
          ? `${Math.max(1, Math.floor((nowEpoch - candidate.latestEpoch) / 60000))} minutes past its latest recorded commitment. Review, reschedule or close this job before it re-enters the live run.`
          : "Its recorded service date has passed. Review, reschedule or close this job before it re-enters the live run.",
      };
      attention.push(candidate);
      continue;
    }
    if (
      !isActive &&
      candidate.serviceDateKey &&
      candidate.serviceDateKey > today
    ) {
      candidate.processorCode = "UPCOMING";
      candidate.pressure = {
        ...candidate.pressure,
        bucket: 8,
        level: "future",
        label: "Upcoming",
        explanation: `Scheduled for ${candidate.jobDate || candidate.earliestTime || candidate.serviceDateKey}. Live traffic and departure ETA will be calculated on the service date.`,
      };
      upcoming.push(candidate);
      continue;
    }
    liveCandidates.push(candidate);
  }

  liveCandidates.sort(processorCandidateSort);
  const routing = await processorApplyRoadTimes(
    env,
    liveCandidates,
    now,
    originInput,
  );
  liveCandidates.sort((left, right) => {
    const leftPosition = Number.isFinite(left.position)
      ? left.position
      : Number.MAX_SAFE_INTEGER;
    const rightPosition = Number.isFinite(right.position)
      ? right.position
      : Number.MAX_SAFE_INTEGER;
    return leftPosition - rightPosition || processorCandidateSort(left, right);
  });
  liveCandidates.forEach((candidate, index) => {
    candidate.position = index + 1;
  });
  attention.sort(
    (left, right) =>
      (left.latestEpoch ?? 0) - (right.latestEpoch ?? 0) ||
      String(left.createdAt).localeCompare(String(right.createdAt)),
  );
  upcoming.sort(
    (left, right) =>
      (left.earliestEpoch ?? Number.MAX_SAFE_INTEGER) -
        (right.earliestEpoch ?? Number.MAX_SAFE_INTEGER) ||
      processorServiceRank(left.servicePriority) -
        processorServiceRank(right.servicePriority),
  );
  const conflicts = processorConflicts(liveCandidates).filter((conflict) =>
    conflict.jobs.some((reference) =>
      liveCandidates.some(
        (candidate) =>
          candidate.reference === reference &&
          candidate.processorCode !== "EXPIRED_COMMITMENT",
      ),
    ),
  );
  return {
    generatedAt: now.toISOString(),
    today,
    mode: "commitment_first",
    recommended: liveCandidates[0] || null,
    candidates: liveCandidates,
    attention,
    upcoming,
    conflicts,
    routing,
    counts: {
      jobs: liveCandidates.length,
      routeConflicts: liveCandidates.filter(
        (candidate) => candidate.processorCode === "ROUTE_CONFLICT",
      ).length,
      atRisk: liveCandidates.filter(
        (candidate) => candidate.processorCode === "AT_RISK",
      ).length,
      upcoming: upcoming.length,
      attention: attention.length,
    },
    limits: [
      "Future-date jobs remain visible under Upcoming but do not receive a leave-now ETA or live-route position.",
      "Expired commitments are separated for review and never masquerade as a new cross-job route conflict.",
      "Pickup-before-drop-off is enforced by exposing only each job's next incomplete stop.",
      routing.mode === "traffic_aware"
        ? "The queue combines commitments, service priority and live traffic, measuring every planned leg from the stop before it."
        : "If road-time data is unavailable, commitment-first ranking stays active and the fallback is shown clearly.",
      `The live multi-leg road plan assesses up to ${PROCESSOR_ROUTE_LIMIT} next stops per reassessment and includes a ${PROCESSOR_STOP_BUFFER_MINUTES}-minute handling buffer between stops.`,
    ],
  };
}

function historyStatusLabel(status) {
  return (
    {
      pending: "Pending",
      approved: "Approved",
      active: "Active",
      delivered: "Delivered",
      declined: "Declined",
      cancelled: "Cancelled",
    }[String(status || "").toLowerCase()] || cleanText(status, 50)
  );
}

function simpleOperationsHistory(jobEvents, bookingEvents, stops) {
  const stopLabels = {};
  let dropoffNumber = 0;
  for (const stop of stops || []) {
    if (stop.stop_type === "pickup") {
      stopLabels[stop.id] = { label: "Pickup", address: stop.address };
    } else {
      dropoffNumber += 1;
      stopLabels[stop.id] = {
        label: `Drop-off ${dropoffNumber}`,
        address: stop.address,
      };
    }
  }

  const combined = [
    ...(jobEvents || []).map((event) => ({ ...event, source_table: "job" })),
    ...(bookingEvents || []).map((event) => ({
      ...event,
      source_table: "booking",
    })),
  ].sort((left, right) =>
    String(left.created_at).localeCompare(String(right.created_at)),
  );
  const seenStatusChanges = new Set();
  const seenAccountActions = new Set();
  const history = [];

  for (const event of combined) {
    const data = parseJson(event.event_data, {});
    const previousStatus = data.previousStatus || event.previous_status || null;
    const newStatus = data.newStatus || event.new_status || null;
    const note = cleanText(data.note, 2000);
    const changedBy = cleanText(
      data.changedBy || data.updatedBy || data.assignedBy,
      254,
    );

    if (data.action === "account_linked" || data.action === "account_unlinked") {
      const accountKey = [
        event.created_at,
        data.action,
        data.reference,
        data.previousAccountId,
        data.accountId,
      ].join("|");
      if (seenAccountActions.has(accountKey)) continue;
      seenAccountActions.add(accountKey);
    }

    if (previousStatus || newStatus) {
      const duplicateKey = [
        event.created_at,
        previousStatus,
        newStatus,
        note,
        changedBy,
      ].join("|");
      if (seenStatusChanges.has(duplicateKey)) continue;
      seenStatusChanges.add(duplicateKey);

      const title =
        String(newStatus).toLowerCase() === "pending"
          ? "Returned to pending"
          : historyStatusLabel(newStatus) || "Status changed";
      const detail = [
        previousStatus && newStatus
          ? `${historyStatusLabel(previousStatus)} → ${historyStatusLabel(newStatus)}`
          : null,
        note ? `Note: ${note}` : null,
        changedBy ? `By ${changedBy}` : null,
      ]
        .filter(Boolean)
        .join(" · ");
      history.push({
        id: event.id,
        event_type: title,
        event_data: detail,
        created_at: event.created_at,
      });
      continue;
    }

    const stop = stopLabels[event.stop_id];
    let title = "Activity updated";
    let detail = "";
    if (data.source === "booking_request") {
      title = "Job created";
      detail = "Booking received and added to Operations";
    } else if (data.action === "operations_job_created") {
      title = "Job created in Operations";
      detail = changedBy ? `Created by ${changedBy}` : "Created manually";
    } else if (
      data.action === "delivery_photo_uploaded" ||
      event.event_type === "delivery_photo_uploaded"
    ) {
      title = data.replaced ? "Delivery photo replaced" : "Delivery photo uploaded";
      detail = [
        data.contentType ? data.contentType.replace("image/", "").toUpperCase() : null,
        data.sizeBytes ? `${Math.round(Number(data.sizeBytes) / 1024)} KB` : null,
      ]
        .filter(Boolean)
        .join(" · ");
    } else if (
      data.action === "proof_of_delivery" ||
      event.event_type === "proof_of_delivery"
    ) {
      title = "Proof of delivery recorded";
      detail = [
        data.recipientName ? `Received by ${data.recipientName}` : null,
        data.deliveredAt ? `Delivered ${data.deliveredAt}` : null,
        data.notes ? data.notes : null,
      ]
        .filter(Boolean)
        .join(" · ");
    } else if (
      data.action === "customer_notified" ||
      event.event_type === "customer_notified"
    ) {
      title = "Customer update sent";
      detail = [
        data.notificationType
          ? String(data.notificationType).replace(/_/g, " ")
          : null,
        data.recipient ? `Sent to ${data.recipient}` : null,
        data.subject || null,
      ]
        .filter(Boolean)
        .join(" · ");
    } else if (
      data.action === "details_updated" ||
      event.event_type === "details_updated"
    ) {
      title = "Job details updated";
      detail = Array.isArray(data.fields) ? data.fields.join(", ") : "";
    } else if (event.event_type === "scheduled") {
      title = "Job scheduled";
    } else if (event.event_type === "route_updated") {
      title = stop ? `${stop.label} updated` : "Route updated";
    } else if (event.event_type === "started") {
      title = "Job started";
    } else if (event.event_type === "en_route") {
      title = stop ? `En route to ${stop.label.toLowerCase()}` : "En route";
    } else if (event.event_type === "arrived") {
      title = stop ? `Arrived at ${stop.label.toLowerCase()}` : "Arrived";
    } else if (event.event_type === "stop_completed") {
      title = stop ? `${stop.label} completed` : "Stop completed";
    } else if (event.event_type === "completed") {
      title = "Delivered";
    } else if (event.event_type === "cancelled") {
      title = "Cancelled";
    } else if (
      data.action === "account_linked" ||
      event.event_type === "account_linked"
    ) {
      title = "USC account linked";
      detail = data.usc ? `Linked to ${data.usc}` : "Account linked";
    } else if (
      data.action === "account_unlinked" ||
      event.event_type === "account_unlinked"
    ) {
      title = "USC account unlinked";
    } else if (event.event_type === "finance_updated") {
      title = "Payment & invoice updated";
      detail = [
        data.paymentStatus
          ? `Payment: ${String(data.paymentStatus).replace(/_/g, " ")}`
          : null,
        data.invoiceStatus
          ? `Invoice: ${String(data.invoiceStatus).replace(/_/g, " ")}`
          : null,
        data.invoiceNumber ? `Invoice ${data.invoiceNumber}` : null,
        Number.isFinite(Number(data.amountPaidCents))
          ? `Received: $${(Number(data.amountPaidCents) / 100).toFixed(2)}`
          : null,
      ]
        .filter(Boolean)
        .join(" · ");
    } else if (event.event_type === "note_added") {
      title = "Note added";
    } else if (event.event_type) {
      title = event.event_type
        .replace(/_/g, " ")
        .replace(/\b\w/g, (letter) => letter.toUpperCase());
    }

    const rawText =
      typeof event.event_data === "string" &&
      event.event_data.trim() &&
      !event.event_data.trim().startsWith("{")
        ? cleanText(event.event_data, 2000)
        : "";
    detail = [
      detail || null,
      stop?.address || null,
      note ? `Note: ${note}` : null,
      rawText || null,
      changedBy ? `By ${changedBy}` : null,
    ]
      .filter(Boolean)
      .join(" · ");
    history.push({
      id: event.id,
      event_type: title,
      event_data: detail,
      created_at: event.created_at,
    });
  }

  return history;
}

async function operationsJobDetail(env, reference) {
  const requestRow = await env.DB.prepare(
    `
    SELECT * FROM booking_requests
    WHERE reference = ? COLLATE NOCASE
    LIMIT 1
  `,
  )
    .bind(reference)
    .first();
  if (!requestRow) return null;

  await syncRequestToOrganisedJob(env, requestRow);
  const row = await env.DB.prepare(
    `
    SELECT
      br.*,
      b.id AS booking_id,
      b.booking_status,
      b.payment_status,
      b.usc_used,
      b.quoted_price_cents,
      b.final_price_cents,
      f.id AS finance_id,
      f.business_id AS finance_business_id,
      f.collection_type,
      f.payment_status AS finance_payment_status,
      f.payment_method AS finance_payment_method,
      f.amount_due_cents,
      f.amount_paid_cents,
      f.invoice_status,
      f.invoice_number,
      f.invoice_issued_at,
      f.due_date,
      f.paid_at,
      f.finance_notes,
      f.stripe_checkout_session_id,
      f.stripe_checkout_url,
      f.stripe_checkout_amount_cents,
      f.stripe_payment_intent_id,
      f.stripe_customer_id,
      f.stripe_payment_status,
      f.stripe_checkout_expires_at,
      f.created_at AS finance_created_at,
      f.updated_at AS finance_updated_at,
      j.id AS job_id,
      j.job_status,
      j.service_priority,
      j.current_stop_sequence,
      j.driver_notes,
      j.scheduled_date,
      businesses.business_name AS registered_business_name,
      businesses.usc AS registered_usc
    FROM booking_requests br
    LEFT JOIN bookings b ON b.booking_reference = br.reference COLLATE NOCASE
    LEFT JOIN operations_finance f ON f.booking_id = b.id
    LEFT JOIN jobs j ON j.job_reference = br.reference COLLATE NOCASE
    LEFT JOIN businesses ON businesses.id = br.business_id
    WHERE br.reference = ? COLLATE NOCASE
    LIMIT 1
  `,
  )
    .bind(reference)
    .first();

  const stops = await env.DB.prepare(
    `
    SELECT * FROM job_stops
    WHERE job_id = ?
    ORDER BY COALESCE(route_sequence, stop_sequence), stop_sequence
  `,
  )
    .bind(row.job_id)
    .all();
  const jobEvents = await env.DB.prepare(
    `
    SELECT id, stop_id, event_type, event_data, created_at
    FROM job_events
    WHERE job_id = ?
    ORDER BY created_at DESC
    LIMIT 100
  `,
  )
    .bind(row.job_id)
    .all();
  const bookingEvents = await env.DB.prepare(
    `
    SELECT id, event_type, previous_status, new_status, event_data, created_at
    FROM booking_events
    WHERE booking_id = ?
    ORDER BY created_at DESC
    LIMIT 100
  `,
  )
    .bind(row.booking_id)
    .all();
  const accountEvents = await env.DB.prepare(
    `
    SELECT id, NULL AS stop_id, event_type, event_data, created_at
    FROM business_events
    WHERE event_type IN ('booking_linked', 'booking_unlinked')
      AND json_extract(event_data, '$.reference') = ? COLLATE NOCASE
    ORDER BY created_at DESC
    LIMIT 100
  `,
  )
    .bind(reference)
    .all();
  const financeEvents = await env.DB.prepare(
    `
    SELECT id, NULL AS stop_id, event_type, event_data, created_at
    FROM operations_finance_events
    WHERE booking_id = ?
    ORDER BY created_at DESC
    LIMIT 100
  `,
  )
    .bind(row.booking_id)
    .all();
  const deliveryPhotoRow = await env.DB.prepare(
    `SELECT id, content_type, size_bytes, sha256, uploaded_by, created_at, updated_at
     FROM delivery_proof_photos
     WHERE job_id = ?
     LIMIT 1`,
  )
    .bind(row.job_id)
    .first();

  let account = null;
  if (row.business_id) {
    account = await operationsAccountDetail(env, row.business_id);
  }

  const payload = parseJson(row.payload_json, {});
  const proofEvent = (jobEvents.results || []).find((event) => {
    const data = parseJson(event.event_data, {});
    return (
      event.event_type === "proof_of_delivery" ||
      data.action === "proof_of_delivery"
    );
  });
  const proofOfDelivery = proofEvent
    ? {
        id: proofEvent.id,
        ...parseJson(proofEvent.event_data, {}),
        createdAt: proofEvent.created_at,
      }
    : null;
  const deliveryPhoto = deliveryPhotoSummary(deliveryPhotoRow, row.reference);
  const customerNotifications = (jobEvents.results || [])
    .filter((event) => {
      const data = parseJson(event.event_data, {});
      return (
        event.event_type === "customer_notified" ||
        data.action === "customer_notified"
      );
    })
    .map((event) => ({
      id: event.id,
      ...parseJson(event.event_data, {}),
      createdAt: event.created_at,
    }));
  return {
    ...jobSummary(row),
    bookingId: row.booking_id,
    jobId: row.job_id,
    request: payload.requester || {},
    quote: payload.quote || {},
    paymentMethod:
      row.finance_payment_method || row.payment_method || null,
    emailVerified: Boolean(row.email_verified),
    uscVerified: Boolean(row.usc_verified),
    driverNotes: row.driver_notes,
    scheduledDate: row.scheduled_date,
    finance: financeSummary(row),
    deliveryPhoto,
    proofOfDelivery,
    customerNotifications,
    stops: stops.results || [],
    events: simpleOperationsHistory(
      [
        ...(jobEvents.results || []),
        ...(accountEvents.results || []),
        ...(financeEvents.results || []),
      ],
      bookingEvents.results || [],
      stops.results || [],
    ),
    account,
    execution: executionNextAction({
      ...jobSummary(row),
      stops: stops.results || [],
      deliveryPhoto,
    }),
  };
}

async function listOperationsAccounts(env, search) {
  const query = await env.DB.prepare(
    `
    SELECT
      businesses.*,
      COUNT(DISTINCT br.id) AS booking_count,
      COUNT(DISTINCT CASE WHEN br.status = 'pending' THEN br.id END)
        AS pending_booking_count,
      COUNT(DISTINCT CASE
        WHEN br.status = 'approved' OR b.booking_status = 'collected'
        THEN br.id END) AS live_booking_count,
      COUNT(DISTINCT CASE WHEN b.booking_status = 'delivered' THEN br.id END)
        AS delivered_booking_count,
      COALESCE(SUM(CASE WHEN b.booking_status = 'delivered'
        THEN COALESCE(b.final_price_cents, b.quoted_price_cents, 0)
        ELSE 0 END), 0) AS total_activity_cents
    FROM businesses
    LEFT JOIN booking_requests br ON br.business_id = businesses.id
    LEFT JOIN bookings b ON b.booking_reference = br.reference COLLATE NOCASE
    GROUP BY businesses.id
    ORDER BY businesses.business_name COLLATE NOCASE
  `,
  ).all();
  const tagRows = await env.DB.prepare(
    `
    SELECT bt.business_id, t.code, t.name
    FROM business_tags bt
    JOIN tags t ON t.id = bt.tag_id
    WHERE t.active = 1
    ORDER BY t.code
  `,
  ).all();
  const tagsByBusiness = {};
  for (const tag of tagRows.results || []) {
    (tagsByBusiness[tag.business_id] ||= []).push({
      code: tag.code,
      name: tag.name,
    });
  }
  const needle = String(search || "")
    .trim()
    .toLowerCase();
  return (query.results || [])
    .map((row) => ({
      id: row.id,
      businessName: row.business_name,
      usc: row.usc,
      contactName: row.contact_name,
      authorisedEmail: row.authorised_email,
      authorisedPhone: row.authorised_phone,
      accountState: row.account_state,
      invoiceEligible: Boolean(row.invoice_eligible),
      paymentTermsDays: Number(row.payment_terms_days || 0),
      completedPrepaidDeliveries: Number(row.completed_prepaid_deliveries || 0),
      firstTwoJobsFree: Boolean(row.first_two_jobs_free),
      contactSetupRequired:
        !validEmail(normalizeEmail(row.authorised_email)) ||
        !validPhone(normalizePhone(row.authorised_phone)),
      notes: row.account_notes,
      bookingCount: Number(row.booking_count || 0),
      pendingBookingCount: Number(row.pending_booking_count || 0),
      liveBookingCount: Number(row.live_booking_count || 0),
      deliveredBookingCount: Number(row.delivered_booking_count || 0),
      totalActivityCents: Number(row.total_activity_cents || 0),
      tags: tagsByBusiness[row.id] || [],
      createdAt: row.created_at,
      updatedAt: row.updated_at,
    }))
    .filter((account) => {
      if (!needle) return true;
      return [
        account.businessName,
        account.usc,
        account.contactName,
        account.authorisedEmail,
        account.authorisedPhone,
        ...(account.tags || []).map((tag) => tag.code),
      ].some((value) =>
        String(value || "")
          .toLowerCase()
          .includes(needle),
      );
    });
}

async function operationsAccountDetail(env, businessId) {
  const accounts = await listOperationsAccounts(env, "");
  const account = accounts.find((item) => item.id === businessId);
  if (!account) return null;
  const bookings = await env.DB.prepare(
    `
    SELECT br.reference, br.status, br.service_level, b.id AS booking_id,
      br.indicative_total_cents, br.pickup_address,
      br.primary_dropoff_address, br.created_at,
      b.booking_status, b.payment_status, b.quoted_price_cents,
      b.final_price_cents, j.job_status,
      f.id AS finance_id,
      f.business_id AS finance_business_id,
      f.collection_type,
      f.payment_status AS finance_payment_status,
      f.payment_method AS finance_payment_method,
      f.amount_due_cents,
      f.amount_paid_cents,
      f.invoice_status,
      f.invoice_number,
      f.invoice_issued_at,
      f.due_date,
      f.paid_at,
      f.finance_notes,
      f.stripe_checkout_session_id,
      f.stripe_checkout_url,
      f.stripe_checkout_amount_cents,
      f.stripe_payment_intent_id,
      f.stripe_customer_id,
      f.stripe_payment_status,
      f.stripe_checkout_expires_at,
      f.created_at AS finance_created_at,
      f.updated_at AS finance_updated_at
    FROM booking_requests br
    LEFT JOIN bookings b
      ON b.booking_reference = br.reference COLLATE NOCASE
    LEFT JOIN jobs j
      ON j.job_reference = br.reference COLLATE NOCASE
    LEFT JOIN operations_finance f ON f.booking_id = b.id
    WHERE br.business_id = ?
    ORDER BY br.created_at DESC
    LIMIT 100
  `,
  )
    .bind(businessId)
    .all();
  const benefits = await env.DB.prepare(
    `
    SELECT
      t.code AS tag_code,
      tb.id AS benefit_id,
      tb.benefit_code,
      tb.name,
      tb.description,
      tb.benefit_type,
      tb.benefit_config_json,
      tb.reset_period_days,
      MAX(br.redeemed_at) AS last_redeemed_at
    FROM business_tags bt
    JOIN tags t ON t.id = bt.tag_id
    JOIN tag_benefits tb ON tb.tag_id = t.id AND tb.active = 1
    LEFT JOIN benefit_redemptions br
      ON br.benefit_id = tb.id AND br.business_id = bt.business_id
    WHERE bt.business_id = ?
    GROUP BY tb.id
    ORDER BY t.code, tb.name
  `,
  )
    .bind(businessId)
    .all();
  const redemptions = await env.DB.prepare(
    `
    SELECT br.*, tb.benefit_code, b.booking_reference
    FROM benefit_redemptions br
    JOIN tag_benefits tb ON tb.id = br.benefit_id
    LEFT JOIN bookings b ON b.id = br.booking_id
    WHERE br.business_id = ?
    ORDER BY br.redeemed_at DESC
    LIMIT 500
  `,
  )
    .bind(businessId)
    .all();
  const events = await env.DB.prepare(
    `
    SELECT id, event_type, event_data, created_at
    FROM business_events
    WHERE business_id = ?
    ORDER BY created_at ASC
    LIMIT 500
  `,
  )
    .bind(businessId)
    .all();
  const redemptionRows = redemptions.results || [];
  const nowEpoch = Date.now();
  return {
    ...account,
    bookings: (bookings.results || []).map((booking) => ({
      ...booking,
      displayStatus: canonicalJobStatus(booking),
      finance: financeSummary(booking),
      payment_status:
        financeSummary(booking)?.effectiveStatus ||
        booking.payment_status ||
        "not_started",
      totalCents:
        booking.final_price_cents ??
        booking.quoted_price_cents ??
        booking.indicative_total_cents ??
        null,
    })),
    benefits: (benefits.results || []).map((benefit) => ({
      ...benefit,
      benefit_config: parseJson(benefit.benefit_config_json, {}),
      ...benefitAvailability(benefit, redemptionRows, nowEpoch),
    })),
    redemptions: redemptionRows,
    events: simpleBusinessHistory(events.results || []),
  };
}

function benefitAvailability(benefit, redemptions, nowEpoch = Date.now()) {
  const config = parseJson(benefit.benefit_config_json, {});
  const resetDays = Math.max(1, Number(benefit.reset_period_days || 1));
  const cutoff = nowEpoch - resetDays * 86400000;
  const inPeriod = (redemptions || []).filter((redemption) => {
    const redeemedAt = Date.parse(
      `${String(redemption.redeemed_at || "").replace(" ", "T")}Z`,
    );
    return redemption.benefit_id === benefit.benefit_id && redeemedAt >= cutoff;
  });
  const allowedJobs = Math.max(
    1,
    Number(config.eligible_jobs_per_period || 1),
  );
  const freeQuantity = Math.max(1, Number(config.free_fragile_items || 1));
  const usedQuantity = inPeriod.reduce(
    (total, redemption) => total + Number(redemption.quantity || 0),
    0,
  );
  const latestEpoch = inPeriod.reduce((latest, redemption) => {
    const value = Date.parse(
      `${String(redemption.redeemed_at || "").replace(" ", "T")}Z`,
    );
    return Number.isFinite(value) ? Math.max(latest, value) : latest;
  }, 0);
  return {
    available: inPeriod.length < allowedJobs,
    allowedJobs,
    usedJobs: inPeriod.length,
    freeQuantity,
    usedQuantity,
    remainingQuantity: inPeriod.length < allowedJobs ? freeQuantity : 0,
    resetsAt: latestEpoch
      ? new Date(latestEpoch + resetDays * 86400000).toISOString()
      : null,
  };
}

function simpleBusinessHistory(events) {
  return (events || [])
    .slice()
    .sort((left, right) =>
      String(right.created_at).localeCompare(String(left.created_at)),
    )
    .map((event) => {
      const data = parseJson(event.event_data, {});
      const by = cleanText(
        data.createdBy || data.updatedBy || data.changedBy || data.assignedBy,
        254,
      );
      const titles = {
        created: "USC account created",
        updated: "Account details updated",
        tag_assigned: "Tag assigned",
        tag_removed: "Tag removed",
        booking_linked: "Job linked",
        booking_unlinked: "Job unlinked",
        benefit_redeemed: "Benefit redeemed",
        finance_updated: "Payment & invoice updated",
        delivery_photo_uploaded: "Delivery photo uploaded",
        proof_of_delivery: "Proof of delivery recorded",
        customer_notified: "Customer update sent",
        job_created: "Internal job created",
        job_updated: "Job details updated",
      };
      const details = [
        data.code ? `Tag: ${data.code}` : null,
        data.reference ? `Job: ${data.reference}` : null,
        data.benefitName ? data.benefitName : null,
        data.quantity ? `Quantity: ${data.quantity}` : null,
        data.paymentStatus
          ? `Payment: ${String(data.paymentStatus).replace(/_/g, " ")}`
          : null,
        data.invoiceNumber ? `Invoice: ${data.invoiceNumber}` : null,
        data.recipientName ? `Received by: ${data.recipientName}` : null,
        data.notificationType
          ? `Notice: ${String(data.notificationType).replace(/_/g, " ")}`
          : null,
        Array.isArray(data.fields) && data.fields.length
          ? `Changed: ${data.fields.join(", ")}`
          : null,
        cleanText(data.note, 1000) ? `Note: ${cleanText(data.note, 1000)}` : null,
        by ? `By ${by}` : null,
      ]
        .filter(Boolean)
        .join(" · ");
      return {
        id: event.id,
        eventType:
          titles[event.event_type] ||
          cleanText(event.event_type, 100)
            .replace(/_/g, " ")
            .replace(/\b\w/g, (letter) => letter.toUpperCase()),
        detail: details,
        createdAt: event.created_at,
      };
    });
}

function normaliseUsc(value) {
  return cleanText(value, 40)
    .toUpperCase()
    .replace(/[^A-Z0-9-]/g, "");
}

async function firstTwoJobsFreeRemaining(env, businessId, enabled) {
  if (!businessId || !enabled) return 0;
  const row = await env.DB.prepare(
    `SELECT COALESCE(MAX(usc_job_number), 0) AS used_jobs
     FROM booking_requests
     WHERE business_id = ?`,
  )
    .bind(businessId)
    .first();
  return Math.max(0, 2 - Math.max(0, Number(row?.used_jobs || 0)));
}

async function authenticateUscCredentials(env, input = {}) {
  const usc = normaliseUsc(input.usc);
  const email = normalizeEmail(input.authorisedEmail ?? input.email);
  const phone = normalizePhone(input.authorisedPhone ?? input.phone);

  if (!usc) {
    return {
      ok: false,
      authenticated: false,
      code: "invalid_authentication_input",
      error: "USC is required",
      httpStatus: 400,
    };
  }

  const business = await env.DB.prepare(
    `
    SELECT
      id,
      business_name,
      usc,
      authorised_email,
      authorised_phone,
      status,
      account_state,
      invoice_eligible,
      completed_prepaid_deliveries,
      first_two_jobs_free
    FROM businesses
    WHERE usc = ? COLLATE NOCASE
    LIMIT 1
  `,
  )
    .bind(usc)
    .first();

  if (!business) {
    return {
      ok: false,
      authenticated: false,
      code: "usc_authentication_failed",
      error: "That USC is not registered",
      httpStatus: 401,
    };
  }

  if (business.status === "suspended" || business.account_state === "suspended") {
    return {
      ok: false,
      authenticated: false,
      code: "usc_account_suspended",
      error: "This USC account is suspended",
      httpStatus: 401,
    };
  }

  const storedEmail = normalizeEmail(business.authorised_email);
  const storedPhone = normalizePhone(business.authorised_phone);
  const contactSetupRequired = !validEmail(storedEmail) || !validPhone(storedPhone);

  if (contactSetupRequired) {
    return {
      ok: false,
      authenticated: false,
      code: "usc_contact_setup_required",
      error: "This USC needs its official email and mobile set before first use",
      claimRequired: true,
      businessId: business.id,
      usc: business.usc,
      businessName: business.business_name,
      firstTwoJobsFree: Boolean(business.first_two_jobs_free),
      freeDeliveriesRemaining: await firstTwoJobsFreeRemaining(
        env,
        business.id,
        Boolean(business.first_two_jobs_free),
      ),
      httpStatus: 409,
    };
  }

  if (!validEmail(email) || !validPhone(phone)) {
    return {
      ok: false,
      authenticated: false,
      code: "invalid_authentication_input",
      error: "USC, authorised email and authorised phone are required",
      httpStatus: 400,
    };
  }

  const detailsMatch = storedEmail === email && storedPhone === phone;

  if (!detailsMatch) {
    return {
      ok: false,
      authenticated: false,
      code: "usc_authentication_failed",
      error: "USC or authorised contact details do not match",
      httpStatus: 401,
    };
  }

  return {
    ok: true,
    authenticated: true,
    code: "usc_authenticated",
    businessId: business.id,
    usc: business.usc,
    businessName: business.business_name,
    accountStatus: business.status,
    invoiceEligible:
      Boolean(business.invoice_eligible) ||
      business.status === "invoice_eligible" ||
      business.status === "invoicing",
    completedPrepaidDeliveries: Number(business.completed_prepaid_deliveries || 0),
    firstTwoJobsFree: Boolean(business.first_two_jobs_free),
    freeDeliveriesRemaining: await firstTwoJobsFreeRemaining(
      env,
      business.id,
      Boolean(business.first_two_jobs_free),
    ),
    httpStatus: 200,
  };
}

function boundedInteger(value, fallback, minimum, maximum) {
  const parsed = Number(value);
  if (!Number.isFinite(parsed)) return fallback;
  return Math.min(maximum, Math.max(minimum, Math.trunc(parsed)));
}

function sorrinbotUscSessionDurations(env) {
  const idleSeconds = boundedInteger(
    env.SORRINBOT_USC_SESSION_IDLE_SECONDS,
    SORRINBOT_USC_SESSION_IDLE_SECONDS_DEFAULT,
    5 * 60,
    2 * 60 * 60,
  );
  const maximumSeconds = boundedInteger(
    env.SORRINBOT_USC_SESSION_MAX_SECONDS,
    SORRINBOT_USC_SESSION_MAX_SECONDS_DEFAULT,
    idleSeconds,
    24 * 60 * 60,
  );
  return { idleSeconds, maximumSeconds };
}

async function hmacHex(secret, value) {
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(String(secret || "")),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const signature = await crypto.subtle.sign(
    "HMAC",
    key,
    new TextEncoder().encode(String(value || "")),
  );
  return Array.from(new Uint8Array(signature))
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");
}

async function sorrinbotResponseIdHash(env, responseId) {
  return hmacHex(env.SORRINBOT_INTERNAL_KEY, `usc-session:${String(responseId || "")}`);
}

function isoAfter(date, seconds) {
  return new Date(date.getTime() + seconds * 1000).toISOString();
}

async function purgeExpiredSorrinbotUscSessions(env, nowIso) {
  await env.DB.prepare(
    `DELETE FROM sorrinbot_usc_session_states
     WHERE expires_at <= ? OR absolute_expires_at <= ?`,
  ).bind(nowIso, nowIso).run();
}

async function activeSorrinbotBusinessById(env, businessId) {
  return env.DB.prepare(
    `SELECT
       id, business_name, usc, status, account_state,
       invoice_eligible, completed_prepaid_deliveries
     FROM businesses
     WHERE id = ?
       AND status <> 'suspended'
       AND account_state <> 'suspended'
     LIMIT 1`,
  ).bind(businessId).first();
}

function safeSorrinbotSessionBusiness(business) {
  if (!business) return null;
  return {
    businessId: business.id,
    usc: business.usc,
    businessName: business.business_name,
    accountStatus: business.status,
    invoiceEligible:
      Boolean(business.invoice_eligible) ||
      business.status === "invoice_eligible" ||
      business.status === "invoicing",
    completedPrepaidDeliveries: Number(business.completed_prepaid_deliveries || 0),
  };
}

async function resolveSorrinbotUscSession(env, responseId, now = new Date()) {
  const cleanResponseId = cleanText(responseId, 300);
  if (!cleanResponseId) {
    return { ok: true, authenticated: false, state: "none", code: "no_session" };
  }

  const nowIso = now.toISOString();
  await purgeExpiredSorrinbotUscSessions(env, nowIso);
  const responseHash = await sorrinbotResponseIdHash(env, cleanResponseId);
  const row = await env.DB.prepare(
    `SELECT
       s.session_chain_id,
       s.business_id,
       s.authenticated_at,
       s.expires_at,
       s.absolute_expires_at,
       s.revoked_at,
       b.business_name,
       b.usc,
       b.status,
       b.account_state,
       b.invoice_eligible,
       b.completed_prepaid_deliveries
     FROM sorrinbot_usc_session_states s
     JOIN businesses b ON b.id = s.business_id
     WHERE s.response_id_hash = ?
       AND s.revoked_at IS NULL
       AND s.expires_at > ?
       AND s.absolute_expires_at > ?
       AND b.status <> 'suspended'
       AND b.account_state <> 'suspended'
     LIMIT 1`,
  ).bind(responseHash, nowIso, nowIso).first();

  if (!row) {
    return { ok: true, authenticated: false, state: "none", code: "session_not_active" };
  }

  return {
    ok: true,
    authenticated: true,
    state: "authenticated",
    code: "usc_session_authenticated",
    businessId: row.business_id,
    usc: row.usc,
    businessName: row.business_name,
    accountStatus: row.status,
    invoiceEligible:
      Boolean(row.invoice_eligible) ||
      row.status === "invoice_eligible" ||
      row.status === "invoicing",
    completedPrepaidDeliveries: Number(row.completed_prepaid_deliveries || 0),
    authenticatedAt: row.authenticated_at,
    expiresAt: row.expires_at,
    absoluteExpiresAt: row.absolute_expires_at,
    sessionChainId: row.session_chain_id,
  };
}

async function advanceSorrinbotUscSession(
  env,
  { previousResponseId, newResponseId, authenticatedBusinessId },
  now = new Date(),
) {
  const nextResponseId = cleanText(newResponseId, 300);
  if (!nextResponseId) {
    return { ok: false, authenticated: false, code: "missing_new_response_id", httpStatus: 400 };
  }

  const nowIso = now.toISOString();
  await purgeExpiredSorrinbotUscSessions(env, nowIso);
  const { idleSeconds, maximumSeconds } = sorrinbotUscSessionDurations(env);
  let identity = null;
  let authenticatedAt = nowIso;
  let absoluteExpiresAt = isoAfter(now, maximumSeconds);
  let sessionChainId = generateToken(18);

  const trustedBusinessId = cleanText(authenticatedBusinessId, 100);
  if (trustedBusinessId) {
    const business = await activeSorrinbotBusinessById(env, trustedBusinessId);
    if (!business) {
      return { ok: false, authenticated: false, code: "authenticated_business_not_active", httpStatus: 401 };
    }
    identity = safeSorrinbotSessionBusiness(business);
  } else {
    const previous = await resolveSorrinbotUscSession(env, previousResponseId, now);
    if (!previous.authenticated) {
      return { ok: true, authenticated: false, state: "none", code: "no_session_to_advance", httpStatus: 200 };
    }
    identity = {
      businessId: previous.businessId,
      usc: previous.usc,
      businessName: previous.businessName,
      accountStatus: previous.accountStatus,
      invoiceEligible: previous.invoiceEligible,
      completedPrepaidDeliveries: previous.completedPrepaidDeliveries,
    };
    authenticatedAt = previous.authenticatedAt;
    absoluteExpiresAt = previous.absoluteExpiresAt;
    sessionChainId = previous.sessionChainId;
  }

  const absoluteMs = Date.parse(absoluteExpiresAt);
  if (!Number.isFinite(absoluteMs) || absoluteMs <= now.getTime()) {
    return { ok: true, authenticated: false, state: "none", code: "session_max_lifetime_reached", httpStatus: 200 };
  }

  const idleExpiryMs = now.getTime() + idleSeconds * 1000;
  const expiresAt = new Date(Math.min(idleExpiryMs, absoluteMs)).toISOString();
  const responseHash = await sorrinbotResponseIdHash(env, nextResponseId);
  const id = `sbus_${generateToken(18)}`;

  await env.DB.prepare(
    `INSERT INTO sorrinbot_usc_session_states (
       id, session_chain_id, response_id_hash, business_id,
       authenticated_at, expires_at, absolute_expires_at,
       last_seen_at, revoked_at
     ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, NULL)
     ON CONFLICT(response_id_hash) DO UPDATE SET
       session_chain_id = excluded.session_chain_id,
       business_id = excluded.business_id,
       authenticated_at = excluded.authenticated_at,
       expires_at = excluded.expires_at,
       absolute_expires_at = excluded.absolute_expires_at,
       last_seen_at = excluded.last_seen_at,
       revoked_at = NULL`,
  ).bind(
    id,
    sessionChainId,
    responseHash,
    identity.businessId,
    authenticatedAt,
    expiresAt,
    absoluteExpiresAt,
    nowIso,
  ).run();

  return {
    ok: true,
    authenticated: true,
    state: "authenticated",
    code: "usc_session_advanced",
    ...identity,
    authenticatedAt,
    expiresAt,
    absoluteExpiresAt,
    httpStatus: 200,
  };
}

async function revokeSorrinbotUscSession(env, responseId, now = new Date()) {
  const current = await resolveSorrinbotUscSession(env, responseId, now);
  if (!current.authenticated) {
    return { ok: true, authenticated: false, state: "revoked", code: "no_active_session", httpStatus: 200 };
  }

  const nowIso = now.toISOString();
  await env.DB.prepare(
    `UPDATE sorrinbot_usc_session_states
     SET revoked_at = ?, last_seen_at = ?
     WHERE session_chain_id = ? AND revoked_at IS NULL`,
  ).bind(nowIso, nowIso, current.sessionChainId).run();

  return { ok: true, authenticated: false, state: "revoked", code: "usc_session_revoked", httpStatus: 200 };
}


function sorrinbotSessionResumeDuration(env) {
  return boundedInteger(
    env.SORRINBOT_SESSION_RESUME_SECONDS,
    SORRINBOT_SESSION_RESUME_SECONDS_DEFAULT,
    30 * 60,
    24 * 60 * 60,
  );
}

async function sorrinbotSessionResumeTokenHash(env, resumeToken) {
  return hmacHex(env.SORRINBOT_INTERNAL_KEY, `session-resume:${String(resumeToken || "")}`);
}

async function purgeExpiredSorrinbotSessionResumes(env, nowIso) {
  await env.DB.prepare(
    `DELETE FROM sorrinbot_session_resume_states
     WHERE expires_at <= ? OR revoked_at IS NOT NULL`,
  ).bind(nowIso).run();
}

async function resolveSorrinbotSessionResume(env, resumeToken, now = new Date()) {
  const token = cleanText(resumeToken, 500);
  if (!token) {
    return { ok: true, resumed: false, code: "no_resume_token", httpStatus: 200 };
  }

  const nowIso = now.toISOString();
  await purgeExpiredSorrinbotSessionResumes(env, nowIso);
  const tokenHash = await sorrinbotSessionResumeTokenHash(env, token);
  const row = await env.DB.prepare(
    `SELECT response_id, next_turn_number, expires_at
     FROM sorrinbot_session_resume_states
     WHERE resume_token_hash = ?
       AND revoked_at IS NULL
       AND expires_at > ?
     LIMIT 1`,
  ).bind(tokenHash, nowIso).first();

  if (!row) {
    return { ok: true, resumed: false, code: "resume_not_active", httpStatus: 200 };
  }

  await env.DB.prepare(
    `UPDATE sorrinbot_session_resume_states
     SET last_seen_at = ?
     WHERE resume_token_hash = ?`,
  ).bind(nowIso, tokenHash).run();

  return {
    ok: true,
    resumed: true,
    code: "conversation_resumed",
    responseId: row.response_id,
    nextTurnNumber: Math.max(1, Math.trunc(Number(row.next_turn_number || 1))),
    expiresAt: row.expires_at,
    version: SORRINBOT_SESSION_RESUME_VERSION,
    httpStatus: 200,
  };
}

async function advanceSorrinbotSessionResume(
  env,
  { previousResumeToken, newResponseId, nextTurnNumber },
  now = new Date(),
) {
  const responseId = cleanText(newResponseId, 300);
  const nextTurn = Math.max(1, Math.trunc(Number(nextTurnNumber || 1)));
  if (!responseId) {
    return { ok: false, code: "missing_resume_response_id", httpStatus: 400 };
  }
  if (!Number.isInteger(nextTurn) || nextTurn < 1 || nextTurn > 1000) {
    return { ok: false, code: "invalid_resume_turn_number", httpStatus: 400 };
  }

  const nowIso = now.toISOString();
  await purgeExpiredSorrinbotSessionResumes(env, nowIso);
  const previousToken = cleanText(previousResumeToken, 500);
  if (previousToken) {
    const previousHash = await sorrinbotSessionResumeTokenHash(env, previousToken);
    await env.DB.prepare(
      `UPDATE sorrinbot_session_resume_states
       SET revoked_at = ?, last_seen_at = ?
       WHERE resume_token_hash = ? AND revoked_at IS NULL`,
    ).bind(nowIso, nowIso, previousHash).run();
  }

  const resumeToken = generateToken(24);
  const tokenHash = await sorrinbotSessionResumeTokenHash(env, resumeToken);
  const expiresAt = isoAfter(now, sorrinbotSessionResumeDuration(env));
  await env.DB.prepare(
    `INSERT INTO sorrinbot_session_resume_states (
       resume_token_hash, response_id, next_turn_number,
       created_at, last_seen_at, expires_at, revoked_at
     ) VALUES (?, ?, ?, ?, ?, ?, NULL)`,
  ).bind(tokenHash, responseId, nextTurn, nowIso, nowIso, expiresAt).run();

  return {
    ok: true,
    code: "resume_token_issued",
    resumeToken,
    nextTurnNumber: nextTurn,
    expiresAt,
    version: SORRINBOT_SESSION_RESUME_VERSION,
    httpStatus: 200,
  };
}

async function revokeSorrinbotSessionResume(env, resumeToken, now = new Date()) {
  const token = cleanText(resumeToken, 500);
  if (!token) {
    return { ok: true, revoked: false, code: "no_resume_token", httpStatus: 200 };
  }
  const nowIso = now.toISOString();
  const tokenHash = await sorrinbotSessionResumeTokenHash(env, token);
  const result = await env.DB.prepare(
    `UPDATE sorrinbot_session_resume_states
     SET revoked_at = ?, last_seen_at = ?
     WHERE resume_token_hash = ? AND revoked_at IS NULL`,
  ).bind(nowIso, nowIso, tokenHash).run();
  return {
    ok: true,
    revoked: Number(result?.meta?.changes || 0) > 0,
    code: "resume_token_revoked",
    httpStatus: 200,
  };
}

async function sorrinbotBusinessProfileResponseHash(env, responseId) {
  return hmacHex(env.SORRINBOT_INTERNAL_KEY, `business-profile:${String(responseId || "")}`);
}

function sorrinbotBusinessProfileExpirySeconds(env) {
  return boundedInteger(
    env.SORRINBOT_BUSINESS_PROFILE_SECONDS,
    SORRINBOT_ROLLING_BUSINESS_PROFILE_SECONDS_DEFAULT,
    30 * 60,
    24 * 60 * 60,
  );
}

async function purgeExpiredSorrinbotBusinessProfiles(env, nowIso) {
  await env.DB.prepare(
    `DELETE FROM sorrinbot_rolling_business_profiles WHERE expires_at <= ?`,
  ).bind(nowIso).run();
}

async function resolveSorrinbotBusinessProfile(env, responseId, now = new Date()) {
  const cleanResponseId = cleanText(responseId, 300);
  if (!cleanResponseId) {
    return { ok: true, code: "no_existing_business_profile", profile: null, httpStatus: 200 };
  }
  const nowIso = now.toISOString();
  await purgeExpiredSorrinbotBusinessProfiles(env, nowIso);
  const responseHash = await sorrinbotBusinessProfileResponseHash(env, cleanResponseId);
  const row = await env.DB.prepare(
    `SELECT profile_json, revision, expires_at
     FROM sorrinbot_rolling_business_profiles
     WHERE response_key_hash = ? AND expires_at > ?
     LIMIT 1`,
  ).bind(responseHash, nowIso).first();
  if (!row) return { ok: true, code: "no_existing_business_profile", profile: null, httpStatus: 200 };
  let profile;
  try { profile = JSON.parse(String(row.profile_json || "{}")); } catch {
    return { ok: false, code: "business_profile_corrupt", profile: null, httpStatus: 500 };
  }
  return {
    ok: true,
    code: "business_profile_resolved",
    profile,
    revision: Number(row.revision || 0),
    expiresAt: row.expires_at,
    httpStatus: 200,
  };
}

async function storeSorrinbotBusinessProfile(env, responseId, profile, now = new Date()) {
  const cleanResponseId = cleanText(responseId, 300);
  if (!cleanResponseId || !profile || typeof profile !== "object" || Array.isArray(profile)) {
    return { ok: false, stored: false, code: "invalid_business_profile_input", httpStatus: 400 };
  }
  const profileJson = JSON.stringify(profile);
  if (profileJson.length > 16000) {
    return { ok: false, stored: false, code: "business_profile_too_large", httpStatus: 400 };
  }
  const nowIso = now.toISOString();
  await purgeExpiredSorrinbotBusinessProfiles(env, nowIso);
  const responseHash = await sorrinbotBusinessProfileResponseHash(env, cleanResponseId);
  const expiresAt = isoAfter(now, sorrinbotBusinessProfileExpirySeconds(env));
  const revision = Math.max(0, Math.trunc(Number(profile.revision || 0)));
  await env.DB.prepare(
    `INSERT INTO sorrinbot_rolling_business_profiles
       (response_key_hash, profile_json, revision, created_at, updated_at, expires_at)
     VALUES (?, ?, ?, ?, ?, ?)
     ON CONFLICT(response_key_hash) DO UPDATE SET
       profile_json = excluded.profile_json,
       revision = excluded.revision,
       updated_at = excluded.updated_at,
       expires_at = excluded.expires_at`,
  ).bind(responseHash, profileJson, revision, nowIso, nowIso, expiresAt).run();
  return {
    ok: true,
    stored: true,
    code: "business_profile_stored",
    revision,
    expiresAt,
    httpStatus: 200,
  };
}

function normalizeSorrinbotMembershipEmail(value) {
  return cleanText(value, 254).toLowerCase();
}

function validSorrinbotMembershipEmail(value) {
  const email = normalizeSorrinbotMembershipEmail(value);
  return Boolean(email && email.length <= 254 && /^[^\s@]+@[^\s@]+\.[^\s@]{2,63}$/.test(email));
}

async function subscribeSorrinbotMembershipUpdates(env, input = {}, now = new Date()) {
  if (input?.consentConfirmed !== true) {
    return { ok: false, subscribed: false, code: "explicit_consent_required", error: "Explicit membership-update consent is required.", httpStatus: 400 };
  }
  const consentBasis = cleanText(input?.consentBasis, 80);
  if (!["current_message", "earlier_explicit_turn_in_current_thread"].includes(consentBasis)) {
    return { ok: false, subscribed: false, code: "invalid_consent_basis", error: "The membership-update consent basis is invalid.", httpStatus: 400 };
  }
  if (cleanText(input?.scope, 80) !== "membership_updates") {
    return { ok: false, subscribed: false, code: "invalid_consent_scope", error: "Only membership-update consent can be recorded here.", httpStatus: 400 };
  }
  const email = normalizeSorrinbotMembershipEmail(input?.email);
  if (!validSorrinbotMembershipEmail(email)) {
    return { ok: false, subscribed: false, code: "valid_email_required", error: "A valid email address is required.", httpStatus: 400 };
  }

  const existing = await env.DB.prepare(
    `SELECT status FROM sorrinbot_membership_mailing_list WHERE email_normalized = ? LIMIT 1`,
  ).bind(email).first();
  if (existing?.status === "active") {
    return {
      ok: true,
      subscribed: true,
      alreadySubscribed: true,
      code: "membership_updates_already_subscribed",
      scope: "membership_updates",
      engineVersion: SORRINBOT_MEMBERSHIP_MAILING_LIST_VERSION,
      httpStatus: 200,
    };
  }

  const nowIso = now.toISOString();
  if (existing) {
    await env.DB.prepare(
      `UPDATE sorrinbot_membership_mailing_list
       SET status = 'active', consent_scope = 'membership_updates', consent_source = 'sorrinbot_chat',
           consent_basis = ?, consented_at = ?, updated_at = ?, unsubscribed_at = NULL
       WHERE email_normalized = ?`,
    ).bind(consentBasis, nowIso, nowIso, email).run();
  } else {
    await env.DB.prepare(
      `INSERT INTO sorrinbot_membership_mailing_list
       (id, email_normalized, status, consent_scope, consent_source, consent_basis, consented_at, created_at, updated_at, unsubscribed_at)
       VALUES (?, ?, 'active', 'membership_updates', 'sorrinbot_chat', ?, ?, ?, ?, NULL)`,
    ).bind(`sbml_${generateToken(18)}`, email, consentBasis, nowIso, nowIso, nowIso).run();
  }

  return {
    ok: true,
    subscribed: true,
    alreadySubscribed: false,
    code: existing ? "membership_updates_resubscribed" : "membership_updates_subscribed",
    scope: "membership_updates",
    engineVersion: SORRINBOT_MEMBERSHIP_MAILING_LIST_VERSION,
    httpStatus: 200,
  };
}


function normalizeSorrinbotConsultationEmail(value) {
  return cleanText(value, 254).toLowerCase();
}

function normalizeSorrinbotConsultationPhone(value) {
  const raw = cleanText(value, 80);
  if (!raw) return "";
  const plus = raw.startsWith("+");
  const digits = raw.replace(/\D/g, "");
  if (digits.length < 8 || digits.length > 15) return "";
  return `${plus ? "+" : ""}${digits}`;
}

function validSorrinbotConsultationContact(type, value) {
  if (type === "email") {
    const email = normalizeSorrinbotConsultationEmail(value);
    return Boolean(email && /^[^\s@]+@[^\s@]+\.[^\s@]{2,63}$/.test(email));
  }
  if (type === "phone") return Boolean(normalizeSorrinbotConsultationPhone(value));
  return false;
}

function consultationRequestReference(now = new Date()) {
  const date = now.toISOString().slice(0, 10).replace(/-/g, "");
  const suffix = crypto.randomUUID().replace(/-/g, "").slice(0, 8).toUpperCase();
  return `AI-CONS-${date}-${suffix}`;
}

async function notifySorrinbotConsultationRequest(env, request) {
  try {
    const timing = request.preferredTiming ? `\nPreferred timing: ${request.preferredTiming}` : "";
    const text =
      `A new SorrinBot consultation request has been recorded.\n\n` +
      `Reference: ${request.requestReference}\n` +
      `Status: pending\n` +
      `Contact: ${request.contactType} — ${request.contactValue}\n` +
      `Business context: ${request.businessContext}\n` +
      `Consultation focus: ${request.consultationFocus}${timing}\n\n` +
      `This is a consultation request, not a booked meeting.`;
    await sendEmail(env, {
      to: env.SORRIN_AI_EMAIL || "ai@sorrin.com.au",
      from: "Sorrin AI <ai@sorrin.com.au>",
      replyTo: "ai@sorrin.com.au",
      subject: `SorrinBot consultation request ${request.requestReference}`,
      text,
      html: `<div style="font-family:Arial,sans-serif;max-width:720px;margin:auto;padding:32px;color:#111;line-height:1.55;"><h1>NEW SORRINBOT CONSULTATION REQUEST</h1><p><strong>${escapeHtml(request.requestReference)}</strong> · pending</p><p><strong>Contact:</strong> ${escapeHtml(request.contactType)} — ${escapeHtml(request.contactValue)}</p><p><strong>Business context:</strong><br>${escapeHtml(request.businessContext)}</p><p><strong>Consultation focus:</strong><br>${escapeHtml(request.consultationFocus)}</p>${request.preferredTiming ? `<p><strong>Preferred timing:</strong><br>${escapeHtml(request.preferredTiming)}</p>` : ""}<p style="color:#666;font-size:13px;margin-top:28px;">This is a consultation request, not a booked meeting.</p></div>`,
    });
    return null;
  } catch (error) {
    return cleanText(error?.message, 300) || "Consultation request notification could not be sent.";
  }
}

async function submitSorrinbotConsultationRequest(env, input = {}, now = new Date()) {
  if (input?.contactPermissionConfirmed !== true) {
    return { ok: false, submitted: false, code: "consultation_contact_permission_required", error: "Permission to use the supplied contact path for consultation follow-up is required.", httpStatus: 400 };
  }
  if (cleanText(input?.scope, 80) !== "consultation_followup") {
    return { ok: false, submitted: false, code: "invalid_consultation_contact_scope", error: "Only consultation follow-up contact can be recorded here.", httpStatus: 400 };
  }
  const contactType = cleanText(input?.contactType, 20);
  const contactValue = contactType === "email"
    ? normalizeSorrinbotConsultationEmail(input?.contactValue)
    : normalizeSorrinbotConsultationPhone(input?.contactValue);
  if (!validSorrinbotConsultationContact(contactType, contactValue)) {
    return { ok: false, submitted: false, code: "valid_consultation_contact_required", error: "A valid consultation follow-up email or phone number is required.", httpStatus: 400 };
  }
  const contactBasis = cleanText(input?.contactBasis, 90);
  if (!["current_message", "earlier_visitor_provided_in_current_consultation_thread"].includes(contactBasis)) {
    return { ok: false, submitted: false, code: "invalid_consultation_contact_basis", error: "The consultation contact basis is invalid.", httpStatus: 400 };
  }
  const requestBasis = cleanText(input?.requestBasis, 80);
  if (!["current_message", "earlier_explicit_turn_in_current_thread"].includes(requestBasis)) {
    return { ok: false, submitted: false, code: "invalid_consultation_request_basis", error: "The consultation request basis is invalid.", httpStatus: 400 };
  }
  const businessContext = cleanText(input?.businessContext, 700);
  const consultationFocus = cleanText(input?.consultationFocus, 1200);
  const preferredTiming = cleanText(input?.preferredTiming, 300) || null;
  if (businessContext.length < 2 || consultationFocus.length < 2) {
    return { ok: false, submitted: false, code: "consultation_prequalification_required", error: "Business context and consultation focus are required before submission.", httpStatus: 400 };
  }
  const requestKey = cleanText(input?.requestKey, 160);
  if (!requestKey) {
    return { ok: false, submitted: false, code: "consultation_request_key_required", error: "A trusted consultation request key is required.", httpStatus: 400 };
  }

  const existing = await env.DB.prepare(
    `SELECT request_reference, status FROM sorrinbot_consultation_requests WHERE request_key = ? LIMIT 1`,
  ).bind(requestKey).first();
  if (existing) {
    return {
      ok: true,
      submitted: true,
      alreadySubmitted: true,
      code: "consultation_request_already_submitted",
      requestReference: existing.request_reference,
      status: existing.status,
      meetingBooked: false,
      engineVersion: SORRINBOT_CONSULTATION_REQUEST_VERSION,
      httpStatus: 200,
    };
  }

  const requestReference = consultationRequestReference(now);
  const nowIso = now.toISOString();
  await env.DB.prepare(
    `INSERT INTO sorrinbot_consultation_requests
       (id, request_reference, request_key, status, contact_type, contact_value, contact_scope,
        contact_basis, request_basis, business_context, consultation_focus, preferred_timing,
        source, submitted_at, created_at, updated_at)
     VALUES (?, ?, ?, 'pending', ?, ?, 'consultation_followup', ?, ?, ?, ?, ?, 'sorrinbot_chat', ?, ?, ?)`,
  ).bind(
    `sbcr_${generateToken(18)}`,
    requestReference,
    requestKey,
    contactType,
    contactValue,
    contactBasis,
    requestBasis,
    businessContext,
    consultationFocus,
    preferredTiming,
    nowIso,
    nowIso,
    nowIso,
  ).run();

  const notificationWarning = await notifySorrinbotConsultationRequest(env, {
    requestReference,
    contactType,
    contactValue,
    businessContext,
    consultationFocus,
    preferredTiming,
  });

  return {
    ok: true,
    submitted: true,
    alreadySubmitted: false,
    code: "consultation_request_submitted",
    requestReference,
    status: "pending",
    meetingBooked: false,
    notificationSent: !notificationWarning,
    notificationWarning,
    engineVersion: SORRINBOT_CONSULTATION_REQUEST_VERSION,
    httpStatus: notificationWarning ? 202 : 201,
  };
}

function uscNameToken(value) {
  return cleanText(value, 250)
    .normalize("NFKD")
    .replace(/[\u0300-\u036f]/g, "")
    .replace(/\b(?:PTY|LTD|LIMITED|TRADING|AS)\b/gi, " ")
    .replace(/[^A-Za-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .replace(/-+/g, "-")
    .slice(0, 22)
    .replace(/-+$/g, "")
    .toUpperCase() || "ACCOUNT";
}

async function generatedUsc(env, businessName) {
  const prefix = `USC-${uscNameToken(businessName)}`;
  const rows = await env.DB.prepare(
    `SELECT usc FROM businesses WHERE usc LIKE ? COLLATE NOCASE`,
  )
    .bind(`${prefix}-%`)
    .all();
  const sequence = (rows.results || []).reduce((highest, row) => {
    const match = String(row.usc || "").match(/-(\d+)$/);
    return match ? Math.max(highest, Number(match[1])) : highest;
  }, 0) + 1;
  return `${prefix}-${String(sequence).padStart(2, "0")}`;
}

async function startSorrinbotUscRegistration(env, input = {}) {
  const businessName = cleanText(input.businessName, 250);
  const authorisedEmail = normalizeEmail(input.authorisedEmail);
  const authorisedPhone = normalizePhone(input.authorisedPhone);
  const contactName = cleanText(input.contactName, 200) || null;

  if (!businessName || !validEmail(authorisedEmail) || !validPhone(authorisedPhone)) {
    return {
      ok: false,
      started: false,
      code: "invalid_registration_input",
      error: "Business name, authorised email and authorised phone are required.",
      httpStatus: 400,
    };
  }

  const limits = await env.DB.prepare(
    `SELECT COUNT(*) AS email_count
     FROM email_verifications
     WHERE email = ? COLLATE NOCASE
       AND created_at >= datetime('now', '-15 minutes')`,
  ).bind(authorisedEmail).first();
  if (Number(limits?.email_count || 0) >= 3) {
    return {
      ok: false,
      started: false,
      code: "registration_rate_limited",
      error: "Too many verification requests. Try again later.",
      httpStatus: 429,
    };
  }

  const registrationId = `sbreg_${generateToken(18)}`;
  const verificationId = crypto.randomUUID();
  const plannedBusinessId = crypto.randomUUID();
  const code = generateCode();
  const codeHash = await hashValue(`${verificationId}:${code}`);
  const requestHash = await hashValue(`sorrinbot-registration:${authorisedEmail}`);

  await env.DB.batch([
    env.DB.prepare(
      `INSERT INTO email_verifications (
         id, email, code_hash, request_ip_hash, expires_at
       ) VALUES (?, ?, ?, ?, datetime('now', '+10 minutes'))`,
    ).bind(verificationId, authorisedEmail, codeHash, requestHash),
    env.DB.prepare(
      `INSERT INTO sorrinbot_usc_registration_preparations (
         id, planned_business_id, email_verification_id, business_name,
         authorised_email, authorised_phone, contact_name, status, expires_at
       ) VALUES (?, ?, ?, ?, ?, ?, ?, 'awaiting_verification', datetime('now', '+10 minutes'))`,
    ).bind(
      registrationId,
      plannedBusinessId,
      verificationId,
      businessName,
      authorisedEmail,
      authorisedPhone,
      contactName,
    ),
  ]);

  try {
    await sendEmail(env, {
      to: authorisedEmail,
      subject: "Verify your Sorrin USC registration",
      text:
        `Your Sorrin USC registration verification code is ${code}. ` +
        "It expires in 10 minutes. If you did not request this, ignore this email.",
      html: `
        <div style="font-family:Arial,sans-serif;max-width:560px;margin:auto;padding:32px;color:#111;">
          <h1 style="margin:0 0 22px;">SORRIN COURIER</h1>
          <p>Enter this code in your SorrinBot conversation to verify your USC registration:</p>
          <div style="font-size:34px;font-weight:700;letter-spacing:8px;margin:26px 0;">${code}</div>
          <p>This code expires in 10 minutes.</p>
          <p style="color:#666;font-size:13px;margin-top:28px;">If you did not request this registration, you can safely ignore this email.</p>
        </div>
      `,
    });
  } catch (error) {
    await env.DB.prepare(`DELETE FROM email_verifications WHERE id = ?`)
      .bind(verificationId)
      .run();
    return {
      ok: false,
      started: false,
      code: "registration_email_failed",
      error: cleanText(error?.message, 300) || "Verification email could not be sent.",
      httpStatus: 502,
    };
  }

  return {
    ok: true,
    started: true,
    code: "usc_registration_verification_sent",
    registrationVersion: SORRINBOT_USC_REGISTRATION_VERSION,
    registrationId,
    expiresInSeconds: 600,
    httpStatus: 200,
  };
}

async function completeSorrinbotUscRegistration(env, input = {}) {
  const registrationId = cleanText(input.registrationId, 120);
  const verificationCode = cleanText(input.verificationCode, 12);
  if (!registrationId || !/^\d{6}$/.test(verificationCode)) {
    return {
      ok: false,
      registered: false,
      code: "invalid_registration_verification",
      error: "A valid registration ID and six-digit verification code are required.",
      httpStatus: 400,
    };
  }

  const preparation = await env.DB.prepare(
    `SELECT
       p.id, p.planned_business_id, p.business_id, p.business_name,
       p.authorised_email, p.authorised_phone, p.contact_name, p.status, p.usc,
       p.expires_at, p.email_verification_id,
       v.code_hash, v.attempts, v.status AS verification_status,
       CASE WHEN p.expires_at <= datetime('now') OR v.expires_at <= datetime('now') THEN 1 ELSE 0 END AS expired
     FROM sorrinbot_usc_registration_preparations p
     JOIN email_verifications v ON v.id = p.email_verification_id
     WHERE p.id = ?
     LIMIT 1`,
  ).bind(registrationId).first();

  if (!preparation) {
    return {
      ok: false,
      registered: false,
      code: "registration_not_found",
      error: "That USC registration is unavailable or has expired.",
      httpStatus: 404,
    };
  }

  if (preparation.status === "completed" && preparation.business_id) {
    const existingCompleted = await env.DB.prepare(
      `SELECT id, business_name, usc, status, account_state, invoice_eligible, completed_prepaid_deliveries
       FROM businesses WHERE id = ? LIMIT 1`,
    ).bind(preparation.business_id).first();
    if (existingCompleted && existingCompleted.account_state !== "suspended" && existingCompleted.status !== "suspended") {
      return {
        ok: true,
        registered: true,
        idempotent: true,
        code: "usc_registration_already_completed",
        registrationVersion: SORRINBOT_USC_REGISTRATION_VERSION,
        businessId: existingCompleted.id,
        businessName: existingCompleted.business_name,
        usc: existingCompleted.usc,
        accountStatus: existingCompleted.status,
        invoiceEligible: Boolean(existingCompleted.invoice_eligible),
        completedPrepaidDeliveries: Number(existingCompleted.completed_prepaid_deliveries || 0),
        httpStatus: 200,
      };
    }
  }

  if (Number(preparation.expired) === 1 || preparation.status !== "awaiting_verification" || preparation.verification_status !== "pending") {
    if (Number(preparation.expired) === 1) {
      await env.DB.batch([
        env.DB.prepare(`UPDATE sorrinbot_usc_registration_preparations SET status = 'expired', updated_at = datetime('now') WHERE id = ? AND status = 'awaiting_verification'`).bind(registrationId),
        env.DB.prepare(`UPDATE email_verifications SET status = 'expired' WHERE id = ? AND status = 'pending'`).bind(preparation.email_verification_id),
      ]);
    }
    return {
      ok: false,
      registered: false,
      code: "registration_verification_unavailable",
      error: "That verification is unavailable or has expired. Start a fresh USC registration verification.",
      httpStatus: 400,
    };
  }

  const suppliedHash = await hashValue(`${preparation.email_verification_id}:${verificationCode}`);
  if (suppliedHash !== preparation.code_hash) {
    const attempts = Number(preparation.attempts || 0) + 1;
    const verificationStatus = attempts >= 5 ? "locked" : "pending";
    await env.DB.prepare(`UPDATE email_verifications SET attempts = ?, status = ? WHERE id = ?`)
      .bind(attempts, verificationStatus, preparation.email_verification_id)
      .run();
    return {
      ok: false,
      registered: false,
      code: attempts >= 5 ? "registration_verification_locked" : "registration_verification_incorrect",
      error: attempts >= 5
        ? "Too many incorrect attempts. Start a fresh USC registration verification."
        : "Verification code is incorrect.",
      httpStatus: 400,
    };
  }

  const exactExisting = await env.DB.prepare(
    `SELECT id, business_name, usc, status, account_state, invoice_eligible, completed_prepaid_deliveries
     FROM businesses
     WHERE lower(business_name) = lower(?)
       AND authorised_email = ? COLLATE NOCASE
       AND authorised_phone = ?
     LIMIT 1`,
  ).bind(
    preparation.business_name,
    normalizeEmail(preparation.authorised_email),
    normalizePhone(preparation.authorised_phone),
  ).first();

  if (exactExisting) {
    const suspended = exactExisting.status === "suspended" || exactExisting.account_state === "suspended";
    await env.DB.batch([
      env.DB.prepare(
        `UPDATE email_verifications
         SET status = 'verified', verified_at = datetime('now')
         WHERE id = ? AND status = 'pending'`,
      ).bind(preparation.email_verification_id),
      env.DB.prepare(
        `UPDATE sorrinbot_usc_registration_preparations
         SET status = ?, business_id = ?, usc = ?, completed_at = CASE WHEN ? = 'completed' THEN datetime('now') ELSE completed_at END, updated_at = datetime('now')
         WHERE id = ?`,
      ).bind(suspended ? "cancelled" : "completed", exactExisting.id, exactExisting.usc, suspended ? "cancelled" : "completed", registrationId),
    ]);
    if (suspended) {
      return {
        ok: false,
        registered: false,
        code: "existing_usc_requires_review",
        error: "Those verified details correspond to an account that requires Sorrin review. A duplicate USC was not created.",
        httpStatus: 409,
      };
    }
    return {
      ok: true,
      registered: true,
      existingResolved: true,
      code: "existing_usc_resolved",
      registrationVersion: SORRINBOT_USC_REGISTRATION_VERSION,
      businessId: exactExisting.id,
      businessName: exactExisting.business_name,
      usc: exactExisting.usc,
      accountStatus: exactExisting.status,
      invoiceEligible: Boolean(exactExisting.invoice_eligible),
      completedPrepaidDeliveries: Number(exactExisting.completed_prepaid_deliveries || 0),
      httpStatus: 200,
    };
  }

  let lastError = null;
  for (let attempt = 0; attempt < 3; attempt += 1) {
    const usc = await generatedUsc(env, preparation.business_name);
    try {
      await env.DB.batch([
        env.DB.prepare(
          `INSERT INTO businesses (
             id, business_name, usc, authorised_email, authorised_phone, status,
             contact_name, account_state, invoice_eligible, payment_terms_days,
             completed_prepaid_deliveries
           ) VALUES (?, ?, ?, ?, ?, 'prepaid', ?, 'active', 0, 0, 0)`,
        ).bind(
          preparation.planned_business_id,
          preparation.business_name,
          usc,
          normalizeEmail(preparation.authorised_email),
          normalizePhone(preparation.authorised_phone),
          cleanText(preparation.contact_name, 200) || null,
        ),
        env.DB.prepare(
          `INSERT INTO business_events (id, business_id, event_type, event_data)
           VALUES (?, ?, 'created', ?)`,
        ).bind(
          crypto.randomUUID(),
          preparation.planned_business_id,
          JSON.stringify({ createdBy: "sorrinbot_registration", registrationId }),
        ),
        env.DB.prepare(
          `UPDATE email_verifications
           SET status = 'verified', verified_at = datetime('now')
           WHERE id = ? AND status = 'pending'`,
        ).bind(preparation.email_verification_id),
        env.DB.prepare(
          `UPDATE sorrinbot_usc_registration_preparations
           SET status = 'completed', business_id = ?, usc = ?, completed_at = datetime('now'), updated_at = datetime('now')
           WHERE id = ? AND status = 'awaiting_verification'`,
        ).bind(preparation.planned_business_id, usc, registrationId),
      ]);
      return {
        ok: true,
        registered: true,
        code: "usc_registered",
        registrationVersion: SORRINBOT_USC_REGISTRATION_VERSION,
        businessId: preparation.planned_business_id,
        businessName: preparation.business_name,
        usc,
        accountStatus: "prepaid",
        invoiceEligible: false,
        completedPrepaidDeliveries: 0,
        httpStatus: 201,
      };
    } catch (error) {
      lastError = error;
      if (!/unique|constraint/i.test(String(error?.message || ""))) break;
    }
  }

  console.error({ event: "sorrinbot_usc_registration_create_error", message: lastError?.message || "unknown" });
  return {
    ok: false,
    registered: false,
    code: "usc_registration_create_failed",
    error: "The USC could not be created. Please try the registration again.",
    httpStatus: 409,
  };
}

function accountStatusForLegacy(accountState, invoiceEligible) {
  if (accountState === "suspended") return "suspended";
  return invoiceEligible ? "invoice_eligible" : "prepaid";
}

function normaliseFinanceUpdate(
  current,
  body,
  invoiceNumber,
  today = dateKeyInSydney(),
  paymentTermsDays = 0,
) {
  const collectionType = FINANCE_COLLECTION_TYPES.has(body?.collectionType)
    ? body.collectionType
    : current.collectionType || "prepayment";
  let paymentStatus = FINANCE_PAYMENT_STATUSES.has(body?.paymentStatus)
    ? body.paymentStatus
    : current.paymentStatus || "not_started";
  let invoiceStatus = FINANCE_INVOICE_STATUSES.has(body?.invoiceStatus)
    ? body.invoiceStatus
    : current.invoiceStatus || "not_required";
  const amountDueCents = Math.max(
    0,
    Math.min(100000000, Math.round(Number(body?.amountDueCents ?? current.amountDueCents ?? 0))),
  );
  let amountPaidCents = Math.max(
    0,
    Math.min(100000000, Math.round(Number(body?.amountPaidCents ?? current.amountPaidCents ?? 0))),
  );
  let resolvedInvoiceNumber = cleanText(
    body?.invoiceNumber ?? current.invoiceNumber,
    100,
  ) || null;
  let dueDate = cleanText(body?.dueDate ?? current.dueDate, 20) || null;
  let invoiceIssuedAt = current.invoiceIssuedAt || null;
  let paidAt = current.paidAt || null;

  if (collectionType === "prepayment") {
    invoiceStatus = "not_required";
    resolvedInvoiceNumber = null;
    dueDate = null;
    invoiceIssuedAt = null;
  } else {
    if (invoiceStatus === "not_required") invoiceStatus = "draft";
    if (invoiceStatus === "issued") {
      resolvedInvoiceNumber = resolvedInvoiceNumber || invoiceNumber;
      dueDate = dueDate || addDaysToDateKey(today, paymentTermsDays);
      invoiceIssuedAt = invoiceIssuedAt || new Date().toISOString();
      if (paymentStatus === "not_started") paymentStatus = "awaiting_payment";
    }
  }

  if (["waived", "refunded"].includes(paymentStatus)) {
    if (paymentStatus === "waived") paidAt = null;
  } else if (paymentStatus === "paid" || invoiceStatus === "paid") {
    paymentStatus = "paid";
    if (collectionType === "invoice") invoiceStatus = "paid";
    amountPaidCents = Math.max(amountPaidCents, amountDueCents);
    paidAt = paidAt || new Date().toISOString();
  } else if (amountDueCents > 0 && amountPaidCents >= amountDueCents) {
    paymentStatus = "paid";
    if (collectionType === "invoice") invoiceStatus = "paid";
    paidAt = paidAt || new Date().toISOString();
  } else if (amountPaidCents > 0) {
    paymentStatus = "partially_paid";
    paidAt = null;
  } else if (!["waived", "refunded"].includes(paymentStatus)) {
    paidAt = null;
  }

  return {
    collectionType,
    paymentStatus,
    paymentMethod:
      cleanText(body?.paymentMethod ?? current.paymentMethod, 100) || null,
    amountDueCents,
    amountPaidCents,
    invoiceStatus,
    invoiceNumber: resolvedInvoiceNumber,
    invoiceIssuedAt,
    dueDate,
    paidAt,
    notes: cleanText(body?.notes ?? current.notes, 3000) || null,
  };
}

async function generatedInvoiceNumber(env, now = new Date()) {
  const day = dateKeyInSydney(now).replace(/-/g, "").slice(2);
  const prefix = `SOR-INV-${day}-`;
  const rows = await env.DB.prepare(
    `SELECT invoice_number FROM operations_finance
     WHERE invoice_number LIKE ? COLLATE NOCASE`,
  )
    .bind(`${prefix}%`)
    .all();
  const sequence = (rows.results || []).reduce((highest, row) => {
    const match = String(row.invoice_number || "").match(/-(\d+)$/);
    return match ? Math.max(highest, Number(match[1])) : highest;
  }, 0) + 1;
  return `${prefix}${String(sequence).padStart(3, "0")}`;
}

async function listOperationsFinance(env, search = "") {
  const rows = await env.DB.prepare(
    `
    SELECT
      f.id AS finance_id,
      f.booking_id,
      f.business_id AS finance_business_id,
      f.collection_type,
      f.payment_status AS finance_payment_status,
      f.payment_method AS finance_payment_method,
      f.amount_due_cents,
      f.amount_paid_cents,
      f.invoice_status,
      f.invoice_number,
      f.invoice_issued_at,
      f.due_date,
      f.paid_at,
      f.finance_notes,
      f.stripe_checkout_session_id,
      f.stripe_checkout_url,
      f.stripe_checkout_amount_cents,
      f.stripe_payment_intent_id,
      f.stripe_customer_id,
      f.stripe_payment_status,
      f.stripe_checkout_expires_at,
      f.created_at AS finance_created_at,
      f.updated_at AS finance_updated_at,
      br.reference,
      br.status AS request_status,
      br.requester_name,
      br.requester_email,
      br.requester_phone,
      br.service_level,
      br.pickup_address,
      br.primary_dropoff_address,
      br.payload_json,
      b.booking_status,
      j.job_status,
      businesses.business_name,
      businesses.usc
    FROM operations_finance f
    JOIN bookings b ON b.id = f.booking_id
    JOIN booking_requests br
      ON br.reference = b.booking_reference COLLATE NOCASE
    LEFT JOIN jobs j ON j.booking_id = b.id
    LEFT JOIN businesses ON businesses.id = f.business_id
    ORDER BY
      CASE
        WHEN f.payment_status NOT IN ('paid', 'waived', 'refunded')
          AND f.invoice_status = 'issued'
          AND f.due_date < date('now') THEN 0
        WHEN f.payment_status NOT IN ('paid', 'waived', 'refunded') THEN 1
        ELSE 2
      END,
      COALESCE(f.due_date, '9999-12-31'),
      f.updated_at DESC
    LIMIT 1000
  `,
  ).all();
  const needle = String(search || "").trim().toLowerCase();
  return (rows.results || [])
    .map((row) => {
      const finance = financeSummary(row);
      return {
        ...finance,
        reference: row.reference,
        customerName: row.requester_name,
        customerEmail: row.requester_email,
        customerPhone: row.requester_phone,
        businessName: row.business_name,
        usc: row.usc,
        serviceLevel: row.service_level,
        pickupAddress: row.pickup_address,
        primaryDropoffAddress: row.primary_dropoff_address,
        jobStatus: canonicalJobStatus(row),
      };
    })
    .sort((left, right) => {
      const rank = (item) =>
        item.effectiveStatus === "overdue"
          ? 0
          : ["paid", "waived", "refunded"].includes(item.effectiveStatus)
            ? 2
            : 1;
      return (
        rank(left) - rank(right) ||
        String(left.dueDate || "9999-12-31").localeCompare(
          String(right.dueDate || "9999-12-31"),
        ) ||
        String(right.updatedAt || "").localeCompare(String(left.updatedAt || ""))
      );
    })
    .filter((finance) => {
      if (!needle) return true;
      return [
        finance.reference,
        finance.customerName,
        finance.customerEmail,
        finance.customerPhone,
        finance.businessName,
        finance.usc,
        finance.invoiceNumber,
      ].some((value) => String(value || "").toLowerCase().includes(needle));
    });
}

function operationsMoney(cents) {
  return new Intl.NumberFormat("en-AU", {
    style: "currency",
    currency: "AUD",
  }).format(Math.max(0, Number(cents || 0)) / 100);
}

function printableOperationsDocument(title, body) {
  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>${escapeHtml(title)}</title><style>
body{font-family:Arial,sans-serif;color:#111;margin:0;background:#eee}main{width:min(840px,calc(100% - 32px));margin:24px auto;background:#fff;padding:52px;box-sizing:border-box}.top{display:flex;justify-content:space-between;gap:30px;border-bottom:3px solid #111;padding-bottom:26px}.brand{font-size:42px;font-weight:900;letter-spacing:.08em}.meta{text-align:right}.grid{display:grid;grid-template-columns:1fr 1fr;gap:20px;margin:30px 0}.box{border:1px solid #ccc;padding:18px}.box span,th{font-size:11px;text-transform:uppercase;letter-spacing:.12em;color:#666}table{width:100%;border-collapse:collapse;margin:28px 0}th,td{text-align:left;padding:14px 10px;border-bottom:1px solid #ddd}td:last-child,th:last-child{text-align:right}.total{font-size:22px;font-weight:800}.muted{color:#666;line-height:1.55}.print{position:fixed;right:20px;top:20px;border:0;background:#111;color:#fff;padding:12px 18px;font-weight:800;cursor:pointer}@media print{body{background:#fff}.print{display:none}main{width:auto;margin:0;padding:20px}}
</style></head><body><button class="print" onclick="window.print()">PRINT / SAVE PDF</button><main>${body}</main></body></html>`;
}

function operationsInvoiceHtml(job) {
  const finance = job.finance || {};
  const invoiceTitle = finance.invoiceNumber || `Payment record ${job.reference}`;
  const customer = job.account?.businessName || job.requesterName || "Customer";
  const issued = finance.invoiceIssuedAt
    ? dateOnlyFromDateTime(finance.invoiceIssuedAt)
    : dateKeyInSydney();
  const body = `<div class="top"><div><div class="brand">SORRIN</div><p class="muted">Salem Lloyd trading as Sorrin<br>ABN 46 912 027 923<br>courier@sorrin.com.au · 0452 200 359</p></div><div class="meta"><h1>${escapeHtml(finance.invoiceNumber ? "INVOICE" : "PAYMENT RECORD")}</h1><strong>${escapeHtml(invoiceTitle)}</strong><p class="muted">Issued ${escapeHtml(issued)}${finance.dueDate ? `<br>Due ${escapeHtml(finance.dueDate)}` : ""}</p></div></div>
  <div class="grid"><div class="box"><span>Bill to</span><h3>${escapeHtml(customer)}</h3><p>${escapeHtml(job.requesterName || "")}<br>${escapeHtml(job.requesterEmail || "")}<br>${escapeHtml(job.requesterPhone || "")}</p></div><div class="box"><span>Courier job</span><h3>${escapeHtml(job.reference)}</h3><p>${escapeHtml(job.pickupAddress)}<br>to<br>${escapeHtml(job.primaryDropoffAddress)}</p></div></div>
  <table><thead><tr><th>Description</th><th>Amount</th></tr></thead><tbody><tr><td>${escapeHtml(job.serviceLevel || "Courier delivery")}</td><td>${operationsMoney(finance.amountDueCents)}</td></tr><tr><td>Amount received</td><td>${operationsMoney(finance.amountPaidCents)}</td></tr><tr class="total"><td>Outstanding</td><td>${operationsMoney(finance.outstandingCents)}</td></tr></tbody></table>
  <p><strong>Status:</strong> ${escapeHtml(String(finance.effectiveStatus || finance.paymentStatus || "not started").replace(/_/g, " "))}</p>${finance.notes ? `<p class="muted"><strong>Notes:</strong> ${escapeHtml(finance.notes)}</p>` : ""}<p class="muted">Thank you for supporting an independent Ballarat business.</p>`;
  return printableOperationsDocument(invoiceTitle, body);
}

function operationsAccountStatementHtml(account) {
  const rows = (account.bookings || [])
    .map((booking) => {
      const finance = booking.finance || {};
      return `<tr><td>${escapeHtml(booking.reference)}</td><td>${escapeHtml(booking.created_at || "")}</td><td>${escapeHtml(booking.displayStatus || booking.status || "")}</td><td>${operationsMoney(booking.totalCents)}</td><td>${operationsMoney(finance.outstandingCents)}</td></tr>`;
    })
    .join("");
  const outstanding = (account.bookings || []).reduce(
    (total, booking) => total + Number(booking.finance?.outstandingCents || 0),
    0,
  );
  const body = `<div class="top"><div><div class="brand">SORRIN</div><p class="muted">USC account statement<br>Salem Lloyd trading as Sorrin<br>ABN 46 912 027 923</p></div><div class="meta"><h1>ACCOUNT STATEMENT</h1><strong>${escapeHtml(account.businessName)}</strong><p>${escapeHtml(account.usc)}</p><p class="muted">Generated ${escapeHtml(dateKeyInSydney())}</p></div></div><div class="grid"><div class="box"><span>Authorised contact</span><h3>${escapeHtml(account.contactName || account.businessName)}</h3><p>${escapeHtml(account.authorisedEmail)}<br>${escapeHtml(account.authorisedPhone)}</p></div><div class="box"><span>Account position</span><h3>${operationsMoney(outstanding)} outstanding</h3><p>${Number(account.bookingCount || 0)} total job(s)<br>${Number(account.deliveredBookingCount || 0)} delivered</p></div></div><table><thead><tr><th>Job</th><th>Date</th><th>Status</th><th>Value</th><th>Outstanding</th></tr></thead><tbody>${rows || '<tr><td colspan="5">No linked jobs.</td></tr>'}</tbody></table>`;
  return printableOperationsDocument(`${account.usc} statement`, body);
}

function operationsNotification(job, type) {
  const name = cleanText(job.requesterName, 200) || "there";
  const reference = job.reference;
  const next = (job.stops || []).find(
    (stop) => !["completed", "skipped", "cancelled"].includes(stop.stop_status),
  );
  const invoice = job.finance?.invoiceNumber || "your invoice";
  const due = job.finance?.dueDate ? ` It is due ${job.finance.dueDate}.` : "";
  const outstanding = operationsMoney(job.finance?.outstandingCents || 0);
  const templates = {
    approved: job.paymentGate?.blocked
      ? {
          subject: `Sorrin booking approved - payment required - ${reference}`,
          message: `Hi ${name},\n\nYour Sorrin courier booking ${reference} has been approved. Prepayment of ${operationsMoney(job.paymentGate.outstandingCents)} is required before dispatch. If a secure Stripe payment link has been generated, it will arrive separately.\n\nPickup: ${job.pickupAddress}\nDrop-off: ${job.primaryDropoffAddress}\n\nKind regards,\nSorrin`,
        }
      : {
          subject: `Sorrin booking confirmed - ${reference}`,
          message: `Hi ${name},\n\nYour Sorrin courier booking ${reference} has been approved and confirmed.\n\nPickup: ${job.pickupAddress}\nDrop-off: ${job.primaryDropoffAddress}\n\nKind regards,\nSorrin`,
        },
    pickup_en_route: {
      subject: `Sorrin is on the way - ${reference}`,
      message: `Hi ${name},\n\nSorrin is now on the way${next?.address ? ` to ${next.address}` : " for your courier job"}. Your reference is ${reference}.\n\nKind regards,\nSorrin`,
    },
    delivered: {
      subject: `Sorrin delivery completed - ${reference}`,
      message: `Hi ${name},\n\nYour courier job ${reference} has been completed and delivered.\n\nThank you for supporting another Aussie.\n\nKind regards,\nSorrin`,
    },
    invoice_issued: {
      subject: `Sorrin invoice ${invoice} - ${reference}`,
      message: `Hi ${name},\n\nInvoice ${invoice} has been issued for courier job ${reference}. The total is ${operationsMoney(job.finance?.amountDueCents || 0)}.${due}\n\nKind regards,\nSorrin`,
    },
    payment_reminder: {
      subject: `Payment reminder - ${invoice}`,
      message: `Hi ${name},\n\nThis is a payment reminder for ${invoice}, linked to courier job ${reference}. The outstanding balance is ${outstanding}.${due}\n\nKind regards,\nSorrin`,
    },
  };
  return templates[type] || null;
}

function normaliseOperationsJobInput(body, account = null) {
  const source = body && typeof body === "object" ? body : {};
  const pickup = source.pickup && typeof source.pickup === "object" ? source.pickup : {};
  const dropoff = source.dropoff && typeof source.dropoff === "object" ? source.dropoff : {};
  const requesterName = cleanText(
    source.requesterName || account?.contactName || account?.businessName,
    200,
  );
  const requesterEmail = normalizeEmail(
    source.requesterEmail || account?.authorisedEmail,
  );
  const requesterPhone = normalizePhone(
    source.requesterPhone || account?.authorisedPhone,
  );
  const servicePriorityValue = servicePriority(source.serviceLevel);
  const serviceLevel =
    servicePriorityValue === "priority"
      ? "PRIORITY"
      : servicePriorityValue === "express"
        ? "EXPRESS"
        : "FLEXIBLE";
  const jobDate = validDateKey(source.jobDate);
  const pickupAddress = cleanText(pickup.address || source.pickupAddress, 500);
  const dropoffAddress = cleanText(
    dropoff.address || source.primaryDropoffAddress,
    500,
  );
  const totalDollars = numberOrNull(source.totalDollars);
  const totalCents = Number.isInteger(Number(source.totalCents))
    ? Math.max(0, Number(source.totalCents))
    : totalDollars == null
      ? null
      : Math.max(0, Math.round(totalDollars * 100));
  const problems = [];
  if (!requesterName) problems.push("Customer name is required");
  if (!validEmail(requesterEmail)) problems.push("Enter a valid customer email");
  if (!validPhone(requesterPhone)) problems.push("Enter a valid Australian phone number");
  if (!jobDate) problems.push("Choose a valid job date");
  if (!pickupAddress) problems.push("Pickup address is required");
  if (!dropoffAddress) problems.push("Drop-off address is required");
  if (totalCents == null) problems.push("Enter a valid job price");

  const pickupEarliest = validTimeText(pickup.earliestTime, "09:00");
  const pickupLatest = validTimeText(pickup.latestTime, pickupEarliest);
  const dropoffEarliest = validTimeText(dropoff.earliestTime, pickupLatest);
  const dropoffLatest = validTimeText(dropoff.latestTime, dropoffEarliest);
  const quote = {
    service: serviceLevel,
    total: Number(totalCents || 0) / 100,
    routeKm: numberOrNull(source.routeKm),
    manualQuote: booleanInteger(source.manualQuote),
    cargoNotes: cleanText(source.cargoNotes, 4000) || null,
    pickup: {
      jobDate,
      address: pickupAddress,
      contact: cleanText(pickup.contactName, 200) || requesterName,
      contactPhone: normalizePhone(pickup.contactPhone || requesterPhone),
      earliestPickupTime: pickupEarliest,
      latestPickupTime: pickupLatest,
      latestCollectionDay: jobDate,
      strictWindow: booleanInteger(pickup.strictWindow),
      notes: cleanText(pickup.notes, 2000) || null,
    },
    dropoffs: [
      {
        jobDate,
        address: dropoffAddress,
        contact: cleanText(dropoff.contactName, 200) || null,
        contactPhone: normalizePhone(dropoff.contactPhone),
        earliestDropoffDay: jobDate,
        earliestDropoffTime: dropoffEarliest,
        latestDropoffTime: dropoffLatest,
        strictWindow: booleanInteger(dropoff.strictWindow),
        notes: cleanText(dropoff.notes, 2000) || null,
      },
    ],
  };
  return {
    problems,
    requesterName,
    requesterEmail,
    requesterPhone,
    serviceLevel,
    jobDate,
    pickupAddress,
    dropoffAddress,
    totalCents,
    paymentMethod: cleanText(source.paymentMethod, 80) || null,
    initialStatus: source.initialStatus === "pending" ? "pending" : "approved",
    quote,
    payloadJson: JSON.stringify({
      requester: {
        name: requesterName,
        email: requesterEmail,
        phone: requesterPhone,
        businessName: account?.businessName || null,
      },
      quote,
    }),
  };
}

async function operationsApi(request, env, url) {
  const path = url.pathname.replace(/\/+$/, "");

  if (request.method === "POST" && path === "/operations/api/login") {
    if (!env.OPS_ADMIN_PASSWORD || !env.OPS_SESSION_SECRET) {
      return operationsJson(
        {
          authenticated: false,
          error: "Operations access has not been configured",
        },
        503,
      );
    }
    const body = await requestBody(request);
    const email = normalizeEmail(body?.email);
    const password = String(body?.password || "");
    const adminEmail = normalizeEmail(
      env.OPS_ADMIN_EMAIL || "courier@sorrin.com.au",
    );
    const clientIp = request.headers.get("CF-Connecting-IP") || "unknown";
    const ipHash = await hashValue(`sorrin-operations:${clientIp}`);
    const rate = await env.DB.prepare(
      `
      SELECT COUNT(*) AS failures
      FROM operations_login_attempts
      WHERE request_ip_hash = ?
        AND succeeded = 0
        AND created_at >= datetime('now', '-15 minutes')
    `,
    )
      .bind(ipHash)
      .first();
    if (Number(rate?.failures || 0) >= 8) {
      return operationsJson(
        {
          authenticated: false,
          error: "Too many attempts. Try again in 15 minutes.",
        },
        429,
      );
    }
    const valid =
      constantTimeEqual(email, adminEmail) &&
      constantTimeEqual(password, env.OPS_ADMIN_PASSWORD);
    await env.DB.prepare(
      `
      INSERT INTO operations_login_attempts (
        id, request_ip_hash, attempted_email, succeeded
      ) VALUES (?, ?, ?, ?)
    `,
    )
      .bind(crypto.randomUUID(), ipHash, email, valid ? 1 : 0)
      .run();
    if (!valid) {
      return operationsJson(
        { authenticated: false, error: "Email or password is incorrect" },
        401,
      );
    }
    const token = await createOperationsSession(env, adminEmail);
    return operationsJson({ authenticated: true, email: adminEmail }, 200, {
      "Set-Cookie": operationsCookie(token),
    });
  }

  if (request.method === "POST" && path === "/operations/api/logout") {
    return operationsJson({ authenticated: false }, 200, {
      "Set-Cookie": expiredOperationsCookie(),
    });
  }

  const session = await operationsSession(request, env);
  if (!session)
    return operationsJson(
      { authenticated: false, error: "Sign in required" },
      401,
    );

  if (request.method === "GET" && path === "/operations/api/session") {
    return operationsJson({
      authenticated: true,
      email: session.email,
      build: OPS_BUILD,
    });
  }

  if (request.method === "GET" && path === "/operations/api/stripe/status") {
    const mode = stripeMode(env);
    return operationsJson({
      configured: stripeConfigured(env),
      mode,
      secretKey: mode === "test" || mode === "live",
      webhookSecret: String(env.STRIPE_WEBHOOK_SECRET || "").startsWith("whsec_"),
      webhookPath: "/stripe/webhook",
      productionReady: mode === "live" && stripeConfigured(env),
      configurationProblem: stripeConfigurationProblem(env),
    });
  }

  if (request.method === "GET" && path === "/operations/api/overview") {
    const synced = await syncLegacyRequests(env);
    const [jobs, accounts, finances] = await Promise.all([
      listOperationsJobs(env, "all", ""),
      listOperationsAccounts(env, ""),
      listOperationsFinance(env, ""),
    ]);
    const counts = jobs.reduce((result, job) => {
      result[job.status] = (result[job.status] || 0) + 1;
      return result;
    }, {});
    return operationsJson({ synced, counts, jobs, accounts, finances });
  }

  if (request.method === "GET" && path === "/operations/api/processor") {
    const latitude = numberOrNull(url.searchParams.get("originLat"));
    const longitude = numberOrNull(url.searchParams.get("originLng"));
    const address = cleanText(url.searchParams.get("origin"), 500);
    const label = cleanText(url.searchParams.get("originLabel"), 200);
    return operationsJson({
      processor: await buildConsciousProcessor(env, new Date(), {
        latitude,
        longitude,
        address,
        label,
      }),
    });
  }

  if (request.method === "GET" && path === "/operations/api/jobs") {
    const view = cleanText(
      url.searchParams.get("view") || "all",
      20,
    ).toLowerCase();
    const search = cleanText(url.searchParams.get("search"), 200);
    return operationsJson({
      jobs: await listOperationsJobs(env, view, search),
    });
  }

  if (request.method === "GET" && path === "/operations/api/job-record") {
    const search = cleanText(url.searchParams.get("search"), 200);
    return operationsJson({
      jobs: await listOperationsJobs(env, "all", search, true, 10000),
    });
  }

  if (request.method === "POST" && path === "/operations/api/jobs") {
    const body = await requestBody(request);
    const accountId = cleanText(body?.accountId, 100) || null;
    let account = null;
    if (accountId) {
      account = await operationsAccountDetail(env, accountId);
      if (!account) return operationsJson({ error: "USC account not found" }, 404);
      if (account.accountState !== "active") {
        return operationsJson({ error: "This USC account is suspended" }, 409);
      }
    }
    const input = normaliseOperationsJobInput(body, account);
    if (input.problems.length) {
      return operationsJson({ error: input.problems.join(". ") }, 400);
    }
    if (input.payloadJson.length > 100000) {
      return operationsJson({ error: "Job details are too large" }, 413);
    }
    const id = crypto.randomUUID();
    const numbering = await nextJobNumbers(env, account?.id || null);
    const freeAdjustment = await firstTwoJobsFreeAdjustment(
      env,
      account?.id || null,
      numbering.uscJobNumber,
      input.totalCents,
    );
    if (freeAdjustment.applied) {
      applyFirstTwoJobsFreeToQuote(input.quote, freeAdjustment);
      input.totalCents = 0;
      input.payloadJson = JSON.stringify({
        requester: {
          name: input.requesterName,
          email: input.requesterEmail,
          phone: input.requesterPhone,
          businessName: account?.businessName || null,
        },
        quote: input.quote,
      });
    }
    const reference = bookingReference(
      input.quote,
      input.pickupAddress,
      input.dropoffAddress,
      {
        usc: account?.usc || null,
        globalJobNumber: numbering.globalJobNumber,
        uscJobNumber: numbering.uscJobNumber,
      },
    );
    const requestHash = await hashValue(`operations-manual:${session.email}`);
    const verificationId = crypto.randomUUID();
    const verificationCodeHash = await hashValue(
      `${verificationId}:operations-created`,
    );
    const verificationTokenHash = await hashValue(generateToken());
    await env.DB.batch([
      env.DB.prepare(
        `INSERT INTO email_verifications (
          id, email, code_hash, request_ip_hash, expires_at, status,
          verified_at, token_hash, token_expires_at
        ) VALUES (
          ?, ?, ?, ?, datetime('now', '+10 minutes'), 'verified',
          datetime('now'), ?, datetime('now', '+30 minutes')
        )`,
      ).bind(
        verificationId,
        input.requesterEmail,
        verificationCodeHash,
        requestHash,
        verificationTokenHash,
      ),
      env.DB.prepare(
        `INSERT INTO booking_requests (
          id, reference, global_job_number, usc_job_number, booking_type, business_id, business_name_or_usc,
          requester_name, requester_email, requester_phone, payment_method,
          email_verification_id, email_verified, usc_verified, service_level,
          manual_quote, route_km, indicative_total_cents, pickup_address,
          primary_dropoff_address, status, payload_json, request_ip_hash
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?, ?, ?, ?, ?, ?, 'pending', ?, ?)`,
      ).bind(
        id,
        reference,
        numbering.globalJobNumber,
        numbering.uscJobNumber,
        account ? "business" : "guest",
        account?.id || null,
        account?.usc || account?.businessName || null,
        input.requesterName,
        input.requesterEmail,
        input.requesterPhone,
        input.paymentMethod,
        verificationId,
        account ? 1 : 0,
        input.serviceLevel,
        booleanInteger(body?.manualQuote),
        numberOrNull(body?.routeKm),
        input.totalCents,
        input.pickupAddress,
        input.dropoffAddress,
        input.payloadJson,
        requestHash,
      ),
    ]);
    const requestRow = {
      id,
      reference,
      booking_type: account ? "business" : "guest",
      business_id: account?.id || null,
      business_name_or_usc: account?.usc || account?.businessName || null,
      requester_name: input.requesterName,
      requester_email: input.requesterEmail,
      requester_phone: input.requesterPhone,
      payment_method: input.paymentMethod,
      service_level: input.serviceLevel,
      indicative_total_cents: input.totalCents,
      pickup_address: input.pickupAddress,
      primary_dropoff_address: input.dropoffAddress,
      payload_json: input.payloadJson,
      usc_verified: account ? 1 : 0,
      usc_used: account?.usc || null,
    };
    const records = await syncRequestToOrganisedJob(env, requestRow);
    const values = statusDatabaseValues(input.initialStatus);
    const eventData = JSON.stringify({
      source: "operations_manual",
      action: "operations_job_created",
      reference,
      status: input.initialStatus,
      createdBy: session.email,
      firstTwoJobsFreeApplied: Boolean(freeAdjustment.applied),
      originalTotalCents: freeAdjustment.originalTotalCents,
    });
    const statements = [
      env.DB.prepare(
        `UPDATE booking_requests SET status = ?, updated_at = datetime('now') WHERE id = ?`,
      ).bind(values.request, id),
      env.DB.prepare(
        `UPDATE bookings SET booking_status = ?, updated_at = datetime('now') WHERE id = ?`,
      ).bind(values.booking, records.bookingId),
      env.DB.prepare(
        `UPDATE jobs SET job_status = ?, scheduled_date = ?, updated_at = datetime('now') WHERE id = ?`,
      ).bind(values.job, input.jobDate, records.jobId),
      env.DB.prepare(
        `INSERT INTO job_events (id, job_id, event_type, event_data) VALUES (?, ?, 'route_updated', ?)`,
      ).bind(crypto.randomUUID(), records.jobId, eventData),
    ];
    if (input.initialStatus === "approved") {
      statements.push(
        env.DB.prepare(
          `INSERT INTO booking_events (id, booking_id, event_type, previous_status, new_status, event_data)
           VALUES (?, ?, 'status_changed', 'pending', 'approved', ?)`,
        ).bind(crypto.randomUUID(), records.bookingId, eventData),
      );
    }
    if (account) {
      statements.push(
        env.DB.prepare(
          `INSERT INTO business_events (id, business_id, event_type, event_data)
           VALUES (?, ?, 'job_created', ?)`,
        ).bind(crypto.randomUUID(), account.id, eventData),
      );
    }
    await env.DB.batch(statements);
    let createdJob = await operationsJobDetail(env, reference);
    let paymentCheckout = null;
    if (input.initialStatus === "approved") {
      paymentCheckout = await autoCheckoutForApprovedPrepayment(
        env,
        createdJob,
        session.email,
      );
      if (paymentCheckout?.attempted) {
        createdJob = await operationsJobDetail(env, reference);
      }
    }
    return operationsJson(
      {
        job: createdJob,
        jobs: await listOperationsJobs(env, "all", ""),
        paymentCheckout,
      },
      201,
    );
  }

  if (request.method === "GET" && path === "/operations/api/export/jobs.csv") {
    const jobs = await listOperationsJobs(env, "all", "");
    return csvResponse(`sorrin-jobs-${dateKeyInSydney()}.csv`, [
      ["Reference", "Status", "Customer", "Email", "Phone", "USC", "Service", "Job date", "Pickup", "Drop-off", "Value (AUD)", "Payment"],
      ...jobs.map((job) => [
        job.reference,
        job.status,
        job.businessName || job.requesterName,
        job.requesterEmail,
        job.requesterPhone,
        job.usc || "",
        job.serviceLevel,
        job.jobDate || "",
        job.pickupAddress,
        job.primaryDropoffAddress,
        (Number(job.totalCents || 0) / 100).toFixed(2),
        job.finance?.effectiveStatus || job.paymentStatus,
      ]),
    ]);
  }

  if (request.method === "GET" && path === "/operations/api/export/accounts.csv") {
    const accounts = await listOperationsAccounts(env, "");
    return csvResponse(`sorrin-usc-accounts-${dateKeyInSydney()}.csv`, [
      ["USC", "Business", "State", "Contact", "Email", "Phone", "Invoice eligible", "First two jobs free", "Terms (days)", "Jobs", "Delivered", "Activity (AUD)"],
      ...accounts.map((account) => [
        account.usc,
        account.businessName,
        account.accountState,
        account.contactName,
        account.authorisedEmail,
        account.authorisedPhone,
        account.invoiceEligible ? "Yes" : "No",
        account.firstTwoJobsFree ? "Yes" : "No",
        account.paymentTermsDays,
        account.bookingCount,
        account.deliveredBookingCount,
        (Number(account.totalActivityCents || 0) / 100).toFixed(2),
      ]),
    ]);
  }

  if (request.method === "GET" && path === "/operations/api/export/finance.csv") {
    const finances = await listOperationsFinance(env, "");
    return csvResponse(`sorrin-finance-${dateKeyInSydney()}.csv`, [
      ["Reference", "Invoice", "Customer", "USC", "Collection", "Payment", "Invoice status", "Due date", "Amount (AUD)", "Paid (AUD)", "Outstanding (AUD)"],
      ...finances.map((finance) => [
        finance.reference,
        finance.invoiceNumber || "",
        finance.businessName || finance.customerName,
        finance.usc || "",
        finance.collectionType,
        finance.effectiveStatus,
        finance.invoiceStatus,
        finance.dueDate || "",
        (Number(finance.amountDueCents || 0) / 100).toFixed(2),
        (Number(finance.amountPaidCents || 0) / 100).toFixed(2),
        (Number(finance.outstandingCents || 0) / 100).toFixed(2),
      ]),
    ]);
  }

  if (request.method === "POST" && path === "/operations/api/jobs/sync") {
    return operationsJson({ synced: await syncLegacyRequests(env, 500) });
  }

  if (request.method === "GET" && path === "/operations/api/finance") {
    return operationsJson({
      finances: await listOperationsFinance(
        env,
        cleanText(url.searchParams.get("search"), 200),
      ),
    });
  }

  const jobDetailsMatch = path.match(
    /^\/operations\/api\/jobs\/([^/]+)\/details$/,
  );
  if (request.method === "PATCH" && jobDetailsMatch) {
    const reference = decodeURIComponent(jobDetailsMatch[1]).toUpperCase();
    const current = await operationsJobDetail(env, reference);
    if (!current) return operationsJson({ error: "Job not found" }, 404);
    if (!["pending", "approved"].includes(current.status)) {
      return operationsJson(
        { error: "Only pending or approved jobs can be edited" },
        409,
      );
    }
    const body = await requestBody(request);
    const input = normaliseOperationsJobInput(body, current.account);
    if (current.quote?.firstTwoJobsFreeApplied) {
      const requestedTotal = input.totalCents;
      input.totalCents = 0;
      input.quote.originalTotal =
        numberOrNull(current.quote.originalTotal) ??
        (requestedTotal == null ? null : Number(requestedTotal) / 100);
      input.quote.total = 0;
      input.quote.firstTwoJobsFreeApplied = true;
      input.quote.firstTwoJobsFreeJobNumber =
        current.quote.firstTwoJobsFreeJobNumber || current.uscJobNumber || null;
    }
    if (input.problems.length) {
      return operationsJson({ error: input.problems.join(". ") }, 400);
    }
    if (Number(input.totalCents) < Number(current.finance?.amountPaidCents || 0)) {
      return operationsJson(
        { error: "Job price cannot be lower than the amount already received" },
        409,
      );
    }
    const previousDropoffs = Array.isArray(current.quote?.dropoffs)
      ? current.quote.dropoffs
      : [];
    const nextQuote = {
      ...current.quote,
      ...input.quote,
      pickup: { ...(current.quote?.pickup || {}), ...input.quote.pickup },
      dropoffs: [
        { ...(previousDropoffs[0] || {}), ...input.quote.dropoffs[0] },
        ...previousDropoffs.slice(1),
      ],
    };
    const payloadJson = JSON.stringify({
      requester: {
        ...(current.request || {}),
        name: input.requesterName,
        email: input.requesterEmail,
        phone: input.requesterPhone,
        businessName: current.account?.businessName || current.businessName || null,
      },
      quote: nextQuote,
    });
    const eventData = JSON.stringify({
      action: "details_updated",
      reference,
      fields: ["customer", "service", "schedule", "stops", "price"],
      previousTotalCents: current.totalCents,
      totalCents: input.totalCents,
      changedBy: session.email,
    });
    const statements = [
      env.DB.prepare(
        `UPDATE booking_requests SET
          requester_name = ?, requester_email = ?, requester_phone = ?,
          payment_method = ?, service_level = ?, manual_quote = ?, route_km = ?,
          indicative_total_cents = ?, pickup_address = ?,
          primary_dropoff_address = ?, payload_json = ?, updated_at = datetime('now')
         WHERE reference = ? COLLATE NOCASE`,
      ).bind(
        input.requesterName,
        input.requesterEmail,
        input.requesterPhone,
        input.paymentMethod,
        input.serviceLevel,
        booleanInteger(body?.manualQuote),
        numberOrNull(body?.routeKm),
        input.totalCents,
        input.pickupAddress,
        input.dropoffAddress,
        payloadJson,
        reference,
      ),
      env.DB.prepare(
        `UPDATE bookings SET customer_name = ?, customer_email = ?, customer_phone = ?,
          request_data = ?, quoted_price_cents = ?, updated_at = datetime('now')
         WHERE id = ?`,
      ).bind(
        input.requesterName,
        input.requesterEmail,
        input.requesterPhone,
        payloadJson,
        input.totalCents,
        current.bookingId,
      ),
      env.DB.prepare(
        `UPDATE jobs SET service_priority = ?, scheduled_date = ?, updated_at = datetime('now')
         WHERE id = ?`,
      ).bind(servicePriority(input.serviceLevel), input.jobDate, current.jobId),
      env.DB.prepare(
        `UPDATE operations_finance SET payment_method = ?, amount_due_cents = ?,
          updated_at = datetime('now') WHERE booking_id = ?`,
      ).bind(input.paymentMethod, input.totalCents, current.bookingId),
      env.DB.prepare(
        `INSERT INTO job_events (id, job_id, event_type, event_data)
         VALUES (?, ?, 'route_updated', ?)`,
      ).bind(crypto.randomUUID(), current.jobId, eventData),
    ];
    const suppliedStops = Array.isArray(body?.stops) ? body.stops : [];
    for (const [index, stop] of current.stops.entries()) {
      const supplied = suppliedStops.find((item) => item?.id === stop.id) || {};
      const defaults = index === 0 ? input.quote.pickup : input.quote.dropoffs[0];
      const address = cleanText(
        supplied.address || (index === 0 ? input.pickupAddress : index === 1 ? input.dropoffAddress : stop.address),
        500,
      );
      if (!address) return operationsJson({ error: `Stop ${index + 1} needs an address` }, 400);
      const earliestTime = validTimeText(
        supplied.earliestTime,
        timeOnlyFromDateTime(stop.earliest_time) ||
          (index === 0 ? defaults.earliestPickupTime : defaults.earliestDropoffTime),
      );
      const latestTime = validTimeText(
        supplied.latestTime,
        timeOnlyFromDateTime(stop.latest_time) ||
          (index === 0 ? defaults.latestPickupTime : defaults.latestDropoffTime),
      );
      statements.push(
        env.DB.prepare(
          `UPDATE job_stops SET address = ?, contact_name = ?, contact_phone = ?,
            earliest_time = ?, latest_time = ?, strict_window = ?, stop_notes = ?,
            updated_at = datetime('now') WHERE id = ? AND job_id = ?`,
        ).bind(
          address,
          cleanText(supplied.contactName || stop.contact_name || defaults.contact, 200) || null,
          normalizePhone(supplied.contactPhone || stop.contact_phone || defaults.contactPhone) || null,
          localDateTime(input.jobDate, earliestTime),
          localDateTime(input.jobDate, latestTime),
          supplied.strictWindow == null ? Number(stop.strict_window || 0) : booleanInteger(supplied.strictWindow),
          cleanText(supplied.notes ?? stop.stop_notes ?? defaults.notes, 2000) || null,
          stop.id,
          current.jobId,
        ),
      );
    }
    if (current.businessId) {
      statements.push(
        env.DB.prepare(
          `INSERT INTO business_events (id, business_id, event_type, event_data)
           VALUES (?, ?, 'job_updated', ?)`,
        ).bind(crypto.randomUUID(), current.businessId, eventData),
      );
    }
    await env.DB.batch(statements);
    let updatedJob = await operationsJobDetail(env, reference);
    let paymentCheckout = null;
    if (
      updatedJob.status === "approved" &&
      Number(input.totalCents) !== Number(current.totalCents) &&
      updatedJob.paymentGate?.blocked
    ) {
      paymentCheckout = await autoCheckoutForApprovedPrepayment(
        env,
        updatedJob,
        session.email,
      );
      if (paymentCheckout?.attempted) {
        updatedJob = await operationsJobDetail(env, reference);
      }
    }
    return operationsJson({ job: updatedJob, paymentCheckout });
  }

  const deliveryPhotoMatch = path.match(
    /^\/operations\/api\/jobs\/([^/]+)\/delivery-photo$/,
  );
  if ((request.method === "GET" || request.method === "POST") && deliveryPhotoMatch) {
    const reference = decodeURIComponent(deliveryPhotoMatch[1]).toUpperCase();
    if (!env.DELIVERY_PHOTOS) {
      return operationsJson(
        { error: "Delivery photo storage is not configured", code: "delivery_photo_storage_missing" },
        503,
      );
    }
    const current = await operationsJobDetail(env, reference);
    if (!current) return operationsJson({ error: "Job not found" }, 404);
    const stored = await env.DB.prepare(
      `SELECT * FROM delivery_proof_photos WHERE job_id = ? LIMIT 1`,
    )
      .bind(current.jobId)
      .first();

    if (request.method === "GET") {
      if (!stored?.object_key) {
        return operationsJson({ error: "Delivery photo not found" }, 404);
      }
      const object = await env.DELIVERY_PHOTOS.get(stored.object_key);
      if (!object) {
        return operationsJson({ error: "Stored delivery photo is unavailable" }, 404);
      }
      return new Response(object.body, {
        headers: {
          "Content-Type": stored.content_type || object.httpMetadata?.contentType || "application/octet-stream",
          "Content-Length": String(stored.size_bytes || object.size || ""),
          "Content-Disposition": `inline; filename="delivery-photo.${DELIVERY_PHOTO_TYPES.get(stored.content_type) || "jpg"}"`,
          "Cache-Control": "private, no-store",
          "X-Content-Type-Options": "nosniff",
          "X-Sorrin-Operations-Build": OPS_BUILD,
        },
      });
    }

    if (["declined", "cancelled"].includes(current.status)) {
      return operationsJson({ error: "A delivery photo cannot be added to a cancelled or declined job" }, 409);
    }
    let upload;
    try {
      upload = await deliveryPhotoUpload(request);
    } catch (error) {
      return operationsJson({ error: error.message }, Number(error.status || 400));
    }
    const photoId = stored?.id || crypto.randomUUID();
    const safeReference = reference.replace(/[^A-Z0-9._-]+/g, "-");
    const objectKey = `delivery-proofs/${safeReference}/${crypto.randomUUID()}.${upload.extension}`;
    await env.DELIVERY_PHOTOS.put(objectKey, upload.buffer, {
      httpMetadata: { contentType: upload.contentType },
      customMetadata: {
        reference,
        uploadedBy: session.email,
        sha256: upload.sha256,
      },
    });
    const eventData = {
      action: "delivery_photo_uploaded",
      reference,
      contentType: upload.contentType,
      sizeBytes: upload.sizeBytes,
      sha256: upload.sha256,
      replaced: Boolean(stored?.id),
      uploadedBy: session.email,
    };
    const statements = [
      env.DB.prepare(
        `INSERT INTO delivery_proof_photos (
           id, job_id, booking_id, booking_reference, object_key,
           content_type, size_bytes, sha256, uploaded_by, created_at, updated_at
         ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'), datetime('now'))
         ON CONFLICT(job_id) DO UPDATE SET
           booking_id = excluded.booking_id,
           booking_reference = excluded.booking_reference,
           object_key = excluded.object_key,
           content_type = excluded.content_type,
           size_bytes = excluded.size_bytes,
           sha256 = excluded.sha256,
           uploaded_by = excluded.uploaded_by,
           updated_at = datetime('now')`,
      ).bind(
        photoId,
        current.jobId,
        current.bookingId,
        reference,
        objectKey,
        upload.contentType,
        upload.sizeBytes,
        upload.sha256,
        session.email,
      ),
      env.DB.prepare(
        `INSERT INTO job_events (id, job_id, event_type, event_data)
         VALUES (?, ?, 'delivery_photo_uploaded', ?)`,
      ).bind(crypto.randomUUID(), current.jobId, JSON.stringify(eventData)),
    ];
    if (current.businessId) {
      statements.push(
        env.DB.prepare(
          `INSERT INTO business_events (id, business_id, event_type, event_data)
           VALUES (?, ?, 'delivery_photo_uploaded', ?)`,
        ).bind(crypto.randomUUID(), current.businessId, JSON.stringify(eventData)),
      );
    }
    try {
      await env.DB.batch(statements);
    } catch (error) {
      await env.DELIVERY_PHOTOS.delete(objectKey);
      throw error;
    }
    if (stored?.object_key && stored.object_key !== objectKey) {
      try {
        await env.DELIVERY_PHOTOS.delete(stored.object_key);
      } catch {
        // The new photo remains authoritative even if stale-object cleanup is delayed.
      }
    }
    return operationsJson({ job: await operationsJobDetail(env, reference) });
  }

  const proofMatch = path.match(
    /^\/operations\/api\/jobs\/([^/]+)\/proof-of-delivery$/,
  );
  if (request.method === "POST" && proofMatch) {
    const reference = decodeURIComponent(proofMatch[1]).toUpperCase();
    const current = await operationsJobDetail(env, reference);
    if (!current) return operationsJson({ error: "Job not found" }, 404);
    if (current.status !== "delivered") {
      return operationsJson(
        { error: "Complete the job before recording proof of delivery" },
        409,
      );
    }
    const body = await requestBody(request);
    const recipientName = cleanText(body?.recipientName, 200);
    const notes = cleanText(body?.notes, 2000) || null;
    const deliveredAt = cleanText(body?.deliveredAt, 40) || new Date().toISOString();
    if (!recipientName) {
      return operationsJson({ error: "Recipient name is required" }, 400);
    }
    const eventData = JSON.stringify({
      action: "proof_of_delivery",
      reference,
      recipientName,
      deliveredAt,
      notes,
      recordedBy: session.email,
    });
    const statements = [
      env.DB.prepare(
        `INSERT INTO job_events (id, job_id, event_type, event_data)
         VALUES (?, ?, 'note_added', ?)`,
      ).bind(crypto.randomUUID(), current.jobId, eventData),
    ];
    if (current.businessId) {
      statements.push(
        env.DB.prepare(
          `INSERT INTO business_events (id, business_id, event_type, event_data)
           VALUES (?, ?, 'proof_of_delivery', ?)`,
        ).bind(crypto.randomUUID(), current.businessId, eventData),
      );
    }
    await env.DB.batch(statements);
    return operationsJson({ job: await operationsJobDetail(env, reference) });
  }

  const notifyMatch = path.match(
    /^\/operations\/api\/jobs\/([^/]+)\/notify$/,
  );
  if (request.method === "POST" && notifyMatch) {
    const reference = decodeURIComponent(notifyMatch[1]).toUpperCase();
    const current = await operationsJobDetail(env, reference);
    if (!current) return operationsJson({ error: "Job not found" }, 404);
    const body = await requestBody(request);
    const notificationType = cleanText(body?.type, 40);
    if (!OPERATIONS_NOTIFICATION_TYPES.has(notificationType)) {
      return operationsJson({ error: "Choose a valid customer update" }, 400);
    }
    if (!validEmail(current.requesterEmail)) {
      return operationsJson({ error: "Customer email is not valid" }, 409);
    }
    if (notificationType === "invoice_issued" && !current.finance?.invoiceNumber) {
      return operationsJson({ error: "Issue the invoice before sending it" }, 409);
    }
    if (notificationType === "payment_reminder" && !current.finance?.outstandingCents) {
      return operationsJson({ error: "There is no outstanding balance" }, 409);
    }
    const notification = operationsNotification(current, notificationType);
    await sendEmail(env, {
      to: current.requesterEmail,
      subject: notification.subject,
      text: notification.message,
      html: `<div style="font-family:Arial,sans-serif;max-width:680px;margin:auto;padding:32px;color:#111;line-height:1.55;white-space:pre-line">${escapeHtml(notification.message)}</div>`,
    });
    const eventData = JSON.stringify({
      action: "customer_notified",
      reference,
      notificationType,
      recipient: current.requesterEmail,
      subject: notification.subject,
      sentBy: session.email,
    });
    const statements = [
      env.DB.prepare(
        `INSERT INTO job_events (id, job_id, event_type, event_data)
         VALUES (?, ?, 'note_added', ?)`,
      ).bind(crypto.randomUUID(), current.jobId, eventData),
    ];
    if (current.businessId) {
      statements.push(
        env.DB.prepare(
          `INSERT INTO business_events (id, business_id, event_type, event_data)
           VALUES (?, ?, 'customer_notified', ?)`,
        ).bind(crypto.randomUUID(), current.businessId, eventData),
      );
    }
    await env.DB.batch(statements);
    return operationsJson({ job: await operationsJobDetail(env, reference) });
  }

  const executeJobMatch = path.match(
    /^\/operations\/api\/jobs\/([^/]+)\/execute-next$/,
  );
  if (request.method === "POST" && executeJobMatch) {
    const reference = decodeURIComponent(executeJobMatch[1]).toUpperCase();
    const current = await operationsJobDetail(env, reference);
    if (!current) return operationsJson({ error: "Job not found" }, 404);
    const action = executionNextAction(current);
    if (!action.enabled) {
      return operationsJson(
        { error: action.label || "This job cannot advance" },
        409,
      );
    }
    const stop = current.stops.find((item) => item.id === action.stopId);
    if (!stop) return operationsJson({ error: "Next stop not found" }, 409);
    const eventData = JSON.stringify({
      action: action.code,
      changedBy: session.email,
      stopSequence: Number(stop.stop_sequence || 1),
      address: stop.address,
    });
    const statements = [];

    if (action.code === "start_job" || action.code === "start_leg") {
      statements.push(
        env.DB.prepare(
          `UPDATE booking_requests
           SET status = 'approved', updated_at = datetime('now')
           WHERE reference = ? COLLATE NOCASE`,
        ).bind(reference),
        env.DB.prepare(
          `UPDATE bookings
           SET booking_status = 'collected', updated_at = datetime('now')
           WHERE booking_reference = ? COLLATE NOCASE`,
        ).bind(reference),
        env.DB.prepare(
          `UPDATE jobs
           SET job_status = 'active', current_stop_sequence = ?,
             started_at = COALESCE(started_at, datetime('now')),
             updated_at = datetime('now')
           WHERE id = ?`,
        ).bind(stop.stop_sequence, current.jobId),
        env.DB.prepare(
          `UPDATE job_stops
           SET stop_status = 'en_route', updated_at = datetime('now')
           WHERE id = ? AND job_id = ?`,
        ).bind(stop.id, current.jobId),
      );
      if (action.code === "start_job") {
        statements.push(
          env.DB.prepare(
            `INSERT INTO job_events (id, job_id, event_type, event_data)
             VALUES (?, ?, 'started', ?)`,
          ).bind(crypto.randomUUID(), current.jobId, eventData),
        );
      }
      statements.push(
        env.DB.prepare(
          `INSERT INTO job_events
             (id, job_id, stop_id, event_type, event_data)
           VALUES (?, ?, ?, 'en_route', ?)`,
        ).bind(crypto.randomUUID(), current.jobId, stop.id, eventData),
      );
    } else if (action.code === "arrive") {
      statements.push(
        env.DB.prepare(
          `UPDATE job_stops
           SET stop_status = 'arrived',
             actual_arrival = COALESCE(actual_arrival, datetime('now')),
             updated_at = datetime('now')
           WHERE id = ? AND job_id = ?`,
        ).bind(stop.id, current.jobId),
        env.DB.prepare(
          `INSERT INTO job_events
             (id, job_id, stop_id, event_type, event_data)
           VALUES (?, ?, ?, 'arrived', ?)`,
        ).bind(crypto.randomUUID(), current.jobId, stop.id, eventData),
      );
    } else {
      const nextStop = current.stops.find(
        (item) =>
          item.id !== stop.id &&
          !["completed", "skipped", "cancelled"].includes(item.stop_status),
      );
      statements.push(
        env.DB.prepare(
          `UPDATE job_stops
           SET stop_status = 'completed',
             completed_at = COALESCE(completed_at, datetime('now')),
             updated_at = datetime('now')
           WHERE id = ? AND job_id = ?`,
        ).bind(stop.id, current.jobId),
        env.DB.prepare(
          `INSERT INTO job_events
             (id, job_id, stop_id, event_type, event_data)
           VALUES (?, ?, ?, 'stop_completed', ?)`,
        ).bind(crypto.randomUUID(), current.jobId, stop.id, eventData),
      );
      if (nextStop) {
        statements.push(
          env.DB.prepare(
            `UPDATE jobs SET current_stop_sequence = ?, updated_at = datetime('now')
             WHERE id = ?`,
          ).bind(nextStop.stop_sequence, current.jobId),
        );
      } else {
        statements.push(
          env.DB.prepare(
            `UPDATE booking_requests
             SET status = 'completed', updated_at = datetime('now')
             WHERE reference = ? COLLATE NOCASE`,
          ).bind(reference),
          env.DB.prepare(
            `UPDATE bookings
             SET booking_status = 'delivered', updated_at = datetime('now')
             WHERE booking_reference = ? COLLATE NOCASE`,
          ).bind(reference),
          env.DB.prepare(
            `UPDATE jobs
             SET job_status = 'completed', completed_at = datetime('now'),
               updated_at = datetime('now')
             WHERE id = ?`,
          ).bind(current.jobId),
          env.DB.prepare(
            `INSERT INTO job_events (id, job_id, event_type, event_data)
             VALUES (?, ?, 'completed', ?)`,
          ).bind(crypto.randomUUID(), current.jobId, eventData),
        );
      }
    }
    await env.DB.batch(statements);
    return operationsJson({
      action: action.code,
      job: await operationsJobDetail(env, reference),
    });
  }

  const jobFinanceMatch = path.match(
    /^\/operations\/api\/jobs\/([^/]+)\/finance$/,
  );
  if (request.method === "PATCH" && jobFinanceMatch) {
    const reference = decodeURIComponent(jobFinanceMatch[1]).toUpperCase();
    const body = await requestBody(request);
    const currentJob = await operationsJobDetail(env, reference);
    if (!currentJob) return operationsJson({ error: "Job not found" }, 404);
    if (!currentJob.finance) {
      return operationsJson(
        { error: "Finance record missing. Apply migration 002 first." },
        409,
      );
    }
    if (
      body?.collectionType === "invoice" &&
      !currentJob.account?.invoiceEligible
    ) {
      return operationsJson(
        { error: "Invoice collection is only available to an invoice-eligible USC account" },
        409,
      );
    }
    const invoiceNumber = await generatedInvoiceNumber(env);
    const next = normaliseFinanceUpdate(
      currentJob.finance,
      body || {},
      invoiceNumber,
      dateKeyInSydney(),
      Number(currentJob.account?.paymentTermsDays || 0),
    );
    const changedFields = [
      "collectionType",
      "paymentStatus",
      "paymentMethod",
      "amountDueCents",
      "amountPaidCents",
      "invoiceStatus",
      "invoiceNumber",
      "dueDate",
      "notes",
    ].filter((field) => String(currentJob.finance[field] ?? "") !== String(next[field] ?? ""));
    if (!changedFields.length) {
      return operationsJson({
        job: currentJob,
        finances: await listOperationsFinance(env, ""),
      });
    }
    const eventData = {
      reference,
      fields: changedFields,
      collectionType: next.collectionType,
      paymentStatus: next.paymentStatus,
      amountPaidCents: next.amountPaidCents,
      invoiceStatus: next.invoiceStatus,
      invoiceNumber: next.invoiceNumber,
      changedBy: session.email,
    };
    const statements = [
      env.DB.prepare(
        `UPDATE operations_finance SET
          business_id = ?, collection_type = ?, payment_status = ?,
          payment_method = ?, amount_due_cents = ?, amount_paid_cents = ?,
          invoice_status = ?, invoice_number = ?, invoice_issued_at = ?,
          due_date = ?, paid_at = ?, finance_notes = ?,
          updated_at = datetime('now')
         WHERE id = ?`,
      ).bind(
        currentJob.businessId || null,
        next.collectionType,
        next.paymentStatus,
        next.paymentMethod,
        next.amountDueCents,
        next.amountPaidCents,
        next.invoiceStatus,
        next.invoiceNumber,
        next.invoiceIssuedAt,
        next.dueDate,
        next.paidAt,
        next.notes,
        currentJob.finance.id,
      ),
      env.DB.prepare(
        `UPDATE bookings SET payment_status = ?, updated_at = datetime('now')
         WHERE id = ?`,
      ).bind(next.paymentStatus, currentJob.bookingId),
      env.DB.prepare(
        `INSERT INTO operations_finance_events
          (id, finance_id, booking_id, event_type, event_data)
         VALUES (?, ?, ?, 'finance_updated', ?)`,
      ).bind(
        crypto.randomUUID(),
        currentJob.finance.id,
        currentJob.bookingId,
        JSON.stringify(eventData),
      ),
    ];
    if (currentJob.businessId) {
      statements.push(
        env.DB.prepare(
          `INSERT INTO business_events (id, business_id, event_type, event_data)
           VALUES (?, ?, 'finance_updated', ?)`,
        ).bind(
          crypto.randomUUID(),
          currentJob.businessId,
          JSON.stringify(eventData),
        ),
      );
    }
    await env.DB.batch(statements);
    return operationsJson({
      job: await operationsJobDetail(env, reference),
      finances: await listOperationsFinance(env, ""),
    });
  }

  const stripeCheckoutMatch = path.match(
    /^\/operations\/api\/jobs\/([^/]+)\/stripe-checkout$/,
  );
  if (request.method === "POST" && stripeCheckoutMatch) {
    const reference = decodeURIComponent(stripeCheckoutMatch[1]).toUpperCase();
    const currentJob = await operationsJobDetail(env, reference);
    if (!currentJob) return operationsJson({ error: "Job not found" }, 404);
    if (["declined", "cancelled"].includes(currentJob.status)) {
      return operationsJson(
        { error: "A cancelled or declined job cannot take payment" },
        409,
      );
    }
    try {
      const checkout = await createStripeCheckoutForJob(
        env,
        currentJob,
        session.email,
      );
      return operationsJson(
        {
          checkout,
          job: await operationsJobDetail(env, reference),
          finances: await listOperationsFinance(env, ""),
        },
        checkout.reused ? 200 : 201,
      );
    } catch (error) {
      return operationsJson({ error: error.message }, 409);
    }
  }

  const jobAccountMatch = path.match(
    /^\/operations\/api\/jobs\/([^/]+)\/account$/,
  );
  if (request.method === "PATCH" && jobAccountMatch) {
    const reference = decodeURIComponent(jobAccountMatch[1]).toUpperCase();
    const body = await requestBody(request);
    const accountId = cleanText(body?.accountId, 100) || null;
    const current = await operationsJobDetail(env, reference);
    if (!current) return operationsJson({ error: "Job not found" }, 404);
    if (current.businessId === accountId) {
      return operationsJson({ job: current });
    }
    let target = null;
    if (accountId) {
      target = await env.DB.prepare(
        `
        SELECT id, business_name, usc, account_state, invoice_eligible
        FROM businesses
        WHERE id = ?
        LIMIT 1
      `,
      )
        .bind(accountId)
        .first();
      if (!target) return operationsJson({ error: "USC account not found" }, 404);
      if (target.account_state === "suspended") {
        return operationsJson(
          { error: "Reactivate this USC account before linking new work" },
          409,
        );
      }
    }
    const previousAccountId = current.businessId || null;
    const accountAction = accountId ? "account_linked" : "account_unlinked";
    const eventData = {
      action: accountAction,
      reference,
      previousAccountId,
      accountId,
      usc: target?.usc || null,
      changedBy: session.email,
    };
    const statements = [
      env.DB.prepare(
        `
        UPDATE booking_requests
        SET business_id = ?, updated_at = datetime('now')
        WHERE reference = ? COLLATE NOCASE
      `,
      ).bind(accountId, reference),
      env.DB.prepare(
        `
        UPDATE bookings
        SET business_id = ?, usc_used = ?, updated_at = datetime('now')
        WHERE booking_reference = ? COLLATE NOCASE
      `,
      ).bind(accountId, target?.usc || null, reference),
      env.DB.prepare(
        `
        UPDATE operations_finance
        SET business_id = ?,
          collection_type = CASE WHEN ? = 1 THEN 'invoice' ELSE 'prepayment' END,
          invoice_status = CASE
            WHEN payment_status = 'paid' THEN CASE WHEN ? = 1 THEN 'paid' ELSE 'not_required' END
            WHEN ? = 1 THEN CASE WHEN invoice_status = 'not_required' THEN 'draft' ELSE invoice_status END
            ELSE 'not_required'
          END,
          invoice_number = CASE WHEN ? = 1 THEN invoice_number ELSE NULL END,
          invoice_issued_at = CASE WHEN ? = 1 THEN invoice_issued_at ELSE NULL END,
          due_date = CASE WHEN ? = 1 THEN due_date ELSE NULL END,
          updated_at = datetime('now')
        WHERE booking_id = ?
      `,
      ).bind(
        accountId,
        target?.invoice_eligible ? 1 : 0,
        target?.invoice_eligible ? 1 : 0,
        target?.invoice_eligible ? 1 : 0,
        target?.invoice_eligible ? 1 : 0,
        target?.invoice_eligible ? 1 : 0,
        target?.invoice_eligible ? 1 : 0,
        current.bookingId,
      ),
    ];
    if (previousAccountId) {
      statements.push(
        env.DB.prepare(
          `
          INSERT INTO business_events (id, business_id, event_type, event_data)
          VALUES (?, ?, 'booking_unlinked', ?)
        `,
        ).bind(
          crypto.randomUUID(),
          previousAccountId,
          JSON.stringify(eventData),
        ),
      );
    }
    if (accountId) {
      statements.push(
        env.DB.prepare(
          `
          INSERT INTO business_events (id, business_id, event_type, event_data)
          VALUES (?, ?, 'booking_linked', ?)
        `,
        ).bind(crypto.randomUUID(), accountId, JSON.stringify(eventData)),
      );
    }
    await env.DB.batch(statements);
    return operationsJson({
      job: await operationsJobDetail(env, reference),
      accounts: await listOperationsAccounts(env, ""),
      finances: await listOperationsFinance(env, ""),
    });
  }

  const jobMatch = path.match(/^\/operations\/api\/jobs\/([^/]+)$/);
  if (jobMatch) {
    const reference = decodeURIComponent(jobMatch[1]).toUpperCase();
    if (request.method === "GET") {
      const job = await operationsJobDetail(env, reference);
      return job
        ? operationsJson({ job })
        : operationsJson({ error: "Job not found" }, 404);
    }
    if (request.method === "PATCH") {
      const body = await requestBody(request);
      const status = cleanText(body?.status, 20).toLowerCase();
      const note = cleanText(body?.note, 2000);
      if (!OPERATIONS_STATUSES.has(status)) {
        return operationsJson({ error: "Choose a valid status" }, 400);
      }
      const current = await operationsJobDetail(env, reference);
      if (!current) return operationsJson({ error: "Job not found" }, 404);
      if (status === "delivered" && !current.deliveryPhoto) {
        return operationsJson(
          {
            error: "Upload a delivery photo before marking this job as delivered",
            code: "delivery_photo_required",
          },
          409,
        );
      }
      if (status === "active" && current.status !== "active") {
        const gate = paymentDispatchGate(current);
        if (gate.blocked) {
          return operationsJson(
            {
              error: `Prepayment of ${operationsMoney(gate.outstandingCents)} is required before dispatch`,
              code: gate.code,
            },
            409,
          );
        }
      }
      const values = statusDatabaseValues(status);
      const eventType =
        status === "active"
          ? "started"
          : status === "delivered"
            ? "completed"
            : ["declined", "cancelled"].includes(status)
              ? "cancelled"
              : "route_updated";
      const eventData = JSON.stringify({
        previousStatus: current.status,
        newStatus: status,
        note: note || null,
        changedBy: session.email,
      });
      const statements = [
        env.DB.prepare(
          `
          UPDATE booking_requests
          SET status = ?, updated_at = datetime('now')
          WHERE reference = ? COLLATE NOCASE
        `,
        ).bind(values.request, reference),
        env.DB.prepare(
          `
          UPDATE bookings
          SET booking_status = ?, updated_at = datetime('now')
          WHERE booking_reference = ? COLLATE NOCASE
        `,
        ).bind(values.booking, reference),
        env.DB.prepare(
          `
          UPDATE jobs
          SET job_status = ?,
            started_at = CASE WHEN ? = 'active' AND started_at IS NULL THEN datetime('now') ELSE started_at END,
            completed_at = CASE WHEN ? = 'completed' THEN datetime('now') ELSE completed_at END,
            updated_at = datetime('now')
          WHERE job_reference = ? COLLATE NOCASE
        `,
        ).bind(values.job, values.job, values.job, reference),
        env.DB.prepare(
          `
          INSERT INTO booking_events (
            id, booking_id, event_type, previous_status, new_status, event_data
          ) VALUES (?, ?, 'status_changed', ?, ?, ?)
        `,
        ).bind(
          crypto.randomUUID(),
          current.bookingId,
          current.status,
          status,
          eventData,
        ),
        env.DB.prepare(
          `
          INSERT INTO job_events (id, job_id, event_type, event_data)
          VALUES (?, ?, ?, ?)
        `,
        ).bind(crypto.randomUUID(), current.jobId, eventType, eventData),
      ];
      if (status === "delivered") {
        statements.push(
          env.DB.prepare(
            `
          UPDATE job_stops SET stop_status = 'completed',
            completed_at = COALESCE(completed_at, datetime('now')),
            updated_at = datetime('now')
          WHERE job_id = ?
        `,
          ).bind(current.jobId),
        );
      }
      if (note) {
        statements.push(
          env.DB.prepare(
            `
          UPDATE jobs SET driver_notes = CASE
            WHEN driver_notes IS NULL OR driver_notes = '' THEN ?
            ELSE driver_notes || char(10) || ? END
          WHERE id = ?
        `,
          ).bind(note, note, current.jobId),
        );
      }
      await env.DB.batch(statements);
      let updatedJob = await operationsJobDetail(env, reference);
      let paymentCheckout = null;
      if (status === "approved" && current.status !== "approved") {
        paymentCheckout = await autoCheckoutForApprovedPrepayment(
          env,
          updatedJob,
          session.email,
        );
        if (paymentCheckout?.attempted) {
          updatedJob = await operationsJobDetail(env, reference);
        }
      }
      return operationsJson({ job: updatedJob, paymentCheckout });
    }
  }

  const archiveJobMatch = path.match(
    /^\/operations\/api\/jobs\/([^/]+)\/(archive|restore|force-close)$/,
  );
  if (request.method === "POST" && archiveJobMatch) {
    const reference = decodeURIComponent(archiveJobMatch[1]).toUpperCase();
    const action = archiveJobMatch[2];
    const current = await operationsJobDetail(env, reference);
    if (!current) return operationsJson({ error: "Job not found" }, 404);

    if (action === "archive") {
      await env.DB.batch([
        env.DB.prepare(
          `UPDATE booking_requests SET operations_archived_at = datetime('now'),
             operations_archived_by = ?, updated_at = datetime('now')
           WHERE reference = ? COLLATE NOCASE`,
        ).bind(session.email, reference),
        env.DB.prepare(
          `INSERT INTO job_events (id, job_id, event_type, event_data)
           VALUES (?, ?, 'archived', ?)`,
        ).bind(
          crypto.randomUUID(),
          current.jobId,
          JSON.stringify({ action: "archived", changedBy: session.email }),
        ),
      ]);
      return operationsJson({ archived: true, reference });
    }

    if (action === "restore") {
      await env.DB.batch([
        env.DB.prepare(
          `UPDATE booking_requests SET operations_archived_at = NULL,
             operations_archived_by = NULL, updated_at = datetime('now')
           WHERE reference = ? COLLATE NOCASE`,
        ).bind(reference),
        env.DB.prepare(
          `INSERT INTO job_events (id, job_id, event_type, event_data)
           VALUES (?, ?, 'restored', ?)`,
        ).bind(
          crypto.randomUUID(),
          current.jobId,
          JSON.stringify({ action: "restored", changedBy: session.email }),
        ),
      ]);
      return operationsJson({ job: await operationsJobDetail(env, reference) });
    }

    if (!current.deliveryPhoto) {
      return operationsJson(
        {
          error: "Upload a delivery photo before force-closing this job as delivered",
          code: "delivery_photo_required",
        },
        409,
      );
    }

    const eventData = JSON.stringify({
      action: "force_closed",
      previousStatus: current.status,
      changedBy: session.email,
    });
    await env.DB.batch([
      env.DB.prepare(
        `UPDATE booking_requests SET status = 'completed', updated_at = datetime('now')
         WHERE reference = ? COLLATE NOCASE`,
      ).bind(reference),
      env.DB.prepare(
        `UPDATE bookings SET booking_status = 'delivered', updated_at = datetime('now')
         WHERE booking_reference = ? COLLATE NOCASE`,
      ).bind(reference),
      env.DB.prepare(
        `UPDATE jobs SET job_status = 'completed',
           completed_at = COALESCE(completed_at, datetime('now')),
           updated_at = datetime('now')
         WHERE job_reference = ? COLLATE NOCASE`,
      ).bind(reference),
      env.DB.prepare(
        `UPDATE job_stops SET stop_status = 'completed',
           completed_at = COALESCE(completed_at, datetime('now')),
           updated_at = datetime('now')
         WHERE job_id = ? AND stop_status NOT IN ('completed','skipped','cancelled')`,
      ).bind(current.jobId),
      env.DB.prepare(
        `INSERT INTO booking_events (
           id, booking_id, event_type, previous_status, new_status, event_data
         ) VALUES (?, ?, 'status_changed', ?, 'delivered', ?)`,
      ).bind(
        crypto.randomUUID(),
        current.bookingId,
        current.status,
        eventData,
      ),
      env.DB.prepare(
        `INSERT INTO job_events (id, job_id, event_type, event_data)
         VALUES (?, ?, 'force_closed', ?)`,
      ).bind(crypto.randomUUID(), current.jobId, eventData),
    ]);
    return operationsJson({ job: await operationsJobDetail(env, reference) });
  }

  const stopMatch = path.match(
    /^\/operations\/api\/jobs\/([^/]+)\/stops\/([^/]+)$/,
  );
  if (request.method === "PATCH" && stopMatch) {
    const reference = decodeURIComponent(stopMatch[1]).toUpperCase();
    const stopId = decodeURIComponent(stopMatch[2]);
    const body = await requestBody(request);
    const stopStatus = cleanText(body?.status, 20).toLowerCase();
    if (
      ![
        "pending",
        "en_route",
        "arrived",
        "completed",
        "skipped",
        "cancelled",
      ].includes(stopStatus)
    ) {
      return operationsJson({ error: "Choose a valid stop status" }, 400);
    }
    const job = await operationsJobDetail(env, reference);
    if (!job || !job.stops.some((stop) => stop.id === stopId)) {
      return operationsJson({ error: "Stop not found" }, 404);
    }
    const completesFinalStop =
      stopStatus === "completed" &&
      job.stops.every(
        (stop) =>
          stop.id === stopId ||
          ["completed", "skipped", "cancelled"].includes(stop.stop_status),
      );
    if (completesFinalStop && !job.deliveryPhoto) {
      return operationsJson(
        {
          error: "Upload a delivery photo before completing the final stop",
          code: "delivery_photo_required",
        },
        409,
      );
    }
    if (stopStatus === "en_route" && job.status === "approved") {
      const gate = paymentDispatchGate(job);
      if (gate.blocked) {
        return operationsJson(
          {
            error: `Prepayment of ${operationsMoney(gate.outstandingCents)} is required before dispatch`,
            code: gate.code,
          },
          409,
        );
      }
    }
    const stopEventType =
      stopStatus === "completed"
        ? "stop_completed"
        : stopStatus === "en_route"
          ? "en_route"
          : stopStatus === "arrived"
            ? "arrived"
            : stopStatus === "cancelled"
              ? "cancelled"
              : "route_updated";
    const stopStatements = [
      env.DB.prepare(
        `
        UPDATE job_stops SET stop_status = ?,
          actual_arrival = CASE WHEN ? = 'arrived' THEN datetime('now') ELSE actual_arrival END,
          completed_at = CASE WHEN ? = 'completed' THEN datetime('now') ELSE completed_at END,
          updated_at = datetime('now')
        WHERE id = ? AND job_id = ?
      `,
      ).bind(stopStatus, stopStatus, stopStatus, stopId, job.jobId),
      env.DB.prepare(
        `
        INSERT INTO job_events (id, job_id, stop_id, event_type, event_data)
        VALUES (?, ?, ?, ?, ?)
      `,
      ).bind(
        crypto.randomUUID(),
        job.jobId,
        stopId,
        stopEventType,
        JSON.stringify({ status: stopStatus, changedBy: session.email }),
      ),
    ];
    if (stopStatus === "en_route" && job.status === "approved") {
      stopStatements.push(
        env.DB.prepare(
          `UPDATE bookings SET booking_status = 'collected', updated_at = datetime('now')
           WHERE booking_reference = ? COLLATE NOCASE`,
        ).bind(reference),
        env.DB.prepare(
          `UPDATE jobs SET job_status = 'active',
             started_at = COALESCE(started_at, datetime('now')),
             updated_at = datetime('now') WHERE id = ?`,
        ).bind(job.jobId),
        env.DB.prepare(
          `INSERT INTO job_events (id, job_id, event_type, event_data)
           VALUES (?, ?, 'started', ?)`,
        ).bind(
          crypto.randomUUID(),
          job.jobId,
          JSON.stringify({ changedBy: session.email }),
        ),
      );
    }
    await env.DB.batch(stopStatements);
    const refreshed = await operationsJobDetail(env, reference);
    const nextStop = refreshed.stops.find(
      (stop) =>
        !["completed", "skipped", "cancelled"].includes(stop.stop_status),
    );
    if (nextStop) {
      await env.DB.prepare(
        `
        UPDATE jobs SET current_stop_sequence = ?, updated_at = datetime('now')
        WHERE id = ?
      `,
      )
        .bind(nextStop.stop_sequence, job.jobId)
        .run();
    } else if (stopStatus === "completed") {
      await env.DB.batch([
        env.DB.prepare(
          `UPDATE booking_requests SET status = 'completed', updated_at = datetime('now')
           WHERE reference = ? COLLATE NOCASE`,
        ).bind(reference),
        env.DB.prepare(
          `UPDATE bookings SET booking_status = 'delivered', updated_at = datetime('now')
           WHERE booking_reference = ? COLLATE NOCASE`,
        ).bind(reference),
        env.DB.prepare(
          `UPDATE jobs SET job_status = 'completed', completed_at = datetime('now'),
             updated_at = datetime('now') WHERE id = ?`,
        ).bind(job.jobId),
        env.DB.prepare(
          `INSERT INTO job_events (id, job_id, event_type, event_data)
           VALUES (?, ?, 'completed', ?)`,
        ).bind(
          crypto.randomUUID(),
          job.jobId,
          JSON.stringify({ changedBy: session.email }),
        ),
      ]);
    }
    return operationsJson({ job: await operationsJobDetail(env, reference) });
  }

  if (request.method === "GET" && path === "/operations/api/accounts") {
    return operationsJson({
      accounts: await listOperationsAccounts(
        env,
        cleanText(url.searchParams.get("search"), 200),
      ),
    });
  }

  if (request.method === "POST" && path === "/operations/api/accounts") {
    const body = await requestBody(request);
    const businessName = cleanText(body?.businessName, 250);
    let usc = normaliseUsc(body?.usc);
    const authorisedEmail = normalizeEmail(body?.authorisedEmail);
    const authorisedPhone = normalizePhone(body?.authorisedPhone);
    const contactName = cleanText(body?.contactName, 200) || null;
    const accountState =
      body?.accountState === "suspended" ? "suspended" : "active";
    const invoiceEligible = booleanInteger(body?.invoiceEligible);
    const paymentTermsDays = Math.max(
      0,
      Math.min(120, Number(body?.paymentTermsDays || 0)),
    );
    const completedPrepaidDeliveries = Math.max(
      0,
      Math.floor(Number(body?.completedPrepaidDeliveries || 0)),
    );
    const firstTwoJobsFree = booleanInteger(body?.firstTwoJobsFree);
    const notes = cleanText(body?.notes, 5000) || null;
    if (!businessName) {
      return operationsJson({ error: "Business name is required" }, 400);
    }
    if (authorisedEmail && !validEmail(authorisedEmail)) {
      return operationsJson({ error: "Enter a valid authorised email or leave it blank" }, 400);
    }
    if (authorisedPhone && !validPhone(authorisedPhone)) {
      return operationsJson({ error: "Enter a valid authorised phone or leave it blank" }, 400);
    }
    if (!usc) usc = await generatedUsc(env, businessName);
    const id = crypto.randomUUID();
    try {
      await env.DB.batch([
        env.DB.prepare(
          `
          INSERT INTO businesses (
            id, business_name, usc, authorised_email, authorised_phone,
            status, contact_name, account_state, invoice_eligible,
            payment_terms_days, account_notes, completed_prepaid_deliveries,
            first_two_jobs_free
          ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        `,
        ).bind(
          id,
          businessName,
          usc,
          authorisedEmail,
          authorisedPhone,
          accountStatusForLegacy(accountState, invoiceEligible),
          contactName,
          accountState,
          invoiceEligible,
          paymentTermsDays,
          notes,
          completedPrepaidDeliveries,
          firstTwoJobsFree,
        ),
        env.DB.prepare(
          `
          INSERT INTO business_events (id, business_id, event_type, event_data)
          VALUES (?, ?, 'created', ?)
        `,
        ).bind(
          crypto.randomUUID(),
          id,
          JSON.stringify({ createdBy: session.email }),
        ),
      ]);
    } catch (error) {
      return operationsJson(
        { error: String(error.message || "Account could not be created") },
        409,
      );
    }
    return operationsJson(
      { account: await operationsAccountDetail(env, id) },
      201,
    );
  }

  const accountMatch = path.match(/^\/operations\/api\/accounts\/([^/]+)$/);
  if (accountMatch) {
    const businessId = decodeURIComponent(accountMatch[1]);
    if (request.method === "GET") {
      const account = await operationsAccountDetail(env, businessId);
      return account
        ? operationsJson({ account })
        : operationsJson({ error: "Account not found" }, 404);
    }
    if (request.method === "PATCH") {
      const body = await requestBody(request);
      const current = await operationsAccountDetail(env, businessId);
      if (!current) return operationsJson({ error: "Account not found" }, 404);
      const businessName = cleanText(
        body?.businessName ?? current.businessName,
        250,
      );
      const usc = normaliseUsc(body?.usc ?? current.usc);
      const authorisedEmail = normalizeEmail(
        body?.authorisedEmail ?? current.authorisedEmail,
      );
      const authorisedPhone = normalizePhone(
        body?.authorisedPhone ?? current.authorisedPhone,
      );
      const contactName =
        cleanText(body?.contactName ?? current.contactName, 200) || null;
      const accountState =
        (body?.accountState ?? current.accountState) === "suspended"
          ? "suspended"
          : "active";
      const invoiceEligible = booleanInteger(
        body?.invoiceEligible ?? current.invoiceEligible,
      );
      const paymentTermsDays = Math.max(
        0,
        Math.min(
          120,
          Number(body?.paymentTermsDays ?? current.paymentTermsDays),
        ),
      );
      const completedPrepaidDeliveries = Math.max(
        0,
        Math.floor(
          Number(
            body?.completedPrepaidDeliveries ??
              current.completedPrepaidDeliveries,
          ),
        ),
      );
      const firstTwoJobsFree = booleanInteger(
        body?.firstTwoJobsFree ?? current.firstTwoJobsFree,
      );
      const notes = cleanText(body?.notes ?? current.notes, 5000) || null;
      if (!businessName || !usc) {
        return operationsJson({ error: "Business name and USC are required" }, 400);
      }
      if (authorisedEmail && !validEmail(authorisedEmail)) {
        return operationsJson({ error: "Enter a valid authorised email or leave it blank" }, 400);
      }
      if (authorisedPhone && !validPhone(authorisedPhone)) {
        return operationsJson({ error: "Enter a valid authorised phone or leave it blank" }, 400);
      }
      const changedFields = [
        current.businessName !== businessName ? "business name" : null,
        current.usc !== usc ? "USC" : null,
        current.contactName !== contactName ? "contact name" : null,
        current.authorisedEmail !== authorisedEmail ? "email" : null,
        normalizePhone(current.authorisedPhone) !== authorisedPhone
          ? "phone"
          : null,
        current.accountState !== accountState ? "account state" : null,
        Boolean(current.invoiceEligible) !== Boolean(invoiceEligible)
          ? "invoice eligibility"
          : null,
        Number(current.paymentTermsDays || 0) !== paymentTermsDays
          ? "payment terms"
          : null,
        Number(current.completedPrepaidDeliveries || 0) !==
        completedPrepaidDeliveries
          ? "completed prepaid deliveries"
          : null,
        Boolean(current.firstTwoJobsFree) !== Boolean(firstTwoJobsFree)
          ? "first two jobs free"
          : null,
        (current.notes || null) !== notes ? "notes" : null,
      ].filter(Boolean);
      await env.DB.batch([
        env.DB.prepare(
          `
          UPDATE businesses SET
            business_name = ?, usc = ?, authorised_email = ?, authorised_phone = ?,
            status = ?, contact_name = ?, account_state = ?, invoice_eligible = ?,
            payment_terms_days = ?, account_notes = ?, updated_at = datetime('now'),
            completed_prepaid_deliveries = ?, first_two_jobs_free = ?
          WHERE id = ?
        `,
        ).bind(
          businessName,
          usc,
          authorisedEmail,
          authorisedPhone,
          accountStatusForLegacy(accountState, invoiceEligible),
          contactName,
          accountState,
          invoiceEligible,
          paymentTermsDays,
          notes,
          completedPrepaidDeliveries,
          firstTwoJobsFree,
          businessId,
        ),
        env.DB.prepare(
          `
          INSERT INTO business_events (id, business_id, event_type, event_data)
          VALUES (?, ?, 'updated', ?)
        `,
        ).bind(
          crypto.randomUUID(),
          businessId,
          JSON.stringify({ updatedBy: session.email, fields: changedFields }),
        ),
      ]);
      return operationsJson({
        account: await operationsAccountDetail(env, businessId),
      });
    }
    if (request.method === "DELETE") {
      const current = await operationsAccountDetail(env, businessId);
      if (!current) return operationsJson({ error: "Account not found" }, 404);
      await env.DB.batch([
        env.DB.prepare(
          `UPDATE booking_requests
           SET business_id = NULL, usc_verified = 0, updated_at = datetime('now')
           WHERE business_id = ?`,
        ).bind(businessId),
        env.DB.prepare(
          `UPDATE bookings
           SET business_id = NULL, updated_at = datetime('now')
           WHERE business_id = ?`,
        ).bind(businessId),
        env.DB.prepare(
          `UPDATE operations_finance
           SET business_id = NULL, updated_at = datetime('now')
           WHERE business_id = ?`,
        ).bind(businessId),
        env.DB.prepare(`DELETE FROM benefit_redemptions WHERE business_id = ?`).bind(
          businessId,
        ),
        env.DB.prepare(`DELETE FROM business_tags WHERE business_id = ?`).bind(
          businessId,
        ),
        env.DB.prepare(`DELETE FROM business_events WHERE business_id = ?`).bind(
          businessId,
        ),
        env.DB.prepare(`DELETE FROM businesses WHERE id = ?`).bind(businessId),
      ]);
      return operationsJson({
        deleted: true,
        id: businessId,
        usc: current.usc,
        retainedJobCount: Number(current.bookingCount || 0),
      });
    }
  }

  const accountTagMatch = path.match(
    /^\/operations\/api\/accounts\/([^/]+)\/tags$/,
  );
  if (request.method === "POST" && accountTagMatch) {
    const businessId = decodeURIComponent(accountTagMatch[1]);
    const body = await requestBody(request);
    const code = normaliseUsc(body?.code);
    const tag = await env.DB.prepare(
      `SELECT id FROM tags WHERE code = ? COLLATE NOCASE AND active = 1`,
    )
      .bind(code)
      .first();
    if (!tag) return operationsJson({ error: "Tag not found" }, 404);
    await env.DB.batch([
      env.DB.prepare(
        `
        INSERT OR IGNORE INTO business_tags (id, business_id, tag_id, assigned_by)
        VALUES (?, ?, ?, ?)
      `,
      ).bind(crypto.randomUUID(), businessId, tag.id, session.email),
      env.DB.prepare(
        `
        INSERT INTO business_events (id, business_id, event_type, event_data)
        VALUES (?, ?, 'tag_assigned', ?)
      `,
      ).bind(
        crypto.randomUUID(),
        businessId,
        JSON.stringify({ code, assignedBy: session.email }),
      ),
    ]);
    return operationsJson({
      account: await operationsAccountDetail(env, businessId),
    });
  }
  if (request.method === "DELETE" && accountTagMatch) {
    const businessId = decodeURIComponent(accountTagMatch[1]);
    const code = normaliseUsc(url.searchParams.get("code"));
    await env.DB.batch([
      env.DB.prepare(
        `
        DELETE FROM business_tags
        WHERE business_id = ?
          AND tag_id IN (SELECT id FROM tags WHERE code = ? COLLATE NOCASE)
      `,
      ).bind(businessId, code),
      env.DB.prepare(
        `
        INSERT INTO business_events (id, business_id, event_type, event_data)
        VALUES (?, ?, 'tag_removed', ?)
      `,
      ).bind(
        crypto.randomUUID(),
        businessId,
        JSON.stringify({ code, changedBy: session.email }),
      ),
    ]);
    return operationsJson({
      account: await operationsAccountDetail(env, businessId),
    });
  }

  const accountBenefitMatch = path.match(
    /^\/operations\/api\/accounts\/([^/]+)\/benefits\/([^/]+)\/redeem$/,
  );
  if (request.method === "POST" && accountBenefitMatch) {
    const businessId = decodeURIComponent(accountBenefitMatch[1]);
    const benefitId = decodeURIComponent(accountBenefitMatch[2]);
    const body = await requestBody(request);
    const reference = cleanText(body?.reference, 180).toUpperCase();
    const quantity = Math.max(1, Math.floor(Number(body?.quantity || 1)));
    const note = cleanText(body?.note, 1000) || null;
    const account = await operationsAccountDetail(env, businessId);
    if (!account) return operationsJson({ error: "Account not found" }, 404);
    const benefit = (account.benefits || []).find(
      (item) => item.benefit_id === benefitId,
    );
    if (!benefit)
      return operationsJson({ error: "Benefit is not active for this account" }, 404);
    if (!benefit.available)
      return operationsJson(
        {
          error: benefit.resetsAt
            ? `Benefit is already used and resets ${benefit.resetsAt}`
            : "Benefit is already used for this period",
        },
        409,
      );
    if (quantity > Number(benefit.remainingQuantity || 0)) {
      return operationsJson(
        { error: `This benefit covers up to ${benefit.remainingQuantity} item(s)` },
        400,
      );
    }
    if (!reference)
      return operationsJson(
        { error: "Choose the linked job receiving this benefit" },
        400,
      );
    const booking = await env.DB.prepare(
      `
      SELECT b.id
      FROM bookings b
      JOIN booking_requests br
        ON br.reference = b.booking_reference COLLATE NOCASE
      WHERE br.reference = ? COLLATE NOCASE
        AND br.business_id = ?
      LIMIT 1
    `,
    )
      .bind(reference, businessId)
      .first();
    if (!booking)
      return operationsJson(
        { error: "That job is not linked to this USC account" },
        400,
      );
    const eventData = {
      benefitName: benefit.name,
      benefitCode: benefit.benefit_code,
      reference,
      quantity,
      note,
      changedBy: session.email,
    };
    await env.DB.batch([
      env.DB.prepare(
        `
        INSERT INTO benefit_redemptions (
          id, benefit_id, business_id, booking_id, quantity, details_json
        ) VALUES (?, ?, ?, ?, ?, ?)
      `,
      ).bind(
        crypto.randomUUID(),
        benefitId,
        businessId,
        booking.id,
        quantity,
        JSON.stringify(eventData),
      ),
      env.DB.prepare(
        `
        INSERT INTO business_events (id, business_id, event_type, event_data)
        VALUES (?, ?, 'benefit_redeemed', ?)
      `,
      ).bind(crypto.randomUUID(), businessId, JSON.stringify(eventData)),
    ]);
    return operationsJson({
      account: await operationsAccountDetail(env, businessId),
    });
  }

  if (request.method === "GET" && path === "/operations/api/tags") {
    const tags = await env.DB.prepare(
      `
      SELECT t.*, tb.id AS benefit_id, tb.benefit_code, tb.name AS benefit_name,
        tb.description AS benefit_description, tb.benefit_type,
        tb.benefit_config_json, tb.reset_period_days
      FROM tags t
      LEFT JOIN tag_benefits tb ON tb.tag_id = t.id AND tb.active = 1
      WHERE t.active = 1
      ORDER BY t.code, tb.name
    `,
    ).all();
    return operationsJson({ tags: tags.results || [] });
  }

  return operationsJson({ error: "Not found" }, 404);
}

function operationsDashboardHtml(env) {
  return String.raw`<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <meta name="robots" content="noindex,nofollow,noarchive">
  <title>Sorrin Operations</title>
  <style>
    :root{--ink:#0a0a0a;--paper:#f4f2ee;--panel:#fff;--muted:#706f6c;--line:#d8d4cc;--blue:#0d57d8;--green:#19714a;--amber:#9d5b00;--red:#a62c2c;--shadow:0 18px 55px rgba(10,10,10,.11)}
    *{box-sizing:border-box}html{background:var(--paper);color:var(--ink);font-family:Inter,ui-sans-serif,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}body{margin:0;min-height:100vh}button,input,select,textarea{font:inherit}button,a{touch-action:manipulation}.hidden{display:none!important}
    .login{min-height:100vh;display:grid;place-items:center;padding:24px;background:radial-gradient(circle at 75% 15%,#dce8ff 0,transparent 31%),var(--paper)}.login-card{width:min(430px,100%);background:var(--panel);border:1px solid var(--line);box-shadow:var(--shadow);padding:38px}.wordmark{font-family:Impact,Haettenschweiler,"Arial Narrow Bold",sans-serif;font-size:50px;line-height:.85;letter-spacing:.03em}.eyebrow{font-size:11px;letter-spacing:.23em;text-transform:uppercase;color:var(--muted);font-weight:800}.login h1{font-size:25px;margin:30px 0 8px}.login p{color:var(--muted);line-height:1.5}.field{display:grid;gap:7px;margin:16px 0}.field label{font-size:12px;font-weight:800;letter-spacing:.04em;text-transform:uppercase}.field input,.field select,.field textarea,.search{width:100%;border:1px solid var(--line);background:#fff;padding:12px 13px;border-radius:0;outline:none}.field input:focus,.field select:focus,.field textarea:focus,.search:focus{border-color:var(--blue);box-shadow:0 0 0 3px rgba(13,87,216,.12)}.field textarea{min-height:100px;resize:vertical}.primary,.secondary,.danger,.status-btn,.nav-btn{border:0;padding:12px 16px;font-weight:800;cursor:pointer;text-decoration:none;display:inline-flex;align-items:center;justify-content:center;gap:8px}.primary{background:var(--ink);color:#fff}.secondary{background:#ece9e2;color:var(--ink)}.danger{background:#f7e8e8;color:var(--red)}.primary:hover,.nav-btn:hover{background:var(--blue)}.error{color:var(--red);font-size:13px;margin-top:12px}.busy{opacity:.55;pointer-events:none}
    .shell{min-height:100vh;display:grid;grid-template-columns:240px 1fr}.rail{background:var(--ink);color:#fff;padding:28px 18px;position:sticky;top:0;height:100vh;display:flex;flex-direction:column}.rail .wordmark{font-size:42px}.rail .eyebrow{color:#aaa}.tabs{display:grid;gap:5px;margin-top:42px}.tab{border:0;background:transparent;color:#aaa;text-align:left;padding:13px 14px;font-weight:800;cursor:pointer}.tab.active,.tab:hover{background:#202020;color:#fff}.rail-foot{margin-top:auto}.rail-foot button{width:100%;border:1px solid #3c3c3c;background:transparent;color:#bbb;padding:10px;cursor:pointer}.main{min-width:0}.topbar{height:86px;padding:0 32px;border-bottom:1px solid var(--line);display:flex;align-items:center;justify-content:space-between;background:rgba(244,242,238,.94);position:sticky;top:0;z-index:5;backdrop-filter:blur(12px)}.topbar h1{font-size:22px;margin:0}.topbar small{color:var(--muted)}.content{padding:28px 32px 50px}.stats{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:12px;margin-bottom:24px}.stat{background:var(--panel);border:1px solid var(--line);padding:18px}.stat strong{display:block;font-size:28px}.stat span{font-size:11px;text-transform:uppercase;letter-spacing:.12em;color:var(--muted);font-weight:800}.toolbar{display:flex;gap:10px;align-items:center;margin-bottom:18px}.toolbar .search{max-width:420px}.segmented{display:flex;border:1px solid var(--line);background:#fff}.segmented button{border:0;border-right:1px solid var(--line);background:#fff;padding:10px 13px;font-weight:700;cursor:pointer}.segmented button:last-child{border-right:0}.segmented button.active{background:var(--ink);color:#fff}.split{display:grid;grid-template-columns:minmax(330px,.9fr) minmax(460px,1.35fr);gap:18px;align-items:start}.list{display:grid;gap:9px}.card{width:100%;text-align:left;background:var(--panel);border:1px solid var(--line);padding:17px;cursor:pointer}.card:hover,.card.selected{border-color:var(--ink);box-shadow:0 8px 22px rgba(0,0,0,.07)}.card-top{display:flex;align-items:center;justify-content:space-between;gap:12px}.reference{font-size:13px;font-weight:900;letter-spacing:.03em}.card h3{margin:11px 0 4px;font-size:17px}.card p{margin:3px 0;color:var(--muted);font-size:13px;line-height:1.4}.badge{display:inline-flex;padding:5px 8px;font-size:10px;text-transform:uppercase;letter-spacing:.1em;font-weight:900;background:#e9e9e9}.badge.pending{background:#fff0d7;color:var(--amber)}.badge.approved{background:#e3ecff;color:var(--blue)}.badge.active{background:#dff5e9;color:var(--green)}.badge.delivered{background:#e5e5e5;color:#333}.badge.declined,.badge.cancelled{background:#f7e2e2;color:var(--red)}.detail{background:var(--panel);border:1px solid var(--line);min-height:560px}.empty{padding:70px 25px;text-align:center;color:var(--muted)}.detail-head{padding:24px;border-bottom:1px solid var(--line)}.detail-head h2{margin:9px 0 4px;font-size:24px}.detail-head p{margin:0;color:var(--muted)}.detail-actions{display:flex;flex-wrap:wrap;gap:8px;margin-top:18px}.nav-btn{background:var(--blue);color:#fff}.contact-btn{border:1px solid var(--line);background:#fff;color:var(--ink);padding:11px 14px;font-weight:800;text-decoration:none}.detail-body{padding:24px}.section{margin-bottom:26px}.section h3{font-size:11px;text-transform:uppercase;letter-spacing:.16em;margin:0 0 12px}.data-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:13px}.datum{border-top:1px solid var(--line);padding-top:9px}.datum span{display:block;font-size:10px;text-transform:uppercase;letter-spacing:.08em;color:var(--muted);font-weight:800;margin-bottom:3px}.datum strong{font-size:14px;line-height:1.4;word-break:break-word}.stops{display:grid;gap:10px}.stop{border:1px solid var(--line);padding:15px}.stop-top{display:flex;justify-content:space-between;gap:12px}.stop h4{margin:0 0 5px}.stop p{margin:3px 0;color:var(--muted);font-size:13px}.stop-actions{display:flex;flex-wrap:wrap;gap:7px;margin-top:12px}.stop-actions button,.stop-actions a{border:1px solid var(--line);background:#fff;color:var(--ink);padding:8px 10px;font-size:12px;font-weight:800;text-decoration:none;cursor:pointer}.timeline{display:grid;gap:0}.event{border-left:2px solid var(--line);padding:0 0 17px 15px;position:relative}.event:before{content:"";position:absolute;left:-6px;top:2px;width:10px;height:10px;border-radius:50%;background:var(--ink)}.event strong{font-size:13px}.event p{font-size:12px;color:var(--muted);margin:3px 0}.status-row{display:flex;gap:8px}.status-row select{flex:1;border:1px solid var(--line);padding:10px}.status-btn{background:var(--ink);color:#fff}.account-card .tags{margin-top:11px}.tag{display:inline-flex;background:#e7efff;color:var(--blue);padding:5px 8px;font-size:10px;font-weight:900;letter-spacing:.08em;margin:0 4px 4px 0}.tag-remove{border:0;background:transparent;color:inherit;font-weight:900;cursor:pointer;margin-left:5px}.money{font-variant-numeric:tabular-nums}.account-form{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:0 14px}.account-form .wide{grid-column:1/-1}.check{display:flex;align-items:center;gap:9px;padding-top:24px}.check input{width:18px;height:18px}.benefit{background:#f1f6ff;border-left:3px solid var(--blue);padding:13px;margin-top:10px}.benefit strong{font-size:13px}.benefit p{margin:4px 0 0;color:var(--muted);font-size:12px}.mobile-nav{display:none}.notice{padding:12px 14px;background:#fff7e8;color:#754a00;font-size:13px;margin-bottom:15px;border-left:3px solid #d58b12}.processor-hero{background:var(--ink);color:#fff;padding:26px;margin-bottom:16px;display:grid;grid-template-columns:minmax(0,1fr) minmax(300px,430px);gap:24px;align-items:end}.processor-hero .eyebrow{color:#9dbbff}.processor-hero h2{font-size:30px;margin:8px 0}.processor-hero p{color:#bbb;max-width:720px;margin:0;line-height:1.5}.processor-hero .primary{background:#fff;color:var(--ink);white-space:nowrap}.processor-origin{display:grid;grid-template-columns:minmax(0,1fr) auto;gap:8px}.processor-origin label{grid-column:1/-1;color:#aaa;font-size:10px;font-weight:900;letter-spacing:.12em;text-transform:uppercase}.processor-origin input{width:100%;border:1px solid #4c4c4c;background:#171717;color:#fff;padding:11px 12px;min-width:0}.processor-origin-actions{grid-column:1/-1;display:grid;grid-template-columns:1fr 1fr;gap:8px}.processor-origin .secondary{background:#2b2b2b;color:#fff}.route-status{border-left:3px solid var(--blue);padding:11px 12px;background:#edf3ff;margin-bottom:12px;font-size:12px;color:#39475d}.route-status.fallback{border-left-color:var(--amber);background:#fff7e8;color:#754a00}.processor-grid{display:grid;grid-template-columns:minmax(0,1.5fr) minmax(280px,.65fr);gap:16px;align-items:start}.processor-stack{display:grid;gap:10px}.processor-card{background:#fff;border:1px solid var(--line);padding:18px;display:grid;grid-template-columns:42px minmax(0,1fr) auto;gap:15px;align-items:start}.processor-card.recommended{border:2px solid var(--blue);box-shadow:0 10px 30px rgba(13,87,216,.1)}.processor-order{font-size:28px;font-weight:900;color:#b3b0aa;line-height:1}.processor-card.recommended .processor-order{color:var(--blue)}.processor-card h3{font-size:17px;margin:5px 0}.processor-card p{font-size:13px;color:var(--muted);margin:4px 0;line-height:1.45}.processor-card .road-time{color:var(--ink);font-weight:800}.processor-actions{display:flex;flex-direction:column;gap:7px;align-items:stretch}.processor-actions a,.processor-actions button{font-size:11px;padding:9px 10px}.pressure{display:inline-flex;padding:5px 8px;font-size:10px;text-transform:uppercase;letter-spacing:.09em;font-weight:900}.pressure.critical{background:#f7e2e2;color:var(--red)}.pressure.warning{background:#fff0d7;color:var(--amber)}.pressure.normal{background:#e3ecff;color:var(--blue)}.pressure.future{background:#eceae5;color:#686662}.processor-side{display:grid;gap:12px}.processor-panel{background:#fff;border:1px solid var(--line);padding:18px}.processor-panel h3{font-size:11px;text-transform:uppercase;letter-spacing:.15em;margin:0 0 12px}.processor-panel p,.processor-panel li{font-size:12px;line-height:1.5;color:var(--muted)}.processor-panel ul{margin:0;padding-left:18px}.conflict{border-left:3px solid var(--amber);padding:9px 0 9px 11px;margin:8px 0}.processor-empty{background:#fff;border:1px solid var(--line);padding:60px 25px;text-align:center;color:var(--muted)}
    .processor-section-title{margin:26px 0 10px;font-size:11px;letter-spacing:.16em;text-transform:uppercase}.processor-card.upcoming{background:#f8f7f4}.processor-card.attention{border-left:4px solid var(--red)}.pressure.on-track{background:#dff5e9;color:var(--green)}.pressure.at-risk{background:#fff0d7;color:var(--amber)}.pressure.route-conflict,.pressure.expired-commitment{background:#f7e2e2;color:var(--red)}.account-kpis{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:8px;padding:16px 24px;border-bottom:1px solid var(--line);background:#faf9f7}.account-kpi strong{display:block;font-size:19px}.account-kpi span{font-size:9px;letter-spacing:.09em;text-transform:uppercase;color:var(--muted);font-weight:900}.usc-link{border:1px solid var(--line);padding:15px;background:#faf9f7}.usc-link .status-row{margin-top:10px}.benefit.available{border-left-color:var(--green);background:#eef8f3}.benefit.used{border-left-color:var(--amber);background:#fff7e8}.benefit-controls{display:grid;grid-template-columns:minmax(0,1fr) 90px auto;gap:7px;margin-top:10px}.benefit-controls select,.benefit-controls input{border:1px solid var(--line);padding:8px;min-width:0}.business-timeline{margin-top:12px}.account-form-note{grid-column:1/-1;padding:10px 12px;background:#f1f6ff;color:#39475d;font-size:12px}.usc-generate{margin-top:7px;align-self:start}.execution-panel{border:2px solid var(--ink);padding:16px;background:#f8f7f4}.execution-panel h3{font-size:13px;margin-bottom:8px}.execution-panel p{font-size:12px;color:var(--muted)}.execution-primary{background:var(--green);color:#fff;min-width:180px}.nav-options{display:flex;flex-wrap:wrap;gap:7px}.nav-options a{border:1px solid var(--line);background:#fff;color:var(--ink);padding:9px 11px;font-size:11px;font-weight:900;text-decoration:none}.finance-form{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:0 14px}.finance-form .wide{grid-column:1/-1}.finance-card.overdue{border-left:4px solid var(--red)}.finance-card.outstanding{border-left:4px solid var(--amber)}.finance-card.settled{border-left:4px solid var(--green)}.finance-meta{display:flex;gap:8px;flex-wrap:wrap;margin-top:9px}.finance-status{display:inline-flex;padding:5px 8px;font-size:10px;text-transform:uppercase;letter-spacing:.09em;font-weight:900;background:#eceae5}.finance-status.overdue{background:#f7e2e2;color:var(--red)}.finance-status.paid,.finance-status.waived{background:#dff5e9;color:var(--green)}.finance-status.awaiting_payment,.finance-status.partially_paid{background:#fff0d7;color:var(--amber)}
    @media(max-width:980px){.stats{grid-template-columns:repeat(2,1fr)}.split,.processor-grid,.processor-hero{grid-template-columns:1fr}.detail{min-height:0}.detail.open{position:fixed;inset:0;z-index:20;overflow:auto}.detail.open .detail-head{position:sticky;top:0;background:#fff;z-index:2}.detail-close{display:inline-flex!important}}@media(max-width:700px){.shell{display:block}.rail{height:auto;position:sticky;z-index:10;padding:14px 16px;display:flex;flex-direction:row;align-items:center}.rail .wordmark{font-size:31px}.rail .eyebrow,.rail-foot,.tabs{display:none}.mobile-nav{display:flex;margin-left:auto;gap:3px}.mobile-nav button{border:0;background:#1c1c1c;color:#aaa;padding:9px 6px;font-size:9px;font-weight:800}.mobile-nav button.active{color:#fff;background:#333}.topbar{height:70px;padding:0 17px}.topbar h1{font-size:18px}.content{padding:17px}.stats,.account-kpis{grid-template-columns:repeat(2,1fr)}.stat{padding:13px}.stat strong{font-size:22px}.toolbar{align-items:stretch;flex-direction:column}.toolbar .search{max-width:none}.segmented{overflow:auto}.segmented button{white-space:nowrap;flex:1}.split{display:block}.list{margin-bottom:12px}.data-grid,.account-form,.finance-form{grid-template-columns:1fr}.account-form .wide,.account-form-note,.finance-form .wide{grid-column:auto}.detail-head,.detail-body{padding:18px}.status-row{flex-direction:column}.login-card{padding:28px 23px}.processor-hero{padding:21px}.processor-hero h2{font-size:25px}.processor-origin,.processor-origin-actions{grid-template-columns:1fr}.processor-origin label,.processor-origin-actions{grid-column:1}.processor-hero .primary,.processor-origin .secondary{width:100%}.processor-card{grid-template-columns:32px minmax(0,1fr);padding:15px;gap:10px}.processor-actions{grid-column:1/-1;display:grid;grid-template-columns:1fr 1fr}.processor-order{font-size:22px}.benefit-controls{grid-template-columns:1fr}.account-kpis{padding:14px 18px}}

    .collapsible{border:1px solid var(--line);background:#fff;margin-bottom:18px}.collapsible>summary{cursor:pointer;list-style:none;padding:13px 15px;font-size:11px;text-transform:uppercase;letter-spacing:.14em;font-weight:900;display:flex;justify-content:space-between;gap:12px;align-items:center}.collapsible>summary::-webkit-details-marker{display:none}.collapsible>summary:after{content:"+";font-size:18px;line-height:1;color:var(--muted)}.collapsible[open]>summary:after{content:"−"}.collapsible-content{padding:0 15px 15px}.job-record-footer{display:flex;justify-content:center;padding:24px 0 0}.job-record-footer button{min-width:240px}.record-modal{position:fixed;inset:0;z-index:50;background:rgba(0,0,0,.55);display:grid;place-items:center;padding:22px}.record-shell{position:relative;width:min(1180px,100%);max-height:92vh;overflow:auto;background:var(--paper);border:1px solid #222;box-shadow:0 30px 100px rgba(0,0,0,.32);padding:26px}.record-close{position:absolute;right:18px;top:15px;border:0;background:transparent;font-size:30px;line-height:1;cursor:pointer}.record-head{padding-right:50px;margin-bottom:18px}.record-head h2{margin:5px 0 7px}.record-grid{display:grid;grid-template-columns:minmax(300px,.8fr) minmax(430px,1.2fr);gap:16px;align-items:start}.record-list{display:grid;gap:8px;max-height:68vh;overflow:auto}.record-detail{background:#fff;border:1px solid var(--line);min-height:400px}.archived-chip{display:inline-flex;padding:5px 8px;background:#efe7e7;color:#8d3030;font-size:10px;font-weight:900;letter-spacing:.08em}.detail-actions .danger{border:0}.section.usc-link{border-left:3px solid var(--blue);padding-left:14px}.notification-composer{margin-bottom:12px}.notification-history .event:last-child{padding-bottom:0}.archive-banner{padding:11px 13px;background:#f6eaea;border-left:3px solid var(--red);color:#7d2929;font-size:12px;margin-bottom:16px}
    @media(max-width:900px){.record-grid{grid-template-columns:1fr}.record-list{max-height:300px}.record-shell{padding:20px 14px}.record-modal{padding:8px}}

    /* FINAL V20 COMMAND CONSOLE — UX polish on the V19 redesign. */
    :root{--ink:#f2f4f7;--paper:#0b0d10;--panel:#111419;--surface:#15191f;--surface-2:#1b2027;--muted:#8c95a3;--line:#252b34;--line-strong:#343c47;--blue:#0d57d8;--green:#0d57d8;--amber:#ffb648;--red:#ff646d;--acid:var(--blue);--shadow:0 24px 80px rgba(0,0,0,.34)}
    html{background:var(--paper);color:var(--ink);font-size:14px}body{background:radial-gradient(circle at 84% -10%,rgba(91,140,255,.08),transparent 31%),var(--paper);color:var(--ink)}button,a,input,select,textarea{transition:border-color .14s ease,background-color .14s ease,color .14s ease,transform .14s ease,box-shadow .14s ease}button:focus-visible,a:focus-visible,input:focus-visible,select:focus-visible,textarea:focus-visible,summary:focus-visible{outline:2px solid var(--acid);outline-offset:2px}
    .login{background:radial-gradient(circle at 75% 15%,rgba(91,140,255,.13),transparent 31%),radial-gradient(circle at 20% 90%,rgba(13,87,216,.08),transparent 26%),var(--paper)}.login-card{background:rgba(17,20,25,.96);border:1px solid var(--line-strong);border-radius:14px;box-shadow:0 35px 110px rgba(0,0,0,.55);padding:38px}.login-card:before{content:"SECURE ACCESS";display:block;color:var(--acid);font-size:8px;font-weight:950;letter-spacing:.18em;margin-bottom:22px}.wordmark{font-family:Inter,ui-sans-serif,system-ui,sans-serif;font-size:31px;font-weight:1000;letter-spacing:-.05em;line-height:1}.eyebrow{font-size:8px;letter-spacing:.17em;color:#707a86}.login h1{font-size:26px;letter-spacing:-.04em}.login p{color:var(--muted);font-size:12px}.field label{color:#929ca8;font-size:8px;letter-spacing:.12em}.field input,.field select,.field textarea,.search,.status-row select,.benefit-controls select,.benefit-controls input{border:1px solid #2b323c;background:var(--surface);color:var(--ink);border-radius:8px;padding:11px 12px}.field input:focus,.field select:focus,.field textarea:focus,.search:focus{border-color:#566270;box-shadow:0 0 0 3px rgba(91,140,255,.08)}
    .primary,.secondary,.danger,.status-btn,.nav-btn,.contact-btn{min-height:38px;border:1px solid var(--line-strong);border-radius:8px;padding:0 13px;font-size:10px;font-weight:900;letter-spacing:.02em}.primary,.status-btn{border-color:var(--acid);background:var(--acid);color:#fff;box-shadow:0 7px 25px rgba(13,87,216,.08)}.primary:hover,.status-btn:hover{background:#2f74e6;border-color:#2f74e6;transform:translateY(-1px)}.secondary,.contact-btn{background:#171b21;color:#c1c8d0}.secondary:hover,.contact-btn:hover{border-color:#4b5664;color:#fff}.danger{border-color:rgba(255,100,109,.2);background:rgba(255,100,109,.07);color:var(--red)}.nav-btn{border-color:var(--acid);background:var(--acid);color:#fff}.busy{opacity:.48;filter:saturate(.5)}
    .shell{grid-template-columns:264px minmax(0,1fr)}.rail{background:rgba(8,9,11,.98);border-right:1px solid #1d2229;padding:24px 18px 18px}.brand-lockup{display:flex;align-items:center;gap:11px;padding:0 7px}.brand-cube{width:36px;height:36px;border:1px solid #252b34;background:#000;display:block;transform:none;box-shadow:none}.rail .wordmark{font-size:21px}.rail .eyebrow{color:#737c88;margin-top:5px}.nav-caption{margin:47px 0 8px;padding:0 11px;color:#5d6570;font-size:8px;font-weight:900;letter-spacing:.18em;text-transform:uppercase}.tabs{gap:5px;margin-top:0}.tab{width:100%;min-height:58px;border:1px solid transparent;border-radius:9px;background:transparent;color:#d7dce3;padding:9px 10px;display:grid;grid-template-columns:48px minmax(0,1fr) auto;gap:10px;align-items:center;text-align:left}.tab:hover{background:#111419;border-color:#1c2128;color:#fff;transform:translateX(2px)}.tab.active{background:linear-gradient(90deg,rgba(13,87,216,.12),rgba(13,87,216,.035));border-color:rgba(13,87,216,.18);color:#fff}.tab-key{width:46px;height:30px;border-radius:7px;background:#171b21;border:1px solid #292f38;display:grid;place-items:center;color:#949eab;font-size:9px;font-weight:950}.tab.active .tab-key{background:var(--acid);border-color:var(--acid);color:#fff;box-shadow:0 0 24px rgba(13,87,216,.14)}.tab-copy strong,.tab-copy small{display:block}.tab-copy strong{font-size:12px}.tab-copy small{color:#69727f;font-size:9px;margin-top:3px}.tab kbd,.command-trigger kbd,.command-panel kbd{border:1px solid #343c46;border-bottom-color:#222831;border-radius:5px;background:#1b2027;color:#8b95a1;padding:3px 5px;font:800 8px/1.2 ui-monospace,SFMono-Regular,Menlo,monospace}.tab kbd{color:#4f5761}.rail-foot{display:grid;gap:9px}.rail-foot .system-state{border:1px solid #20262d;border-radius:8px;background:#0d1013;padding:10px 11px;color:#7f8995;font-size:9px;display:flex;align-items:center;gap:8px}.system-state span{width:7px;height:7px;border-radius:50%;background:var(--green);box-shadow:0 0 10px rgba(13,87,216,.6)}.build-label{color:#474f59;font-size:7px;font-weight:900;letter-spacing:.1em;padding:5px 2px 0}.rail-foot button{border:1px solid #272e36;border-radius:7px;background:#111419;color:#7f8995;font-size:9px}.rail-foot button:hover{border-color:#46515e;color:#fff}
    .topbar{height:102px;padding:0 30px 0 34px;border-bottom:1px solid var(--line);background:rgba(11,13,16,.88);backdrop-filter:blur(18px)}.breadcrumb{color:#5d6672;font-size:8px;font-weight:900;letter-spacing:.16em}.topbar h1{font-size:23px;line-height:1;letter-spacing:-.035em;margin:8px 0 5px}.topbar small{color:var(--muted);font-size:10px}.topbar-actions{display:flex;align-items:center;gap:8px}.command-trigger{width:210px;height:39px;border:1px solid #2c333d;border-radius:8px;background:#12161b;padding:0 8px 0 12px;color:#737e8a;display:flex;align-items:center;justify-content:space-between;cursor:pointer;font-size:10px}.command-trigger:hover{border-color:#45505e;background:#181d24}.content{padding:24px 30px 52px 34px}
    .stats{gap:0;border:1px solid var(--line);border-radius:10px;background:#0f1216;margin-bottom:16px;overflow:hidden}.stat{min-height:70px;border:0;border-right:1px solid var(--line);background:transparent;padding:14px 17px;position:relative}.stat:last-child{border-right:0}.stat:before{content:"";position:absolute;left:17px;top:21px;width:7px;height:7px;border-radius:50%;background:#646e7a}.stat:nth-child(1):before{background:var(--amber);box-shadow:0 0 10px rgba(255,182,72,.45)}.stat:nth-child(2):before{background:var(--blue);box-shadow:0 0 10px rgba(91,140,255,.45)}.stat:nth-child(3):before{background:var(--green);box-shadow:0 0 10px rgba(13,87,216,.45)}.stat strong{font-size:19px;letter-spacing:-.02em;padding-left:16px}.stat span{font-size:8px;letter-spacing:.12em;padding-left:16px;color:#717b88}.toolbar{min-height:62px;margin:0;padding:11px 13px;border:1px solid var(--line);border-bottom:0;border-radius:10px 10px 0 0;background:#0f1216;gap:9px}.toolbar .search{max-width:none;flex:1;min-width:240px;height:39px}.search::placeholder{color:#626c79}.segmented{height:38px;padding:3px;border:1px solid #2b323c;border-radius:8px;background:var(--surface)}.segmented button{border:0;border-radius:6px;background:transparent;color:#747e8b;padding:0 11px;font-size:9px}.segmented button.active{background:#2a313a;color:#fff;box-shadow:0 2px 6px rgba(0,0,0,.25)}
    .split{grid-template-columns:minmax(330px,38%) minmax(0,1fr);gap:0;align-items:stretch;border:1px solid var(--line);border-radius:0 0 12px 12px;overflow:hidden;min-height:calc(100vh - 292px);background:var(--panel)}.list{gap:7px;padding:11px;border-right:1px solid var(--line);background:#0f1216;align-content:start}.card{border:1px solid #222831;border-radius:9px;background:#14181d;color:var(--ink);padding:14px;transition:.14s ease}.card:hover{border-color:#3b4552;background:#181d23;transform:translateY(-1px);box-shadow:none}.card.selected{border-color:rgba(13,87,216,.42);background:linear-gradient(110deg,rgba(13,87,216,.075),#171b21 46%);box-shadow:inset 3px 0 0 var(--acid)}.reference{color:#aeb7c2;font-size:9px;font-family:ui-monospace,SFMono-Regular,Menlo,monospace;letter-spacing:.06em}.card h3{font-size:13px;margin:11px 0 7px}.card p{color:#747e89;font-size:10px;margin:3px 0}.badge,.finance-status,.pressure,.archived-chip{border:1px solid #303741;border-radius:999px;padding:4px 7px;background:#222831;color:#a7b0bb;font-size:7px;letter-spacing:.1em}.badge.pending{border-color:rgba(255,182,72,.25);background:rgba(255,182,72,.08);color:var(--amber)}.badge.approved{border-color:rgba(91,140,255,.25);background:rgba(91,140,255,.08);color:#85a8ff}.badge.active,.finance-status.paid,.finance-status.waived{border-color:rgba(13,87,216,.25);background:rgba(13,87,216,.08);color:var(--green)}.badge.delivered{background:#202630;color:#9ca6b2}.badge.declined,.badge.cancelled,.finance-status.overdue,.archived-chip{border-color:rgba(255,100,109,.25);background:rgba(255,100,109,.08);color:var(--red)}.finance-status.awaiting_payment,.finance-status.partially_paid{border-color:rgba(255,182,72,.25);background:rgba(255,182,72,.08);color:var(--amber)}
    .detail{min-height:100%;border:0;background:var(--panel)}.empty{color:#68737f;font-size:11px;background:radial-gradient(circle at 50% 40%,rgba(91,140,255,.05),transparent 30%)}.detail-head{padding:22px 24px 18px;border-bottom:1px solid var(--line);background:linear-gradient(135deg,#171c22,#111419 60%)}.detail-head h2{font-size:25px;letter-spacing:-.04em;margin:13px 0 6px}.detail-head p{color:#7f8996;font-size:10px}.detail-actions{gap:7px;margin-top:18px}.detail-body{padding:20px 24px 30px}.section{margin-bottom:22px}.section h3{color:#d8dde3;font-size:9px;letter-spacing:.14em}.data-grid{gap:10px}.datum{border-top:1px solid var(--line);padding-top:10px}.datum span{color:#69737f;font-size:7px}.datum strong{font-size:10px;color:#e1e5e9}.stops{gap:8px}.stop{border:1px solid #282f38;border-radius:8px;background:var(--surface);padding:14px}.stop h4{font-size:11px}.stop p{color:#737e8a;font-size:9px}.stop-actions button,.stop-actions a{border:1px solid #343c46;border-radius:7px;background:#1a1f25;color:#b6bec7;font-size:8px}.timeline .event{border-left-color:#343c46}.event:before{background:var(--acid);box-shadow:0 0 9px rgba(13,87,216,.25)}.event strong{font-size:10px}.event p{font-size:9px;color:#78838f}.notice,.route-status.fallback{border:1px solid rgba(255,182,72,.18);border-left:3px solid var(--amber);border-radius:8px;background:rgba(255,182,72,.06);color:#e3bc80}.archive-banner{border:1px solid rgba(255,100,109,.15);border-left:3px solid var(--red);border-radius:8px;background:rgba(255,100,109,.06);color:#e59a9e}.usc-link,.execution-panel{border:1px solid #2c343d;border-radius:8px;background:var(--surface)}.section.usc-link{border-left:3px solid var(--blue)}.execution-panel{border:1px solid rgba(13,87,216,.28);border-left:4px solid var(--blue);background:linear-gradient(135deg,rgba(13,87,216,.12),#15191f 52%);box-shadow:inset 0 1px 0 rgba(255,255,255,.025)}.execution-panel h3{font-size:10px;letter-spacing:.16em}.execution-panel p{font-size:10px;line-height:1.5}.execution-primary{min-width:220px;min-height:46px;border:1px solid #2f74e6;border-radius:9px;background:linear-gradient(180deg,#1765df,#0d57d8);color:#fff;font-size:11px;font-weight:950;letter-spacing:.035em;box-shadow:0 10px 26px rgba(13,87,216,.22)}.execution-primary:hover{background:linear-gradient(180deg,#2f74e6,#1765df);border-color:#4d89eb;transform:translateY(-1px);box-shadow:0 13px 30px rgba(13,87,216,.28)}.execution-primary:disabled{opacity:.42;box-shadow:none;transform:none;cursor:not-allowed}.nav-options a{border:1px solid #343c46;border-radius:7px;background:#1a1f25;color:#b6bec7;font-size:8px}.account-kpis{border-bottom:1px solid var(--line);background:#0f1216}.account-kpi strong{font-size:16px}.account-kpi span{color:#717b88;font-size:7px}.benefit{border:1px solid rgba(91,140,255,.16);border-left:3px solid var(--blue);border-radius:8px;background:rgba(91,140,255,.06)}.benefit.available{background:rgba(13,87,216,.06);border-color:rgba(13,87,216,.16);border-left-color:var(--green)}.benefit.used{background:rgba(255,182,72,.06);border-color:rgba(255,182,72,.16);border-left-color:var(--amber)}.tag{border:1px solid rgba(91,140,255,.23);border-radius:999px;background:rgba(91,140,255,.08);color:#91afff;font-size:7px}.check input{accent-color:var(--acid)}
    .processor-hero{border:1px solid #30383f;border-radius:12px;background:radial-gradient(circle at 10% 140%,rgba(13,87,216,.16),transparent 36%),linear-gradient(115deg,#13171b,#1d242b);padding:30px;margin-bottom:16px}.processor-hero .eyebrow{color:#82909d}.processor-hero h2{font-size:38px;letter-spacing:-.05em}.processor-hero p{color:#929ba5;font-size:11px}.processor-origin label{color:#68737e;font-size:7px}.processor-origin input{border:1px solid #343d47;border-radius:8px;background:rgba(8,10,12,.68);color:#fff}.processor-origin .secondary{background:#1a1f25;color:#b6bec7}.processor-hero .primary{background:var(--acid);color:#fff}.route-status{border:1px solid rgba(91,140,255,.18);border-left:3px solid var(--blue);border-radius:8px;background:rgba(91,140,255,.06);color:#a9b9da}.processor-card,.processor-panel,.processor-empty{border:1px solid #282f38;border-radius:9px;background:#14181d;color:var(--ink)}.processor-card.recommended{border:1px solid rgba(13,87,216,.42);background:linear-gradient(110deg,rgba(13,87,216,.075),#171b21 46%);box-shadow:inset 3px 0 0 var(--acid)}.processor-card.upcoming{background:#111419}.processor-order{color:#535e6a}.processor-card.recommended .processor-order{color:var(--acid)}.processor-card h3{font-size:13px}.processor-card p,.processor-panel p,.processor-panel li{color:#727c88;font-size:9px}.processor-card .road-time{color:#bfc6ce}.processor-panel h3{font-size:8px;color:#cbd2da}.pressure.critical,.pressure.route-conflict,.pressure.expired-commitment{border-color:rgba(255,100,109,.25);background:rgba(255,100,109,.08);color:var(--red)}.pressure.warning,.pressure.at-risk{border-color:rgba(255,182,72,.25);background:rgba(255,182,72,.08);color:var(--amber)}.pressure.normal{border-color:rgba(91,140,255,.25);background:rgba(91,140,255,.08);color:#85a8ff}.pressure.on-track{border-color:rgba(13,87,216,.25);background:rgba(13,87,216,.08);color:var(--green)}.conflict{border-left-color:var(--amber)}
    .collapsible{border:1px solid var(--line);border-radius:8px;background:var(--surface);overflow:hidden}.collapsible>summary{font-size:8px;color:#c3cad2}.collapsible>summary:after{color:var(--acid)}.record-modal{background:rgba(0,0,0,.76);backdrop-filter:blur(8px)}.record-shell{border:1px solid #3b4551;border-radius:13px;background:var(--paper);box-shadow:0 35px 100px rgba(0,0,0,.65)}.record-detail{border:1px solid var(--line);border-radius:9px;background:var(--panel)}.record-close{color:#c5cbd2}
    .command-modal{position:fixed;inset:0;z-index:80;background:rgba(0,0,0,.72);backdrop-filter:blur(7px);display:grid;place-items:start center;padding-top:11vh}.command-panel{width:min(560px,calc(100% - 28px));max-height:78vh;overflow:auto;border:1px solid #3b4551;border-radius:13px;background:#111419;box-shadow:0 35px 100px rgba(0,0,0,.65)}.command-head{height:62px;display:grid;grid-template-columns:28px 1fr auto;align-items:center;gap:8px;padding:0 15px;border-bottom:1px solid var(--line)}.command-head h2{font-size:13px;margin:0}.command-glyph{color:var(--acid);font-size:20px}.command-group{padding:9px}.command-caption{color:#5f6975;text-transform:uppercase;font-size:7px;font-weight:900;letter-spacing:.14em;padding:7px}.command-group button{width:100%;min-height:54px;border:0;border-radius:8px;background:transparent;padding:6px 8px;display:grid;grid-template-columns:50px minmax(0,1fr) auto;gap:10px;align-items:center;text-align:left;cursor:pointer}.command-group button:hover{background:#1a1f26}.command-group button strong,.command-group button small{display:block}.command-group button strong{font-size:10px}.command-group button small{color:#6f7985;font-size:8px;margin-top:3px}.command-actions{border-top:1px solid var(--line)}.command-foot{height:38px;border-top:1px solid var(--line);background:#0e1115;padding:0 14px;display:flex;align-items:center;gap:15px;color:#606a76;font-size:8px}.command-open{overflow:hidden}.ops-toast{position:fixed;z-index:100;right:22px;bottom:22px;max-width:min(430px,calc(100% - 28px));border:1px solid rgba(13,87,216,.3);border-radius:9px;background:#171c1f;box-shadow:var(--shadow);color:#dfe4e8;padding:12px 15px;display:flex;align-items:center;gap:9px}.ops-toast>span{width:19px;height:19px;flex:0 0 19px;border-radius:50%;background:var(--acid);color:#fff;display:grid;place-items:center;font-size:9px;font-weight:950}.ops-toast p{margin:0;font-size:10px;line-height:1.4}.ops-toast.error{border-color:rgba(255,100,109,.35)}.ops-toast.error>span{background:var(--red);color:#fff}.ops-toast.error>span:before{content:"!"}.ops-toast.error>span{font-size:0}.ops-toast.error>span:before{font-size:10px}
    .job-record-footer{padding-top:14px}.job-record-footer button{min-width:0}.finance-card.overdue{border-left-color:var(--red)}.finance-card.outstanding{border-left-color:var(--amber)}.finance-card.settled{border-left-color:var(--green)}
    /* FINAL V20 UX POLISH */
    .detail.open .detail-head,.detail.full-page .detail-head{background:linear-gradient(135deg,#171c22,#111419 60%);color:var(--ink)}.detail-head{overflow:visible}.detail-head .card-top{min-width:0}.detail-actions{align-items:center}.detail-actions>*{white-space:nowrap;line-height:1.1}.detail-close{margin:0 0 14px;position:relative;z-index:3}.detail.full-page{position:fixed!important;inset:0!important;z-index:70!important;overflow:auto!important;min-height:100vh!important;border:0!important;background:var(--paper)!important}.detail.full-page .detail-close{display:inline-flex!important}.detail.full-page .detail-head{position:sticky;top:0;z-index:4;box-shadow:0 10px 28px rgba(0,0,0,.18)}.detail.full-page .detail-body{width:min(1120px,100%);margin:0 auto;padding:28px 30px 54px}.detail.full-page .detail-head{padding:24px 30px 20px}.job-summary .detail-body{padding-top:18px}.summary-route{display:grid;grid-template-columns:1fr auto 1fr;gap:10px;align-items:center;margin:4px 0 18px}.summary-route .summary-stop{border:1px solid var(--line);border-radius:8px;background:var(--surface);padding:13px;min-width:0}.summary-route .summary-stop span{display:block;color:var(--muted);font-size:7px;font-weight:900;letter-spacing:.11em;text-transform:uppercase;margin-bottom:5px}.summary-route .summary-stop strong{display:block;font-size:10px;line-height:1.45;word-break:break-word}.summary-route .summary-arrow{color:#5f6a77;font-size:16px}.summary-open{margin-top:18px;display:flex;justify-content:flex-end}.summary-open .primary{min-width:160px}.account-delete-note{color:#7f8996;font-size:9px;margin:8px 0 0}
    @media(max-width:1080px){.shell{grid-template-columns:82px minmax(0,1fr)}.rail{padding-inline:12px}.brand-lockup{padding:0;justify-content:center}.brand-lockup>div:last-child,.nav-caption,.tab-copy,.tab kbd,.rail-foot{display:none}.tab{grid-template-columns:1fr;justify-items:center}.content{padding-inline:20px}.topbar{padding-inline:20px}.command-trigger{width:42px;padding:0;justify-content:center}.command-trigger span{display:none}.split{grid-template-columns:320px minmax(0,1fr)}.data-grid{grid-template-columns:repeat(2,minmax(0,1fr))}}
    @media(max-width:760px){.shell{display:block}.rail{position:fixed;inset:auto 0 0;height:66px;padding:6px 7px calc(6px + env(safe-area-inset-bottom));border:0;border-top:1px solid var(--line);background:rgba(8,10,12,.96);display:block;z-index:45}.rail>.brand-lockup,.rail>.tabs,.rail>.nav-caption,.rail>.rail-foot{display:none}.mobile-nav{width:100%;height:100%;margin:0;display:grid;grid-template-columns:repeat(4,1fr);gap:4px}.mobile-nav button{border:0;border-radius:8px;background:transparent;color:#67717d;padding:5px;font-size:8px;font-weight:900}.mobile-nav button.active{background:rgba(13,87,216,.12);color:var(--acid)}.topbar{height:82px;padding:0 14px}.breadcrumb,.topbar small,.command-trigger{display:none}.topbar h1{font-size:19px}.content{padding:12px 12px 88px}.stats{grid-template-columns:repeat(2,1fr)}.stat{min-height:60px;padding:11px}.stat:nth-child(2){border-right:0}.stat:nth-child(-n+2){border-bottom:1px solid var(--line)}.stat strong,.stat span{padding-left:14px}.toolbar{align-items:stretch;flex-direction:column}.toolbar .search{min-width:0}.segmented{overflow:auto}.split{display:block;min-height:0}.list{border-right:0;margin:0}.detail.open{background:var(--panel)}.detail.open .detail-head{background:linear-gradient(135deg,#171c22,#111419 60%)}.data-grid,.account-form,.finance-form{grid-template-columns:1fr}.processor-hero{padding:22px 18px}.processor-hero h2{font-size:29px}.processor-card{grid-template-columns:28px minmax(0,1fr)}.processor-actions{grid-template-columns:1fr 1fr}.ops-toast{left:12px;right:12px;bottom:78px}.command-modal{padding-top:7vh}.command-foot{justify-content:space-between}.record-modal{padding:6px}}
    @media(max-width:620px){.summary-route{grid-template-columns:1fr}.summary-route .summary-arrow{display:none}.detail.full-page .detail-body,.detail.full-page .detail-head{padding-left:17px;padding-right:17px}.execution-primary{width:100%;min-width:0}}
    /* FINAL V22 MANDATORY DELIVERY PHOTO */
    .delivery-photo-section{border:1px solid rgba(13,87,216,.32);border-left:4px solid var(--blue);border-radius:9px;background:linear-gradient(135deg,rgba(13,87,216,.10),#15191f 58%);padding:16px}.delivery-photo-section h3{font-size:10px}.delivery-photo-section>p{color:#8e98a5;font-size:10px;line-height:1.5}.delivery-photo-frame{margin:12px 0;border:1px solid #313a44;border-radius:9px;overflow:hidden;background:#090b0e}.delivery-photo-frame img{display:block;width:100%;max-height:440px;object-fit:contain;background:#080a0c}.delivery-photo-meta{display:flex;flex-wrap:wrap;gap:7px;margin:9px 0 14px;color:#7f8996;font-size:8px}.delivery-photo-form{display:grid;gap:10px}.delivery-photo-choices{display:flex;flex-wrap:wrap;gap:8px}.photo-picker{position:relative;overflow:hidden;cursor:pointer}.photo-picker input{position:absolute;inline-size:1px;block-size:1px;opacity:0;pointer-events:none}.delivery-photo-preview{display:none;border:1px solid #313a44;border-radius:9px;overflow:hidden;background:#090b0e}.delivery-photo-preview.ready{display:block}.delivery-photo-preview img{display:block;width:100%;max-height:360px;object-fit:contain}.delivery-photo-file{color:#87919d;font-size:9px;min-height:14px}.delivery-photo-submit{justify-self:start}.delivery-photo-required{border-color:rgba(255,182,72,.3);border-left-color:var(--amber);background:linear-gradient(135deg,rgba(255,182,72,.08),#15191f 58%)}.delivery-photo-complete{border-left-color:var(--blue)}.photo-gate-note{color:var(--amber);font-size:9px;font-weight:850;letter-spacing:.03em}.execution-panel.photo-blocked .execution-primary{border-color:#4a4140;background:#252525;color:#8d8d8d;box-shadow:none}.stop-actions button.photo-blocked{opacity:.45;cursor:not-allowed}.detail-actions button.photo-blocked{opacity:.45;cursor:not-allowed}
    @media(max-width:620px){.delivery-photo-choices{display:grid;grid-template-columns:1fr 1fr}.photo-picker,.delivery-photo-submit{width:100%}.delivery-photo-submit{justify-self:stretch}}
    /* FINAL V21 SUMMARY / FINANCE / NAV POLISH */
    .detail-actions{display:flex;align-items:center;flex-wrap:wrap;gap:8px}.detail-actions>button,.detail-actions>a{display:inline-flex!important;align-items:center!important;justify-content:center!important;height:38px;min-height:38px;margin:0!important;padding:0 13px!important;line-height:1!important;text-decoration:none!important;vertical-align:middle}.detail-actions .contact-btn{text-decoration:none!important}.summary-stage{display:flex;align-items:center;justify-content:space-between;gap:12px;margin:0 0 15px;padding:12px 13px;border:1px solid rgba(13,87,216,.22);border-left:3px solid var(--blue);border-radius:8px;background:rgba(13,87,216,.07)}.summary-stage strong{font-size:9px;letter-spacing:.12em;text-transform:uppercase}.summary-stage span{color:#8d99aa;font-size:9px;text-align:right}.finance-summary .detail-body{padding-top:18px}.mark-paid[disabled]{opacity:.42;cursor:default;transform:none!important}.summary-delete{margin-left:0!important}
    @media(max-width:1080px) and (min-width:761px){.brand-lockup{width:100%;justify-content:center}.tabs{width:100%;margin-top:10px!important;justify-items:center}.tab{width:58px!important;min-height:58px;padding:9px 5px!important;display:flex!important;align-items:center!important;justify-content:center!important;transform:none!important}.tab:hover{transform:none!important}.tab-key{margin:0 auto}}
    @media(prefers-reduced-motion:reduce){*{transition:none!important;scroll-behavior:auto!important}}
  </style>
</head>
<body>
  <section id="login" class="login">
    <form id="login-form" class="login-card">
      <div class="wordmark">SORRIN</div><div class="eyebrow">Private operations</div>
      <h1>Sign in</h1><p>USC account control and courier job organisation.</p>
      <div class="field"><label for="login-email">Email</label><input id="login-email" name="email" type="email" value="courier@sorrin.com.au" autocomplete="username" required></div>
      <div class="field"><label for="login-password">Password</label><input id="login-password" name="password" type="password" autocomplete="current-password" required></div>
      <button class="primary" type="submit" style="width:100%">ENTER OPERATIONS</button>
      <div id="login-error" class="error" role="alert"></div>
    </form>
  </section>
  <div id="app" class="shell hidden">
    <aside class="rail"><div class="brand-lockup"><div class="brand-cube" aria-hidden="true"></div><div><div class="wordmark">SORRIN</div><div class="eyebrow">Command console</div></div></div>
      <div class="nav-caption">Operations</div>
      <nav class="tabs" aria-label="Primary navigation"><button class="tab" data-section="processor"><span class="tab-key">NOW</span><span class="tab-copy"><strong>Dispatch</strong><small>Live run</small></span><kbd>⌘1</kbd></button><button class="tab active" data-section="jobs"><span class="tab-key">JOBS</span><span class="tab-copy"><strong>Jobs</strong><small>Book & execute</small></span><kbd>⌘2</kbd></button><button class="tab" data-section="finance"><span class="tab-key">$$$</span><span class="tab-copy"><strong>Finance</strong><small>Collect & invoice</small></span><kbd>⌘3</kbd></button><button class="tab" data-section="accounts"><span class="tab-key">USC</span><span class="tab-copy"><strong>USC accounts</strong><small>Clients & benefits</small></span><kbd>⌘4</kbd></button></nav>
      <div class="mobile-nav"><button data-section="processor">ROUTE</button><button class="active" data-section="jobs">JOBS</button><button data-section="finance">MONEY</button><button data-section="accounts">USC</button></div>
      <div class="rail-foot"><div class="system-state"><span></span>All systems operational</div><div class="build-label">BUILD ${OPS_BUILD}</div><button id="logout">Sign out</button></div>
    </aside>
    <main class="main"><header class="topbar"><div class="topbar-title"><div id="section-breadcrumb" class="breadcrumb">OPERATIONS / JOBS</div><h1 id="page-title">Courier jobs</h1><small id="page-subtitle">Approve, execute and close every movement</small></div><div class="topbar-actions"><button id="command-switcher" class="command-trigger" type="button"><span>Jump or search</span><kbd>⌘ K</kbd></button><button id="new-job-top" class="primary">+ NEW JOB</button><button id="new-account-top" class="primary hidden">+ NEW ACCOUNT</button></div></header>
      <div class="content">
        <div id="job-stats" class="stats"></div>
        <section id="processor-section" class="hidden">
          <div class="processor-hero"><div><div class="eyebrow">Traffic-aware live run</div><h2>One queue. Every commitment.</h2><p>Approved and active jobs are assessed together against the selected starting point. Future-date work stays visible without corrupting today’s route, while every live leg is measured from the stop before it.</p></div><div class="processor-origin"><label for="processor-origin">Start this assessment from</label><input id="processor-origin" name="processorOrigin" value="Myer Ballarat, 18 Armstrong Street South, Ballarat Central VIC 3350, Australia" autocomplete="street-address"><div class="processor-origin-actions"><button id="processor-location" class="secondary" type="button">USE MY LOCATION</button><button id="refresh-processor" class="primary" type="button">REASSESS ROUTE</button></div></div></div>
          <div id="processor-output"><div class="processor-empty">Open the processor to assess the current run.</div></div>
        </section>
        <section id="jobs-section">
          <div class="toolbar"><input id="job-search" name="jobSearch" class="search" type="search" aria-label="Search courier jobs" placeholder="Search reference, customer, USC, phone or address">
            <div id="job-views" class="segmented"><button class="active" data-view="pending">Pending</button><button data-view="current">Current</button><button data-view="completed">Completed</button><button data-view="all">All</button></div><a class="secondary" href="/operations/api/export/jobs.csv">EXPORT CSV</a>
          </div>
          <div class="split"><div id="job-list" class="list"></div><article id="job-detail" class="detail"><div class="empty">Select a job for a quick summary. Double-click any job to open the full record.</div></article></div>
          <div class="job-record-footer"><button id="full-job-record" class="secondary" type="button">FULL JOB RECORD</button></div>
        </section>
        <section id="accounts-section" class="hidden">
          <div class="toolbar"><input id="account-search" name="accountSearch" class="search" type="search" aria-label="Search USC accounts" placeholder="Search USC, business, email, phone or tag"><button id="new-account" class="primary">NEW ACCOUNT</button><a class="secondary" href="/operations/api/export/accounts.csv">EXPORT CSV</a></div>
          <div class="split"><div id="account-list" class="list"></div><article id="account-detail" class="detail"><div class="empty">Select an account or create a new one.</div></article></div>
        </section>
        <section id="finance-section" class="hidden">
          <div id="finance-stats" class="stats"></div>
          <div class="toolbar"><input id="finance-search" name="financeSearch" class="search" type="search" aria-label="Search payments and invoices" placeholder="Search job, customer, USC or invoice"><div id="finance-views" class="segmented"><button class="active" data-finance-view="outstanding">Outstanding</button><button data-finance-view="overdue">Overdue</button><button data-finance-view="settled">Settled</button><button data-finance-view="all">All</button></div><a class="secondary" href="/operations/api/export/finance.csv">EXPORT CSV</a></div>
          <div class="split"><div id="finance-list" class="list"></div><article id="finance-detail" class="detail"><div class="empty">Select a finance record for a quick summary. Double-click any record to open the full finance window.</div></article></div>
        </section>
      </div>
    </main>
  </div>
  <div id="command-modal" class="command-modal hidden" role="dialog" aria-modal="true" aria-labelledby="command-title"><div class="command-panel"><div class="command-head"><span class="command-glyph">⌕</span><h2 id="command-title">Jump anywhere</h2><kbd>ESC</kbd></div><div class="command-group"><div class="command-caption">Switch component</div><button type="button" data-command-section="processor"><span class="tab-key">NOW</span><span><strong>Dispatch</strong><small>Live run</small></span><kbd>⌘1</kbd></button><button type="button" data-command-section="jobs"><span class="tab-key">JOBS</span><span><strong>Courier jobs</strong><small>Book & execute</small></span><kbd>⌘2</kbd></button><button type="button" data-command-section="finance"><span class="tab-key">$$$</span><span><strong>Finance</strong><small>Collect & invoice</small></span><kbd>⌘3</kbd></button><button type="button" data-command-section="accounts"><span class="tab-key">USC</span><span><strong>USC accounts</strong><small>Clients & benefits</small></span><kbd>⌘4</kbd></button></div><div class="command-group command-actions"><div class="command-caption">Quick actions</div><button type="button" data-command-action="new-job"><span class="tab-key">+</span><span><strong>Create courier job</strong><small>Open a fresh booking</small></span></button><button type="button" data-command-action="new-account"><span class="tab-key">+</span><span><strong>Create USC account</strong><small>Add a private client account</small></span></button><button type="button" data-command-action="job-record"><span class="tab-key">↗</span><span><strong>Full job record</strong><small>Open permanent operations history</small></span></button></div><div class="command-foot"><span>⌘1–4 Switch</span><span>/ Focus search</span><span>ESC Close</span></div></div></div>
  <div id="ops-toast" class="ops-toast hidden" role="status" aria-live="polite"><span>✓</span><p></p></div>
  <div id="job-record-modal" class="record-modal hidden" role="dialog" aria-modal="true" aria-labelledby="job-record-title"><div class="record-shell"><button id="job-record-close" class="record-close" type="button" aria-label="Close full job record">×</button><div class="record-head"><div class="eyebrow">Permanent operations history</div><h2 id="job-record-title">Full job record</h2><p style="color:var(--muted);margin:0">Every courier job remains here, including jobs removed from the main Courier jobs screen.</p></div><div class="toolbar"><input id="job-record-search" class="search" type="search" aria-label="Search full job record" placeholder="Search reference, customer, USC or address"></div><div class="record-grid"><div id="job-record-list" class="record-list"></div><article id="job-record-detail" class="record-detail"><div class="empty">Select a record to inspect it.</div></article></div></div></div>
  <script>
    var processorHome="Myer Ballarat, 18 Armstrong Street South, Ballarat Central VIC 3350, Australia";
    var savedProcessorOrigin=localStorage.getItem("sorrin_processor_origin")||processorHome;
    if(/^(?:3350|Ballarat Central(?: Victoria)? 3350(?:, Australia)?|3350 Victoria Road.*NSW)$/i.test(savedProcessorOrigin))savedProcessorOrigin=processorHome;
    var state={jobs:[],accounts:[],finances:[],tags:[],processor:null,processorLoading:false,processorOrigin:{address:savedProcessorOrigin,latitude:null,longitude:null,label:null},section:"jobs",jobView:"pending",financeView:"outstanding",selectedJob:null,selectedAccount:null,selectedFinance:null,jobRecord:[],stripeMode:"${stripeMode(env)}"};
    var sectionOrder=["processor","jobs","finance","accounts"];
    var savedSection=String(location.hash||"").replace("#","")||localStorage.getItem("sorrin_ops_section")||"jobs";
    if(sectionOrder.indexOf(savedSection)<0)savedSection="jobs";
    var toastTimer=null;
    var jobClickTimer=null;
    var financeClickTimer=null;
    function showToast(message){var toast=document.getElementById("ops-toast");if(!toast)return;var text=String(message||"");toast.querySelector("p").textContent=text;toast.classList.toggle("error",/(error|failed|cannot|invalid|unavailable|not found)/i.test(text));toast.classList.remove("hidden");clearTimeout(toastTimer);toastTimer=setTimeout(function(){toast.classList.add("hidden");},4200);}
    window.alert=function(message){showToast(message);};
    function setCommandOpen(open){var modal=document.getElementById("command-modal");modal.classList.toggle("hidden",!open);document.body.classList.toggle("command-open",open);}
    function focusSectionSearch(){var targets={jobs:"job-search",accounts:"account-search",finance:"finance-search",processor:"processor-origin"};var input=document.getElementById(targets[state.section]);if(input){input.focus();if(input.select)input.select();}}
    function esc(value){return String(value==null?"":value).replace(/[&<>"']/g,function(character){return({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#039;"})[character];});}
    function money(cents){return cents==null?"Manual quote":"$"+(Number(cents)/100).toFixed(2);}
    function dateText(value){if(!value)return "—";var date=new Date(String(value).replace(" ","T")+"Z");return isNaN(date)?String(value):date.toLocaleString("en-AU",{dateStyle:"medium",timeStyle:"short"});}
    function timeText(value){if(!value)return "—";var date=new Date(value);return isNaN(date)?String(value):date.toLocaleTimeString("en-AU",{hour:"numeric",minute:"2-digit"});}
    function maps(address){return "https://www.google.com/maps/dir/?api=1&destination="+encodeURIComponent(address||"");}
    function appleMaps(address){return "https://maps.apple.com/?daddr="+encodeURIComponent(address||"")+"&dirflg=d";}
    function waze(address){return "https://www.waze.com/ul?q="+encodeURIComponent(address||"")+"&navigate=yes";}
    function navOptions(address){return '<div class="nav-options"><a href="'+maps(address)+'" target="_blank" rel="noopener">GOOGLE MAPS</a><a href="'+appleMaps(address)+'" target="_blank" rel="noopener">APPLE MAPS</a><a href="'+waze(address)+'" target="_blank" rel="noopener">WAZE</a></div>';}
    async function api(path,options){options=options||{};var config={method:options.method||"GET",headers:{}};if(options.body!==undefined){config.headers["Content-Type"]="application/json";config.body=JSON.stringify(options.body);}var response=await fetch(path,config);var result=await response.json().catch(function(){return{};});if(!response.ok){var build=response.headers.get("X-Sorrin-Operations-Build")||result.build||"unknown build";var message=result.detail?(result.error||"Request failed")+" — "+result.detail:(result.error||"Request failed");var error=new Error("["+build+"] "+message);error.status=response.status;throw error;}return result;}
    function showLogin(){document.getElementById("login").classList.remove("hidden");document.getElementById("app").classList.add("hidden");}
    function showApp(){document.getElementById("login").classList.add("hidden");document.getElementById("app").classList.remove("hidden");}
    async function boot(){document.getElementById("processor-origin").value=state.processorOrigin.address;try{await api("/operations/api/session");showApp();await refresh();switchSection(savedSection);}catch(error){showLogin();}}
    async function refresh(){var data=await api("/operations/api/overview");state.jobs=data.jobs||[];state.accounts=data.accounts||[];state.finances=data.finances||[];try{var tags=await api("/operations/api/tags");state.tags=tags.tags||[];}catch(error){state.tags=[];}renderStats();renderJobs();renderAccounts();renderFinances();if(state.section==="processor")await loadProcessor();}
    function renderStats(){var counts={pending:0,approved:0,active:0,delivered:0};state.jobs.forEach(function(job){counts[job.status]=(counts[job.status]||0)+1;});document.getElementById("job-stats").innerHTML='<div class="stat"><strong>'+counts.pending+'</strong><span>Pending</span></div><div class="stat"><strong>'+counts.approved+'</strong><span>Approved</span></div><div class="stat"><strong>'+counts.active+'</strong><span>Current</span></div><div class="stat"><strong>'+counts.delivered+'</strong><span>Delivered</span></div>';}
    async function loadProcessor(){if(state.processorLoading)return;state.processorLoading=true;var output=document.getElementById("processor-output");var input=document.getElementById("processor-origin");var query=new URLSearchParams();if(state.processorOrigin.latitude!=null&&state.processorOrigin.longitude!=null){query.set("originLat",state.processorOrigin.latitude);query.set("originLng",state.processorOrigin.longitude);query.set("originLabel",state.processorOrigin.label||"Current device location");}else{state.processorOrigin.address=input.value.trim()||processorHome;localStorage.setItem("sorrin_processor_origin",state.processorOrigin.address);query.set("origin",state.processorOrigin.address);}output.innerHTML='<div class="processor-empty">Comparing every approved and active job against current road conditions…</div>';try{var data=await api("/operations/api/processor?"+query.toString());state.processor=data.processor||null;renderProcessor();}catch(error){output.innerHTML='<div class="processor-empty">'+esc(error.message)+'</div>';}finally{state.processorLoading=false;}}
    function useProcessorLocation(){var button=document.getElementById("processor-location");if(!navigator.geolocation){alert("This device cannot provide its current location.");return;}button.classList.add("busy");navigator.geolocation.getCurrentPosition(function(position){state.processorOrigin.latitude=position.coords.latitude;state.processorOrigin.longitude=position.coords.longitude;state.processorOrigin.label="Current device location";document.getElementById("processor-origin").value=state.processorOrigin.label;button.classList.remove("busy");loadProcessor();},function(){button.classList.remove("busy");alert("Current location was not available. Enter a starting address instead.");},{enableHighAccuracy:true,timeout:12000,maximumAge:30000});}
    function renderProcessor(){var processor=state.processor;var output=document.getElementById("processor-output");if(!processor||!(processor.candidates||[]).length){output.innerHTML='<div class="processor-empty"><strong>No actionable jobs.</strong><br><br>Approve a pending job and it will enter the shared queue.</div>';return;}var routing=processor.routing||{};var routeClass=routing.mode==="traffic_aware"||routing.mode==="road_time"?"":" fallback";var routeTitle=routing.mode==="traffic_aware"?"LIVE TRAFFIC ACTIVE":routing.mode==="road_time"?"CURRENT ROAD TIMES ACTIVE":"COMMITMENT-ONLY FALLBACK";var origin=routing.origin&&routing.origin.label?" Start: "+routing.origin.label+".":"";var routeStatus='<div class="route-status'+routeClass+'"><strong>'+esc(routeTitle)+'</strong> · '+esc(routing.message||"")+esc(origin)+'</div>';var cards=processor.candidates.map(function(item,index){var stopLabel=item.stopType==="pickup"?"Pickup":"Drop-off "+Math.max(1,item.stopSequence-1);var deadlineLabel=item.deadlineStopType==="dropoff"?"Drop-off "+Math.max(1,item.deadlineStopSequence-1)+" deadline":"Latest";var timing=item.latestTime?deadlineLabel+": "+item.latestTime:(item.earliestTime?"Ready: "+item.earliestTime:"No fixed time");var road=Number.isFinite(item.travelMinutes)?'<p class="road-time">'+item.travelMinutes+' min · '+Number(item.travelKm||0).toFixed(1)+' km from start · ETA '+esc(timeText(item.etaAt))+'</p>':'';return '<article class="processor-card '+(index===0?'recommended':'')+'"><div class="processor-order">'+item.position+'</div><div><div class="card-top"><span class="reference">'+esc(item.reference)+'</span><span class="pressure '+esc(item.pressure.level)+'">'+esc(item.pressure.label)+'</span></div><h3>'+esc(stopLabel)+' · '+esc(item.suburb)+'</h3><p>'+esc(item.address)+'</p>'+road+'<p><strong>'+esc(item.serviceLevel)+'</strong> · '+esc(timing)+'</p><p>'+esc(item.pressure.explanation)+'</p>'+(index===0?'<p><strong>RECOMMENDED NEXT STOP</strong></p>':'')+'</div><div class="processor-actions"><a class="nav-btn" href="'+maps(item.address)+'" target="_blank" rel="noopener">NAVIGATE</a><button class="secondary" data-processor-job="'+esc(item.reference)+'">OPEN JOB</button></div></article>';}).join("");var conflicts=(processor.conflicts||[]).map(function(conflict){return '<div class="conflict"><strong>'+(conflict.level==="critical"?"Projected route conflict":"Potential timing clash")+'</strong><p>'+esc(conflict.message)+'</p></div>';}).join("")||'<p>No route or close-deadline clashes detected.</p>';var limits=(processor.limits||[]).map(function(limit){return '<li>'+esc(limit)+'</li>';}).join("");var counts=processor.counts||{};output.innerHTML=routeStatus+'<div class="stats"><div class="stat"><strong>'+Number(counts.jobs||0)+'</strong><span>Actionable jobs</span></div><div class="stat"><strong>'+Number(counts.critical||0)+'</strong><span>Critical now</span></div><div class="stat"><strong>'+Number(counts.strict||0)+'</strong><span>Strict windows</span></div><div class="stat"><strong>'+Number(counts.potentialConflicts||0)+'</strong><span>Potential clashes</span></div></div><div class="processor-grid"><div class="processor-stack">'+cards+'</div><aside class="processor-side"><div class="processor-panel"><h3>Timing watch</h3>'+conflicts+'</div><div class="processor-panel"><h3>Processor rules</h3><ul>'+limits+'</ul></div></aside></div>';output.querySelectorAll("[data-processor-job]").forEach(function(button){button.addEventListener("click",function(){switchSection("jobs");openJob(button.dataset.processorJob,false);});});}
    function filteredJobs(){var search=document.getElementById("job-search").value.trim().toLowerCase();return state.jobs.filter(function(job){var matchesView=state.jobView==="all"||(state.jobView==="pending"&&["pending","approved"].indexOf(job.status)>-1)||(state.jobView==="current"&&job.status==="active")||(state.jobView==="completed"&&["delivered","declined","cancelled"].indexOf(job.status)>-1);var hay=[job.reference,job.requesterName,job.requesterEmail,job.requesterPhone,job.businessName,job.usc,job.pickupAddress,job.primaryDropoffAddress].join(" ").toLowerCase();return matchesView&&(!search||hay.indexOf(search)>-1);});}
    function renderJobs(){var jobs=filteredJobs();var list=document.getElementById("job-list");if(!jobs.length){list.innerHTML='<div class="empty">No jobs in this view.</div>';return;}list.innerHTML=jobs.map(function(job){return '<button class="card '+(state.selectedJob===job.reference?'selected':'')+'" data-job="'+esc(job.reference)+'" title="Click for summary · Double-click for full job"><div class="card-top"><span class="reference">'+esc(job.reference)+'</span><span class="badge '+esc(job.status)+'">'+esc(job.status)+'</span></div><h3>'+esc(job.requesterName)+'</h3><p>'+esc(job.pickupAddress)+' → '+esc(job.primaryDropoffAddress)+'</p><p><strong>'+esc(job.serviceLevel)+'</strong> · <span class="money">'+money(job.totalCents)+'</span></p></button>';}).join("");list.querySelectorAll("[data-job]").forEach(function(button){button.addEventListener("click",function(){clearTimeout(jobClickTimer);jobClickTimer=setTimeout(function(){openJob(button.dataset.job,false);},220);});button.addEventListener("dblclick",function(event){event.preventDefault();clearTimeout(jobClickTimer);openJob(button.dataset.job,true);});});}
    function renderJobSummary(job){var panel=document.getElementById("job-detail");var pickup=(job.stops||[]).find(function(stop){return stop.stop_type==="pickup";});var upcoming=nextStop(job);var dropoff=(job.stops||[]).filter(function(stop){return stop.stop_type==="dropoff";}).slice(-1)[0];var finance=job.finance||{};var action=job.execution||{};panel.classList.add("job-summary");panel.innerHTML='<div class="detail-head"><div class="card-top"><span class="reference">'+esc(job.reference)+'</span><span class="badge '+esc(job.status)+'">'+esc(job.status)+'</span></div><h2>'+esc(job.requesterName)+'</h2><p>'+esc(job.serviceLevel)+' · '+money(job.totalCents)+'</p><div class="detail-actions">'+(pickup?'<a class="nav-btn" href="'+maps(pickup.address)+'" target="_blank" rel="noopener">NAVIGATE TO PICKUP</a>':'')+(upcoming?'<a class="secondary" href="'+maps(upcoming.address)+'" target="_blank" rel="noopener">NEXT STOP</a>':'')+'<a class="contact-btn" href="tel:'+esc(job.requesterPhone)+'">CALL</a><a class="contact-btn" href="mailto:'+esc(job.requesterEmail)+'">EMAIL</a></div></div><div class="detail-body"><div class="summary-route"><div class="summary-stop"><span>Pickup</span><strong>'+esc(pickup&&pickup.address||job.pickupAddress||'—')+'</strong></div><div class="summary-arrow">→</div><div class="summary-stop"><span>Final drop-off</span><strong>'+esc(dropoff&&dropoff.address||job.primaryDropoffAddress||'—')+'</strong></div></div><div class="data-grid"><div class="datum"><span>USC</span><strong>'+esc(job.usc||'Guest / not linked')+'</strong></div><div class="datum"><span>Payment</span><strong>'+esc(finance.effectiveStatus||job.paymentStatus||'Not started')+'</strong></div><div class="datum"><span>Outstanding</span><strong>'+(job.finance?money(finance.outstandingCents||0):'—')+'</strong></div><div class="datum"><span>Next action</span><strong>'+esc(action.label||'No action required')+'</strong></div><div class="datum"><span>Phone</span><strong>'+esc(job.requesterPhone||'—')+'</strong></div><div class="datum"><span>Submitted</span><strong>'+dateText(job.createdAt)+'</strong></div></div>'+(action.enabled?'<section class="section execution-panel" style="margin-top:20px"><h3>Live job execution</h3><p>'+(upcoming?'Next: '+esc(upcoming.stop_type)+' · '+esc(upcoming.address):'Every stop is closed.')+'</p><button type="button" class="execution-primary" id="summary-execute-next">'+esc(action.label||'ADVANCE JOB')+'</button></section>':'')+'<div class="summary-open"><button type="button" class="primary" id="open-full-job">OPEN FULL JOB</button></div></div>';var open=document.getElementById("open-full-job");if(open)open.addEventListener("click",function(){openJob(job.reference,true);});var execute=document.getElementById("summary-execute-next");if(execute)execute.addEventListener("click",function(){executeNext(job.reference,execute,false);});}
    async function openJob(reference,fullPage){state.selectedJob=reference;renderJobs();var panel=document.getElementById("job-detail");panel.classList.remove("job-summary");panel.classList.toggle("full-page",Boolean(fullPage));panel.classList.toggle("open",Boolean(fullPage));panel.innerHTML='<div class="empty">Opening job…</div>';try{var data=await api("/operations/api/jobs/"+encodeURIComponent(reference));if(fullPage)renderJobDetail(data.job);else renderJobSummary(data.job);}catch(error){panel.innerHTML='<div class="empty">'+esc(error.message)+'</div>';}}
    function cargoText(job){var quote=job.quote||{};var parts=[quote.packageLabel,quote.itemCount?quote.itemCount+" item(s)":null,quote.dimensions,quote.perishable==="Yes"?"Perishable":null].filter(Boolean);return parts.join(" · ")||"Not supplied";}
    function nextStop(job){return (job.stops||[]).find(function(stop){return ["completed","skipped","cancelled"].indexOf(stop.stop_status)<0;})||(job.stops||[])[job.stops.length-1];}
    function renderJobDetail(job){var quote=job.quote||{};var upcoming=nextStop(job);var pickup=(job.stops||[]).find(function(stop){return stop.stop_type==="pickup";});var surcharges=(quote.surcharges||[]).map(function(item){return esc(item.label)+" ($"+Number(item.price||0).toFixed(2)+")";}).join(", ")||"None";var stops=(job.stops||[]).map(function(stop){return '<div class="stop"><div class="stop-top"><div><h4>'+esc(stop.stop_sequence)+'. '+esc(stop.stop_type)+'</h4><p>'+esc(stop.address)+'</p><p>'+esc(stop.earliest_time||"Any time")+(stop.latest_time?' → '+esc(stop.latest_time):'')+'</p></div><span class="badge '+esc(stop.stop_status)+'">'+esc(stop.stop_status)+'</span></div><div class="stop-actions"><a href="'+maps(stop.address)+'" target="_blank" rel="noopener">NAVIGATE</a>'+(["completed","skipped","cancelled"].indexOf(stop.stop_status)<0?'<button data-stop="'+esc(stop.id)+'" data-stop-status="en_route">EN ROUTE</button><button data-stop="'+esc(stop.id)+'" data-stop-status="arrived">ARRIVED</button><button data-stop="'+esc(stop.id)+'" data-stop-status="completed">COMPLETE</button>':'')+'</div></div>';}).join("");var events=(job.events||[]).map(function(event){var data=typeof event.event_data==="string"?event.event_data:"";return '<div class="event"><strong>'+esc((event.event_type||"event").replace(/_/g," "))+'</strong><p>'+dateText(event.created_at)+'</p>'+(data?'<p>'+esc(data.length>180?data.slice(0,180)+"…":data)+'</p>':'')+'</div>';}).join("")||'<p>No history yet.</p>';var account=job.account?'<div class="datum"><span>USC account</span><strong>'+esc(job.account.businessName)+' · '+esc(job.account.usc)+'</strong></div>':'';document.getElementById("job-detail").innerHTML='<div class="detail-head"><button class="secondary detail-close hidden" id="close-job">CLOSE</button><div class="card-top"><span class="reference">'+esc(job.reference)+'</span><span class="badge '+esc(job.status)+'">'+esc(job.status)+'</span></div><h2>'+esc(job.requesterName)+'</h2><p>'+esc(job.serviceLevel)+' · '+money(job.totalCents)+'</p><div class="detail-actions">'+(pickup?'<a class="nav-btn" href="'+maps(pickup.address)+'" target="_blank" rel="noopener">NAVIGATE TO PICKUP</a>':'')+(upcoming?'<a class="nav-btn" href="'+maps(upcoming.address)+'" target="_blank" rel="noopener">NAVIGATE TO NEXT STOP</a>':'')+'<a class="contact-btn" href="tel:'+esc(job.requesterPhone)+'">CALL</a><a class="contact-btn" href="mailto:'+esc(job.requesterEmail)+'">EMAIL</a></div></div><div class="detail-body"><section class="section"><h3>Change status</h3><div class="status-row"><select id="job-status" name="jobStatus" aria-label="Job status">'+["pending","approved","active","delivered","declined","cancelled"].map(function(status){return '<option '+(job.status===status?'selected':'')+' value="'+status+'">'+status.toUpperCase()+'</option>';}).join("")+'</select><button class="status-btn" id="save-job-status">SAVE STATUS</button></div><div class="field"><label for="job-note">Optional note</label><textarea id="job-note" name="jobNote" placeholder="Add context to the status history"></textarea></div></section><section class="section"><h3>Job details</h3><div class="data-grid"><div class="datum"><span>Customer</span><strong>'+esc(job.requesterName)+'</strong></div>'+account+'<div class="datum"><span>Phone</span><strong>'+esc(job.requesterPhone)+'</strong></div><div class="datum"><span>Email</span><strong>'+esc(job.requesterEmail)+'</strong></div><div class="datum"><span>Cargo</span><strong>'+esc(cargoText(job))+'</strong></div><div class="datum"><span>Price</span><strong>'+money(job.totalCents)+'</strong></div><div class="datum"><span>Surcharges</span><strong>'+surcharges+'</strong></div><div class="datum"><span>Payment</span><strong>'+esc(job.paymentMethod||job.paymentStatus||"Not started")+'</strong></div><div class="datum"><span>Submitted</span><strong>'+dateText(job.createdAt)+'</strong></div></div></section><section class="section"><h3>Route order</h3><div class="stops">'+stops+'</div></section><section class="section"><h3>Cargo notes</h3><p>'+esc(quote.cargoNotes||"None")+'</p></section><section class="section"><h3>Status history</h3><div class="timeline">'+events+'</div></section></div>';var close=document.getElementById("close-job");if(close)close.addEventListener("click",function(){openJob(job.reference,false);});document.getElementById("save-job-status").addEventListener("click",function(){saveJobStatus(job.reference);});document.querySelectorAll("[data-stop-status]").forEach(function(button){button.addEventListener("click",function(){saveStop(job.reference,button.dataset.stop,button.dataset.stopStatus);});});}
    async function saveJobStatus(reference){var button=document.getElementById("save-job-status");button.classList.add("busy");try{var data=await api("/operations/api/jobs/"+encodeURIComponent(reference),{method:"PATCH",body:{status:document.getElementById("job-status").value,note:document.getElementById("job-note").value}});state.jobs=state.jobs.map(function(job){return job.reference===reference?Object.assign({},job,{status:data.job.status,paymentStatus:data.job.paymentStatus,finance:data.job.finance,paymentGate:data.job.paymentGate}):job;});renderStats();renderJobs();renderJobDetail(data.job);state.processor=null;if(data.paymentCheckout&&data.paymentCheckout.error){alert('Job approved and safely payment-gated, but the Stripe payment link could not be created: '+data.paymentCheckout.error);}else if(data.paymentCheckout&&data.paymentCheckout.checkout&&!data.paymentCheckout.checkout.emailSent){alert('Job approved and payment-gated. Stripe checkout was created, but the customer email failed: '+(data.paymentCheckout.checkout.emailError||'unknown email error'));}}catch(error){alert(error.message);}finally{button.classList.remove("busy");}}
    async function saveStop(reference,stopId,status){try{var data=await api("/operations/api/jobs/"+encodeURIComponent(reference)+"/stops/"+encodeURIComponent(stopId),{method:"PATCH",body:{status:status}});renderJobDetail(data.job);state.processor=null;}catch(error){alert(error.message);}}
    async function executeNext(reference,button,fromProcessor){if(button)button.classList.add("busy");try{var data=await api("/operations/api/jobs/"+encodeURIComponent(reference)+"/execute-next",{method:"POST",body:{}});state.jobs=state.jobs.map(function(job){return job.reference===reference?Object.assign({},job,{status:data.job.status,paymentStatus:data.job.paymentStatus,finance:data.job.finance}):job;});renderStats();renderJobs();if(!fromProcessor||state.selectedJob===reference){var full=document.getElementById("job-detail").classList.contains("full-page");if(full)renderJobDetail(data.job);else renderJobSummary(data.job);}state.processor=null;if(state.section==="processor")await loadProcessor();}catch(error){alert(error.message);}finally{if(button)button.classList.remove("busy");}}
    function filteredAccounts(){var search=document.getElementById("account-search").value.trim().toLowerCase();return state.accounts.filter(function(account){var hay=[account.businessName,account.usc,account.contactName,account.authorisedEmail,account.authorisedPhone].concat((account.tags||[]).map(function(tag){return tag.code;})).join(" ").toLowerCase();return !search||hay.indexOf(search)>-1;});}
    function renderAccounts(){var accounts=filteredAccounts();var list=document.getElementById("account-list");if(!accounts.length){list.innerHTML='<div class="empty">No USC accounts yet.</div>';return;}list.innerHTML=accounts.map(function(account){return '<button class="card account-card '+(state.selectedAccount===account.id?'selected':'')+'" data-account="'+esc(account.id)+'"><div class="card-top"><span class="reference">'+esc(account.usc)+'</span><span class="badge '+(account.accountState==="active"?'active':'cancelled')+'">'+esc(account.accountState)+'</span></div><h3>'+esc(account.businessName)+'</h3><p>'+esc(account.authorisedEmail)+' · '+esc(account.authorisedPhone)+'</p><p>'+account.bookingCount+' booking(s) · '+money(account.totalActivityCents)+'</p><div class="tags">'+(account.tags||[]).map(function(tag){return '<span class="tag">'+esc(tag.code)+'</span>';}).join("")+'</div></button>';}).join("");list.querySelectorAll("[data-account]").forEach(function(button){button.addEventListener("click",function(){openAccount(button.dataset.account);});});}
    async function openAccount(id){state.selectedAccount=id;renderAccounts();var panel=document.getElementById("account-detail");panel.classList.add("open");panel.innerHTML='<div class="empty">Opening account…</div>';try{var data=await api("/operations/api/accounts/"+encodeURIComponent(id));renderAccountForm(data.account);}catch(error){panel.innerHTML='<div class="empty">'+esc(error.message)+'</div>';}}
    function newAccount(){state.selectedAccount=null;renderAccounts();document.getElementById("account-detail").classList.add("open");renderAccountForm(null);}
    function renderAccountForm(account){account=account||{accountState:"active",invoiceEligible:false,paymentTermsDays:0,tags:[],benefits:[],bookings:[]};var isNew=!account.id;var tags=(account.tags||[]).map(function(tag){return '<span class="tag">'+esc(tag.code)+(isNew?'':'<button class="tag-remove" data-remove-tag="'+esc(tag.code)+'">×</button>')+'</span>';}).join("")||'<span style="color:var(--muted);font-size:13px">No tags assigned</span>';var availableCodes=[];state.tags.forEach(function(tag){if(availableCodes.indexOf(tag.code)<0&&!(account.tags||[]).some(function(current){return current.code===tag.code;}))availableCodes.push(tag.code);});var benefits=(account.benefits||[]).map(function(benefit){return '<div class="benefit"><strong>'+esc(benefit.name)+'</strong><p>'+esc(benefit.description||"")+(benefit.last_redeemed_at?' · Last used '+dateText(benefit.last_redeemed_at):' · Not yet used')+'</p></div>';}).join("")||'<p style="color:var(--muted)">No active benefits.</p>';var history=(account.bookings||[]).map(function(booking){return '<button class="card" data-history-job="'+esc(booking.reference)+'"><div class="card-top"><span class="reference">'+esc(booking.reference)+'</span><span class="badge '+esc(booking.status)+'">'+esc(booking.status)+'</span></div><p>'+esc(booking.pickup_address)+' → '+esc(booking.primary_dropoff_address)+'</p></button>';}).join("")||'<p style="color:var(--muted)">No booking history.</p>';document.getElementById("account-detail").innerHTML='<div class="detail-head"><button class="secondary detail-close hidden" id="close-account">CLOSE</button><span class="eyebrow">'+(isNew?'New USC account':esc(account.usc))+'</span><h2>'+(isNew?'Create account':esc(account.businessName))+'</h2><p>'+(isNew?'Internal account administration only':account.bookingCount+' bookings · '+money(account.totalActivityCents))+'</p></div><div class="detail-body"><form id="account-form" class="account-form"><div class="field"><label for="account-business-name">Business / customer name</label><input id="account-business-name" name="businessName" value="'+esc(account.businessName)+'" required></div><div class="field"><label for="account-usc">Unique USC</label><input id="account-usc" name="usc" value="'+esc(account.usc)+'" placeholder="e.g. FLORA-001" required></div><div class="field"><label for="account-contact-name">Contact name</label><input id="account-contact-name" name="contactName" value="'+esc(account.contactName)+'"></div><div class="field"><label for="account-authorised-email">Authorised email (optional until first use)</label><input id="account-authorised-email" name="authorisedEmail" type="email" value="'+esc(account.authorisedEmail)+'" placeholder="Set now or customer sets on first use"></div><div class="field"><label for="account-authorised-phone">Authorised phone (optional until first use)</label><input id="account-authorised-phone" name="authorisedPhone" value="'+esc(account.authorisedPhone)+'" placeholder="Set now or customer sets on first use"></div><div class="field"><label for="account-state">Account state</label><select id="account-state" name="accountState"><option value="active" '+(account.accountState==="active"?'selected':'')+'>Active</option><option value="suspended" '+(account.accountState==="suspended"?'selected':'')+'>Suspended</option></select></div><label class="check"><input name="invoiceEligible" type="checkbox" '+(account.invoiceEligible?'checked':'')+'> Invoice eligible</label><div class="field"><label for="account-payment-terms">Payment terms (days)</label><input id="account-payment-terms" name="paymentTermsDays" type="number" min="0" max="120" value="'+Number(account.paymentTermsDays||0)+'"></div><div class="field wide"><label for="account-notes">Account notes</label><textarea id="account-notes" name="notes">'+esc(account.notes)+'</textarea></div><div class="wide"><button class="primary" type="submit">'+(isNew?'CREATE ACCOUNT':'SAVE ACCOUNT')+'</button></div></form>'+(!isNew?'<section class="section" style="margin-top:32px"><h3>Tags and benefits</h3><div>'+tags+'</div><div class="status-row" style="margin-top:12px"><select id="tag-select" name="tagCode" aria-label="Choose account tag"><option value="">Choose a tag</option>'+availableCodes.map(function(code){return '<option value="'+esc(code)+'">'+esc(code)+'</option>';}).join("")+'</select><button class="status-btn" id="add-tag">ADD TAG</button></div>'+benefits+'</section><section class="section"><h3>Booking history</h3><div class="list">'+history+'</div></section>':'')+'</div>';document.getElementById("account-form").addEventListener("submit",function(event){event.preventDefault();saveAccount(account.id,event.currentTarget);});var close=document.getElementById("close-account");if(close)close.addEventListener("click",function(){document.getElementById("account-detail").classList.remove("open");});var addTag=document.getElementById("add-tag");if(addTag)addTag.addEventListener("click",function(){assignTag(account.id);});document.querySelectorAll("[data-remove-tag]").forEach(function(button){button.addEventListener("click",function(){removeTag(account.id,button.dataset.removeTag);});});document.querySelectorAll("[data-history-job]").forEach(function(button){button.addEventListener("click",function(){switchSection("jobs");openJob(button.dataset.historyJob,false);});});}
    var renderAccountFormBase=renderAccountForm;
    renderAccountForm=function(account){renderAccountFormBase(account);var form=document.getElementById("account-form");if(!form)return;var notes=form.elements.notes&&form.elements.notes.closest(".field");var freeField=document.createElement("label");freeField.className="check";freeField.innerHTML='<input name="firstTwoJobsFree" type="checkbox" '+(account&&account.firstTwoJobsFree?'checked':'')+'> FIRST TWO JOBS FREE';if(notes)form.insertBefore(freeField,notes);var field=document.createElement("div");field.className="field";field.innerHTML='<label for="account-completed-prepaid">Completed prepaid deliveries</label><input id="account-completed-prepaid" name="completedPrepaidDeliveries" type="number" min="0" step="1" value="'+Number(account&&account.completedPrepaidDeliveries||0)+'">';if(notes)form.insertBefore(field,notes);};
    async function saveAccount(id,form){var values=Object.fromEntries(new FormData(form).entries());values.invoiceEligible=form.elements.invoiceEligible.checked;values.firstTwoJobsFree=Boolean(form.elements.firstTwoJobsFree&&form.elements.firstTwoJobsFree.checked);try{var data=await api(id?"/operations/api/accounts/"+encodeURIComponent(id):"/operations/api/accounts",{method:id?"PATCH":"POST",body:values});state.accounts=id?state.accounts.map(function(account){return account.id===id?data.account:account;}):[data.account].concat(state.accounts);state.selectedAccount=data.account.id;renderAccounts();renderAccountForm(data.account);}catch(error){alert(error.message);}}
    async function assignTag(id){var code=document.getElementById("tag-select").value;if(!code)return;try{var data=await api("/operations/api/accounts/"+encodeURIComponent(id)+"/tags",{method:"POST",body:{code:code}});state.accounts=state.accounts.map(function(account){return account.id===id?data.account:account;});renderAccounts();renderAccountForm(data.account);}catch(error){alert(error.message);}}
    async function removeTag(id,code){try{var data=await api("/operations/api/accounts/"+encodeURIComponent(id)+"/tags?code="+encodeURIComponent(code),{method:"DELETE"});state.accounts=state.accounts.map(function(account){return account.id===id?data.account:account;});renderAccounts();renderAccountForm(data.account);}catch(error){alert(error.message);}}
    dateText=function(value){if(!value)return "—";var raw=String(value);var normalised=/Z$|[+-]\d\d:\d\d$/.test(raw)?raw:raw.replace(" ","T")+"Z";var date=new Date(normalised);return isNaN(date)?raw:date.toLocaleString("en-AU",{dateStyle:"medium",timeStyle:"short"});};
    loadProcessor=async function(){if(state.processorLoading)return;state.processorLoading=true;var output=document.getElementById("processor-output");var input=document.getElementById("processor-origin");var query=new URLSearchParams();if(state.processorOrigin.latitude!=null&&state.processorOrigin.longitude!=null){query.set("originLat",state.processorOrigin.latitude);query.set("originLng",state.processorOrigin.longitude);query.set("originLabel",state.processorOrigin.label||"Current device location");}else{state.processorOrigin.address=input.value.trim()||processorHome;input.value=state.processorOrigin.address;localStorage.setItem("sorrin_processor_origin",state.processorOrigin.address);query.set("origin",state.processorOrigin.address);}output.innerHTML='<div class="processor-empty">Building the live run, upcoming schedule and attention list…</div>';try{var data=await api("/operations/api/processor?"+query.toString());state.processor=data.processor||null;renderProcessor();}catch(error){output.innerHTML='<div class="processor-empty">'+esc(error.message)+'</div>';}finally{state.processorLoading=false;}};
    function processorPressureClass(item){return String(item&&item.processorCode||"").toLowerCase().replace(/_/g,"-")||String(item&&item.pressure&&item.pressure.level||"normal");}
    function processorStopLabel(item){return item.stopType==="pickup"?"Pickup":"Drop-off "+Math.max(1,Number(item.stopSequence||1)-1);}
    function processorOpenButton(item){return '<button class="secondary" data-processor-job="'+esc(item.reference)+'">OPEN JOB</button>';}
    function processorExecutionButton(item){var action=item.execution||{};return action.enabled?'<button class="execution-primary" data-processor-execute="'+esc(item.reference)+'">'+esc(action.label||"ADVANCE JOB")+'</button>':'';}
    function processorLiveCard(item,index){var deadlineLabel=item.deadlineStopType==="dropoff"?"Drop-off "+Math.max(1,Number(item.deadlineStopSequence||1)-1)+" deadline":"Latest";var timing=item.latestTime?deadlineLabel+": "+item.latestTime:(item.earliestTime?"Ready: "+item.earliestTime:"No fixed time");var road=Number.isFinite(item.travelMinutes)?'<p class="road-time">LEG '+Number(item.position||index+1)+' · '+item.travelMinutes+' min · '+Number(item.travelKm||0).toFixed(1)+' km from '+esc(item.travelFrom||"previous stop")+' · planned arrival '+esc(timeText(item.etaAt))+'</p>':'';return '<article class="processor-card '+(index===0?'recommended':'')+'"><div class="processor-order">'+Number(item.position||index+1)+'</div><div><div class="card-top"><span class="reference">'+esc(item.reference)+'</span><span class="pressure '+processorPressureClass(item)+'">'+esc(item.pressure.label)+'</span></div><h3>'+esc(processorStopLabel(item))+' · '+esc(item.suburb)+'</h3><p>'+esc(item.address)+'</p>'+road+'<p><strong>'+esc(item.serviceLevel)+'</strong> · '+esc(timing)+'</p><p>'+esc(item.pressure.explanation)+'</p>'+(index===0?'<p><strong>RECOMMENDED NEXT STOP</strong></p>':'')+'</div><div class="processor-actions"><a class="nav-btn" href="'+maps(item.address)+'" target="_blank" rel="noopener">NAVIGATE</a>'+processorExecutionButton(item)+processorOpenButton(item)+'</div></article>';}
    function processorUpcomingCard(item){return '<article class="processor-card upcoming"><div class="processor-order">·</div><div><div class="card-top"><span class="reference">'+esc(item.reference)+'</span><span class="pressure future">UPCOMING</span></div><h3>'+esc(processorStopLabel(item))+' · '+esc(item.suburb)+'</h3><p>'+esc(item.address)+'</p><p><strong>'+esc(item.serviceLevel)+'</strong> · '+esc(item.earliestTime||item.jobDate||"Future date")+'</p><p>'+esc(item.pressure.explanation)+'</p></div><div class="processor-actions">'+processorOpenButton(item)+'</div></article>';}
    function processorAttentionCard(item){return '<article class="processor-card attention"><div class="processor-order">!</div><div><div class="card-top"><span class="reference">'+esc(item.reference)+'</span><span class="pressure expired-commitment">EXPIRED COMMITMENT</span></div><h3>'+esc(processorStopLabel(item))+' · '+esc(item.suburb)+'</h3><p>'+esc(item.address)+'</p><p>'+esc(item.pressure.explanation)+'</p></div><div class="processor-actions">'+processorOpenButton(item)+'</div></article>';}
    renderProcessor=function(){var processor=state.processor;var output=document.getElementById("processor-output");if(!processor){output.innerHTML='<div class="processor-empty">Open the processor to assess the current run.</div>';return;}var live=processor.candidates||[];var upcoming=processor.upcoming||[];var attention=processor.attention||[];var routing=processor.routing||{};var routeClass=routing.mode==="traffic_aware"||routing.mode==="road_time"?"":" fallback";var routeTitle=routing.mode==="traffic_aware"?"LIVE TRAFFIC ACTIVE":routing.mode==="road_time"?"CURRENT ROAD TIMES ACTIVE":live.length?"COMMITMENT-ONLY FALLBACK":"NO LIVE RUN REQUIRED";var origin=routing.origin&&routing.origin.label?" Start: "+routing.origin.label+".":"";var routeStatus='<div class="route-status'+routeClass+'"><strong>'+esc(routeTitle)+'</strong> · '+esc(routing.message||"No live jobs require routing right now.")+esc(origin)+'</div>';var counts=processor.counts||{};var stats='<div class="stats"><div class="stat"><strong>'+Number(counts.jobs||0)+'</strong><span>Live stops</span></div><div class="stat"><strong>'+Number(counts.routeConflicts||0)+'</strong><span>Route conflicts</span></div><div class="stat"><strong>'+Number(counts.atRisk||0)+'</strong><span>At risk</span></div><div class="stat"><strong>'+Number(counts.upcoming||0)+'</strong><span>Upcoming</span></div></div>';var liveCards=live.length?live.map(processorLiveCard).join(""):'<div class="processor-empty">No stop needs live routing right now.</div>';var conflicts=(processor.conflicts||[]).map(function(conflict){return '<div class="conflict"><strong>'+(conflict.level==="critical"?"Projected route conflict":"Potential timing clash")+'</strong><p>'+esc(conflict.message)+'</p></div>';}).join("")||'<p>No genuine cross-job route clashes detected.</p>';var limits=(processor.limits||[]).map(function(limit){return '<li>'+esc(limit)+'</li>';}).join("");var attentionHtml=attention.length?'<h3 class="processor-section-title">Attention required</h3><div class="processor-stack">'+attention.map(processorAttentionCard).join("")+'</div>':'';var upcomingHtml=upcoming.length?'<h3 class="processor-section-title">Upcoming schedule</h3><div class="processor-stack">'+upcoming.map(processorUpcomingCard).join("")+'</div>':'';output.innerHTML=routeStatus+stats+'<div class="processor-grid"><div><h3 class="processor-section-title">Live route</h3><div class="processor-stack">'+liveCards+'</div>'+attentionHtml+upcomingHtml+'</div><aside class="processor-side"><div class="processor-panel"><h3>Timing watch</h3>'+conflicts+'</div><div class="processor-panel"><h3>Processor rules</h3><ul>'+limits+'</ul></div></aside></div>';output.querySelectorAll("[data-processor-job]").forEach(function(button){button.addEventListener("click",function(){switchSection("jobs");openJob(button.dataset.processorJob,false);});});output.querySelectorAll("[data-processor-execute]").forEach(function(button){button.addEventListener("click",function(){executeNext(button.dataset.processorExecute,button,true);});});};
    var processorLiveCardBase=processorLiveCard;
    processorLiveCard=function(item,index){var html=processorLiveCardBase(item,index);if(Number(item.waitMinutes||0)>30){html=html.replace(/<a class="nav-btn"[^>]*>NAVIGATE<\/a>/,'<button class="secondary" type="button" disabled>NOT READY</button>').replace(/<button class="execution-primary"[^>]*>[^<]*<\/button>/,'<button class="secondary" type="button" disabled>WAIT FOR READY TIME</button>').replace("RECOMMENDED NEXT STOP","NEXT PLANNED STOP");}return html;};
    var renderJobDetailV7=renderJobDetail;
    renderJobDetail=function(job){renderJobDetailV7(job);var body=document.querySelector("#job-detail .detail-body");if(!body)return;var accounts=state.accounts.slice().sort(function(a,b){return String(a.businessName).localeCompare(String(b.businessName));});var options='<option value="">No USC account linked</option>'+accounts.map(function(account){var disabled=account.accountState==="suspended"&&account.id!==job.businessId?' disabled':'';return '<option value="'+esc(account.id)+'" '+(account.id===job.businessId?'selected':'')+disabled+'>'+esc(account.usc)+' · '+esc(account.businessName)+(account.accountState==="suspended"?' · SUSPENDED':'')+'</option>';}).join("");var section=document.createElement("section");section.className="section usc-link";section.innerHTML='<h3>USC account link</h3><p style="font-size:12px;color:var(--muted)">Internal account assignment for benefits, invoicing and customer history.</p><div class="status-row"><select id="job-account-select" name="jobAccountId" aria-label="USC account link">'+options+'</select><button class="status-btn" id="save-job-account">SAVE USC LINK</button>'+(job.businessId?'<button class="secondary" id="open-job-account">OPEN ACCOUNT</button>':'')+'</div>';var firstSection=body.querySelector(".section");if(firstSection&&firstSection.nextSibling)body.insertBefore(section,firstSection.nextSibling);else body.insertBefore(section,body.firstChild);document.getElementById("save-job-account").addEventListener("click",function(){linkJobAccount(job.reference);});var openButton=document.getElementById("open-job-account");if(openButton)openButton.addEventListener("click",function(){switchSection("accounts");openAccount(job.businessId);});};
    function selectedOption(value,current,label){return '<option value="'+esc(value)+'" '+(value===current?'selected':'')+'>'+esc(label)+'</option>';}
    function financeFormHtml(finance,reference,prefix){finance=finance||{};prefix=prefix||"finance";return '<form class="finance-form" data-finance-form="'+esc(reference)+'"><div class="field"><label for="'+prefix+'-collection">Collection</label><select id="'+prefix+'-collection" name="collectionType">'+selectedOption("prepayment",finance.collectionType,"Prepayment")+selectedOption("invoice",finance.collectionType,"Invoice")+'</select></div><div class="field"><label for="'+prefix+'-payment-status">Payment status</label><select id="'+prefix+'-payment-status" name="paymentStatus">'+[["not_started","Not started"],["awaiting_payment","Awaiting payment"],["partially_paid","Partially paid"],["paid","Paid"],["waived","Waived"],["refunded","Refunded"]].map(function(item){return selectedOption(item[0],finance.paymentStatus,item[1]);}).join("")+'</select></div><div class="field"><label for="'+prefix+'-method">Payment method</label><input id="'+prefix+'-method" name="paymentMethod" value="'+esc(finance.paymentMethod||"")+'" placeholder="Stripe, bank transfer, cash…"></div><div class="field"><label for="'+prefix+'-invoice-status">Invoice status</label><select id="'+prefix+'-invoice-status" name="invoiceStatus">'+[["not_required","Not required"],["draft","Draft"],["issued","Issued"],["paid","Paid"],["void","Void"]].map(function(item){return selectedOption(item[0],finance.invoiceStatus,item[1]);}).join("")+'</select></div><div class="field"><label for="'+prefix+'-amount-due">Amount due ($)</label><input id="'+prefix+'-amount-due" name="amountDue" type="number" min="0" step="0.01" value="'+(Number(finance.amountDueCents||0)/100).toFixed(2)+'"></div><div class="field"><label for="'+prefix+'-amount-paid">Amount received ($)</label><input id="'+prefix+'-amount-paid" name="amountPaid" type="number" min="0" step="0.01" value="'+(Number(finance.amountPaidCents||0)/100).toFixed(2)+'"></div><div class="field"><label for="'+prefix+'-invoice-number">Invoice number</label><input id="'+prefix+'-invoice-number" name="invoiceNumber" value="'+esc(finance.invoiceNumber||"")+'" placeholder="Generated when issued"></div><div class="field"><label for="'+prefix+'-due-date">Due date</label><input id="'+prefix+'-due-date" name="dueDate" type="date" value="'+esc(finance.dueDate||"")+'"></div><div class="field wide"><label for="'+prefix+'-notes">Finance notes</label><textarea id="'+prefix+'-notes" name="notes" placeholder="Internal payment or invoice notes">'+esc(finance.notes||"")+'</textarea></div><div class="wide"><button class="primary" type="submit">UPDATE</button></div></form>';}
    function financeBody(form){var values=Object.fromEntries(new FormData(form).entries());values.amountDueCents=Math.max(0,Math.round(Number(values.amountDue||0)*100));values.amountPaidCents=Math.max(0,Math.round(Number(values.amountPaid||0)*100));delete values.amountDue;delete values.amountPaid;return values;}
    async function saveFinance(reference,form){var button=form.querySelector('button[type="submit"]');button.classList.add("busy");try{var data=await api("/operations/api/jobs/"+encodeURIComponent(reference)+"/finance",{method:"PATCH",body:financeBody(form)});state.finances=data.finances||state.finances;state.jobs=state.jobs.map(function(job){return job.reference===reference?Object.assign({},job,{paymentStatus:data.job.paymentStatus,finance:data.job.finance}):job;});renderJobs();renderFinances();if(state.selectedJob===reference)renderJobDetail(data.job);if(state.selectedFinance===data.job.finance.id)renderFinanceDetail(state.finances.find(function(item){return item.id===data.job.finance.id;})||Object.assign({},data.job.finance,{reference:reference}));}catch(error){alert(error.message);}finally{button.classList.remove("busy");}}
    var renderJobDetailV10=renderJobDetail;
    renderJobDetail=function(job){renderJobDetailV10(job);var body=document.querySelector("#job-detail .detail-body");if(!body)return;var upcoming=nextStop(job);var action=job.execution||{};var execution=document.createElement("section");execution.className="section execution-panel";execution.innerHTML='<h3>Live job execution</h3><p>'+(upcoming?'Next: '+esc(upcoming.stop_type)+' · '+esc(upcoming.address):'Every stop is closed.')+'</p>'+(upcoming?navOptions(upcoming.address):'')+'<div style="margin-top:12px"><button type="button" class="execution-primary" id="job-execute-next" '+(action.enabled?'':'disabled')+'>'+esc(action.label||"JOB COMPLETE")+'</button></div>';body.insertBefore(execution,body.firstChild);var execute=document.getElementById("job-execute-next");if(execute&&action.enabled)execute.addEventListener("click",function(){executeNext(job.reference,execute,false);});if(job.finance){var financeSection=document.createElement("section");financeSection.className="section";financeSection.innerHTML='<h3>Payment & invoice</h3><div class="finance-meta"><span class="finance-status '+esc(job.finance.effectiveStatus)+'">'+esc(String(job.finance.effectiveStatus||"not started").replace(/_/g," "))+'</span><span class="finance-status">Outstanding '+money(job.finance.outstandingCents)+'</span></div>'+financeFormHtml(job.finance,job.reference,"job-finance");var routeSection=Array.from(body.querySelectorAll(".section")).find(function(section){return section.querySelector("h3")&&section.querySelector("h3").textContent==="Route order";});if(routeSection)body.insertBefore(financeSection,routeSection);else body.appendChild(financeSection);financeSection.querySelector("[data-finance-form]").addEventListener("submit",function(event){event.preventDefault();saveFinance(job.reference,event.currentTarget);});}};
    async function linkJobAccount(reference){var button=document.getElementById("save-job-account");var accountId=document.getElementById("job-account-select").value||null;button.classList.add("busy");try{var data=await api("/operations/api/jobs/"+encodeURIComponent(reference)+"/account",{method:"PATCH",body:{accountId:accountId}});state.accounts=data.accounts||state.accounts;state.finances=data.finances||state.finances;state.jobs=state.jobs.map(function(job){return job.reference===reference?Object.assign({},job,{businessId:data.job.businessId,businessName:data.job.businessName,usc:data.job.usc,finance:data.job.finance,paymentStatus:data.job.paymentStatus}):job;});renderJobs();renderAccounts();renderFinances();renderJobDetail(data.job);state.processor=null;}catch(error){alert(error.message);}finally{button.classList.remove("busy");}}
    var renderAccountFormV7=renderAccountForm;
    renderAccountForm=function(account){renderAccountFormV7(account);var form=document.getElementById("account-form");if(!form)return;var businessInput=form.elements.businessName;var uscInput=form.elements.usc;if(uscInput){uscInput.required=false;uscInput.placeholder="Leave blank to generate automatically";var generate=document.createElement("button");generate.type="button";generate.className="secondary usc-generate";generate.textContent="GENERATE USC";generate.addEventListener("click",function(){uscInput.value=suggestedUsc(businessInput.value);});uscInput.parentNode.appendChild(generate);}var submit=form.querySelector('button[type="submit"]');if(submit){var note=document.createElement("div");note.className="account-form-note";note.textContent="USCs are internal account identifiers. Link bookings from the job record so history, benefits and invoicing stay together.";submit.parentNode.parentNode.insertBefore(note,submit.parentNode);}if(!account||!account.id)return;var head=document.querySelector("#account-detail .detail-head");if(head){var kpis=document.createElement("div");kpis.className="account-kpis";kpis.innerHTML='<div class="account-kpi"><strong>'+Number(account.bookingCount||0)+'</strong><span>Total jobs</span></div><div class="account-kpi"><strong>'+Number(account.liveBookingCount||0)+'</strong><span>Live jobs</span></div><div class="account-kpi"><strong>'+Number(account.deliveredBookingCount||0)+'</strong><span>Delivered</span></div><div class="account-kpi"><strong>'+money(account.totalActivityCents)+'</strong><span>Delivered value</span></div>';head.insertAdjacentElement("afterend",kpis);}var benefitCards=document.querySelectorAll("#account-detail .benefit");(account.benefits||[]).forEach(function(benefit,index){var card=benefitCards[index];if(!card)return;card.classList.add(benefit.available?"available":"used");var status=document.createElement("p");status.innerHTML=benefit.available?'<strong>AVAILABLE NOW · '+Number(benefit.remainingQuantity||0)+' ITEM(S)</strong>':'<strong>USED · RESETS '+esc(dateText(benefit.resetsAt))+'</strong>';card.appendChild(status);var controls=document.createElement("div");controls.className="benefit-controls";var jobOptions='<option value="">Choose linked job</option>'+(account.bookings||[]).map(function(booking){return '<option value="'+esc(booking.reference)+'">'+esc(booking.reference)+' · '+esc(booking.displayStatus||booking.status)+'</option>';}).join("");controls.innerHTML='<select name="benefitJob" aria-label="Linked job receiving benefit" data-benefit-job>'+jobOptions+'</select><input name="benefitQuantity" aria-label="Benefit quantity" data-benefit-quantity type="number" min="1" max="'+Number(benefit.remainingQuantity||1)+'" value="'+Math.max(1,Number(benefit.remainingQuantity||1))+'"><button type="button" class="status-btn" data-redeem-benefit="'+esc(benefit.benefit_id)+'" '+(benefit.available?'':'disabled')+'>APPLY TO JOB</button>';card.appendChild(controls);controls.querySelector("[data-redeem-benefit]").addEventListener("click",function(){redeemBenefit(account.id,benefit.benefit_id,controls);});});var sections=document.querySelectorAll("#account-detail .section");var bookingSection=Array.from(sections).find(function(section){return section.querySelector("h3")&&section.querySelector("h3").textContent==="Booking history";});if(bookingSection){var list=bookingSection.querySelector(".list");list.innerHTML=(account.bookings||[]).map(function(booking){return '<button class="card" data-history-job="'+esc(booking.reference)+'"><div class="card-top"><span class="reference">'+esc(booking.reference)+'</span><span class="badge '+esc(booking.displayStatus||booking.status)+'">'+esc(booking.displayStatus||booking.status)+'</span></div><p>'+esc(booking.pickup_address)+' → '+esc(booking.primary_dropoff_address)+'</p><p>'+money(booking.totalCents)+' · '+esc(booking.payment_status||"not started")+'</p></button>';}).join("")||'<p style="color:var(--muted)">No linked booking history.</p>';list.querySelectorAll("[data-history-job]").forEach(function(button){button.addEventListener("click",function(){switchSection("jobs");openJob(button.dataset.historyJob,false);});});var historySection=document.createElement("section");historySection.className="section";historySection.innerHTML='<h3>Account activity</h3><div class="timeline business-timeline">'+((account.events||[]).map(function(event){return '<div class="event"><strong>'+esc(event.eventType)+'</strong><p>'+dateText(event.createdAt)+'</p>'+(event.detail?'<p>'+esc(event.detail)+'</p>':'')+'</div>';}).join("")||'<p>No account activity yet.</p>')+'</div>';bookingSection.insertAdjacentElement("afterend",historySection);}};
    function suggestedUsc(name){var token=String(name||"ACCOUNT").toUpperCase().replace(/\b(?:PTY|LTD|LIMITED|TRADING|AS)\b/g," ").replace(/[^A-Z0-9]+/g,"-").replace(/^-+|-+$/g,"").slice(0,22).replace(/-+$/g,"")||"ACCOUNT";var prefix="USC-"+token+"-";var used=state.accounts.map(function(account){return String(account.usc||"").toUpperCase();});var sequence=1;while(used.indexOf(prefix+String(sequence).padStart(2,"0"))>-1)sequence+=1;return prefix+String(sequence).padStart(2,"0");}
    async function redeemBenefit(accountId,benefitId,controls){var reference=controls.querySelector("[data-benefit-job]").value;var quantity=controls.querySelector("[data-benefit-quantity]").value;var button=controls.querySelector("[data-redeem-benefit]");if(!reference){alert("Choose the linked job receiving this benefit.");return;}button.classList.add("busy");try{var data=await api("/operations/api/accounts/"+encodeURIComponent(accountId)+"/benefits/"+encodeURIComponent(benefitId)+"/redeem",{method:"POST",body:{reference:reference,quantity:quantity}});state.accounts=state.accounts.map(function(account){return account.id===accountId?data.account:account;});renderAccounts();renderAccountForm(data.account);}catch(error){alert(error.message);}finally{button.classList.remove("busy");}}
    function financeSettled(item){return ["paid","waived","refunded"].indexOf(item.effectiveStatus)>-1;}
    function filteredFinances(){var search=document.getElementById("finance-search").value.trim().toLowerCase();return state.finances.filter(function(item){var matches=state.financeView==="all"||(state.financeView==="overdue"&&item.effectiveStatus==="overdue")||(state.financeView==="settled"&&financeSettled(item))||(state.financeView==="outstanding"&&!financeSettled(item));var hay=[item.reference,item.customerName,item.customerEmail,item.customerPhone,item.businessName,item.usc,item.invoiceNumber].join(" ").toLowerCase();return matches&&(!search||hay.indexOf(search)>-1);});}
    function financeTone(item){return item.effectiveStatus==="overdue"?"overdue":financeSettled(item)?"settled":"outstanding";}
    function renderFinanceStats(){var counts={outstanding:0,overdue:0,settled:0};var outstandingCents=0;state.finances.forEach(function(item){if(financeSettled(item))counts.settled+=1;else{counts.outstanding+=1;outstandingCents+=Number(item.outstandingCents||0);}if(item.effectiveStatus==="overdue")counts.overdue+=1;});document.getElementById("finance-stats").innerHTML='<div class="stat"><strong>'+counts.outstanding+'</strong><span>Outstanding</span></div><div class="stat"><strong>'+counts.overdue+'</strong><span>Overdue</span></div><div class="stat"><strong>'+counts.settled+'</strong><span>Settled</span></div><div class="stat"><strong>'+money(outstandingCents)+'</strong><span>Still to collect</span></div>';}
    function renderFinances(){renderFinanceStats();var items=filteredFinances();var list=document.getElementById("finance-list");if(!items.length){list.innerHTML='<div class="empty">No finance records in this view.</div>';return;}list.innerHTML=items.map(function(item){return '<button class="card finance-card '+financeTone(item)+' '+(state.selectedFinance===item.id?'selected':'')+'" data-finance="'+esc(item.id)+'"><div class="card-top"><span class="reference">'+esc(item.reference)+'</span><span class="finance-status '+esc(item.effectiveStatus)+'">'+esc(String(item.effectiveStatus).replace(/_/g," "))+'</span></div><h3>'+esc(item.businessName||item.customerName||"Customer")+'</h3><p>'+esc(item.collectionType)+''+(item.invoiceNumber?' · '+esc(item.invoiceNumber):'')+'</p><p><strong>'+money(item.outstandingCents)+' outstanding</strong> · '+money(item.amountPaidCents)+' received</p></button>';}).join("");list.querySelectorAll("[data-finance]").forEach(function(button){button.addEventListener("click",function(){openFinance(button.dataset.finance);});});}
    function openFinance(id){state.selectedFinance=id;renderFinances();var item=state.finances.find(function(finance){return finance.id===id;});if(item)renderFinanceDetail(item);}
    function renderFinanceDetail(item){var panel=document.getElementById("finance-detail");panel.classList.add("open");panel.innerHTML='<div class="detail-head"><button class="secondary detail-close hidden" id="close-finance">CLOSE</button><div class="card-top"><span class="reference">'+esc(item.reference)+'</span><span class="finance-status '+esc(item.effectiveStatus)+'">'+esc(String(item.effectiveStatus).replace(/_/g," "))+'</span></div><h2>'+esc(item.businessName||item.customerName||"Customer")+'</h2><p>'+money(item.amountDueCents)+' due · '+money(item.amountPaidCents)+' received · '+money(item.outstandingCents)+' outstanding</p><div class="detail-actions"><button class="secondary" id="finance-open-job">OPEN JOB</button></div></div><div class="detail-body"><section class="section"><h3>Payment & invoice control</h3>'+financeFormHtml(item,item.reference,"finance-detail-form")+'</section><section class="section"><h3>Job</h3><div class="data-grid"><div class="datum"><span>Status</span><strong>'+esc(item.jobStatus)+'</strong></div><div class="datum"><span>Service</span><strong>'+esc(item.serviceLevel)+'</strong></div><div class="datum"><span>Pickup</span><strong>'+esc(item.pickupAddress)+'</strong></div><div class="datum"><span>Drop-off</span><strong>'+esc(item.primaryDropoffAddress)+'</strong></div><div class="datum"><span>Invoice</span><strong>'+esc(item.invoiceNumber||"Not issued")+'</strong></div><div class="datum"><span>Due date</span><strong>'+esc(item.dueDate||"Not set")+'</strong></div></div></section></div>';var close=document.getElementById("close-finance");if(close)close.addEventListener("click",function(){panel.classList.remove("open");});document.getElementById("finance-open-job").addEventListener("click",function(){switchSection("jobs");openJob(item.reference);});panel.querySelector("[data-finance-form]").addEventListener("submit",function(event){event.preventDefault();saveFinance(item.reference,event.currentTarget);});}
    function jobFormHtml(job){
      job=job||{};var pickup=(job.stops||[]).find(function(stop){return stop.stop_type==="pickup";})||{};var dropoff=(job.stops||[]).find(function(stop){return stop.stop_type==="dropoff";})||{};var quote=job.quote||{};var pickupQuote=quote.pickup||{};var dropQuote=(quote.dropoffs||[])[0]||{};var today=new Date().toISOString().slice(0,10);var accountOptions='<option value="">Guest / no USC account</option>'+state.accounts.filter(function(account){return account.accountState==="active";}).map(function(account){return '<option value="'+esc(account.id)+'" '+(job.businessId===account.id?'selected':'')+'>'+esc(account.usc)+' · '+esc(account.businessName)+'</option>';}).join("");
      return '<div class="detail-head"><button class="secondary detail-close hidden" id="close-job-form">CLOSE</button><div class="eyebrow">'+(job.reference?'Edit courier job':'Internal booking')+'</div><h2>'+(job.reference?esc(job.reference):'CREATE NEW JOB')+'</h2><p>Phone, email and USC bookings enter the same live operating queue.</p></div><div class="detail-body"><form id="job-editor" class="form-grid"><div class="field wide"><label for="job-form-account">USC account</label><select id="job-form-account" name="accountId" '+(job.reference?'disabled':'')+'>'+accountOptions+'</select></div><div class="field"><label for="job-form-name">Customer name</label><input id="job-form-name" name="requesterName" required value="'+esc(job.requesterName||'')+'"></div><div class="field"><label for="job-form-email">Customer email</label><input id="job-form-email" name="requesterEmail" type="email" required value="'+esc(job.requesterEmail||'')+'"></div><div class="field"><label for="job-form-phone">Customer phone</label><input id="job-form-phone" name="requesterPhone" required value="'+esc(job.requesterPhone||'')+'"></div><div class="field"><label for="job-form-service">Service</label><select id="job-form-service" name="serviceLevel">'+['FLEXIBLE','EXPRESS','PRIORITY'].map(function(value){return '<option '+(String(job.serviceLevel||'FLEXIBLE').toUpperCase().indexOf(value)>-1?'selected':'')+'>'+value+'</option>';}).join('')+'</select></div><div class="field"><label for="job-form-date">Job date</label><input id="job-form-date" name="jobDate" type="date" required value="'+esc(job.jobDate||today)+'"></div><div class="field"><label for="job-form-price">Job price ($)</label><input id="job-form-price" name="totalDollars" type="number" min="0" step="0.01" required value="'+(job.totalCents==null?'':(Number(job.totalCents)/100).toFixed(2))+'"></div><div class="field"><label for="job-form-payment">Payment method</label><input id="job-form-payment" name="paymentMethod" value="'+esc(job.paymentMethod||'')+'" placeholder="Card, bank transfer, cash…"></div><div class="field"><label for="job-form-status">Initial status</label><select id="job-form-status" name="initialStatus" '+(job.reference?'disabled':'')+'><option value="approved">APPROVED</option><option value="pending">PENDING</option></select></div><div class="field wide"><label for="job-form-pickup">Pickup address</label><input id="job-form-pickup" name="pickupAddress" required value="'+esc(pickup.address||job.pickupAddress||'')+'"></div><div class="field"><label for="job-form-pickup-start">Pickup from</label><input id="job-form-pickup-start" name="pickupEarliest" type="time" value="'+esc(timeOnly(pickup.earliest_time)||pickupQuote.earliestPickupTime||'09:00')+'"></div><div class="field"><label for="job-form-pickup-end">Pickup by</label><input id="job-form-pickup-end" name="pickupLatest" type="time" value="'+esc(timeOnly(pickup.latest_time)||pickupQuote.latestPickupTime||'09:30')+'"></div><div class="field"><label for="job-form-pickup-contact">Pickup contact</label><input id="job-form-pickup-contact" name="pickupContact" value="'+esc(pickup.contact_name||pickupQuote.contact||'')+'"></div><div class="field"><label for="job-form-pickup-phone">Pickup phone</label><input id="job-form-pickup-phone" name="pickupPhone" value="'+esc(pickup.contact_phone||job.requesterPhone||'')+'"></div><div class="field wide"><label for="job-form-pickup-notes">Pickup notes</label><textarea id="job-form-pickup-notes" name="pickupNotes">'+esc(pickup.stop_notes||pickupQuote.notes||'')+'</textarea></div><div class="field wide"><label for="job-form-dropoff">Drop-off address</label><input id="job-form-dropoff" name="dropoffAddress" required value="'+esc(dropoff.address||job.primaryDropoffAddress||'')+'"></div><div class="field"><label for="job-form-dropoff-start">Deliver from</label><input id="job-form-dropoff-start" name="dropoffEarliest" type="time" value="'+esc(timeOnly(dropoff.earliest_time)||dropQuote.earliestDropoffTime||'10:00')+'"></div><div class="field"><label for="job-form-dropoff-end">Deliver by</label><input id="job-form-dropoff-end" name="dropoffLatest" type="time" value="'+esc(timeOnly(dropoff.latest_time)||dropQuote.latestDropoffTime||'17:00')+'"></div><div class="field"><label for="job-form-dropoff-contact">Recipient</label><input id="job-form-dropoff-contact" name="dropoffContact" value="'+esc(dropoff.contact_name||dropQuote.contact||'')+'"></div><div class="field"><label for="job-form-dropoff-phone">Recipient phone</label><input id="job-form-dropoff-phone" name="dropoffPhone" value="'+esc(dropoff.contact_phone||'')+'"></div><div class="field wide"><label for="job-form-dropoff-notes">Delivery notes</label><textarea id="job-form-dropoff-notes" name="dropoffNotes">'+esc(dropoff.stop_notes||dropQuote.notes||'')+'</textarea></div><div class="field wide"><label for="job-form-cargo">Cargo notes</label><textarea id="job-form-cargo" name="cargoNotes">'+esc(quote.cargoNotes||'')+'</textarea></div><div class="wide"><button class="primary" type="submit">'+(job.reference?'SAVE JOB DETAILS':'CREATE JOB')+'</button></div></form></div>';
    }
    function timeOnly(value){var match=String(value||'').match(/(?:T|\s)(\d{2}:\d{2})/);return match?match[1]:'';}
    function jobEditorBody(form,job){var values=Object.fromEntries(new FormData(form).entries());var body={accountId:values.accountId||job&&job.businessId||null,requesterName:values.requesterName,requesterEmail:values.requesterEmail,requesterPhone:values.requesterPhone,serviceLevel:values.serviceLevel,jobDate:values.jobDate,totalDollars:values.totalDollars,paymentMethod:values.paymentMethod,initialStatus:values.initialStatus||'approved',cargoNotes:values.cargoNotes,pickup:{address:values.pickupAddress,earliestTime:values.pickupEarliest,latestTime:values.pickupLatest,contactName:values.pickupContact,contactPhone:values.pickupPhone,notes:values.pickupNotes},dropoff:{address:values.dropoffAddress,earliestTime:values.dropoffEarliest,latestTime:values.dropoffLatest,contactName:values.dropoffContact,contactPhone:values.dropoffPhone,notes:values.dropoffNotes}};if(job&&job.stops){body.stops=job.stops.map(function(stop,index){return {id:stop.id,address:index===0?values.pickupAddress:index===1?values.dropoffAddress:stop.address,earliestTime:index===0?values.pickupEarliest:index===1?values.dropoffEarliest:timeOnly(stop.earliest_time),latestTime:index===0?values.pickupLatest:index===1?values.dropoffLatest:timeOnly(stop.latest_time),contactName:index===0?values.pickupContact:index===1?values.dropoffContact:stop.contact_name,contactPhone:index===0?values.pickupPhone:index===1?values.dropoffPhone:stop.contact_phone,notes:index===0?values.pickupNotes:index===1?values.dropoffNotes:stop.stop_notes,strictWindow:Boolean(stop.strict_window)};});}return body;}
    function bindJobEditor(job){var form=document.getElementById('job-editor');var close=document.getElementById('close-job-form');if(close)close.addEventListener('click',function(){document.getElementById('job-detail').classList.remove('open');});var account=document.getElementById('job-form-account');if(account&&!job.reference)account.addEventListener('change',function(){var selected=state.accounts.find(function(item){return item.id===account.value;});if(!selected)return;form.elements.requesterName.value=selected.contactName||selected.businessName||'';form.elements.requesterEmail.value=selected.authorisedEmail||'';form.elements.requesterPhone.value=selected.authorisedPhone||'';form.elements.pickupContact.value=selected.contactName||selected.businessName||'';form.elements.pickupPhone.value=selected.authorisedPhone||'';});form.addEventListener('submit',async function(event){event.preventDefault();var button=form.querySelector('button[type="submit"]');button.classList.add('busy');try{var data=await api(job.reference?'/operations/api/jobs/'+encodeURIComponent(job.reference)+'/details':'/operations/api/jobs',{method:job.reference?'PATCH':'POST',body:jobEditorBody(form,job)});await refresh();state.jobView='all';document.querySelectorAll('[data-view]').forEach(function(item){item.classList.toggle('active',item.dataset.view==='all');});await openJob(data.job.reference,true);}catch(error){alert(error.message);}finally{button.classList.remove('busy');}});}
    function newJob(){switchSection('jobs');state.selectedJob=null;renderJobs();var panel=document.getElementById('job-detail');panel.classList.add('open');panel.innerHTML=jobFormHtml({});bindJobEditor({});}
    function editJob(job){var panel=document.getElementById('job-detail');panel.innerHTML=jobFormHtml(job);bindJobEditor(job);}
    async function saveProof(job,form){var values=Object.fromEntries(new FormData(form).entries());var button=form.querySelector('button[type="submit"]');button.classList.add('busy');try{var data=await api('/operations/api/jobs/'+encodeURIComponent(job.reference)+'/proof-of-delivery',{method:'POST',body:values});renderJobDetail(data.job);}catch(error){alert(error.message);}finally{button.classList.remove('busy');}}
    async function sendJobNotice(job,section){var button=section.querySelector('button');var type=section.querySelector('select').value;button.classList.add('busy');try{var data=await api('/operations/api/jobs/'+encodeURIComponent(job.reference)+'/notify',{method:'POST',body:{type:type}});renderJobDetail(data.job);}catch(error){alert(error.message);}finally{button.classList.remove('busy');}}
    async function createStripeCheckout(job,button){var paymentWindow=window.open('about:blank','_blank');button.classList.add('busy');try{var data=await api('/operations/api/jobs/'+encodeURIComponent(job.reference)+'/stripe-checkout',{method:'POST',body:{}});state.finances=data.finances||state.finances;state.jobs=state.jobs.map(function(item){return item.reference===job.reference?Object.assign({},item,{paymentStatus:data.job.paymentStatus,finance:data.job.finance}):item;});renderJobs();renderFinances();renderJobDetail(data.job);if(paymentWindow){paymentWindow.location=data.checkout.url;}else{window.open(data.checkout.url,'_blank','noopener');}if(!data.checkout.emailSent){alert('Stripe checkout created, but the customer email failed: '+(data.checkout.emailError||'unknown email error'));}}catch(error){if(paymentWindow)paymentWindow.close();alert(error.message);}finally{button.classList.remove('busy');}}
    async function copyStripeCheckout(url){try{await navigator.clipboard.writeText(url);alert('Stripe payment link copied.');}catch(error){window.prompt('Copy the Stripe payment link:',url);}}
    var renderJobDetailV12Base=renderJobDetail;
    renderJobDetail=function(job){renderJobDetailV12Base(job);var head=document.querySelector('#job-detail .detail-head');var body=document.querySelector('#job-detail .detail-body');if(!head||!body)return;var actions=head.querySelector('.detail-actions');if(actions){if(['pending','approved'].indexOf(job.status)>-1){var edit=document.createElement('button');edit.type='button';edit.className='secondary';edit.textContent='EDIT JOB';edit.addEventListener('click',function(){editJob(job);});actions.appendChild(edit);}if(job.finance){var invoice=document.createElement('a');invoice.className='secondary';invoice.target='_blank';invoice.rel='noopener';invoice.href='/operations/invoices/'+encodeURIComponent(job.reference);invoice.textContent=job.finance.invoiceNumber?'PRINT INVOICE':'PRINT PAYMENT RECORD';actions.appendChild(invoice);}}
      var notices=document.createElement('section');notices.className='section';notices.innerHTML='<h3>Customer updates</h3><p>Send an approved operational email and keep an audit record against this job.</p><div class="status-row"><select aria-label="Customer update type"><option value="approved">Booking confirmed</option><option value="pickup_en_route">Pickup en route</option><option value="delivered">Delivery completed</option><option value="invoice_issued">Invoice issued</option><option value="payment_reminder">Payment reminder</option></select><button type="button" class="status-btn">SEND UPDATE</button></div><div class="timeline">'+((job.customerNotifications||[]).map(function(item){return '<div class="event"><strong>'+esc(String(item.notificationType||'update').replace(/_/g,' '))+'</strong><p>'+dateText(item.createdAt)+' · '+esc(item.recipient||'')+'</p></div>';}).join('')||'<p>No customer updates sent yet.</p>')+'</div>';body.appendChild(notices);notices.querySelector('button').addEventListener('click',function(){sendJobNotice(job,notices);});
      if(job.paymentGate&&job.paymentGate.blocked){var gate=document.createElement('section');gate.className='section';gate.innerHTML='<h3>Dispatch gate</h3><div class="notice"><strong>PREPAYMENT REQUIRED</strong> · '+money(job.paymentGate.outstandingCents)+' must be received before this job can start. It is excluded from the Conscious Processor until cleared.</div>';body.insertBefore(gate,body.firstChild.nextSibling);}
      if(job.finance&&Number(job.finance.outstandingCents||0)>0&&['declined','cancelled'].indexOf(job.status)<0){var stripe=document.createElement('section');stripe.className='section';var sessionId=String(job.finance.stripeCheckoutSessionId||'');var sessionMode=sessionId.indexOf('cs_live_')===0?'live':(sessionId.indexOf('cs_test_')===0?'test':'unknown');var currentLink=(sessionMode==='unknown'||sessionMode===state.stripeMode)?(job.finance.stripeCheckoutUrl||''):'';var isStripeTest=state.stripeMode==='test';var stripeModeNotice=isStripeTest?'<div class="notice">TEST MODE · No real money will move.</div>':(state.stripeMode==='live'?'<div class="notice"><strong>LIVE STRIPE</strong> · This checkout will collect real money.</div>':'<div class="notice">Stripe is not configured.</div>');if(sessionId&&sessionMode!=='unknown'&&sessionMode!==state.stripeMode)stripeModeNotice+='<div class="notice">The stored Stripe link belongs to '+sessionMode.toUpperCase()+' mode and is intentionally hidden. Create a new checkout in the current mode.</div>';stripe.innerHTML='<h3>Stripe prepayment</h3>'+stripeModeNotice+'<p>Create a hosted Stripe Checkout for '+money(job.finance.outstandingCents)+'. The customer receives the link by email and the signed webhook updates this payment automatically.</p><div class="detail-actions"><button type="button" class="primary" data-stripe-create>CREATE / RE-EMAIL '+(isStripeTest?'TEST ':'')+'CHECKOUT</button>'+(currentLink?'<a class="secondary" target="_blank" rel="noopener" href="'+esc(currentLink)+'">OPEN CURRENT LINK</a><button type="button" class="secondary" data-stripe-copy>COPY LINK</button>':'')+'</div>'+(job.finance.stripePaymentStatus?'<p style="color:var(--muted);font-size:12px">Stripe status: '+esc(job.finance.stripePaymentStatus)+' · expires '+esc(dateText(job.finance.stripeCheckoutExpiresAt))+'</p>':'');body.appendChild(stripe);stripe.querySelector('[data-stripe-create]').addEventListener('click',function(event){createStripeCheckout(job,event.currentTarget);});var copy=stripe.querySelector('[data-stripe-copy]');if(copy)copy.addEventListener('click',function(){copyStripeCheckout(currentLink);});}
      if(job.status==='delivered'){var proof=document.createElement('section');proof.className='section';if(job.proofOfDelivery){proof.innerHTML='<h3>Proof of delivery</h3><div class="data-grid"><div class="datum"><span>Received by</span><strong>'+esc(job.proofOfDelivery.recipientName)+'</strong></div><div class="datum"><span>Delivered at</span><strong>'+esc(dateText(job.proofOfDelivery.deliveredAt))+'</strong></div><div class="datum wide"><span>Notes</span><strong>'+esc(job.proofOfDelivery.notes||'No notes')+'</strong></div></div>';}else{proof.innerHTML='<h3>Proof of delivery</h3><form id="proof-form" class="form-grid"><div class="field"><label for="proof-recipient">Received by</label><input id="proof-recipient" name="recipientName" required></div><div class="field"><label for="proof-time">Delivered at</label><input id="proof-time" name="deliveredAt" type="datetime-local"></div><div class="field wide"><label for="proof-notes">Delivery notes</label><textarea id="proof-notes" name="notes"></textarea></div><div class="wide"><button class="primary" type="submit">SAVE PROOF OF DELIVERY</button></div></form>';}body.appendChild(proof);var proofForm=proof.querySelector('form');if(proofForm)proofForm.addEventListener('submit',function(event){event.preventDefault();saveProof(job,event.currentTarget);});}}
    function wrapSectionAsCollapsible(section,label,openByDefault){if(!section||section.tagName==='DETAILS')return section;var details=document.createElement('details');details.className='collapsible';if(openByDefault)details.open=true;var summary=document.createElement('summary');summary.textContent=label;var content=document.createElement('div');content.className='collapsible-content';Array.from(section.childNodes).forEach(function(node){if(node.nodeType===1&&node.tagName==='H3')return;content.appendChild(node);});details.appendChild(summary);details.appendChild(content);section.replaceWith(details);return details;}
    function findJobSection(body,title){return Array.from(body.querySelectorAll('.section')).find(function(section){var h=section.querySelector('h3');return h&&h.textContent.trim().toLowerCase()===title.toLowerCase();});}
    function addJobAdminActions(job){var head=document.querySelector('#job-detail .detail-head');if(!head)return;var actions=head.querySelector('.detail-actions');if(!actions){actions=document.createElement('div');actions.className='detail-actions';head.appendChild(actions);}if(job.archivedAt){var banner=document.createElement('div');banner.className='archive-banner';banner.textContent='REMOVED FROM COURIER JOBS · retained in Full Job Record'+(job.archivedAt?' · '+dateText(job.archivedAt):'');head.insertAdjacentElement('afterend',banner);var restore=document.createElement('button');restore.type='button';restore.className='secondary';restore.textContent='RESTORE JOB';restore.addEventListener('click',function(){restoreJob(job.reference,restore);});actions.appendChild(restore);}else{var archive=document.createElement('button');archive.type='button';archive.className='danger';archive.textContent='DELETE JOB';archive.addEventListener('click',function(){archiveJob(job.reference,archive);});actions.appendChild(archive);}if(job.status!=='delivered'){var force=document.createElement('button');force.type='button';force.className='secondary';force.textContent='FORCE CLOSE JOB';force.addEventListener('click',function(){forceCloseJob(job.reference,force);});actions.appendChild(force);}}
    function finaliseJobDetail(job){var body=document.querySelector('#job-detail .detail-body');if(!body)return;var usc=body.querySelector('.usc-link');var execution=body.querySelector('.execution-panel');if(usc){if(execution)body.insertBefore(usc,execution);else body.insertBefore(usc,body.firstChild);}var change=findJobSection(body,'Change status');if(change){var note=change.querySelector('.field');if(note){var noteDetails=document.createElement('details');noteDetails.className='collapsible';var noteSummary=document.createElement('summary');noteSummary.textContent='Optional note for status change';var noteContent=document.createElement('div');noteContent.className='collapsible-content';note.replaceWith(noteDetails);noteDetails.appendChild(noteSummary);noteDetails.appendChild(noteContent);noteContent.appendChild(note);}}var route=findJobSection(body,'Route order');wrapSectionAsCollapsible(route,'Route order',false);var finance=findJobSection(body,'Payment & invoice');wrapSectionAsCollapsible(finance,'Payment & invoice',false);var notices=findJobSection(body,'Customer updates');if(notices){var timeline=notices.querySelector('.timeline');if(timeline){timeline.remove();notices.classList.add('notification-composer');var history=document.createElement('details');history.className='collapsible notification-history';var summary=document.createElement('summary');summary.textContent='Notifications';var content=document.createElement('div');content.className='collapsible-content';content.appendChild(timeline);history.appendChild(summary);history.appendChild(content);notices.insertAdjacentElement('afterend',history);}}addJobAdminActions(job);}
    var renderJobDetailFinalBase=renderJobDetail;
    renderJobDetail=function(job){renderJobDetailFinalBase(job);finaliseJobDetail(job);};
    async function archiveJob(reference,button){if(!window.confirm('Delete this job from the Courier jobs screen? The complete record will remain in Full Job Record.'))return;button.classList.add('busy');try{await api('/operations/api/jobs/'+encodeURIComponent(reference)+'/archive',{method:'POST',body:{}});state.selectedJob=null;document.getElementById('job-detail').innerHTML='<div class="empty">Job removed from the Courier jobs screen. Its complete history remains in Full Job Record.</div>';await refresh();}catch(error){alert(error.message);}finally{button.classList.remove('busy');}}
    async function restoreJob(reference,button){button.classList.add('busy');try{var data=await api('/operations/api/jobs/'+encodeURIComponent(reference)+'/restore',{method:'POST',body:{}});await refresh();renderJobDetail(data.job);}catch(error){alert(error.message);}finally{button.classList.remove('busy');}}
    async function forceCloseJob(reference,button){if(!window.confirm('Force close this job as delivered/completed? This closes every remaining stop but does not delete the finance history.'))return;button.classList.add('busy');try{var data=await api('/operations/api/jobs/'+encodeURIComponent(reference)+'/force-close',{method:'POST',body:{}});await refresh();renderJobDetail(data.job);}catch(error){alert(error.message);}finally{button.classList.remove('busy');}}
    function recordCard(job){return '<button class="card" data-record-job="'+esc(job.reference)+'"><div class="card-top"><span class="reference">'+esc(job.reference)+'</span>'+(job.archivedAt?'<span class="archived-chip">REMOVED</span>':'<span class="badge '+esc(job.status)+'">'+esc(job.status)+'</span>')+'</div><h3>'+esc(job.requesterName)+'</h3><p>'+esc(job.pickupAddress)+' → '+esc(job.primaryDropoffAddress)+'</p><p>'+dateText(job.createdAt)+' · '+money(job.totalCents)+'</p></button>';}
    function renderFullJobRecord(){var search=document.getElementById('job-record-search').value.trim().toLowerCase();var jobs=state.jobRecord.filter(function(job){if(!search)return true;return [job.reference,job.requesterName,job.requesterEmail,job.requesterPhone,job.businessName,job.usc,job.pickupAddress,job.primaryDropoffAddress].join(' ').toLowerCase().indexOf(search)>-1;});var list=document.getElementById('job-record-list');list.innerHTML=jobs.length?jobs.map(recordCard).join(''):'<div class="empty">No matching job records.</div>';list.querySelectorAll('[data-record-job]').forEach(function(button){button.addEventListener('click',function(){openRecordJob(button.dataset.recordJob);});});}
    async function openFullJobRecord(){var modal=document.getElementById('job-record-modal');modal.classList.remove('hidden');document.getElementById('job-record-list').innerHTML='<div class="empty">Loading full history…</div>';try{var data=await api('/operations/api/job-record');state.jobRecord=data.jobs||[];renderFullJobRecord();}catch(error){document.getElementById('job-record-list').innerHTML='<div class="empty">'+esc(error.message)+'</div>';}}
    function closeFullJobRecord(){document.getElementById('job-record-modal').classList.add('hidden');}
    async function openRecordJob(reference){var panel=document.getElementById('job-record-detail');panel.innerHTML='<div class="empty">Opening record…</div>';try{var data=await api('/operations/api/jobs/'+encodeURIComponent(reference));var job=data.job;panel.innerHTML='<div class="detail-head"><div class="card-top"><span class="reference">'+esc(job.reference)+'</span>'+(job.archivedAt?'<span class="archived-chip">REMOVED</span>':'<span class="badge '+esc(job.status)+'">'+esc(job.status)+'</span>')+'</div><h2>'+esc(job.requesterName)+'</h2><p>'+esc(job.pickupAddress)+' → '+esc(job.primaryDropoffAddress)+'</p><div class="detail-actions"><button type="button" class="secondary" data-record-open>OPEN FULL JOB</button>'+(job.archivedAt?'<button type="button" class="secondary" data-record-restore>RESTORE JOB</button>':'')+'</div></div><div class="detail-body"><div class="data-grid"><div class="datum"><span>Status</span><strong>'+esc(job.status)+'</strong></div><div class="datum"><span>USC</span><strong>'+esc(job.usc||'Not linked')+'</strong></div><div class="datum"><span>Global job #</span><strong>'+esc(job.globalJobNumber||'Legacy')+'</strong></div><div class="datum"><span>USC job #</span><strong>'+esc(job.uscJobNumber||'—')+'</strong></div><div class="datum"><span>Submitted</span><strong>'+dateText(job.createdAt)+'</strong></div><div class="datum"><span>Payment</span><strong>'+esc(job.paymentStatus||'Not started')+'</strong></div></div><h3 style="margin-top:22px">History</h3><div class="timeline">'+((job.events||[]).map(function(event){return '<div class="event"><strong>'+esc(event.event_type||'Event')+'</strong><p>'+dateText(event.created_at)+'</p>'+(event.event_data?'<p>'+esc(event.event_data)+'</p>':'')+'</div>';}).join('')||'<p>No history.</p>')+'</div></div>';panel.querySelector('[data-record-open]').addEventListener('click',function(){closeFullJobRecord();state.selectedJob=reference;openJob(reference,true);});var restore=panel.querySelector('[data-record-restore]');if(restore)restore.addEventListener('click',async function(){await restoreJob(reference,restore);await openFullJobRecord();});}catch(error){panel.innerHTML='<div class="empty">'+esc(error.message)+'</div>';}}
    var renderAccountFormV12Base=renderAccountForm;
    renderAccountForm=function(account){renderAccountFormV12Base(account);if(!account||!account.id)return;var actions=document.querySelector('#account-detail .detail-actions');if(!actions){var head=document.querySelector('#account-detail .detail-head');if(head){actions=document.createElement('div');actions.className='detail-actions';head.appendChild(actions);}}if(actions&&!actions.querySelector('[data-statement]')){var statement=document.createElement('a');statement.className='secondary';statement.target='_blank';statement.rel='noopener';statement.dataset.statement='1';statement.href='/operations/accounts/'+encodeURIComponent(account.id)+'/statement';statement.textContent='PRINT STATEMENT';actions.appendChild(statement);}if(actions&&!actions.querySelector('[data-delete-account]')){var remove=document.createElement('button');remove.type='button';remove.className='danger';remove.dataset.deleteAccount='1';remove.textContent='DELETE ACCOUNT';remove.addEventListener('click',function(){deleteAccount(account,remove);});actions.appendChild(remove);}};
    async function deleteAccount(account,button){var linked=Number(account.bookingCount||0);var message='Delete USC account '+String(account.usc||'')+'?'+(linked?' This will unlink '+linked+' job'+(linked===1?'':'s')+' from the account, but their job and finance records will remain.':'')+' This cannot be undone.';if(!window.confirm(message))return;button.classList.add('busy');try{await api('/operations/api/accounts/'+encodeURIComponent(account.id),{method:'DELETE'});state.selectedAccount=null;document.getElementById('account-detail').classList.remove('open');document.getElementById('account-detail').innerHTML='<div class="empty">USC account deleted. Historical job and finance records were retained.</div>';await refresh();showToast('USC account deleted.');}catch(error){alert(error.message);}finally{button.classList.remove('busy');}}
    var renderFinanceDetailV12Base=renderFinanceDetail;
    renderFinanceDetail=function(item){renderFinanceDetailV12Base(item);var actions=document.querySelector('#finance-detail .detail-actions');if(actions){var invoice=document.createElement('a');invoice.className='secondary';invoice.target='_blank';invoice.rel='noopener';invoice.href='/operations/invoices/'+encodeURIComponent(item.reference);invoice.textContent=item.invoiceNumber?'PRINT INVOICE':'PRINT PAYMENT RECORD';actions.appendChild(invoice);}};
    /* FINAL V21 INTERACTION POLISH */
    function summaryDatum(label,value){return '<div class="datum"><span>'+esc(label)+'</span><strong>'+esc(value==null||value===''?'—':value)+'</strong></div>';}
    function stopWindow(stop){if(!stop)return 'No fixed window';var earliest=timeOnly(stop.earliest_time);var latest=timeOnly(stop.latest_time);if(earliest&&latest)return earliest+' – '+latest;if(earliest)return 'From '+earliest;if(latest)return 'By '+latest;return 'No fixed window';}
    function stopLabel(stop){if(!stop)return 'No remaining stop';if(stop.stop_type==='pickup')return 'Pickup';var drops=(stop.stop_sequence||2)-1;return 'Drop-off '+Math.max(1,Number(drops||1));}
    function jobSummaryStage(job,pickup,activeStop,dropoff){var action=job.execution||{};var finance=job.finance||{};var unresolved=(job.stops||[]).filter(function(stop){return ['completed','skipped','cancelled'].indexOf(stop.stop_status)<0;});var title='JOB SUMMARY';var note='Key details for the current stage';var datums=[];if(job.status==='pending'){title='WAITING FOR APPROVAL';note='Review the booking before it enters the live queue';datums=[['Approval','Pending'],['Pickup window',stopWindow(pickup)],['Final delivery',stopWindow(dropoff)],['Payment',finance.effectiveStatus||job.paymentStatus||'Not started'],['USC',job.usc||'Guest / not linked'],['Submitted',dateText(job.createdAt)]];}else if(job.status==='approved'){if(action.code==='payment_required'){title='PAYMENT HOLD';note='Prepayment must clear before dispatch';}else{title='READY TO START';note='Pickup is the next operational move';}datums=[['Next stop',stopLabel(activeStop||pickup)],['Pickup window',stopWindow(pickup)],['Pickup contact',(pickup&&pickup.contact_name)||job.requesterName||'—'],['Payment',finance.effectiveStatus||job.paymentStatus||'Not started'],['Outstanding',job.finance?money(finance.outstandingCents||0):'—'],['Next action',action.label||'Start job']];}else if(job.status==='active'){var status=String(activeStop&&activeStop.stop_status||'pending');if(status==='en_route'){title='EN ROUTE · '+stopLabel(activeStop).toUpperCase();note='Current destination and arrival details';}else if(status==='arrived'){title='ARRIVED · '+stopLabel(activeStop).toUpperCase();note='Complete this stop when the handover is finished';}else{title='NEXT LEG · '+stopLabel(activeStop).toUpperCase();note='Ready to continue the live run';}datums=[['Current stop',stopLabel(activeStop)],['Address',(activeStop&&activeStop.address)||'—'],['Time window',stopWindow(activeStop)],['Contact',(activeStop&&activeStop.contact_name)||'—'],['Stops remaining',String(unresolved.length)],['Next action',action.label||'Continue job']];if(activeStop&&activeStop.stop_status==='arrived'){datums[3]=['Contact phone',activeStop.contact_phone||'—'];datums[4]=['Stop notes',activeStop.stop_notes||'None'];datums[5]=['Next action',action.label||'Complete stop'];}}else if(job.status==='delivered'){title='DELIVERED';note='Operational movement is complete';datums=[['Completed','Yes'],['Received by',job.proofOfDelivery&&job.proofOfDelivery.recipientName||dropoff&&dropoff.contact_name||'—'],['Final drop-off',dropoff&&dropoff.address||job.primaryDropoffAddress||'—'],['Payment',finance.effectiveStatus||job.paymentStatus||'Not started'],['Outstanding',job.finance?money(finance.outstandingCents||0):'—'],['USC',job.usc||'Guest / not linked']];}else{title=String(job.status||'JOB').toUpperCase();note='This job is no longer in the live execution flow';datums=[['Status',job.status||'—'],['Payment',finance.effectiveStatus||job.paymentStatus||'Not started'],['Outstanding',job.finance?money(finance.outstandingCents||0):'—'],['Pickup',pickup&&pickup.address||job.pickupAddress||'—'],['Final drop-off',dropoff&&dropoff.address||job.primaryDropoffAddress||'—'],['Submitted',dateText(job.createdAt)]];}return '<div class="summary-stage"><strong>'+esc(title)+'</strong><span>'+esc(note)+'</span></div><div class="data-grid">'+datums.map(function(item){return summaryDatum(item[0],item[1]);}).join('')+'</div>';}
    renderJobSummary=function(job){var panel=document.getElementById('job-detail');var stops=job.stops||[];var pickup=stops.find(function(stop){return stop.stop_type==='pickup';});var activeStop=stops.find(function(stop){return ['completed','skipped','cancelled'].indexOf(stop.stop_status)<0;});var dropoff=stops.filter(function(stop){return stop.stop_type==='dropoff';}).slice(-1)[0];var action=job.execution||{};panel.classList.remove('open','full-page','finance-summary');panel.classList.add('job-summary');var nav=activeStop?'<a class="nav-btn" href="'+maps(activeStop.address)+'" target="_blank" rel="noopener">'+(activeStop.stop_type==='pickup'?'NAVIGATE TO PICKUP':'NAVIGATE TO NEXT STOP')+'</a>':'';var call=job.requesterPhone?'<a class="contact-btn" href="tel:'+esc(job.requesterPhone)+'">CALL</a>':'';var email=job.requesterEmail?'<a class="contact-btn" href="mailto:'+esc(job.requesterEmail)+'">EMAIL</a>':'';panel.innerHTML='<div class="detail-head"><div class="card-top"><span class="reference">'+esc(job.reference)+'</span><span class="badge '+esc(job.status)+'">'+esc(job.status)+'</span></div><h2>'+esc(job.requesterName)+'</h2><p>'+esc(job.serviceLevel)+' · '+money(job.totalCents)+'</p><div class="detail-actions">'+nav+call+email+'<button type="button" class="danger summary-delete" id="summary-delete-job">DELETE JOB</button></div></div><div class="detail-body"><div class="summary-route"><div class="summary-stop"><span>Pickup</span><strong>'+esc(pickup&&pickup.address||job.pickupAddress||'—')+'</strong></div><div class="summary-arrow">→</div><div class="summary-stop"><span>Final drop-off</span><strong>'+esc(dropoff&&dropoff.address||job.primaryDropoffAddress||'—')+'</strong></div></div>'+jobSummaryStage(job,pickup,activeStop,dropoff)+(action.enabled?'<section class="section execution-panel" style="margin-top:20px"><h3>Live job execution</h3><p>'+(activeStop?'Next: '+esc(stopLabel(activeStop))+' · '+esc(activeStop.address):'Every stop is closed.')+'</p><button type="button" class="execution-primary" id="summary-execute-next">'+esc(action.label||'ADVANCE JOB')+'</button></section>':'')+'<div class="summary-open"><button type="button" class="primary" id="open-full-job">OPEN FULL JOB</button></div></div>';var open=document.getElementById('open-full-job');if(open)open.addEventListener('click',function(){openJob(job.reference,true);});var execute=document.getElementById('summary-execute-next');if(execute)execute.addEventListener('click',function(){executeNext(job.reference,execute,false);});var remove=document.getElementById('summary-delete-job');if(remove)remove.addEventListener('click',function(){archiveJob(job.reference,remove);});};
    function renderFinanceSummary(item){var panel=document.getElementById('finance-detail');panel.classList.remove('open','full-page','job-summary');panel.classList.add('finance-summary');var settled=financeSettled(item);panel.innerHTML='<div class="detail-head"><div class="card-top"><span class="reference">'+esc(item.reference)+'</span><span class="finance-status '+esc(item.effectiveStatus)+'">'+esc(String(item.effectiveStatus).replace(/_/g,' '))+'</span></div><h2>'+esc(item.businessName||item.customerName||'Customer')+'</h2><p>'+money(item.amountDueCents)+' due · '+money(item.amountPaidCents)+' received · '+money(item.outstandingCents)+' outstanding</p><div class="detail-actions"><button type="button" class="secondary" id="finance-summary-open-job">OPEN JOB</button><a class="secondary" target="_blank" rel="noopener" href="/operations/invoices/'+encodeURIComponent(item.reference)+'">'+(item.invoiceNumber?'PRINT INVOICE':'PRINT PAYMENT RECORD')+'</a><button type="button" class="primary mark-paid" id="finance-mark-paid" '+(settled?'disabled':'')+'>MARK AS PAID</button></div></div><div class="detail-body"><div class="summary-stage"><strong>'+esc(settled?'PAYMENT SETTLED':'PAYMENT OUTSTANDING')+'</strong><span>'+esc(settled?'No collection action required':'Update or collect against this record')+'</span></div><div class="data-grid">'+summaryDatum('Payment status',String(item.effectiveStatus||item.paymentStatus||'not started').replace(/_/g,' '))+summaryDatum('Collection',String(item.collectionType||'—').replace(/_/g,' '))+summaryDatum('Amount due',money(item.amountDueCents))+summaryDatum('Amount received',money(item.amountPaidCents))+summaryDatum('Outstanding',money(item.outstandingCents))+summaryDatum('Invoice',item.invoiceNumber||'Not issued')+summaryDatum('Due date',item.dueDate||'Not set')+summaryDatum('Job status',item.jobStatus||'—')+'</div><div class="summary-open"><button type="button" class="primary" id="open-full-finance">OPEN FULL FINANCE</button></div></div>';document.getElementById('finance-summary-open-job').addEventListener('click',function(){switchSection('jobs');openJob(item.reference,false);});document.getElementById('open-full-finance').addEventListener('click',function(){openFinance(item.id,true);});var paid=document.getElementById('finance-mark-paid');if(paid&&!settled)paid.addEventListener('click',function(){markFinancePaid(item,paid);});}
    async function markFinancePaid(item,button){button.classList.add('busy');try{var invoiceStatus=item.collectionType==='invoice'?(item.invoiceNumber?'paid':'issued'):(item.invoiceStatus||'not_required');var data=await api('/operations/api/jobs/'+encodeURIComponent(item.reference)+'/finance',{method:'PATCH',body:{collectionType:item.collectionType||'prepayment',paymentStatus:'paid',paymentMethod:item.paymentMethod||'',amountDueCents:Number(item.amountDueCents||0),amountPaidCents:Number(item.amountDueCents||0),invoiceStatus:invoiceStatus,invoiceNumber:item.invoiceNumber||'',dueDate:item.dueDate||'',notes:item.notes||''}});state.finances=data.finances||state.finances;state.jobs=state.jobs.map(function(job){return job.reference===item.reference?Object.assign({},job,{paymentStatus:data.job.paymentStatus,finance:data.job.finance}):job;});renderJobs();renderFinances();var fresh=state.finances.find(function(finance){return finance.id===item.id;})||Object.assign({},item,data.job.finance||{});state.selectedFinance=fresh.id||item.id;renderFinanceSummary(fresh);showToast('Payment marked as paid.');}catch(error){alert(error.message);}finally{button.classList.remove('busy');}}
    renderFinances=function(){renderFinanceStats();var items=filteredFinances();var list=document.getElementById('finance-list');if(!items.length){list.innerHTML='<div class="empty">No finance records in this view.</div>';return;}list.innerHTML=items.map(function(item){return '<button class="card finance-card '+financeTone(item)+' '+(state.selectedFinance===item.id?'selected':'')+'" data-finance="'+esc(item.id)+'" title="Click for summary · Double-click for full finance"><div class="card-top"><span class="reference">'+esc(item.reference)+'</span><span class="finance-status '+esc(item.effectiveStatus)+'">'+esc(String(item.effectiveStatus).replace(/_/g,' '))+'</span></div><h3>'+esc(item.businessName||item.customerName||'Customer')+'</h3><p>'+esc(item.collectionType)+(item.invoiceNumber?' · '+esc(item.invoiceNumber):'')+'</p><p><strong>'+money(item.outstandingCents)+' outstanding</strong> · '+money(item.amountPaidCents)+' received</p></button>';}).join('');list.querySelectorAll('[data-finance]').forEach(function(button){button.addEventListener('click',function(){clearTimeout(financeClickTimer);financeClickTimer=setTimeout(function(){openFinance(button.dataset.finance,false);},220);});button.addEventListener('dblclick',function(event){event.preventDefault();clearTimeout(financeClickTimer);openFinance(button.dataset.finance,true);});});};
    openFinance=function(id,fullPage){state.selectedFinance=id;renderFinances();var item=state.finances.find(function(finance){return finance.id===id;});if(!item)return;if(fullPage)renderFinanceDetail(item,true);else renderFinanceSummary(item);};
    var renderFinanceDetailV20Full=renderFinanceDetail;
    renderFinanceDetail=function(item,fullPage){var panel=document.getElementById('finance-detail');var shouldFull=fullPage===undefined?panel.classList.contains('full-page'):Boolean(fullPage);panel.classList.remove('finance-summary','job-summary');renderFinanceDetailV20Full(item);if(!shouldFull){renderFinanceSummary(item);return;}panel.classList.add('open','full-page');var close=document.getElementById('close-finance');if(close){close.classList.remove('hidden');close.addEventListener('click',function(){renderFinanceSummary(item);});}};
    /* FINAL V22 MANDATORY DELIVERY PHOTO */
    function deliveryPhotoDisplayUrl(job){var photo=job.deliveryPhoto||{};var url=photo.url||('/operations/api/jobs/'+encodeURIComponent(job.reference)+'/delivery-photo');return url+'?v='+encodeURIComponent(photo.uploadedAt||photo.id||'current');}
    function deliveryPhotoSectionHtml(job){var photo=job.deliveryPhoto||null;var uploaded=photo?'<div class="delivery-photo-frame"><img src="'+esc(deliveryPhotoDisplayUrl(job))+'" alt="Delivery photo for '+esc(job.reference)+'"></div><div class="delivery-photo-meta"><span>UPLOADED '+esc(dateText(photo.uploadedAt))+'</span><span>'+esc(Math.max(1,Math.round(Number(photo.sizeBytes||0)/1024)))+' KB</span><span>'+esc(String(photo.contentType||'image').replace('image/','').toUpperCase())+'</span></div>':'';var intro=photo?'Delivery photo secured. You can replace it below if the wrong image was selected.':'One delivery photo is required before this job can be marked as delivered.';return '<section class="section delivery-photo-section '+(photo?'delivery-photo-complete':'delivery-photo-required')+'" data-delivery-photo><h3>Delivery photo</h3><p>'+esc(intro)+'</p>'+uploaded+'<form class="delivery-photo-form"><div class="delivery-photo-choices"><label class="secondary photo-picker">TAKE PHOTO<input type="file" accept="image/jpeg,image/png,image/webp" capture="environment" data-photo-file></label><label class="secondary photo-picker">CHOOSE PHOTO<input type="file" accept="image/jpeg,image/png,image/webp" data-photo-file></label></div><div class="delivery-photo-file" data-photo-name>No photo selected · JPEG, PNG or WebP · maximum 10 MB</div><div class="delivery-photo-preview" data-photo-preview><img alt="Selected delivery photo preview"></div><button type="submit" class="primary delivery-photo-submit" disabled>'+(photo?'UPLOAD REPLACEMENT':'UPLOAD DELIVERY PHOTO')+'</button></form></section>';}
    function bindDeliveryPhotoForm(job,section){var form=section.querySelector('form');if(!form)return;var preview=section.querySelector('[data-photo-preview]');var previewImage=preview.querySelector('img');var name=section.querySelector('[data-photo-name]');var submit=form.querySelector('button[type="submit"]');var previewUrl='';section.querySelectorAll('[data-photo-file]').forEach(function(input){input.addEventListener('change',function(){var file=input.files&&input.files[0];if(!file)return;if(previewUrl)URL.revokeObjectURL(previewUrl);form._deliveryPhotoFile=file;previewUrl=URL.createObjectURL(file);previewImage.src=previewUrl;preview.classList.add('ready');name.textContent=file.name+' · '+Math.max(1,Math.round(Number(file.size||0)/1024))+' KB';submit.disabled=false;section.querySelectorAll('[data-photo-file]').forEach(function(other){if(other!==input)other.value='';});});});form.addEventListener('submit',function(event){event.preventDefault();uploadDeliveryPhoto(job,form,submit);});}
    async function uploadDeliveryPhoto(job,form,button){var file=form._deliveryPhotoFile;if(!file){alert('Choose or take a delivery photo first.');return;}if(Number(file.size||0)>10*1024*1024){alert('Delivery photo must be 10 MB or smaller.');return;}if(['image/jpeg','image/png','image/webp'].indexOf(String(file.type||'').toLowerCase())<0){alert('Delivery photo must be a JPEG, PNG or WebP image.');return;}button.classList.add('busy');var body=new FormData();body.append('photo',file,file.name||'delivery-photo');try{var response=await fetch('/operations/api/jobs/'+encodeURIComponent(job.reference)+'/delivery-photo',{method:'POST',body:body});var result=await response.json().catch(function(){return{};});if(!response.ok){var build=response.headers.get('X-Sorrin-Operations-Build')||result.build||'unknown build';throw new Error('['+build+'] '+(result.error||'Delivery photo upload failed'));}state.jobs=state.jobs.map(function(item){return item.reference===job.reference?Object.assign({},item,{status:result.job.status}):item;});renderJobs();var panel=document.getElementById('job-detail');if(panel.classList.contains('full-page'))renderJobDetail(result.job);else renderJobSummary(result.job);state.processor=null;if(state.section==='processor')await loadProcessor();showToast('Delivery photo uploaded. MARK AS DELIVERED is now available.');}catch(error){alert(error.message);}finally{button.classList.remove('busy');}}
    function installDeliveryPhotoUi(job,fullPage){var panel=document.getElementById('job-detail');var body=panel&&panel.querySelector('.detail-body');if(!body)return;var action=job.execution||{};var show=fullPage?['approved','active','delivered'].indexOf(job.status)>-1:['delivery_photo_required','complete_job'].indexOf(action.code)>-1||job.status==='delivered';var deliveredOption=panel.querySelector('#job-status option[value="delivered"]');if(deliveredOption&&!job.deliveryPhoto){deliveredOption.disabled=true;deliveredOption.textContent='DELIVERED — PHOTO REQUIRED';}if(!show)return;var old=body.querySelector('[data-delivery-photo]');if(old)old.remove();var holder=document.createElement('div');holder.innerHTML=deliveryPhotoSectionHtml(job);var section=holder.firstElementChild;var execution=body.querySelector('.execution-panel');if(execution)body.insertBefore(section,execution);else body.insertBefore(section,body.firstChild);if(action.code==='delivery_photo_required'&&!execution){execution=document.createElement('section');execution.className='section execution-panel photo-blocked';execution.innerHTML='<h3>Live job execution</h3><p>The final handover is ready to close.</p><div class="photo-gate-note">Upload the delivery photo above to unlock MARK AS DELIVERED.</div><div style="margin-top:12px"><button type="button" class="execution-primary" disabled>DELIVERY PHOTO REQUIRED</button></div>';section.insertAdjacentElement('afterend',execution);}bindDeliveryPhotoForm(job,section);if(action.code==='delivery_photo_required'&&execution){execution.classList.add('photo-blocked');if(!execution.querySelector('.photo-gate-note')){var note=document.createElement('div');note.className='photo-gate-note';note.textContent='Upload the delivery photo above to unlock MARK AS DELIVERED.';execution.insertBefore(note,execution.querySelector('div')||execution.lastChild);}}if(!job.deliveryPhoto){var finalButton=action.stopId?Array.from(panel.querySelectorAll('[data-stop][data-stop-status="completed"]')).find(function(candidate){return candidate.dataset.stop===action.stopId;}):null;if(finalButton&&action.code==='delivery_photo_required'){finalButton.disabled=true;finalButton.classList.add('photo-blocked');finalButton.textContent='PHOTO REQUIRED';}Array.from(panel.querySelectorAll('.detail-actions button')).forEach(function(candidate){if(candidate.textContent.trim()==='FORCE CLOSE JOB'){candidate.disabled=true;candidate.classList.add('photo-blocked');candidate.title='Upload a delivery photo first';}});}}
    var renderJobDetailV22Base=renderJobDetail;
    renderJobDetail=function(job){renderJobDetailV22Base(job);installDeliveryPhotoUi(job,true);};
    var renderJobSummaryV22Base=renderJobSummary;
    renderJobSummary=function(job){renderJobSummaryV22Base(job);installDeliveryPhotoUi(job,false);};
    function switchSection(section){state.section=section;localStorage.setItem("sorrin_ops_section",section);history.replaceState(null,"","#"+section);document.querySelectorAll("[data-section]").forEach(function(button){var active=button.dataset.section===section;button.classList.toggle("active",active);button.setAttribute("aria-current",active?"page":"false");});document.getElementById("processor-section").classList.toggle("hidden",section!=="processor");document.getElementById("jobs-section").classList.toggle("hidden",section!=="jobs");document.getElementById("accounts-section").classList.toggle("hidden",section!=="accounts");document.getElementById("finance-section").classList.toggle("hidden",section!=="finance");document.getElementById("job-stats").classList.toggle("hidden",section!=="jobs");document.getElementById("new-job-top").classList.toggle("hidden",section!=="jobs");document.getElementById("new-account-top").classList.toggle("hidden",section!=="accounts");var titles={processor:"Conscious Processor",jobs:"Courier jobs",finance:"Finance",accounts:"USC accounts"};var subtitles={processor:"Live dispatch, ordered by pressure and promise",jobs:"Approve, execute and close every movement",finance:"Prepayments, invoices and collection",accounts:"Private client control, tags and benefits"};var crumbs={processor:"DISPATCH",jobs:"JOBS",finance:"FINANCE",accounts:"USC ACCOUNTS"};document.getElementById("page-title").textContent=titles[section]||titles.jobs;document.getElementById("page-subtitle").textContent=subtitles[section]||subtitles.jobs;document.getElementById("section-breadcrumb").textContent="OPERATIONS / "+(crumbs[section]||crumbs.jobs);document.title=(titles[section]||titles.jobs)+" · Sorrin Command Console";setCommandOpen(false);if(section==="processor")loadProcessor();if(section==="finance")renderFinances();}
    document.getElementById("login-form").addEventListener("submit",async function(event){event.preventDefault();var form=event.currentTarget;var error=document.getElementById("login-error");error.textContent="";form.classList.add("busy");try{await api("/operations/api/login",{method:"POST",body:{email:form.email.value,password:form.password.value}});form.password.value="";showApp();await refresh();}catch(problem){error.textContent=problem.message;}finally{form.classList.remove("busy");}});
    document.querySelectorAll("[data-section]").forEach(function(button){button.addEventListener("click",function(){switchSection(button.dataset.section);});});
    document.querySelectorAll("[data-view]").forEach(function(button){button.addEventListener("click",function(){state.jobView=button.dataset.view;document.querySelectorAll("[data-view]").forEach(function(item){item.classList.toggle("active",item===button);});renderJobs();});});
    document.querySelectorAll("[data-finance-view]").forEach(function(button){button.addEventListener("click",function(){state.financeView=button.dataset.financeView;document.querySelectorAll("[data-finance-view]").forEach(function(item){item.classList.toggle("active",item===button);});renderFinances();});});
    document.getElementById("job-search").addEventListener("input",renderJobs);document.getElementById("account-search").addEventListener("input",renderAccounts);document.getElementById("finance-search").addEventListener("input",renderFinances);document.getElementById("new-account").addEventListener("click",newAccount);document.getElementById("full-job-record").addEventListener("click",openFullJobRecord);document.getElementById("job-record-close").addEventListener("click",closeFullJobRecord);document.getElementById("job-record-search").addEventListener("input",renderFullJobRecord);document.getElementById("job-record-modal").addEventListener("click",function(event){if(event.target===event.currentTarget)closeFullJobRecord();});document.getElementById("new-job-top").addEventListener("click",newJob);document.getElementById("new-account-top").addEventListener("click",newAccount);document.getElementById("processor-origin").addEventListener("input",function(event){state.processorOrigin.latitude=null;state.processorOrigin.longitude=null;state.processorOrigin.label=null;state.processorOrigin.address=event.currentTarget.value;});document.getElementById("processor-origin").addEventListener("keydown",function(event){if(event.key==="Enter"){event.preventDefault();loadProcessor();}});document.getElementById("processor-location").addEventListener("click",useProcessorLocation);document.getElementById("refresh-processor").addEventListener("click",loadProcessor);document.getElementById("logout").addEventListener("click",async function(){await api("/operations/api/logout",{method:"POST"});showLogin();});
    document.getElementById("command-switcher").addEventListener("click",function(){setCommandOpen(true);});
    document.getElementById("command-modal").addEventListener("click",function(event){if(event.target===event.currentTarget)setCommandOpen(false);});
    document.querySelectorAll("[data-command-section]").forEach(function(button){button.addEventListener("click",function(){switchSection(button.dataset.commandSection);});});
    document.querySelectorAll("[data-command-action]").forEach(function(button){button.addEventListener("click",function(){var action=button.dataset.commandAction;setCommandOpen(false);if(action==="new-job"){switchSection("jobs");newJob();}else if(action==="new-account"){switchSection("accounts");newAccount();}else if(action==="job-record"){switchSection("jobs");openFullJobRecord();}});});
    document.addEventListener("keydown",function(event){var tag=(event.target&&event.target.tagName||"").toLowerCase();var typing=tag==="input"||tag==="textarea"||tag==="select"||event.target&&event.target.isContentEditable;if((event.metaKey||event.ctrlKey)&&event.key.toLowerCase()==="k"){event.preventDefault();setCommandOpen(document.getElementById("command-modal").classList.contains("hidden"));return;}if(event.key==="Escape"){setCommandOpen(false);return;}if((event.metaKey||event.ctrlKey)&&/^[1-4]$/.test(event.key)){event.preventDefault();switchSection(sectionOrder[Number(event.key)-1]);return;}if(event.key==="/"&&!typing){event.preventDefault();focusSectionSearch();}});
    boot();
  </script>
</body>
</html>`;
}

const SORRINBOT_QUOTE_ENGINE_VERSION = "A012-1.1.0";
const SORRINBOT_CARGO_ENGINE_VERSION = "A012-1.0.0";
const SORRINBOT_QUOTE_TIME_ZONE = "Australia/Melbourne";
const SORRINBOT_QUOTE_CBD = Object.freeze({
  latitude: -37.5622101,
  longitude: 143.855957,
  label: "Ballarat CBD",
});
const SORRINBOT_QUOTE_PRICE_BANDS = Object.freeze([
  { label: "0-2.5km", maxKm: 2.5, flexible: 10, express: 13, asap: 18.5 },
  { label: "2.6-5.5km", maxKm: 5.5, flexible: 14, express: 16.5, asap: 22 },
  { label: "5.6-11km", maxKm: 11, flexible: 20, express: 22.5, asap: 27 },
  { label: "11.1-15km", maxKm: 15, flexible: 23, express: 26, asap: 30.5 },
  { label: "15.1-20km", maxKm: 20, flexible: 28, express: 31.5, asap: 36 },
  { label: "20.1-30km", maxKm: 30, flexible: 40, express: 44, asap: 50 },
  { label: "30.1-40km", maxKm: 40, flexible: 55, express: 62, asap: 75 },
  { label: "40.1-50km", maxKm: 50, flexible: 68, express: 76, asap: 92 },
  { label: "50.1-60km", maxKm: 60, flexible: 82, express: 94, asap: 115 },
  { label: "60.1-75km", maxKm: 75, flexible: 105, express: 125, asap: 150 },
]);
const SORRINBOT_QUOTE_SERVICE_LABELS = Object.freeze({
  flexible: "FLEXIBLE / 4H+",
  express: "EXPRESS / 2H",
  asap: "PRIORITY / ASAP",
});
const SORRINBOT_QUOTE_SERVICE_RANK = Object.freeze({ flexible: 0, express: 1, asap: 2 });

function sorrinbotQuoteDateValid(value) {
  const text = cleanText(value, 10);
  if (!/^\d{4}-\d{2}-\d{2}$/.test(text)) return false;
  const [year, month, day] = text.split("-").map(Number);
  const date = new Date(Date.UTC(year, month - 1, day));
  return date.getUTCFullYear() === year && date.getUTCMonth() === month - 1 && date.getUTCDate() === day;
}

function sorrinbotQuoteTimeValid(value) {
  return /^([01]\d|2[0-3]):[0-5]\d$/.test(String(value || ""));
}

function sorrinbotQuoteMinutesOfDay(value) {
  if (!sorrinbotQuoteTimeValid(value)) return null;
  const [hour, minute] = value.split(":").map(Number);
  return hour * 60 + minute;
}

function sorrinbotQuoteParts(value = new Date()) {
  return new Intl.DateTimeFormat("en-AU", {
    timeZone: SORRINBOT_QUOTE_TIME_ZONE,
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    hourCycle: "h23",
  })
    .formatToParts(value)
    .reduce(
      (result, part) => ({ ...result, [part.type]: part.value }),
      /** @type {Record<string, string>} */ ({}),
    );
}

function sorrinbotQuoteTodayKey(now = new Date()) {
  const parts = sorrinbotQuoteParts(now);
  return `${parts.year}-${parts.month}-${parts.day}`;
}

function sorrinbotQuoteZonedEpoch(dateKey, timeText = "00:00") {
  if (!sorrinbotQuoteDateValid(dateKey) || !sorrinbotQuoteTimeValid(timeText)) return null;
  const [year, month, day] = dateKey.split("-").map(Number);
  const [hour, minute] = timeText.split(":").map(Number);
  const wanted = Date.UTC(year, month - 1, day, hour, minute, 0, 0);
  let candidate = wanted;
  for (let pass = 0; pass < 4; pass += 1) {
    const local = sorrinbotQuoteParts(new Date(candidate));
    const rendered = Date.UTC(
      Number(local.year),
      Number(local.month) - 1,
      Number(local.day),
      Number(local.hour),
      Number(local.minute),
      0,
      0,
    );
    candidate += wanted - rendered;
  }
  return candidate;
}

function sorrinbotQuotePickupReadyEpoch(pickup, now = new Date()) {
  if (!sorrinbotQuoteDateValid(pickup?.date)) return null;
  if (sorrinbotQuoteTimeValid(pickup?.earliestTime)) {
    return sorrinbotQuoteZonedEpoch(pickup.date, pickup.earliestTime);
  }
  const start = sorrinbotQuoteZonedEpoch(pickup.date, "00:00");
  return pickup.date === sorrinbotQuoteTodayKey(now)
    ? Math.max(start, now.getTime())
    : start;
}

function sorrinbotQuoteLatestEpoch(stop, pickup = false) {
  const date = pickup ? (stop.latestDate || stop.date) : stop.date;
  return sorrinbotQuoteDateValid(date) && sorrinbotQuoteTimeValid(stop?.latestTime)
    ? sorrinbotQuoteZonedEpoch(date, stop.latestTime)
    : null;
}

function sorrinbotQuoteEarliestEpoch(stop, pickup = false, now = new Date()) {
  const date = pickup ? stop.date : (stop.earliestDate || stop.date);
  if (!sorrinbotQuoteDateValid(date)) return null;
  if (sorrinbotQuoteTimeValid(stop?.earliestTime)) {
    return sorrinbotQuoteZonedEpoch(date, stop.earliestTime);
  }
  const start = sorrinbotQuoteZonedEpoch(date, "00:00");
  return date === sorrinbotQuoteTodayKey(now) ? Math.max(start, now.getTime()) : start;
}

function sorrinbotQuoteWindowMinutes(stop, pickup = false) {
  if (!sorrinbotQuoteTimeValid(stop?.earliestTime) || !sorrinbotQuoteTimeValid(stop?.latestTime)) {
    return null;
  }
  const startDate = pickup ? stop.date : (stop.earliestDate || stop.date);
  const endDate = pickup ? (stop.latestDate || stop.date) : stop.date;
  const start = sorrinbotQuoteZonedEpoch(startDate, stop.earliestTime);
  const end = sorrinbotQuoteZonedEpoch(endDate, stop.latestTime);
  if (!Number.isFinite(start) || !Number.isFinite(end) || end < start) return null;
  return (end - start) / 60000;
}

function sorrinbotQuoteNthWeekday(year, month, weekday, occurrence) {
  const first = new Date(Date.UTC(year, month, 1));
  const day = 1 + ((weekday - first.getUTCDay() + 7) % 7) + ((occurrence - 1) * 7);
  return `${year}-${String(month + 1).padStart(2, "0")}-${String(day).padStart(2, "0")}`;
}

function sorrinbotQuoteEasterKey(year) {
  const a = year % 19;
  const b = Math.floor(year / 100);
  const c = year % 100;
  const d = Math.floor(b / 4);
  const e = b % 4;
  const f = Math.floor((b + 8) / 25);
  const g = Math.floor((b - f + 1) / 3);
  const h = (19 * a + b - d - g + 15) % 30;
  const i = Math.floor(c / 4);
  const k = c % 4;
  const l = (32 + 2 * e + 2 * i - h - k) % 7;
  const m = Math.floor((a + 11 * h + 22 * l) / 451);
  const month = Math.floor((h + l - 7 * m + 114) / 31);
  const day = ((h + l - 7 * m + 114) % 31) + 1;
  return `${year}-${String(month).padStart(2, "0")}-${String(day).padStart(2, "0")}`;
}

function sorrinbotQuoteAddDays(dateKey, days) {
  const [year, month, day] = dateKey.split("-").map(Number);
  const date = new Date(Date.UTC(year, month - 1, day));
  date.setUTCDate(date.getUTCDate() + days);
  return date.toISOString().slice(0, 10);
}

function sorrinbotQuotePublicHolidayName(dateKey) {
  if (!sorrinbotQuoteDateValid(dateKey)) return "";
  const year = Number(dateKey.slice(0, 4));
  const holidays = new Map();
  const add = (key, name) => holidays.set(key, name);
  const weekday = (key) => {
    const [y, m, d] = key.split("-").map(Number);
    return new Date(Date.UTC(y, m - 1, d)).getUTCDay();
  };

  const newYear = `${year}-01-01`;
  add(newYear, "New Year's Day");
  if (weekday(newYear) === 6) add(`${year}-01-03`, "New Year's Day additional holiday");
  if (weekday(newYear) === 0) add(`${year}-01-02`, "New Year's Day additional holiday");

  const australiaDay = `${year}-01-26`;
  add(
    weekday(australiaDay) === 6 ? `${year}-01-28`
      : weekday(australiaDay) === 0 ? `${year}-01-27`
        : australiaDay,
    "Australia Day",
  );
  add(sorrinbotQuoteNthWeekday(year, 2, 1, 2), "Labour Day");

  const easter = sorrinbotQuoteEasterKey(year);
  add(sorrinbotQuoteAddDays(easter, -2), "Good Friday");
  add(sorrinbotQuoteAddDays(easter, -1), "Saturday before Easter Sunday");
  add(easter, "Easter Sunday");
  add(sorrinbotQuoteAddDays(easter, 1), "Easter Monday");

  add(`${year}-04-25`, "ANZAC Day");
  add(sorrinbotQuoteNthWeekday(year, 5, 1, 2), "King's Birthday");

  const aflGrandFinalFridays = { 2026: "2026-09-25" };
  if (aflGrandFinalFridays[year]) add(aflGrandFinalFridays[year], "Friday before the AFL Grand Final");

  add(sorrinbotQuoteNthWeekday(year, 10, 2, 1), "Melbourne Cup Day");

  const christmas = `${year}-12-25`;
  const boxing = `${year}-12-26`;
  add(christmas, "Christmas Day");
  add(boxing, "Boxing Day");
  if (weekday(christmas) === 6 || weekday(christmas) === 0) add(`${year}-12-27`, "Christmas Day additional holiday");
  if (weekday(boxing) === 6 || weekday(boxing) === 0) add(`${year}-12-28`, "Boxing Day additional holiday");

  return holidays.get(dateKey) || "";
}

function sorrinbotQuoteIsWeekend(dateKey) {
  if (!sorrinbotQuoteDateValid(dateKey)) return false;
  const [year, month, day] = dateKey.split("-").map(Number);
  const weekday = new Date(Date.UTC(year, month - 1, day)).getUTCDay();
  return weekday === 0 || weekday === 6;
}

function sorrinbotQuoteGetBand(km) {
  return SORRINBOT_QUOTE_PRICE_BANDS.find((row) => km <= row.maxKm) || null;
}

function sorrinbotQuoteAccessBufferMinutes(addOns) {
  const trolley = Boolean(addOns?.trolleyRequired);
  const difficult = Boolean(addOns?.difficultAccess);
  if (trolley && difficult) return 20;
  if (difficult) return 15;
  if (trolley) return 10;
  return 0;
}

async function sorrinbotQuoteRoute(env, points, departureEpoch = null) {
  const token = processorMapboxToken(env);
  if (!token) throw new Error("Routing access is not configured");
  if (!Array.isArray(points) || points.length < 2) throw new Error("At least two route points are required");
  const coordinates = points.map((point) => `${point.longitude},${point.latitude}`).join(";");
  const requestRoute = async (profile, includeDeparture) => {
    const url = new URL(`https://api.mapbox.com/directions/v5/mapbox/${profile}/${coordinates}`);
    url.searchParams.set("access_token", token);
    url.searchParams.set("overview", "false");
    url.searchParams.set("alternatives", "false");
    url.searchParams.set("steps", "false");
    if (includeDeparture && Number.isFinite(departureEpoch)) {
      url.searchParams.set("depart_at", new Date(departureEpoch).toISOString());
    }
    const response = await fetch(url.toString());
    const result = await response.json().catch(() => ({}));
    const route = result?.routes?.[0];
    if (!response.ok || !route) {
      throw new Error(result?.message || "Mapbox route calculation failed");
    }
    return {
      km: Number(route.distance || 0) / 1000,
      durationMinutes: Number(route.duration || 0) / 60,
      legMinutes: Array.isArray(route.legs) ? route.legs.map((leg) => Number(leg.duration || 0) / 60) : [],
      trafficAware: profile === "driving-traffic",
    };
  };
  try {
    return await requestRoute("driving-traffic", true);
  } catch {
    return requestRoute("driving", false);
  }
}


function sorrinbotCargoNumber(value) {
  const number = Number(value);
  return Number.isFinite(number) && number > 0 ? number : null;
}

function sorrinbotCargoDimensions(input) {
  const values = [
    sorrinbotCargoNumber(input?.lengthCm),
    sorrinbotCargoNumber(input?.widthCm),
    sorrinbotCargoNumber(input?.heightCm),
  ];
  return values.every((value) => value != null) ? values : null;
}

function sorrinbotCargoExceedsRotatableBox(dimensions, limits) {
  if (!Array.isArray(dimensions) || dimensions.length !== 3) return null;
  const sortedDimensions = [...dimensions].sort((a, b) => b - a);
  const sortedLimits = [...limits].sort((a, b) => b - a);
  return sortedDimensions.some((dimension, index) => dimension > sortedLimits[index]);
}

function sorrinbotCargoMainVehicleOpening(dimensions) {
  if (!Array.isArray(dimensions) || dimensions.length !== 3) {
    return { known: false, crossSectionFits: null, fitsWithinPublished200Cm: null, requiresLengthReview: false };
  }
  let crossSectionFits = false;
  let fitsWithinPublished200Cm = false;
  let requiresLengthReview = false;
  for (let lengthIndex = 0; lengthIndex < 3; lengthIndex += 1) {
    const length = dimensions[lengthIndex];
    const cross = dimensions.filter((_, index) => index !== lengthIndex).sort((a, b) => b - a);
    const crossFits = cross[0] <= 102 && cross[1] <= 74;
    if (!crossFits) continue;
    crossSectionFits = true;
    if (length <= 200) fitsWithinPublished200Cm = true;
    else requiresLengthReview = true;
  }
  return { known: true, crossSectionFits, fitsWithinPublished200Cm, requiresLengthReview };
}

function sorrinbotCargoPickupNoticeMinutes(input, now = new Date()) {
  if (!sorrinbotQuoteDateValid(input?.pickupDate)) return null;
  const time = sorrinbotQuoteTimeValid(input?.pickupEarliestTime)
    ? input.pickupEarliestTime
    : "00:00";
  const epoch = sorrinbotQuoteZonedEpoch(input.pickupDate, time);
  if (!Number.isFinite(epoch)) return null;
  return Math.floor((epoch - now.getTime()) / 60000);
}

function assessSorrinbotCargoSuitability(input = {}, now = new Date()) {
  const selectedSpace = ["front", "back", "bulky", "suv"].includes(input.selectedSpace)
    ? input.selectedSpace
    : null;
  const itemCountRaw = Number(input.itemCount);
  const itemCount = Number.isInteger(itemCountRaw) && itemCountRaw > 0 ? itemCountRaw : null;
  const dimensions = sorrinbotCargoDimensions(input);
  const knownDimensions = [input.lengthCm, input.widthCm, input.heightCm]
    .map(sorrinbotCargoNumber)
    .filter((value) => value != null);
  const weightKg = sorrinbotCargoNumber(input.weightKg);
  const fragile = Boolean(input.fragile);
  const perishable = Boolean(input.perishable);

  const frontDimensionRuledOut = knownDimensions.some((dimension) => dimension > 50);
  const frontWeightRuledOut = weightKg != null && weightKg >= 10;
  const frontDimensionsFit = dimensions ? dimensions.every((dimension) => dimension <= 50) : null;
  const frontWeightFits = weightKg != null ? weightKg < 10 : null;
  const frontFitsPublishedGuide = frontDimensionsFit === true && frontWeightFits === true;
  const frontRuledOut = frontDimensionRuledOut || frontWeightRuledOut;

  const backRotatableExceeds = dimensions ? sorrinbotCargoExceedsRotatableBox(dimensions, [120, 70, 60]) : null;
  const backDimensionsFitSingle = backRotatableExceeds == null ? null : !backRotatableExceeds;
  const backWeightFits = weightKg != null ? weightKg < 25 : null;
  const backWeightRuledOut = weightKg != null && weightKg >= 25;
  const backDimensionRuledOut = backRotatableExceeds === true;
  const multiItemDimensionWarning = Boolean(
    itemCount != null && itemCount > 1 && dimensions && dimensions.some((dimension) => dimension > 65)
  );
  const backFitsPublishedGuide = backDimensionsFitSingle === true && backWeightFits === true;
  const backRuledOut = backWeightRuledOut || backDimensionRuledOut;
  const opening = sorrinbotCargoMainVehicleOpening(dimensions);

  let recommendedSpace = null;
  let recommendationBasis = null;
  if (!frontRuledOut && frontFitsPublishedGuide && itemCount === 1) {
    recommendedSpace = "front";
    recommendationBasis = "The single item is within the published front-seat size and weight guide.";
  } else if (!backRuledOut && backFitsPublishedGuide) {
    recommendedSpace = "back";
    recommendationBasis = itemCount && itemCount > 1
      ? "The largest supplied item is within the published back-seat guide; combined multi-item fit still depends on the whole load."
      : "The item is within the published back-seat size and weight guide.";
  } else if (backRuledOut) {
    recommendedSpace = "bulky";
    recommendationBasis = "The supplied item is outside the published back-seat guide, so a larger cargo arrangement needs review.";
  } else if (frontRuledOut && !backRuledOut) {
    recommendedSpace = "back";
    recommendationBasis = "The supplied information rules out the front-seat guide but does not rule out the back-seat guide.";
  } else if (selectedSpace) {
    recommendedSpace = selectedSpace;
    recommendationBasis = "There is not enough complete measurement information to justify changing the visitor's declared cargo-space category.";
  }

  let selectedSpaceSuitable = null;
  let selectedSpaceAssessment = "not_selected";
  if (selectedSpace === "front") {
    if (frontRuledOut) {
      selectedSpaceSuitable = false;
      selectedSpaceAssessment = "outside_front_seat_guide";
    } else if (frontFitsPublishedGuide && itemCount === 1) {
      selectedSpaceSuitable = true;
      selectedSpaceAssessment = "within_front_seat_guide";
    } else {
      selectedSpaceAssessment = "front_seat_not_fully_confirmed";
    }
  } else if (selectedSpace === "back") {
    if (backRuledOut) {
      selectedSpaceSuitable = false;
      selectedSpaceAssessment = "outside_back_seat_guide";
    } else if (backFitsPublishedGuide && !multiItemDimensionWarning) {
      selectedSpaceSuitable = true;
      selectedSpaceAssessment = itemCount && itemCount > 1
        ? "consistent_with_back_seat_guide_multi_item"
        : "within_back_seat_guide";
    } else if (multiItemDimensionWarning) {
      selectedSpaceAssessment = "back_seat_multi_item_capacity_warning";
    } else {
      selectedSpaceAssessment = "back_seat_not_fully_confirmed";
    }
  } else if (selectedSpace === "bulky") {
    selectedSpaceAssessment = opening.known && opening.crossSectionFits === false
      ? "published_main_vehicle_opening_not_confirmed"
      : "big_heavy_requires_practical_review";
  } else if (selectedSpace === "suv") {
    selectedSpaceAssessment = "suv_roof_racks_requires_availability_review";
  }

  const autoAdjustToSpace = selectedSpace === "front" && selectedSpaceSuitable === false && recommendedSpace === "back"
    ? "back"
    : null;
  const pickupNoticeMinutes = sorrinbotCargoPickupNoticeMinutes(input, now);
  const suvShortNotice = (selectedSpace === "suv" || recommendedSpace === "suv")
    && Number.isFinite(pickupNoticeMinutes)
    && pickupNoticeMinutes < 720;

  const missingForConfidentAssessment = [];
  if (itemCount == null) missingForConfidentAssessment.push("itemCount");
  if (!dimensions) missingForConfidentAssessment.push("largestItemDimensionsCm");
  if (weightKg == null) missingForConfidentAssessment.push("largestItemWeightKg");

  const requiresSalemReview = Boolean(
    selectedSpace === "bulky" ||
    selectedSpace === "suv" ||
    recommendedSpace === "bulky" ||
    recommendedSpace === "suv" ||
    multiItemDimensionWarning ||
    (opening.known && opening.crossSectionFits === false) ||
    (opening.known && opening.requiresLengthReview)
  );

  let status = "insufficient_information";
  if (selectedSpaceSuitable === false) status = "selected_space_too_small";
  else if (requiresSalemReview) status = "review_required";
  else if (selectedSpaceSuitable === true) status = "within_published_guide";
  else if (recommendedSpace) status = "recommended_space_identified";

  const warnings = [];
  if (frontDimensionRuledOut) warnings.push("At least one supplied dimension is over the published 50cm front-seat guide.");
  if (frontWeightRuledOut) warnings.push("The supplied item weight is not under the published 10kg front-seat guide.");
  if (backDimensionRuledOut) warnings.push("The supplied dimensions do not fit within the published 120 x 70 x 60cm single-item back-seat guide even when rotated.");
  if (backWeightRuledOut) warnings.push("The supplied item weight is not under the published 25kg back-seat guide.");
  if (multiItemDimensionWarning) warnings.push("PATCH26 raises a back-seat capacity warning for multi-item jobs when a largest-item dimension exceeds 65cm.");
  if (opening.known && opening.crossSectionFits === false) warnings.push("The supplied rectangular dimensions do not pass through the published 102 x 74cm main-vehicle opening in any simple orientation.");
  if (opening.known && opening.requiresLengthReview && !opening.fitsWithinPublished200Cm) warnings.push("The cross-section may fit the published opening, but the item is longer than the published minimum 200cm load-length figure and needs Salem to confirm the actual fit.");
  if (fragile) warnings.push("Fragile cargo must be suitably packaged and disclosed; fragility does not itself confirm or reject vehicle fit.");
  if (perishable) warnings.push("Perishable cargo must be disclosed. PRIORITY is strongly recommended and temperature control is not guaranteed.");
  if (suvShortNotice) warnings.push("SUV/roof-rack jobs typically require around 12 hours notice; this request appears to be inside that notice period and needs availability confirmation.");

  return {
    ok: true,
    code: "cargo_assessed",
    assessmentVersion: SORRINBOT_CARGO_ENGINE_VERSION,
    source: "trusted_sorrin_courier_backend",
    status,
    selectedSpace,
    selectedSpaceSuitable,
    selectedSpaceAssessment,
    recommendedSpace,
    recommendationBasis,
    autoAdjustToSpace,
    requiresSalemReview,
    missingForConfidentAssessment,
    itemCount,
    measurements: {
      dimensionsCm: dimensions,
      weightKg,
    },
    guides: {
      frontSeat: { maxWeightExclusiveKg: 10, approximateBoxCm: [50, 50, 50] },
      backSeat: { maxWeightExclusiveKg: 25, approximateRotatableBoxCm: [120, 70, 60], multiItemLargestDimensionWarningCm: 65 },
      mainVehicle: { bootOpeningCm: [102, 74], publishedLoadLengthCmMinimum: 200 },
    },
    mainVehicleOpeningAssessment: opening,
    pickupNoticeMinutes: Number.isFinite(pickupNoticeMinutes) ? pickupNoticeMinutes : null,
    warnings,
  };
}

function sorrinbotQuoteMissingFields(input) {
  const missing = [];
  const service = cleanText(input?.service, 20).toLowerCase();
  if (service && !Object.hasOwn(SORRINBOT_QUOTE_SERVICE_RANK, service)) missing.push("service");
  const pickup = input?.pickup || {};
  if (!cleanText(pickup.address, 500)) missing.push("pickup.address");
  if (!sorrinbotQuoteDateValid(pickup.date)) missing.push("pickup.date");
  if (!sorrinbotQuoteTimeValid(pickup.latestTime)) missing.push("pickup.latestTime");
  if (pickup.earliestTime != null && !sorrinbotQuoteTimeValid(pickup.earliestTime)) missing.push("pickup.earliestTime");
  if (pickup.latestDate != null && !sorrinbotQuoteDateValid(pickup.latestDate)) missing.push("pickup.latestDate");

  const dropoffs = Array.isArray(input?.dropoffs) ? input.dropoffs : [];
  if (!dropoffs.length) missing.push("dropoffs");
  dropoffs.forEach((dropoff, index) => {
    if (!cleanText(dropoff?.address, 500)) missing.push(`dropoffs[${index}].address`);
    if (!sorrinbotQuoteDateValid(dropoff?.date)) missing.push(`dropoffs[${index}].date`);
    if (!sorrinbotQuoteTimeValid(dropoff?.latestTime)) missing.push(`dropoffs[${index}].latestTime`);
    if (dropoff?.earliestTime != null && !sorrinbotQuoteTimeValid(dropoff.earliestTime)) missing.push(`dropoffs[${index}].earliestTime`);
    if (dropoff?.earliestDate != null && !sorrinbotQuoteDateValid(dropoff.earliestDate)) missing.push(`dropoffs[${index}].earliestDate`);
  });

  const cargo = input?.cargo || {};
  if (!["front", "back", "bulky", "suv"].includes(cargo.space)) missing.push("cargo.space");
  if (!Number.isInteger(Number(cargo.itemCount)) || Number(cargo.itemCount) < 1) missing.push("cargo.itemCount");
  return [...new Set(missing)];
}

function sorrinbotQuoteInternalAuthorized(request, env) {
  const configured = String(env.SORRINBOT_INTERNAL_KEY || "");
  const supplied = String(request.headers.get("X-SorrinBot-Internal-Key") || "");
  return Boolean(configured && supplied && constantTimeEqual(configured, supplied));
}

async function calculateSorrinbotCourierQuote(input, env, now = new Date()) {
  const missingFields = sorrinbotQuoteMissingFields(input);
  if (missingFields.length) {
    return {
      ok: false,
      code: "missing_quote_fields",
      error: "More job information is required before an exact indicative quote can be calculated.",
      missingFields,
      engineVersion: SORRINBOT_QUOTE_ENGINE_VERSION,
    };
  }

  const requestedService = cleanText(input.service, 20).toLowerCase();
  const service = Object.hasOwn(SORRINBOT_QUOTE_SERVICE_RANK, requestedService)
    ? requestedService
    : "flexible";
  const pickup = input.pickup;
  const dropoffs = input.dropoffs.slice(0, 8);
  const stops = [pickup, ...dropoffs];
  const cargoAssessment = assessSorrinbotCargoSuitability({
    selectedSpace: input.cargo?.space || null,
    itemCount: input.cargo?.itemCount ?? null,
    lengthCm: input.cargo?.lengthCm ?? null,
    widthCm: input.cargo?.widthCm ?? null,
    heightCm: input.cargo?.heightCm ?? null,
    weightKg: input.cargo?.weightKg ?? null,
    fragile: Number(input.cargo?.additionalFragileItems || 0) > 0,
    perishable: Boolean(input.cargo?.perishable),
    pickupDate: pickup.date || null,
    pickupEarliestTime: pickup.earliestTime || null,
  }, now);
  const effectiveCargoSpace = cargoAssessment.autoAdjustToSpace || input.cargo?.space;
  if (cargoAssessment.selectedSpaceSuitable === false && !cargoAssessment.autoAdjustToSpace) {
    return {
      ok: false,
      code: "cargo_space_review_required",
      error: "The selected cargo-space option is outside Sorrin's published guide for the supplied cargo. A larger cargo option needs to be confirmed before pricing continues.",
      cargoSuitability: cargoAssessment,
      engineVersion: SORRINBOT_QUOTE_ENGINE_VERSION,
    };
  }

  const geocoded = [];
  for (let index = 0; index < stops.length; index += 1) {
    try {
      const resolved = await processorGeocode(env, cleanText(stops[index].address, 500));
      geocoded.push(resolved);
    } catch (error) {
      return {
        ok: false,
        code: "address_not_found",
        error: `Sorrin could not confidently locate ${index === 0 ? "the pickup" : `drop-off ${index}`} address.`,
        addressIndex: index,
        detail: error.message,
        engineVersion: SORRINBOT_QUOTE_ENGINE_VERSION,
      };
    }
  }

  const pickupReadyEpoch = sorrinbotQuotePickupReadyEpoch(pickup, now);
  let mainRoute;
  let cbdMatrix;
  try {
    [mainRoute, cbdMatrix] = await Promise.all([
      sorrinbotQuoteRoute(env, geocoded, pickupReadyEpoch),
      processorTrafficMatrix(env, SORRINBOT_QUOTE_CBD, geocoded),
    ]);
  } catch (error) {
    return {
      ok: false,
      code: "route_calculation_failed",
      error: "The live road route could not be calculated.",
      detail: error.message,
      engineVersion: SORRINBOT_QUOTE_ENGINE_VERSION,
    };
  }

  const routeKm = Math.round(mainRoute.km * 10) / 10;
  const band = sorrinbotQuoteGetBand(routeKm);
  const cbdDistancesKm = geocoded.map((_, index) => {
    const metres = Number(cbdMatrix?.distances?.[0]?.[index + 1]);
    return Number.isFinite(metres) ? metres / 1000 : null;
  });
  const pickupFromCbdKm = cbdDistancesKm[0];
  const lastIndex = geocoded.length;
  const returnMetres = Number(cbdMatrix?.distances?.[lastIndex]?.[0]);
  const returnToCbdKm = Number.isFinite(returnMetres) ? returnMetres / 1000 : null;
  const bothEndsOutside = Number.isFinite(pickupFromCbdKm) && pickupFromCbdKm >= 50 && Number.isFinite(returnToCbdKm) && returnToCbdKm >= 50;
  const manualQuoteReason = !band ? "distance_over_75km" : bothEndsOutside ? "both_ends_50km_plus_from_ballarat" : null;
  const manualQuote = Boolean(manualQuoteReason);

  const effectiveStrict = stops.map((stop, index) => {
    const pickupStop = index === 0;
    const cbdKm = cbdDistancesKm[index];
    const distant = Number.isFinite(cbdKm) && cbdKm > 20;
    const autoTickMinutes = distant ? 75 : 45;
    const windowMinutes = sorrinbotQuoteWindowMinutes(stop, pickupStop);
    const autoStrict = Number.isFinite(windowMinutes) && windowMinutes <= autoTickMinutes;
    return {
      strict: Boolean(stop.strictWindow) || autoStrict,
      requested: Boolean(stop.strictWindow),
      autoStrict,
      windowMinutes,
      cbdKm: Number.isFinite(cbdKm) ? Math.round(cbdKm * 10) / 10 : null,
      priceAud: distant ? 10 : 5,
    };
  });

  const surcharges = [];
  const cargo = input.cargo || {};
  const itemCount = Math.max(1, Number(cargo.itemCount || 1));
  if (effectiveCargoSpace === "bulky") surcharges.push({ code: "bulky", label: "Big/heavy item", priceAud: 10 });
  if (effectiveCargoSpace === "suv") surcharges.push({ code: "suv_roof_racks", label: "SUV/Roof racks", priceAud: 15 });
  if ((effectiveCargoSpace === "back" && itemCount >= 4) || (effectiveCargoSpace === "front" && itemCount >= 5)) {
    surcharges.push({ code: "item_count", label: "Over included item allowance", priceAud: 5 });
  }

  const pickupLatestMinutes = sorrinbotQuoteMinutesOfDay(pickup.latestTime);
  if (Number.isFinite(pickupLatestMinutes) && pickupLatestMinutes <= 510) {
    surcharges.push({ code: "before_0830", label: "Before 8:30am", priceAud: 10 });
  }

  effectiveStrict.forEach((window, index) => {
    if (!window.strict) return;
    surcharges.push({
      code: index === 0 ? "strict_pickup" : "strict_dropoff",
      label: index === 0 ? "Strict pickup window" : `Strict drop-off window${index > 1 ? ` ${index}` : ""}`,
      priceAud: window.priceAud,
    });
  });

  if (dropoffs.length > 1) {
    surcharges.push({
      code: "additional_stops",
      label: `${dropoffs.length - 1} additional stop${dropoffs.length - 1 === 1 ? "" : "s"}`,
      priceAud: (dropoffs.length - 1) * 10,
    });
  }

  const extraFragile = Math.max(0, Math.floor(Number(cargo.additionalFragileItems || 0)));
  if (extraFragile > 0) {
    surcharges.push({
      code: "additional_fragile",
      label: `${extraFragile} additional fragile ${extraFragile === 1 ? "item" : "items"}`,
      priceAud: extraFragile * 5,
    });
  }

  const callMinutes = [pickup, ...dropoffs].map((stop) => Number(stop.callBeforeMinutes || 0));
  callMinutes.forEach((minutes, index) => {
    if (minutes > 5) {
      surcharges.push({
        code: index === 0 ? "pickup_call_before" : "dropoff_call_before",
        label: `Call ${index === 0 ? "pick-up" : `drop-off ${index}`} ${minutes}mins before arrival`,
        priceAud: 5,
      });
    }
  });

  const holdNights = Math.max(0, Math.floor(Number(cargo.overnightHoldNights || 0)));
  if (holdNights > 1) {
    surcharges.push({ code: "multi_night_hold", label: `${holdNights} night hold`, priceAud: 10 });
  }

  if (input.addOns?.trolleyRequired) surcharges.push({ code: "trolley", label: "Trolley required", priceAud: 5 });
  if (input.addOns?.difficultAccess) surcharges.push({ code: "difficult_access", label: "Difficult access", priceAud: 10 });

  const specialDate = stops.some((stop) => sorrinbotQuoteIsWeekend(stop.date) || Boolean(sorrinbotQuotePublicHolidayName(stop.date)));
  if (specialDate) {
    surcharges.push({ code: "weekend_public_holiday", label: "Weekend / public holiday job", priceAud: 15 });
  }

  const additionalStops = Math.max(0, dropoffs.length - 1);
  const accessBuffer = sorrinbotQuoteAccessBufferMinutes(input.addOns);
  const baseHandling = 20;
  const routeMultiplier = mainRoute.trafficAware ? 1.2 : 1.3;
  const handlingAndBuffers = baseHandling + (additionalStops * 25) + accessBuffer;
  const requiredMinutes = (mainRoute.durationMinutes * routeMultiplier) + handlingAndBuffers;
  const finalDeadlineEpoch = sorrinbotQuoteLatestEpoch(dropoffs.at(-1), false);
  const availableMinutes = Number.isFinite(pickupReadyEpoch) && Number.isFinite(finalDeadlineEpoch)
    ? (finalDeadlineEpoch - pickupReadyEpoch) / 60000
    : null;
  const pickupDeadlineEpoch = sorrinbotQuoteLatestEpoch(pickup, true);
  const pickupNoticeMinutes = Number.isFinite(pickupDeadlineEpoch)
    ? (pickupDeadlineEpoch - now.getTime()) / 60000
    : null;

  let requiredRank = 0;
  const feasibilityReasons = [];
  const raise = (rank, reason) => {
    if (rank > requiredRank) requiredRank = rank;
    if (reason && !feasibilityReasons.includes(reason)) feasibilityReasons.push(reason);
  };
  const impossible = Number.isFinite(availableMinutes) && requiredMinutes > availableMinutes;
  if (!impossible && Number.isFinite(availableMinutes)) {
    const slack = availableMinutes - requiredMinutes;
    if (slack < 30) raise(2, "less than 30min scheduling slack remains");
    else if (slack < 60) raise(1, "less than one hour scheduling slack remains");
  }
  if (!impossible && Number.isFinite(pickupNoticeMinutes)) {
    if (pickupNoticeMinutes < 60) raise(2, "collection is required within one hour");
    else if (pickupNoticeMinutes < 120) raise(1, "collection is required within two hours");
  }
  effectiveStrict.forEach((window, index) => {
    if (!window.strict) return;
    const startEpoch = sorrinbotQuoteEarliestEpoch(stops[index], index === 0, now);
    const minutesFromNow = Number.isFinite(startEpoch) ? (startEpoch - now.getTime()) / 60000 : null;
    if (!Number.isFinite(minutesFromNow)) return;
    if (minutesFromNow < 60) raise(2, "a strict window begins within one hour");
    else if (minutesFromNow < 120) raise(1, "a strict window begins within two hours");
  });

  const requiredService = Object.keys(SORRINBOT_QUOTE_SERVICE_RANK).find((key) => SORRINBOT_QUOTE_SERVICE_RANK[key] === requiredRank) || "flexible";
  const selectedRank = SORRINBOT_QUOTE_SERVICE_RANK[service];
  const requiresHigherService = !impossible && selectedRank < requiredRank;

  const earliestTimeValues = stops.map((stop) => sorrinbotQuoteMinutesOfDay(stop.earliestTime)).filter(Number.isFinite);
  const strictEndValues = stops
    .map((stop, index) => effectiveStrict[index].strict ? sorrinbotQuoteMinutesOfDay(stop.latestTime) : null)
    .filter(Number.isFinite);
  const sixPmEpoch = sorrinbotQuoteDateValid(pickup.date) ? sorrinbotQuoteZonedEpoch(pickup.date, "18:00") : null;
  const estimatedCompletionEpoch = Number.isFinite(pickupReadyEpoch) ? pickupReadyEpoch + (requiredMinutes * 60000) : null;
  const routeMayRunAfterSix = Number.isFinite(sixPmEpoch) && Number.isFinite(estimatedCompletionEpoch)
    && (pickupReadyEpoch >= sixPmEpoch || estimatedCompletionEpoch >= sixPmEpoch);
  if (earliestTimeValues.some((minutes) => minutes >= 1080) || strictEndValues.some((minutes) => minutes >= 1080) || routeMayRunAfterSix) {
    surcharges.push({ code: "after_1800", label: "After 6pm", priceAud: 10 });
  }

  const surchargeTotalAud = surcharges.reduce((sum, item) => sum + Number(item.priceAud || 0), 0);
  const basePriceAud = band ? Number(band[service] || 0) : 0;
  const totalAud = band && !manualQuote ? basePriceAud + surchargeTotalAud : null;
  const minimumServiceBase = band ? Number(band[requiredService] || 0) : 0;
  const minimumValidTotalAud = band && !manualQuote && !impossible
    ? minimumServiceBase + surchargeTotalAud
    : null;

  return {
    ok: true,
    code: "quote_calculated",
    engineVersion: SORRINBOT_QUOTE_ENGINE_VERSION,
    source: "trusted_sorrin_courier_backend",
    indicativeOnly: true,
    manualQuote,
    manualQuoteReason,
    routeKm,
    routeMinutes: Math.round(mainRoute.durationMinutes * 10) / 10,
    trafficAware: mainRoute.trafficAware,
    bracket: band?.label || null,
    service,
    serviceWasDefaulted: !requestedService,
    serviceLabel: SORRINBOT_QUOTE_SERVICE_LABELS[service],
    basePriceAud: band ? basePriceAud : null,
    surcharges,
    surchargeTotalAud,
    totalAud,
    minimumValidTotalAud: requiresHigherService ? minimumValidTotalAud : totalAud,
    endpoints: {
      pickupFromBallaratCbdKm: Number.isFinite(pickupFromCbdKm) ? Math.round(pickupFromCbdKm * 10) / 10 : null,
      returnToBallaratCbdKm: Number.isFinite(returnToCbdKm) ? Math.round(returnToCbdKm * 10) / 10 : null,
    },
    strictWindows: effectiveStrict,
    feasibility: {
      impossible,
      requiresHigherService,
      selectedService: service,
      requiredService,
      requiredServiceLabel: SORRINBOT_QUOTE_SERVICE_LABELS[requiredService],
      requiredMinutes: Math.ceil(requiredMinutes),
      availableMinutes: Number.isFinite(availableMinutes) ? Math.floor(availableMinutes) : null,
      pickupNoticeMinutes: Number.isFinite(pickupNoticeMinutes) ? Math.floor(pickupNoticeMinutes) : null,
      reasons: feasibilityReasons,
    },
    cargoSpaceRequested: cargo.space,
    cargoSpaceUsedForPricing: effectiveCargoSpace,
    cargoSpaceAutoAdjusted: Boolean(cargoAssessment.autoAdjustToSpace),
    cargoSuitability: cargoAssessment,
    resolvedAddresses: geocoded.map((point, index) => ({
      role: index === 0 ? "pickup" : "dropoff",
      index: index === 0 ? 0 : index,
      label: point.label,
    })),
    warnings: [
      ...(manualQuote ? ["This route requires Salem to confirm availability and price manually."] : []),
      ...(impossible ? ["The supplied timing appears physically impossible using the current traffic-aware route and handling buffers."] : []),
      ...(requiresHigherService ? [`The supplied timing requires at least ${SORRINBOT_QUOTE_SERVICE_LABELS[requiredService]}.`] : []),
      ...(effectiveCargoSpace === "suv" ? ["SUV/roof-rack jobs typically require around 12 hours notice and availability confirmation."] : []),
      ...(cargoAssessment.autoAdjustToSpace ? [`Cargo space was adjusted from ${cargo.space} to ${cargoAssessment.autoAdjustToSpace} using the published capacity rules.`] : []),
      ...cargoAssessment.warnings,
    ],
  };
}

const SORRINBOT_BOOKING_PREPARATION_ENGINE_VERSION = "A015-1.0.0";
const SORRINBOT_BOOKING_PREPARATION_SECONDS_DEFAULT = 30 * 60;

function sorrinbotBookingPreparationSeconds(env) {
  return boundedInteger(
    env.SORRINBOT_BOOKING_PREPARATION_SECONDS,
    SORRINBOT_BOOKING_PREPARATION_SECONDS_DEFAULT,
    5 * 60,
    60 * 60,
  );
}

async function purgeExpiredSorrinbotBookingPreparations(env, nowIso) {
  await env.DB.prepare(
    `UPDATE sorrinbot_booking_preparations
     SET status = 'expired', updated_at = datetime('now')
     WHERE status = 'prepared' AND expires_at <= ?`,
  ).bind(nowIso).run();
}

function sorrinbotBookingServiceLabel(service) {
  const value = cleanText(service, 20).toLowerCase();
  if (value === "asap" || value === "priority") return "PRIORITY";
  if (value === "express") return "EXPRESS";
  return "FLEXIBLE";
}

function sorrinbotBookingCargoLabel(space) {
  return ({
    front: "Front seat",
    back: "Back seat",
    bulky: "Big / heavy item",
    suv: "SUV / roof racks",
  })[String(space || "").toLowerCase()] || "Not supplied";
}

function sorrinbotBookingDimensions(cargo = {}) {
  const values = [cargo.lengthCm, cargo.widthCm, cargo.heightCm].map((value) => Number(value));
  return values.every(Number.isFinite)
    ? `${values[0]} x ${values[1]} x ${values[2]} cm`
    : "Not supplied";
}

function sorrinbotBookingQuoteInput(booking = {}) {
  const pickup = booking.pickup || {};
  const dropoffs = Array.isArray(booking.dropoffs) ? booking.dropoffs.slice(0, 8) : [];
  const cargo = booking.cargo || {};
  return {
    service: booking.service ?? null,
    pickup: {
      address: pickup.address ?? null,
      date: pickup.date ?? null,
      earliestTime: pickup.earliestTime ?? null,
      latestDate: pickup.latestDate ?? null,
      latestTime: pickup.latestTime ?? null,
      strictWindow: Boolean(pickup.strictWindow),
      callBeforeMinutes: pickup.callBeforeMinutes ?? null,
    },
    dropoffs: dropoffs.map((dropoff) => ({
      address: dropoff.address ?? null,
      date: dropoff.date ?? null,
      earliestDate: dropoff.earliestDate ?? null,
      earliestTime: dropoff.earliestTime ?? null,
      latestTime: dropoff.latestTime ?? null,
      strictWindow: Boolean(dropoff.strictWindow),
      callBeforeMinutes: dropoff.callBeforeMinutes ?? null,
    })),
    cargo: {
      space: cargo.space ?? null,
      itemCount: cargo.itemCount ?? null,
      additionalFragileItems: Math.max(0, Number(cargo.additionalFragileItems || 0)),
      overnightHoldNights: Math.max(0, Number(cargo.overnightHoldNights || 0)),
      lengthCm: cargo.lengthCm ?? null,
      widthCm: cargo.widthCm ?? null,
      heightCm: cargo.heightCm ?? null,
      weightKg: cargo.weightKg ?? null,
      perishable: Boolean(cargo.perishable),
    },
    addOns: {
      trolleyRequired: Boolean(booking.addOns?.trolleyRequired),
      difficultAccess: Boolean(booking.addOns?.difficultAccess),
    },
  };
}

function sorrinbotBookingStoredQuote(booking, quoteResult) {
  const pickup = booking.pickup || {};
  const dropoffs = Array.isArray(booking.dropoffs) ? booking.dropoffs.slice(0, 8) : [];
  const cargo = booking.cargo || {};
  const service = sorrinbotBookingServiceLabel(quoteResult.service);
  return {
    service,
    manualQuote: Boolean(quoteResult.manualQuote),
    routeKm: quoteResult.routeKm ?? null,
    total: quoteResult.totalAud ?? null,
    bracket: quoteResult.bracket ?? null,
    basePrice: quoteResult.basePriceAud ?? null,
    surcharges: (quoteResult.surcharges || []).map((item) => ({
      code: item.code || null,
      label: item.label || "Surcharge",
      price: Number(item.priceAud || 0),
    })),
    freeRequirements: [],
    packageLabel: sorrinbotBookingCargoLabel(quoteResult.cargoSpaceUsedForPricing || cargo.space),
    itemCount: cargo.itemCount ?? null,
    dimensions: sorrinbotBookingDimensions(cargo),
    cargoNotes: cleanText(cargo.notes, 2000) || null,
    perishable: cargo.perishable ? "Yes" : "No",
    pickup: {
      address: cleanText(pickup.address, 500),
      jobDate: cleanText(pickup.date, 30),
      earliestPickupTime: cleanText(pickup.earliestTime, 30) || null,
      latestCollectionDay: cleanText(pickup.latestDate, 30) || cleanText(pickup.date, 30),
      latestPickupTime: cleanText(pickup.latestTime, 30) || null,
      strictWindow: Boolean(pickup.strictWindow),
      callBeforeMinutes: pickup.callBeforeMinutes ?? null,
      contact: cleanText(pickup.contactName, 200) || null,
      contactPhone: cleanText(pickup.contactPhone, 60) || null,
      notes: cleanText(pickup.notes, 2000) || null,
    },
    dropoffs: dropoffs.map((dropoff, index) => ({
      address: cleanText(dropoff.address, 500),
      jobDate: cleanText(dropoff.date, 30),
      earliestDropoffDay: cleanText(dropoff.earliestDate, 30) || cleanText(dropoff.date, 30),
      earliestDropoffTime: cleanText(dropoff.earliestTime, 30) || null,
      latestDropoffTime: cleanText(dropoff.latestTime, 30) || null,
      strictWindow: Boolean(dropoff.strictWindow),
      callBeforeMinutes: dropoff.callBeforeMinutes ?? null,
      contact: cleanText(dropoff.contactName, 200) || null,
      contactPhone: cleanText(dropoff.contactPhone, 60) || null,
      notes: cleanText(dropoff.notes, 2000) || null,
      leaveSafePossible: Boolean(dropoff.leaveSafePossible),
      fragileItem: index === 0 ? Boolean(cargo.fragile) : false,
      additionalFragileCount: index === 0 ? Math.max(0, Number(cargo.additionalFragileItems || 0)) : 0,
      overnightHold: index === 0 ? Math.max(0, Number(cargo.overnightHoldNights || 0)) > 0 : false,
    })),
  };
}

function sorrinbotBookingConfirmationSummary(session, booking, quoteResult) {
  const pickup = booking.pickup || {};
  const dropoffs = Array.isArray(booking.dropoffs) ? booking.dropoffs : [];
  const cargo = booking.cargo || {};
  return {
    businessName: session.businessName || null,
    usc: session.usc || null,
    service: sorrinbotBookingServiceLabel(quoteResult.service),
    pickup: {
      address: quoteResult.resolvedAddresses?.[0]?.label || cleanText(pickup.address, 500),
      date: pickup.date || null,
      earliestTime: pickup.earliestTime ?? null,
      latestDate: pickup.latestDate || pickup.date || null,
      latestTime: pickup.latestTime ?? null,
      strictWindow: Boolean(pickup.strictWindow),
      contactName: cleanText(pickup.contactName, 200) || null,
    },
    dropoffs: dropoffs.map((dropoff, index) => ({
      address: quoteResult.resolvedAddresses?.[index + 1]?.label || cleanText(dropoff.address, 500),
      date: dropoff.date || null,
      earliestDate: dropoff.earliestDate || dropoff.date || null,
      earliestTime: dropoff.earliestTime ?? null,
      latestTime: dropoff.latestTime ?? null,
      strictWindow: Boolean(dropoff.strictWindow),
      contactName: cleanText(dropoff.contactName, 200) || null,
    })),
    cargo: {
      space: quoteResult.cargoSpaceUsedForPricing || cargo.space || null,
      itemCount: cargo.itemCount ?? null,
      dimensions: sorrinbotBookingDimensions(cargo),
      weightKg: cargo.weightKg ?? null,
      fragile: Boolean(cargo.fragile),
      perishable: Boolean(cargo.perishable),
    },
    routeKm: quoteResult.routeKm ?? null,
    manualQuote: Boolean(quoteResult.manualQuote),
    totalAud: quoteResult.totalAud ?? null,
    surcharges: quoteResult.surcharges || [],
    warnings: quoteResult.warnings || [],
  };
}


function sorrinbotRepeatServiceValue(value) {
  const service = String(value || "").toLowerCase();
  if (service === "priority" || service.includes("priority") || service.includes("asap")) return "asap";
  if (service === "express" || service.includes("express")) return "express";
  return "flexible";
}

function sorrinbotRepeatCargoSpace(value) {
  const label = String(value || "").toLowerCase();
  if (label.includes("front")) return "front";
  if (label.includes("back")) return "back";
  if (label.includes("suv") || label.includes("roof")) return "suv";
  if (label.includes("big") || label.includes("heavy") || label.includes("bulky")) return "bulky";
  return null;
}

function sorrinbotRepeatDimensions(value) {
  const text = String(value || "");
  const match = text.match(/(\d+(?:\.\d+)?)\s*[x×]\s*(\d+(?:\.\d+)?)\s*[x×]\s*(\d+(?:\.\d+)?)/i);
  if (!match) return { lengthCm: null, widthCm: null, heightCm: null };
  return { lengthCm: Number(match[1]), widthCm: Number(match[2]), heightCm: Number(match[3]) };
}

function sorrinbotRepeatTimeOnly(value) {
  const text = cleanText(value, 80);
  const match = text.match(/(?:^|\s)([0-2]\d:[0-5]\d)(?::[0-5]\d)?(?:$|\s|Z|[+-])/);
  return match ? match[1] : null;
}

function sorrinbotRepeatDateOnly(value) {
  const text = cleanText(value, 80);
  const match = text.match(/\b(\d{4}-\d{2}-\d{2})\b/);
  return match ? match[1] : null;
}


async function findSorrinbotRepeatJobs(env, { responseId, query, limit }, now = new Date()) {
  const session = await resolveSorrinbotUscSession(env, responseId, now);
  if (!session.authenticated) {
    return { ok: false, found: false, code: "usc_authentication_required", error: "A trusted authenticated USC session is required.", httpStatus: 401 };
  }

  const requestedLimit = Number(limit);
  const safeLimit = Number.isInteger(requestedLimit) ? Math.min(5, Math.max(1, requestedLimit)) : 3;
  const q = cleanText(query, 180).toLowerCase();
  const like = q ? `%${q}%` : null;
  const rowsResult = await env.DB.prepare(
    `SELECT
       b.id AS booking_id,
       b.booking_reference,
       b.request_data,
       b.created_at AS booking_created_at,
       b.updated_at AS booking_updated_at,
       j.id AS job_id,
       j.service_priority,
       j.completed_at
     FROM bookings b
     JOIN jobs j ON j.booking_id = b.id
     WHERE b.business_id = ?
       AND b.checkout_mode = 'account'
       AND b.booking_status = 'delivered'
       AND j.job_status = 'completed'
       AND (
         ? IS NULL
         OR lower(b.booking_reference) LIKE ?
         OR EXISTS (
           SELECT 1 FROM job_stops search_stop
           WHERE search_stop.job_id = j.id
             AND (
               lower(search_stop.address) LIKE ?
               OR lower(COALESCE(search_stop.contact_name, '')) LIKE ?
             )
         )
       )
     ORDER BY COALESCE(j.completed_at, b.updated_at, b.created_at) DESC
     LIMIT ?`,
  ).bind(session.businessId, q || null, like, like, like, safeLimit).all();

  const candidates = [];
  for (const row of rowsResult?.results || []) {
    const stopResult = await env.DB.prepare(
      `SELECT stop_type, stop_sequence, address, contact_name, contact_phone,
              earliest_time, latest_time, strict_window, stop_notes
       FROM job_stops
       WHERE job_id = ?
       ORDER BY stop_sequence ASC`,
    ).bind(row.job_id).all();
    const stops = stopResult?.results || [];
    const pickupRow = stops.find((item) => item.stop_type === "pickup") || stops[0] || null;
    const dropoffRows = stops.filter((item) => item.stop_type === "dropoff");
    const requestData = parseJson(row.request_data, {});
    const quote = requestData?.quote || {};
    const dimensions = sorrinbotRepeatDimensions(quote.dimensions);
    const firstHistoricalDropoff = Array.isArray(quote.dropoffs) ? quote.dropoffs[0] || {} : {};

    const candidate = {
      reference: cleanText(row.booking_reference, 160),
      completedAt: row.completed_at || row.booking_updated_at || row.booking_created_at || null,
      service: sorrinbotRepeatServiceValue(row.service_priority || quote.service),
      pickup: pickupRow ? {
        address: cleanText(pickupRow.address, 500),
        contactName: cleanText(pickupRow.contact_name, 200) || null,
        contactPhone: cleanText(pickupRow.contact_phone, 60) || null,
        previousDate: sorrinbotRepeatDateOnly(pickupRow.earliest_time || pickupRow.latest_time),
        previousEarliestTime: sorrinbotRepeatTimeOnly(pickupRow.earliest_time),
        previousLatestTime: sorrinbotRepeatTimeOnly(pickupRow.latest_time),
        strictWindow: Boolean(pickupRow.strict_window),
      } : null,
      dropoffs: dropoffRows.map((stop) => ({
        address: cleanText(stop.address, 500),
        contactName: cleanText(stop.contact_name, 200) || null,
        contactPhone: cleanText(stop.contact_phone, 60) || null,
        previousDate: sorrinbotRepeatDateOnly(stop.earliest_time || stop.latest_time),
        previousEarliestTime: sorrinbotRepeatTimeOnly(stop.earliest_time),
        previousLatestTime: sorrinbotRepeatTimeOnly(stop.latest_time),
        strictWindow: Boolean(stop.strict_window),
      })),
      cargo: {
        space: sorrinbotRepeatCargoSpace(quote.packageLabel),
        packageLabel: cleanText(quote.packageLabel, 120) || null,
        itemCount: Number.isFinite(Number(quote.itemCount)) ? Number(quote.itemCount) : null,
        ...dimensions,
        weightKg: null,
        fragile: Boolean(firstHistoricalDropoff.fragileItem),
        additionalFragileItems: Number.isFinite(Number(firstHistoricalDropoff.additionalFragileCount)) ? Number(firstHistoricalDropoff.additionalFragileCount) : 0,
        perishable: String(quote.perishable || "").toLowerCase() === "yes",
        notes: cleanText(quote.cargoNotes, 1200) || null,
      },
      historicalOnly: true,
      freshDateRequired: true,
      freshQuoteRequired: true,
    };
    candidates.push(candidate);
  }

  return {
    ok: true,
    found: candidates.length > 0,
    code: candidates.length > 0 ? "repeat_jobs_found" : "no_repeat_jobs_found",
    usc: session.usc,
    businessName: session.businessName,
    candidates,
    candidateCount: candidates.length,
    rules: {
      completedHistoryOnly: true,
      oldDatesAreHistoricalOnly: true,
      currentQuoteRequired: true,
      prepareConfirmStillRequired: true,
    },
    engineVersion: SORRINBOT_REPEAT_JOB_VERSION,
  };
}


function sorrinbotLiveJobPublicStatus(row) {
  const requestStatus = String(row?.request_status || "").toLowerCase();
  const bookingStatus = String(row?.booking_status || "").toLowerCase();
  const jobStatus = String(row?.job_status || "").toLowerCase();
  if (jobStatus === "active" || bookingStatus === "collected") return "active";
  if (
    requestStatus === "approved" ||
    ["approved", "confirmed"].includes(bookingStatus) ||
    jobStatus === "scheduled"
  ) return "approved";
  return "pending";
}

function sorrinbotLiveStopLabel(stop) {
  if (!stop) return null;
  if (String(stop.stop_type || "").toLowerCase() === "pickup") return "Pickup";
  const sequence = Number(stop.stop_sequence || 0);
  return sequence > 2 ? `Drop-off ${sequence - 1}` : "Drop-off";
}

function sorrinbotLiveMilestone(status, stops, currentStopSequence) {
  if (status === "pending") return "Awaiting Sorrin approval";
  const unresolved = (stops || []).filter((stop) => !["completed", "skipped", "cancelled"].includes(String(stop.stop_status || "").toLowerCase()));
  const bySequence = (stops || []).find((stop) => Number(stop.stop_sequence) === Number(currentStopSequence));
  const current = bySequence && !["completed", "skipped", "cancelled"].includes(String(bySequence.stop_status || "").toLowerCase())
    ? bySequence
    : unresolved[0] || null;
  if (status === "approved") {
    if (!current) return "Approved and awaiting pickup";
    return `Approved — next stop: ${sorrinbotLiveStopLabel(current)}`;
  }
  if (!current) return "Active — awaiting next operational update";
  const stopStatus = String(current.stop_status || "pending").toLowerCase();
  const label = sorrinbotLiveStopLabel(current);
  if (stopStatus === "en_route") return `En route to ${String(label || "current stop").toLowerCase()}`;
  if (stopStatus === "arrived") return `Arrived at ${String(label || "current stop").toLowerCase()}`;
  return `Active — next stop: ${label || "current stop"}`;
}

async function findSorrinbotLiveJobs(env, { responseId, query, limit }, now = new Date()) {
  const session = await resolveSorrinbotUscSession(env, responseId, now);
  if (!session.authenticated) {
    return { ok: false, found: false, code: "usc_authentication_required", error: "A trusted authenticated USC session is required.", httpStatus: 401 };
  }

  const requestedLimit = Number(limit);
  const safeLimit = Number.isInteger(requestedLimit) ? Math.min(5, Math.max(1, requestedLimit)) : 3;
  const q = cleanText(query, 180).toLowerCase();
  const like = q ? `%${q}%` : null;
  const rowsResult = await env.DB.prepare(
    `SELECT
       br.reference,
       br.status AS request_status,
       br.service_level,
       br.pickup_address,
       br.primary_dropoff_address,
       br.created_at AS request_created_at,
       br.updated_at AS request_updated_at,
       b.id AS booking_id,
       b.booking_status,
       b.updated_at AS booking_updated_at,
       j.id AS job_id,
       j.job_status,
       j.service_priority,
       j.scheduled_date,
       j.current_stop_sequence,
       j.started_at,
       j.updated_at AS job_updated_at
     FROM booking_requests br
     LEFT JOIN bookings b ON b.booking_reference = br.reference COLLATE NOCASE
     LEFT JOIN jobs j ON j.job_reference = br.reference COLLATE NOCASE
     WHERE br.business_id = ?
       AND br.booking_type = 'business'
       AND br.status NOT IN ('declined', 'cancelled', 'completed')
       AND COALESCE(b.booking_status, 'submitted') NOT IN ('delivered', 'rejected', 'cancelled')
       AND COALESCE(j.job_status, 'unscheduled') NOT IN ('completed', 'cancelled')
       AND (
         ? IS NULL
         OR lower(br.reference) LIKE ?
         OR lower(br.pickup_address) LIKE ?
         OR lower(br.primary_dropoff_address) LIKE ?
         OR EXISTS (
           SELECT 1 FROM job_stops search_stop
           WHERE search_stop.job_id = j.id
             AND lower(search_stop.address) LIKE ?
         )
       )
     ORDER BY
       CASE
         WHEN j.job_status = 'active' OR b.booking_status = 'collected' THEN 1
         WHEN br.status = 'approved' OR b.booking_status IN ('approved', 'confirmed') OR j.job_status = 'scheduled' THEN 2
         ELSE 3
       END,
       COALESCE(j.updated_at, b.updated_at, br.updated_at, br.created_at) DESC
     LIMIT ?`,
  ).bind(session.businessId, q || null, like, like, like, like, safeLimit).all();

  const jobs = [];
  for (const row of rowsResult?.results || []) {
    let stops = [];
    if (row.job_id) {
      const stopResult = await env.DB.prepare(
        `SELECT stop_type, stop_sequence, stop_status, address,
                earliest_time, latest_time, estimated_arrival, actual_arrival,
                completed_at, strict_window
         FROM job_stops
         WHERE job_id = ?
         ORDER BY COALESCE(route_sequence, stop_sequence), stop_sequence`,
      ).bind(row.job_id).all();
      stops = stopResult?.results || [];
    }

    const publicStatus = sorrinbotLiveJobPublicStatus(row);
    const completedStops = stops.filter((stop) => String(stop.stop_status || "").toLowerCase() === "completed").length;
    const remainingStops = stops.filter((stop) => !["completed", "skipped", "cancelled"].includes(String(stop.stop_status || "").toLowerCase())).length;
    const currentBySequence = stops.find((stop) => Number(stop.stop_sequence) === Number(row.current_stop_sequence || 1));
    const currentStop = currentBySequence && !["completed", "skipped", "cancelled"].includes(String(currentBySequence.stop_status || "").toLowerCase())
      ? currentBySequence
      : stops.find((stop) => !["completed", "skipped", "cancelled"].includes(String(stop.stop_status || "").toLowerCase())) || null;

    jobs.push({
      reference: cleanText(row.reference, 160),
      status: publicStatus,
      milestone: sorrinbotLiveMilestone(publicStatus, stops, row.current_stop_sequence),
      service: sorrinbotRepeatServiceValue(row.service_priority || row.service_level),
      scheduledDate: row.scheduled_date || null,
      startedAt: row.started_at || null,
      lastUpdatedAt: row.job_updated_at || row.booking_updated_at || row.request_updated_at || row.request_created_at || null,
      route: {
        pickupAddress: cleanText(row.pickup_address, 500),
        primaryDropoffAddress: cleanText(row.primary_dropoff_address, 500),
      },
      progress: {
        completedStops,
        totalStops: stops.length,
        remainingStops,
        currentStopSequence: currentStop ? Number(currentStop.stop_sequence) : null,
        currentStopLabel: currentStop ? sorrinbotLiveStopLabel(currentStop) : null,
        currentStopStatus: currentStop ? cleanText(currentStop.stop_status, 40).toLowerCase() : null,
      },
      stops: stops.map((stop) => ({
        type: cleanText(stop.stop_type, 20).toLowerCase(),
        sequence: Number(stop.stop_sequence),
        label: sorrinbotLiveStopLabel(stop),
        status: cleanText(stop.stop_status, 40).toLowerCase(),
        address: cleanText(stop.address, 500),
        earliestTime: stop.earliest_time || null,
        latestTime: stop.latest_time || null,
        estimatedArrival: stop.estimated_arrival || null,
        actualArrival: stop.actual_arrival || null,
        completedAt: stop.completed_at || null,
        strictWindow: Boolean(stop.strict_window),
      })),
      liveOnly: true,
      readOnly: true,
    });
  }

  return {
    ok: true,
    found: jobs.length > 0,
    code: jobs.length > 0 ? "live_jobs_found" : "no_live_jobs_found",
    usc: session.usc,
    businessName: session.businessName,
    jobs,
    jobCount: jobs.length,
    rules: {
      authenticatedUscOnly: true,
      nonTerminalJobsOnly: true,
      readOnly: true,
      proofOfDeliveryExcluded: true,
      financeExcluded: true,
      completedHistoryExcluded: true,
    },
    engineVersion: "1.0.0",
  };
}

const SORRINBOT_POD_RETRIEVAL_VERSION = "1.0.0";

async function retrieveSorrinbotProofOfDelivery(env, { responseId, query, limit }, now = new Date()) {
  const session = await resolveSorrinbotUscSession(env, responseId, now);
  if (!session.authenticated) {
    return {
      ok: false,
      found: false,
      code: "usc_authentication_required",
      error: "A trusted authenticated USC session is required.",
      httpStatus: 401,
    };
  }

  const requestedLimit = Number(limit);
  const safeLimit = Number.isInteger(requestedLimit)
    ? Math.min(5, Math.max(1, requestedLimit))
    : 1;
  const q = cleanText(query, 180).toLowerCase();
  const like = q ? `%${q}%` : null;

  const rowsResult = await env.DB.prepare(
    `SELECT
       b.booking_reference,
       b.updated_at AS booking_updated_at,
       j.id AS job_id,
       j.completed_at,
       j.updated_at AS job_updated_at
     FROM bookings b
     JOIN jobs j ON j.booking_id = b.id
     WHERE b.business_id = ?
       AND b.checkout_mode = 'account'
       AND b.booking_status = 'delivered'
       AND j.job_status = 'completed'
       AND (
         ? IS NULL
         OR lower(b.booking_reference) LIKE ?
         OR EXISTS (
           SELECT 1
           FROM job_stops search_stop
           WHERE search_stop.job_id = j.id
             AND (
               lower(search_stop.address) LIKE ?
               OR lower(COALESCE(search_stop.contact_name, '')) LIKE ?
             )
         )
         OR EXISTS (
           SELECT 1
           FROM job_events search_event
           WHERE search_event.job_id = j.id
             AND (
               search_event.event_type = 'proof_of_delivery'
               OR json_extract(search_event.event_data, '$.action') = 'proof_of_delivery'
             )
             AND lower(COALESCE(json_extract(search_event.event_data, '$.recipientName'), '')) LIKE ?
         )
       )
     ORDER BY COALESCE(j.completed_at, j.updated_at, b.updated_at) DESC
     LIMIT ?`,
  ).bind(session.businessId, q || null, like, like, like, like, safeLimit).all();

  const deliveries = [];
  let proofCount = 0;
  for (const row of rowsResult?.results || []) {
    const stopsResult = await env.DB.prepare(
      `SELECT stop_type, stop_sequence, address, contact_name
       FROM job_stops
       WHERE job_id = ?
       ORDER BY stop_sequence ASC`,
    ).bind(row.job_id).all();
    const stops = stopsResult?.results || [];
    const pickup = stops.find((stop) => String(stop.stop_type || '').toLowerCase() === 'pickup') || stops[0] || null;
    const dropoffs = stops.filter((stop) => String(stop.stop_type || '').toLowerCase() === 'dropoff');
    const finalDropoff = dropoffs[dropoffs.length - 1] || stops[stops.length - 1] || null;

    const proofRow = await env.DB.prepare(
      `SELECT event_data, created_at
       FROM job_events
       WHERE job_id = ?
         AND (
           event_type = 'proof_of_delivery'
           OR json_extract(event_data, '$.action') = 'proof_of_delivery'
         )
       ORDER BY created_at DESC
       LIMIT 1`,
    ).bind(row.job_id).first();

    let proof = null;
    if (proofRow) {
      const data = parseJson(proofRow.event_data, {});
      const recipientName = cleanText(data.recipientName, 200);
      const deliveredAt = cleanText(data.deliveredAt, 80);
      const notes = cleanText(data.notes, 2000) || null;
      if (recipientName || deliveredAt || notes) {
        proof = {
          recipientName: recipientName || null,
          deliveredAt: deliveredAt || null,
          notes,
          recordedAt: proofRow.created_at || null,
        };
        proofCount += 1;
      }
    }

    deliveries.push({
      reference: cleanText(row.booking_reference, 160),
      completedAt: row.completed_at || row.job_updated_at || row.booking_updated_at || null,
      route: {
        pickupAddress: pickup ? cleanText(pickup.address, 500) : null,
        finalDropoffAddress: finalDropoff ? cleanText(finalDropoff.address, 500) : null,
      },
      proofAvailable: Boolean(proof),
      proofStatus: proof ? 'recorded' : 'not_recorded',
      proof,
      completedJob: true,
      readOnly: true,
    });
  }

  return {
    ok: true,
    found: deliveries.length > 0,
    code: deliveries.length > 0 ? 'completed_deliveries_found' : 'no_completed_deliveries_found',
    usc: session.usc,
    businessName: session.businessName,
    deliveries,
    deliveryCount: deliveries.length,
    proofCount,
    rules: {
      authenticatedUscOnly: true,
      completedDeliveredJobsOnly: true,
      recordedEventRequiredForProof: true,
      deliveryStatusAloneIsNotProof: true,
      readOnly: true,
      financeExcluded: true,
      internalIdsExcluded: true,
    },
    engineVersion: SORRINBOT_POD_RETRIEVAL_VERSION,
  };
}


function sorrinbotFinancePublicRecord(row) {
  const amountDueCents = Math.max(0, Number(row.amount_due_cents || 0));
  const amountPaidCents = Math.max(0, Number(row.amount_paid_cents || 0));
  const outstandingCents = Math.max(0, amountDueCents - amountPaidCents);
  const effectiveStatus = financeEffectiveStatus({
    payment_status: row.finance_payment_status || row.booking_payment_status || "not_started",
    collection_type: row.collection_type || "prepayment",
    invoice_status: row.invoice_status || "not_required",
    amount_due_cents: amountDueCents,
    amount_paid_cents: amountPaidCents,
    due_date: row.due_date || null,
  });
  return {
    reference: cleanText(row.booking_reference, 180),
    bookingStatus: cleanText(row.booking_status, 80) || null,
    serviceLevel: cleanText(row.service_level, 80) || null,
    route: {
      pickupAddress: cleanText(row.pickup_address, 500) || null,
      primaryDropoffAddress: cleanText(row.primary_dropoff_address, 500) || null,
    },
    collectionType: cleanText(row.collection_type, 40) || "prepayment",
    paymentStatus: effectiveStatus,
    paymentMethod: cleanText(row.finance_payment_method, 80) || null,
    amountDueCents,
    amountDue: operationsMoney(amountDueCents),
    amountPaidCents,
    amountPaid: operationsMoney(amountPaidCents),
    outstandingCents,
    outstanding: operationsMoney(outstandingCents),
    invoice: {
      status: cleanText(row.invoice_status, 40) || "not_required",
      number: cleanText(row.invoice_number, 120) || null,
      issuedAt: row.invoice_issued_at || null,
      dueDate: row.due_date || null,
    },
    paidAt: row.paid_at || null,
    updatedAt: row.finance_updated_at || row.booking_updated_at || null,
    paymentLinkAvailable: Boolean(
      outstandingCents > 0 &&
      row.stripe_checkout_url &&
      Date.parse(row.stripe_checkout_expires_at || "") > Date.now() + 60_000
    ),
    readOnly: true,
  };
}

async function lookupSorrinbotFinance(env, { responseId, query, limit }, now = new Date()) {
  const session = await resolveSorrinbotUscSession(env, responseId, now);
  if (!session.authenticated) {
    return { ok: false, found: false, code: "usc_authentication_required", error: "A trusted authenticated USC session is required.", httpStatus: 401 };
  }
  const requestedLimit = Number(limit);
  const safeLimit = Number.isInteger(requestedLimit) ? Math.min(5, Math.max(1, requestedLimit)) : 3;
  const q = cleanText(query, 180).toLowerCase();
  const like = q ? `%${q}%` : null;
  const rows = await env.DB.prepare(
    `SELECT
       b.booking_reference,
       b.booking_status,
       b.payment_status AS booking_payment_status,
       b.updated_at AS booking_updated_at,
       br.service_level,
       br.pickup_address,
       br.primary_dropoff_address,
       f.collection_type,
       f.payment_status AS finance_payment_status,
       f.payment_method AS finance_payment_method,
       f.amount_due_cents,
       f.amount_paid_cents,
       f.invoice_status,
       f.invoice_number,
       f.invoice_issued_at,
       f.due_date,
       f.paid_at,
       f.stripe_checkout_url,
       f.stripe_checkout_expires_at,
       f.updated_at AS finance_updated_at
     FROM bookings b
     JOIN operations_finance f ON f.booking_id = b.id
     LEFT JOIN booking_requests br ON br.reference = b.booking_reference COLLATE NOCASE
     WHERE b.business_id = ?
       AND b.checkout_mode = 'account'
       AND (
         ? IS NULL
         OR lower(b.booking_reference) LIKE ?
         OR lower(COALESCE(f.invoice_number, '')) LIKE ?
         OR lower(COALESCE(br.pickup_address, '')) LIKE ?
         OR lower(COALESCE(br.primary_dropoff_address, '')) LIKE ?
       )
     ORDER BY COALESCE(f.updated_at, b.updated_at, b.created_at) DESC
     LIMIT ?`,
  ).bind(session.businessId, q || null, like, like, like, like, safeLimit).all();
  const records = (rows?.results || []).map(sorrinbotFinancePublicRecord);
  return {
    ok: true,
    found: records.length > 0,
    code: records.length ? "finance_records_found" : "no_finance_records_found",
    usc: session.usc,
    businessName: session.businessName,
    records,
    recordCount: records.length,
    rules: {
      authenticatedUscOnly: true,
      readOnly: true,
      backendStatusAuthoritative: true,
      userClaimIsNotPaymentProof: true,
      internalIdsExcluded: true,
      stripeIdentifiersExcluded: true,
    },
    engineVersion: SORRINBOT_FINANCE_ASSISTANT_VERSION,
  };
}

async function createSorrinbotPaymentLink(env, { responseId, reference }, now = new Date()) {
  const session = await resolveSorrinbotUscSession(env, responseId, now);
  if (!session.authenticated) {
    return { ok: false, created: false, code: "usc_authentication_required", error: "A trusted authenticated USC session is required.", httpStatus: 401 };
  }
  const publicReference = cleanText(reference, 180).toUpperCase();
  if (!publicReference) {
    return { ok: false, created: false, code: "reference_required", error: "A Sorrin job reference is required.", httpStatus: 400 };
  }
  const owned = await env.DB.prepare(
    `SELECT b.booking_reference
     FROM bookings b
     WHERE b.business_id = ?
       AND b.checkout_mode = 'account'
       AND b.booking_reference = ? COLLATE NOCASE
     LIMIT 1`,
  ).bind(session.businessId, publicReference).first();
  if (!owned) {
    return { ok: false, created: false, code: "finance_record_not_found", error: "No finance record matching that reference was found for this USC.", httpStatus: 404 };
  }
  const job = await operationsJobDetail(env, publicReference);
  if (!job?.finance) {
    return { ok: false, created: false, code: "finance_record_not_ready", error: "The finance record for that job is not available yet.", httpStatus: 409 };
  }
  if (["declined", "cancelled"].includes(String(job.status || "").toLowerCase())) {
    return { ok: false, created: false, code: "job_not_payable", error: "A cancelled or declined job cannot take payment.", httpStatus: 409 };
  }
  if (String(job.status || "").toLowerCase() === "pending") {
    return { ok: false, created: false, code: "payment_not_ready", error: "Payment is not available until the booking has been approved.", httpStatus: 409 };
  }
  const outstandingCents = Math.max(0, Number(job.finance.amountDueCents || 0) - Number(job.finance.amountPaidCents || 0));
  if (!outstandingCents) {
    return { ok: false, created: false, code: "no_outstanding_balance", error: "There is no outstanding balance for that job.", httpStatus: 409 };
  }
  if (["waived", "refunded"].includes(String(job.finance.effectiveStatus || "").toLowerCase())) {
    return { ok: false, created: false, code: "balance_not_payable", error: "That balance is not payable through SorrinBot.", httpStatus: 409 };
  }
  if (job.finance.collectionType === "invoice" && !["issued", "paid"].includes(String(job.finance.invoiceStatus || "").toLowerCase())) {
    return { ok: false, created: false, code: "invoice_not_issued", error: "That invoice has not been issued yet, so SorrinBot cannot create a payment link for it.", httpStatus: 409 };
  }
  try {
    const checkout = await createStripeCheckoutForJob(env, job, "sorrinbot");
    return {
      ok: true,
      created: true,
      code: checkout.reused ? "payment_link_reused" : "payment_link_created",
      reference: publicReference,
      outstandingCents,
      outstanding: operationsMoney(outstandingCents),
      paymentUrl: checkout.url,
      expiresAt: checkout.expiresAt,
      reused: Boolean(checkout.reused),
      emailSent: Boolean(checkout.emailSent),
      emailError: checkout.emailSent ? null : (cleanText(checkout.emailError, 500) || null),
      rules: {
        authenticatedUscOnly: true,
        amountImmutable: true,
        doesNotMarkPaid: true,
        doesNotIssueInvoice: true,
        doesNotWaiveOrRefund: true,
      },
      engineVersion: SORRINBOT_FINANCE_ASSISTANT_VERSION,
    };
  } catch (error) {
    return { ok: false, created: false, code: "payment_link_unavailable", error: cleanText(error?.message, 500) || "A secure payment link could not be created.", httpStatus: 409 };
  }
}


const SORRINBOT_JOB_CHANGE_REQUEST_VERSION = "1.0.0";

function sorrinbotJobChangeRequestSeconds(env) {
  const value = Number(env.SORRINBOT_JOB_CHANGE_REQUEST_TTL_SECONDS || 1800);
  return Number.isFinite(value) ? Math.min(7200, Math.max(300, Math.round(value))) : 1800;
}

async function expireSorrinbotJobChangeRequests(env, nowIso) {
  await env.DB.prepare(
    `UPDATE sorrinbot_job_change_requests
     SET status = 'expired', updated_at = datetime('now')
     WHERE status = 'prepared' AND expires_at <= ?`,
  ).bind(nowIso).run();
}

async function sorrinbotOwnedCurrentJob(env, businessId, reference) {
  const cleanReference = cleanText(reference, 180).toUpperCase();
  if (!cleanReference) return null;
  const row = await env.DB.prepare(
    `SELECT
       br.id AS request_id,
       br.reference,
       br.status AS request_status,
       br.pickup_address,
       br.primary_dropoff_address,
       br.updated_at AS request_updated_at,
       b.id AS booking_id,
       b.booking_status,
       b.payment_status,
       b.updated_at AS booking_updated_at,
       j.id AS job_id,
       j.job_status,
       j.service_priority,
       j.scheduled_date,
       j.started_at,
       j.current_stop_sequence,
       j.updated_at AS job_updated_at
     FROM booking_requests br
     JOIN bookings b ON b.booking_reference = br.reference COLLATE NOCASE
     LEFT JOIN jobs j ON j.booking_id = b.id
     WHERE b.business_id = ?
       AND b.checkout_mode = 'account'
       AND br.reference = ? COLLATE NOCASE
     LIMIT 1`,
  ).bind(businessId, cleanReference).first();
  return row || null;
}

function sorrinbotJobChangePublicStatus(row) {
  if (!row) return 'unknown';
  return sorrinbotLiveJobPublicStatus(row);
}

function sorrinbotJobChangeTerminal(row) {
  const publicStatus = sorrinbotJobChangePublicStatus(row);
  return ['delivered', 'completed', 'cancelled', 'declined', 'rejected'].includes(publicStatus)
    || ['delivered', 'rejected', 'cancelled'].includes(String(row?.booking_status || '').toLowerCase())
    || ['completed', 'cancelled'].includes(String(row?.job_status || '').toLowerCase())
    || ['declined', 'cancelled', 'completed'].includes(String(row?.request_status || '').toLowerCase());
}

function sorrinbotJobChangeUrgent(row) {
  const publicStatus = sorrinbotJobChangePublicStatus(row);
  return publicStatus === 'active'
    || String(row?.job_status || '').toLowerCase() === 'active'
    || String(row?.booking_status || '').toLowerCase() === 'collected';
}

function sorrinbotJobChangeFingerprint(row) {
  return JSON.stringify({
    requestStatus: String(row?.request_status || '').toLowerCase(),
    bookingStatus: String(row?.booking_status || '').toLowerCase(),
    jobStatus: String(row?.job_status || '').toLowerCase(),
    requestUpdatedAt: row?.request_updated_at || null,
    bookingUpdatedAt: row?.booking_updated_at || null,
    jobUpdatedAt: row?.job_updated_at || null,
  });
}

async function sorrinbotJobChangeStops(env, jobId) {
  if (!jobId) return [];
  const result = await env.DB.prepare(
    `SELECT stop_type, stop_sequence, stop_status, address, earliest_time, latest_time
     FROM job_stops
     WHERE job_id = ?
     ORDER BY stop_sequence ASC`,
  ).bind(jobId).all();
  return result?.results || [];
}

function sorrinbotJobChangePublicSummary(row, stops) {
  const publicStatus = sorrinbotJobChangePublicStatus(row);
  const pickup = stops.find((stop) => String(stop.stop_type || '').toLowerCase() === 'pickup') || stops[0] || null;
  const dropoffs = stops.filter((stop) => String(stop.stop_type || '').toLowerCase() === 'dropoff');
  const finalDropoff = dropoffs[dropoffs.length - 1] || stops[stops.length - 1] || null;
  return {
    reference: cleanText(row.reference, 180),
    status: publicStatus,
    milestone: sorrinbotLiveMilestone(publicStatus, stops, row.current_stop_sequence),
    service: sorrinbotRepeatServiceValue(row.service_priority),
    scheduledDate: row.scheduled_date || null,
    startedAt: row.started_at || null,
    route: {
      pickupAddress: cleanText(pickup?.address || row.pickup_address, 500) || null,
      finalDropoffAddress: cleanText(finalDropoff?.address || row.primary_dropoff_address, 500) || null,
    },
  };
}

async function prepareSorrinbotJobChangeRequest(env, { responseId, reference, requestType, requestDetails }, now = new Date()) {
  const session = await resolveSorrinbotUscSession(env, responseId, now);
  if (!session.authenticated) {
    return { ok: false, prepared: false, code: 'usc_authentication_required', error: 'A trusted authenticated USC session is required.', httpStatus: 401 };
  }

  const type = cleanText(requestType, 20).toLowerCase();
  const details = cleanText(requestDetails, 2000) || null;
  const publicReference = cleanText(reference, 180).toUpperCase();
  if (!publicReference || !['amend', 'cancel'].includes(type)) {
    return { ok: false, prepared: false, code: 'invalid_request', error: 'A current job reference and valid request type are required.', httpStatus: 400 };
  }
  if (type === 'amend' && !details) {
    return { ok: false, prepared: false, code: 'amendment_details_required', error: 'The requested amendment must be stated before it can be prepared.', httpStatus: 400 };
  }

  const row = await sorrinbotOwnedCurrentJob(env, session.businessId, publicReference);
  if (!row) {
    return { ok: false, prepared: false, code: 'current_job_not_found', error: 'No eligible current job matching that reference was found for this USC.', httpStatus: 404 };
  }
  if (sorrinbotJobChangeTerminal(row)) {
    return { ok: false, prepared: false, code: 'job_not_changeable', error: 'That job is no longer eligible for a current-job amendment or cancellation request.', httpStatus: 409 };
  }

  const stops = await sorrinbotJobChangeStops(env, row.job_id);
  const jobSummary = sorrinbotJobChangePublicSummary(row, stops);
  const nowIso = now.toISOString();
  await expireSorrinbotJobChangeRequests(env, nowIso);
  const requestId = `sbchg_${generateToken(18)}`;
  const expiresAt = isoAfter(now, sorrinbotJobChangeRequestSeconds(env));
  const snapshot = {
    fingerprint: sorrinbotJobChangeFingerprint(row),
    publicStatus: jobSummary.status,
    milestone: jobSummary.milestone,
    route: jobSummary.route,
    scheduledDate: jobSummary.scheduledDate,
  };

  await env.DB.prepare(
    `INSERT INTO sorrinbot_job_change_requests (
       id, session_chain_id, business_id, booking_reference,
       request_type, request_details, prepared_snapshot_json,
       status, expires_at
     ) VALUES (?, ?, ?, ?, ?, ?, ?, 'prepared', ?)`,
  ).bind(
    requestId,
    session.sessionChainId,
    session.businessId,
    jobSummary.reference,
    type,
    details,
    JSON.stringify(snapshot),
    expiresAt,
  ).run();

  return {
    ok: true,
    prepared: true,
    submitted: false,
    code: 'job_change_request_prepared',
    requestId,
    reference: jobSummary.reference,
    requestType: type,
    requestDetails: details,
    currentJob: jobSummary,
    requiresUrgentReview: sorrinbotJobChangeUrgent(row),
    expiresAt,
    rules: {
      liveJobUnchanged: true,
      explicitLaterConfirmationRequired: true,
      authenticatedUscOnly: true,
      humanReviewRequiredToAction: true,
    },
    engineVersion: SORRINBOT_JOB_CHANGE_REQUEST_VERSION,
  };
}

async function confirmSorrinbotJobChangeRequest(env, { responseId, requestId }, now = new Date()) {
  const session = await resolveSorrinbotUscSession(env, responseId, now);
  if (!session.authenticated) {
    return { ok: false, submitted: false, code: 'usc_authentication_required', error: 'A trusted authenticated USC session is required.', httpStatus: 401 };
  }

  const id = cleanText(requestId, 120);
  if (!id) {
    return { ok: false, submitted: false, code: 'missing_request_id', error: 'A prepared current-job request ID is required.', httpStatus: 400 };
  }

  const nowIso = now.toISOString();
  await expireSorrinbotJobChangeRequests(env, nowIso);
  const prepared = await env.DB.prepare(
    `SELECT *
     FROM sorrinbot_job_change_requests
     WHERE id = ?
       AND business_id = ?
       AND session_chain_id = ?
     LIMIT 1`,
  ).bind(id, session.businessId, session.sessionChainId).first();

  if (!prepared) {
    return { ok: false, submitted: false, code: 'prepared_request_not_found', error: 'That prepared current-job request is not available in this authenticated conversation.', httpStatus: 404 };
  }
  if (prepared.status === 'submitted') {
    return {
      ok: true,
      submitted: true,
      code: 'job_change_request_already_submitted',
      requestId: prepared.id,
      reference: prepared.booking_reference,
      requestType: prepared.request_type,
      requestDetails: prepared.request_details || null,
      status: 'awaiting_operations_review',
      liveJobUnchanged: true,
      engineVersion: SORRINBOT_JOB_CHANGE_REQUEST_VERSION,
    };
  }
  if (prepared.status !== 'prepared' || Date.parse(prepared.expires_at) <= now.getTime()) {
    return { ok: false, submitted: false, code: 'prepared_request_expired', error: 'That prepared current-job request has expired. Prepare it again against the current job state.', httpStatus: 409 };
  }

  const row = await sorrinbotOwnedCurrentJob(env, session.businessId, prepared.booking_reference);
  if (!row || sorrinbotJobChangeTerminal(row)) {
    return { ok: false, submitted: false, code: 'job_not_changeable', error: 'The job is no longer eligible for that amendment or cancellation request.', httpStatus: 409 };
  }

  const snapshot = parseJson(prepared.prepared_snapshot_json, {});
  if (!snapshot?.fingerprint || snapshot.fingerprint !== sorrinbotJobChangeFingerprint(row)) {
    return { ok: false, submitted: false, code: 'job_state_changed', error: 'The live job changed after this request was prepared. Prepare the request again against the current state.', httpStatus: 409 };
  }

  const publicStatus = sorrinbotJobChangePublicStatus(row);
  const eventData = JSON.stringify({
    source: 'sorrinbot',
    action: `customer_${prepared.request_type}_request_submitted`,
    requestId: prepared.id,
    requestType: prepared.request_type,
    requestDetails: prepared.request_details || null,
    note: prepared.request_details || (prepared.request_type === 'cancel' ? 'Customer requested cancellation.' : null),
    usc: session.usc,
  });

  await env.DB.batch([
    env.DB.prepare(
      `UPDATE sorrinbot_job_change_requests
       SET status = 'submitted', submitted_at = ?, updated_at = datetime('now')
       WHERE id = ? AND status = 'prepared'`,
    ).bind(nowIso, prepared.id),
    env.DB.prepare(
      `INSERT INTO booking_events (
         id, booking_id, event_type, previous_status, new_status, event_data
       ) VALUES (?, ?, 'customer_change_request', ?, ?, ?)`,
    ).bind(crypto.randomUUID(), row.booking_id, publicStatus, publicStatus, eventData),
  ]);

  return {
    ok: true,
    submitted: true,
    code: 'job_change_request_submitted',
    requestId: prepared.id,
    reference: prepared.booking_reference,
    requestType: prepared.request_type,
    requestDetails: prepared.request_details || null,
    status: 'awaiting_operations_review',
    requiresUrgentReview: sorrinbotJobChangeUrgent(row),
    liveJobUnchanged: true,
    message: 'The request has been recorded for Sorrin/Operations review. The courier job itself has not been changed or cancelled yet.',
    engineVersion: SORRINBOT_JOB_CHANGE_REQUEST_VERSION,
  };
}

async function sorrinbotBookingBusiness(env, businessId) {
  return env.DB.prepare(
    `SELECT id, business_name, usc, authorised_email, authorised_phone,
            contact_name, status, account_state, invoice_eligible
     FROM businesses
     WHERE id = ? AND status <> 'suspended' AND account_state <> 'suspended'
     LIMIT 1`,
  ).bind(businessId).first();
}

async function prepareSorrinbotCourierBooking(env, { responseId, booking }, now = new Date()) {
  const session = await resolveSorrinbotUscSession(env, responseId, now);
  if (!session.authenticated) {
    return { ok: false, prepared: false, code: "usc_authentication_required", error: "A trusted authenticated USC session is required.", httpStatus: 401 };
  }
  const business = await sorrinbotBookingBusiness(env, session.businessId);
  if (!business) {
    return { ok: false, prepared: false, code: "usc_account_not_active", error: "The authenticated USC is not currently active.", httpStatus: 401 };
  }

  const quoteInput = sorrinbotBookingQuoteInput(booking || {});
  const quoteResult = await calculateSorrinbotCourierQuote(quoteInput, env, now);
  if (!quoteResult.ok) {
    return { ...quoteResult, prepared: false, httpStatus: 400 };
  }
  if (quoteResult.feasibility?.impossible) {
    return { ok: false, prepared: false, code: "booking_timing_impossible", error: "The supplied timing is not physically feasible for this route.", quote: quoteResult, httpStatus: 409 };
  }
  if (quoteResult.feasibility?.requiresHigherService) {
    return {
      ok: false,
      prepared: false,
      code: "higher_service_required",
      error: `The supplied timing requires at least ${quoteResult.feasibility.requiredServiceLabel}.`,
      requiredService: quoteResult.feasibility.requiredService,
      quote: quoteResult,
      httpStatus: 409,
    };
  }

  const nowIso = now.toISOString();
  await purgeExpiredSorrinbotBookingPreparations(env, nowIso);
  const preparationId = `sbprep_${generateToken(18)}`;
  const expiresAt = isoAfter(now, sorrinbotBookingPreparationSeconds(env));
  const storedQuote = sorrinbotBookingStoredQuote(booking || {}, quoteResult);
  const requesterName = cleanText(business.contact_name, 200) || cleanText(business.business_name, 200);
  const payload = {
    requester: {
      bookingType: "business",
      businessNameOrUsc: business.usc,
      uscCode: business.usc,
      requesterName,
      requesterEmail: normalizeEmail(business.authorised_email),
      requesterPhone: normalizePhone(business.authorised_phone),
      paymentMethod: null,
      authenticationSource: "sorrinbot_usc_session",
    },
    quote: storedQuote,
  };
  const summary = sorrinbotBookingConfirmationSummary(session, booking || {}, quoteResult);

  await env.DB.prepare(
    `INSERT INTO sorrinbot_booking_preparations (
       id, session_chain_id, business_id, status,
       booking_payload_json, quote_result_json, confirmation_summary_json,
       expires_at
     ) VALUES (?, ?, ?, 'prepared', ?, ?, ?, ?)`,
  ).bind(
    preparationId,
    session.sessionChainId,
    session.businessId,
    JSON.stringify(payload),
    JSON.stringify(quoteResult),
    JSON.stringify(summary),
    expiresAt,
  ).run();

  return {
    ok: true,
    prepared: true,
    code: "booking_prepared",
    preparationVersion: SORRINBOT_BOOKING_PREPARATION_ENGINE_VERSION,
    preparationId,
    status: "prepared",
    expiresAt,
    requiresExplicitConfirmation: true,
    bindingState: "prepared",
    summary,
    note: "Nothing has been submitted yet. Explicit confirmation is required on a later turn.",
    httpStatus: 200,
  };
}

async function notifySorrinbotBookingSubmission(env, business, reference, payload) {
  const quote = payload.quote || {};
  const requester = payload.requester || {};
  const details = quoteText(quote);
  let warning = null;
  try {
    await sendEmail(env, {
      to: "courier@sorrin.com.au",
      subject: `USC SorrinBot booking request ${reference}`,
      text: `SorrinBot submitted an authenticated USC booking request.\n\nReference: ${reference}\nUSC: ${business.usc}\nBusiness: ${business.business_name}\n\n${details}`,
      html: `<div style="font-family:Arial,sans-serif;max-width:720px;margin:auto;padding:32px;color:#111;line-height:1.5;"><h1>NEW SORRINBOT USC BOOKING</h1><p><strong>${escapeHtml(reference)}</strong></p><p>${escapeHtml(business.usc)} · ${escapeHtml(business.business_name)}</p><pre style="white-space:pre-wrap;font:14px/1.5 Arial,sans-serif;background:#f5f5f5;padding:20px;border-radius:8px;">${escapeHtml(details)}</pre></div>`,
    });
    await sendEmail(env, {
      to: requester.requesterEmail,
      subject: `Sorrin booking request received - ${reference}`,
      text: `Hi ${requester.requesterName},\n\nYour USC booking request has been submitted to Sorrin for approval. It is not confirmed until Sorrin reviews and accepts it.\n\nReference: ${reference}\n\n${details}\n\nKind regards,\nSorrin`,
      html: `<div style="font-family:Arial,sans-serif;max-width:680px;margin:auto;padding:32px;color:#111;line-height:1.5;"><h1>SORRIN COURIER</h1><p>Hi ${escapeHtml(requester.requesterName)},</p><p>Your USC booking request has been submitted to Sorrin for approval. It is not confirmed until Sorrin reviews and accepts it.</p><p><strong>Reference: ${escapeHtml(reference)}</strong></p><pre style="white-space:pre-wrap;font:14px/1.5 Arial,sans-serif;background:#f5f5f5;padding:20px;border-radius:8px;">${escapeHtml(details)}</pre><p>Kind regards,<br>Sorrin</p></div>`,
    });
  } catch (error) {
    warning = error?.message || "Booking notifications could not be sent.";
  }
  return warning;
}

async function confirmSorrinbotCourierBooking(env, { responseId, preparationId }, now = new Date()) {
  const session = await resolveSorrinbotUscSession(env, responseId, now);
  if (!session.authenticated) {
    return { ok: false, submitted: false, code: "usc_authentication_required", error: "A trusted authenticated USC session is required.", httpStatus: 401 };
  }
  const id = cleanText(preparationId, 120);
  if (!id) {
    return { ok: false, submitted: false, code: "missing_preparation_id", error: "A prepared booking ID is required.", httpStatus: 400 };
  }
  const nowIso = now.toISOString();
  await purgeExpiredSorrinbotBookingPreparations(env, nowIso);
  let preparation = await env.DB.prepare(
    `SELECT * FROM sorrinbot_booking_preparations WHERE id = ? LIMIT 1`,
  ).bind(id).first();
  if (!preparation || preparation.business_id !== session.businessId || preparation.session_chain_id !== session.sessionChainId) {
    return { ok: false, submitted: false, code: "preparation_not_available", error: "That prepared booking is not available in this authenticated conversation.", httpStatus: 404 };
  }
  if (preparation.status === "submitted" && preparation.submitted_reference) {
    return {
      ok: true,
      submitted: true,
      code: "booking_request_already_submitted",
      idempotentReplay: true,
      reference: preparation.submitted_reference,
      bookingStatus: "pending",
      approved: false,
      bindingState: "completed",
      httpStatus: 200,
    };
  }
  if (preparation.status === "expired" || Date.parse(preparation.expires_at) <= now.getTime()) {
    return { ok: false, submitted: false, code: "preparation_expired", error: "That prepared booking has expired. Prepare the current details again before submitting.", httpStatus: 410 };
  }
  if (preparation.status !== "prepared" && preparation.status !== "submitting") {
    return { ok: false, submitted: false, code: "preparation_not_confirmable", error: "That prepared booking cannot be submitted in its current state.", httpStatus: 409 };
  }

  const claim = await env.DB.prepare(
    `UPDATE sorrinbot_booking_preparations
     SET status = 'submitting', updated_at = datetime('now')
     WHERE id = ? AND status = 'prepared' AND expires_at > ?`,
  ).bind(id, nowIso).run();
  if (Number(claim?.meta?.changes || 0) === 0 && preparation.status === "prepared") {
    preparation = await env.DB.prepare(`SELECT * FROM sorrinbot_booking_preparations WHERE id = ? LIMIT 1`).bind(id).first();
    if (preparation?.status === "submitted" && preparation.submitted_reference) {
      return { ok: true, submitted: true, code: "booking_request_already_submitted", idempotentReplay: true, reference: preparation.submitted_reference, bookingStatus: "pending", approved: false, bindingState: "completed", httpStatus: 200 };
    }
    if (preparation?.status !== "submitting") {
      return { ok: false, submitted: false, code: "preparation_claim_failed", error: "The prepared booking could not be safely claimed for submission.", httpStatus: 409 };
    }
  }

  const payload = parseJson(preparation.booking_payload_json, {});
  const quote = payload.quote || {};
  const requester = payload.requester || {};
  const business = await sorrinbotBookingBusiness(env, session.businessId);
  if (!business) {
    await env.DB.prepare(`UPDATE sorrinbot_booking_preparations SET status = 'prepared', updated_at = datetime('now') WHERE id = ? AND status = 'submitting'`).bind(id).run();
    return { ok: false, submitted: false, code: "usc_account_not_active", error: "The authenticated USC is not currently active.", httpStatus: 401 };
  }

  const bookingRequestId = `sorrinbot:${id}`;
  let requestRow = await env.DB.prepare(`SELECT * FROM booking_requests WHERE id = ? LIMIT 1`).bind(bookingRequestId).first();
  try {
    if (!requestRow) {
      const numbering = await nextJobNumbers(env, session.businessId);
      const pickupAddress = cleanText(quote.pickup?.address, 500);
      const primaryDropoffAddress = cleanText(Array.isArray(quote.dropoffs) ? quote.dropoffs[0]?.address : "", 500);
      const originalTotal = numberOrNull(quote.total);
      const originalTotalCents = originalTotal == null ? null : Math.max(0, Math.round(originalTotal * 100));
      const freeAdjustment = await firstTwoJobsFreeAdjustment(
        env,
        session.businessId,
        numbering.uscJobNumber,
        originalTotalCents,
      );
      applyFirstTwoJobsFreeToQuote(quote, freeAdjustment);
      const reference = bookingReference(quote, pickupAddress, primaryDropoffAddress, {
        usc: business.usc,
        globalJobNumber: numbering.globalJobNumber,
        uscJobNumber: numbering.uscJobNumber,
      });
      const routeKm = numberOrNull(quote.routeKm);
      const indicativeTotalCents = freeAdjustment.effectiveTotalCents;
      const payloadJson = JSON.stringify(payload);
      const requestHash = await hashValue(`sorrinbot-booking:${session.sessionChainId}`);
      if (!pickupAddress || !primaryDropoffAddress || !requester.requesterName || !validEmail(requester.requesterEmail) || !validPhone(requester.requesterPhone)) {
        throw new Error("Prepared booking payload is incomplete");
      }
      await env.DB.prepare(
        `INSERT INTO booking_requests (
          id, reference, global_job_number, usc_job_number, booking_type, business_id,
          business_name_or_usc, requester_name, requester_email, requester_phone,
          payment_method, email_verification_id, email_verified, usc_verified,
          service_level, manual_quote, route_km, indicative_total_cents,
          pickup_address, primary_dropoff_address, status, payload_json, request_ip_hash
        ) VALUES (?, ?, ?, ?, 'business', ?, ?, ?, ?, ?, ?, ?, 1, 1, ?, ?, ?, ?, ?, ?, 'pending', ?, ?)`,
      ).bind(
        bookingRequestId,
        reference,
        numbering.globalJobNumber,
        numbering.uscJobNumber,
        session.businessId,
        business.usc,
        requester.requesterName,
        requester.requesterEmail,
        requester.requesterPhone,
        requester.paymentMethod || null,
        `sorrinbot-usc-session:${id}`,
        quote.service,
        booleanInteger(quote.manualQuote),
        routeKm,
        indicativeTotalCents,
        pickupAddress,
        primaryDropoffAddress,
        payloadJson,
        requestHash,
      ).run();
      requestRow = await env.DB.prepare(`SELECT * FROM booking_requests WHERE id = ? LIMIT 1`).bind(bookingRequestId).first();
    }

    await syncRequestToOrganisedJob(env, {
      ...requestRow,
      usc_used: business.usc,
    });

    await env.DB.prepare(
      `UPDATE sorrinbot_booking_preparations
       SET status = 'submitted', submitted_reference = ?, submitted_booking_request_id = ?,
           confirmed_at = ?, updated_at = datetime('now')
       WHERE id = ?`,
    ).bind(requestRow.reference, bookingRequestId, nowIso, id).run();

    const notificationWarning = await notifySorrinbotBookingSubmission(env, business, requestRow.reference, payload);
    return {
      ok: true,
      submitted: true,
      code: "booking_request_submitted",
      reference: requestRow.reference,
      bookingStatus: "pending",
      approved: false,
      bindingState: "completed",
      notificationSent: !notificationWarning,
      notificationWarning,
      note: "The booking request is recorded and awaiting Sorrin review/approval.",
      httpStatus: notificationWarning ? 202 : 201,
    };
  } catch (error) {
    const existing = await env.DB.prepare(`SELECT reference FROM booking_requests WHERE id = ? LIMIT 1`).bind(bookingRequestId).first();
    if (!existing) {
      await env.DB.prepare(`UPDATE sorrinbot_booking_preparations SET status = 'prepared', updated_at = datetime('now') WHERE id = ? AND status = 'submitting'`).bind(id).run();
    }
    console.error({ event: "sorrinbot_booking_confirmation_error", preparationId: id, message: error?.message || "unknown" });
    return { ok: false, submitted: false, code: "booking_submission_failed", error: "The prepared booking could not be safely submitted.", httpStatus: 500 };
  }
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (request.method === "OPTIONS") {
      return new Response(null, {
        status: 204,
        headers: corsHeaders(request),
      });
    }

    if (request.method === "POST" && url.pathname === "/stripe/webhook") {
      try {
        return await processStripeWebhook(request, env);
      } catch (error) {
        return operationsJson(
          {
            received: false,
            error: "Stripe webhook processing failed",
            detail: error.message,
            build: OPS_BUILD,
          },
          500,
        );
      }
    }

    if (
      request.method === "GET" &&
      (url.pathname === "/operations" || url.pathname === "/operations/")
    ) {
      return textResponse(operationsDashboardHtml(env));
    }

    const operationsInvoiceMatch = url.pathname.match(
      /^\/operations\/invoices\/([^/]+)\/?$/,
    );
    if (request.method === "GET" && operationsInvoiceMatch) {
      const session = await operationsSession(request, env);
      if (!session) return textResponse("Sign in to Sorrin Operations first.", 401);
      const reference = decodeURIComponent(operationsInvoiceMatch[1]).toUpperCase();
      const job = await operationsJobDetail(env, reference);
      return job
        ? textResponse(operationsInvoiceHtml(job))
        : textResponse("Invoice or payment record not found.", 404);
    }

    const operationsStatementMatch = url.pathname.match(
      /^\/operations\/accounts\/([^/]+)\/statement\/?$/,
    );
    if (request.method === "GET" && operationsStatementMatch) {
      const session = await operationsSession(request, env);
      if (!session) return textResponse("Sign in to Sorrin Operations first.", 401);
      const businessId = decodeURIComponent(operationsStatementMatch[1]);
      const account = await operationsAccountDetail(env, businessId);
      return account
        ? textResponse(operationsAccountStatementHtml(account))
        : textResponse("USC account not found.", 404);
    }

    if (url.pathname.startsWith("/operations/api/")) {
      try {
        return await operationsApi(request, env, url);
      } catch (error) {
        return operationsJson(
          {
            error: "Operations request failed",
            detail: error.message,
            build: OPS_BUILD,
          },
          500,
        );
      }
    }


    if (request.method === "POST" && url.pathname === "/internal/sorrinbot/membership/mailing-list/subscribe") {
      if (!sorrinbotQuoteInternalAuthorized(request, env)) {
        return jsonResponse(request, {
          ok: false, subscribed: false, code: "internal_auth_failed", error: "Internal membership mailing-list access denied",
        }, 401);
      }
      let body;
      try { body = await request.json(); } catch {
        return jsonResponse(request, { ok: false, subscribed: false, code: "invalid_json", error: "Membership mailing-list request must be valid JSON" }, 400);
      }
      try {
        const result = await subscribeSorrinbotMembershipUpdates(env, body);
        const { httpStatus = 200, ...payload } = result;
        return jsonResponse(request, payload, httpStatus);
      } catch (error) {
        console.error({ event: "sorrinbot_membership_mailing_list_error", message: error?.message || "unknown" });
        return jsonResponse(request, { ok: false, subscribed: false, code: "membership_mailing_list_error", error: "Membership update consent could not be recorded." }, 500);
      }
    }


    if (request.method === "POST" && url.pathname === "/internal/sorrinbot/consultation/request") {
      if (!sorrinbotQuoteInternalAuthorized(request, env)) {
        return jsonResponse(request, {
          ok: false, submitted: false, code: "internal_auth_failed", error: "Internal consultation-request access denied",
        }, 401);
      }
      let body;
      try { body = await request.json(); } catch {
        return jsonResponse(request, { ok: false, submitted: false, code: "invalid_json", error: "Consultation request must be valid JSON" }, 400);
      }
      try {
        const result = await submitSorrinbotConsultationRequest(env, body);
        const { httpStatus = 200, ...payload } = result;
        return jsonResponse(request, payload, httpStatus);
      } catch (error) {
        console.error({ event: "sorrinbot_consultation_request_error", message: error?.message || "unknown" });
        return jsonResponse(request, { ok: false, submitted: false, code: "consultation_request_error", error: "Consultation request could not be recorded." }, 500);
      }
    }

    if (request.method === "POST" && url.pathname === "/internal/sorrinbot/usc/session/resolve") {
      if (!sorrinbotQuoteInternalAuthorized(request, env)) {
        return jsonResponse(request, {
          ok: false,
          authenticated: false,
          code: "internal_auth_failed",
          error: "Internal USC session access denied",
        }, 401);
      }
      let body;
      try {
        body = await request.json();
      } catch {
        return jsonResponse(request, {
          ok: false,
          authenticated: false,
          code: "invalid_json",
          error: "USC session request must be valid JSON",
        }, 400);
      }
      try {
        const result = await resolveSorrinbotUscSession(env, body.responseId);
        const { sessionChainId, businessId, ...payload } = result;
        return jsonResponse(request, payload, 200);
      } catch (error) {
        console.error({ event: "sorrinbot_usc_session_resolve_error", message: error?.message || "unknown" });
        return jsonResponse(request, {
          ok: false,
          authenticated: false,
          code: "usc_session_error",
          error: "USC session state could not be checked.",
        }, 500);
      }
    }

    if (request.method === "POST" && url.pathname === "/internal/sorrinbot/usc/session/advance") {
      if (!sorrinbotQuoteInternalAuthorized(request, env)) {
        return jsonResponse(request, {
          ok: false,
          authenticated: false,
          code: "internal_auth_failed",
          error: "Internal USC session access denied",
        }, 401);
      }
      let body;
      try {
        body = await request.json();
      } catch {
        return jsonResponse(request, {
          ok: false,
          authenticated: false,
          code: "invalid_json",
          error: "USC session request must be valid JSON",
        }, 400);
      }
      try {
        const result = /** @type {any} */ (await advanceSorrinbotUscSession(env, body));
        const { httpStatus = 200, sessionChainId, businessId, ...payload } = result;
        return jsonResponse(request, payload, httpStatus);
      } catch (error) {
        console.error({ event: "sorrinbot_usc_session_advance_error", message: error?.message || "unknown" });
        return jsonResponse(request, {
          ok: false,
          authenticated: false,
          code: "usc_session_error",
          error: "USC session state could not be updated.",
        }, 500);
      }
    }

    if (request.method === "POST" && url.pathname === "/internal/sorrinbot/usc/session/revoke") {
      if (!sorrinbotQuoteInternalAuthorized(request, env)) {
        return jsonResponse(request, {
          ok: false,
          authenticated: false,
          code: "internal_auth_failed",
          error: "Internal USC session access denied",
        }, 401);
      }
      let body;
      try {
        body = await request.json();
      } catch {
        return jsonResponse(request, {
          ok: false,
          authenticated: false,
          code: "invalid_json",
          error: "USC session request must be valid JSON",
        }, 400);
      }
      try {
        const result = await revokeSorrinbotUscSession(env, body.responseId);
        const { httpStatus = 200, sessionChainId, businessId, ...payload } = result;
        return jsonResponse(request, payload, httpStatus);
      } catch (error) {
        console.error({ event: "sorrinbot_usc_session_revoke_error", message: error?.message || "unknown" });
        return jsonResponse(request, {
          ok: false,
          authenticated: false,
          code: "usc_session_error",
          error: "USC session state could not be revoked.",
        }, 500);
      }
    }


    if (request.method === "POST" && url.pathname === "/internal/sorrinbot/session-resume/resolve") {
      if (!sorrinbotQuoteInternalAuthorized(request, env)) {
        return jsonResponse(request, { ok: false, resumed: false, code: "internal_auth_failed", error: "Internal session-resume access denied" }, 401);
      }
      let body;
      try { body = await request.json(); } catch {
        return jsonResponse(request, { ok: false, resumed: false, code: "invalid_json", error: "Session-resume request must be valid JSON" }, 400);
      }
      try {
        const result = await resolveSorrinbotSessionResume(env, body.resumeToken);
        const { httpStatus = 200, ...payload } = result;
        return jsonResponse(request, payload, httpStatus);
      } catch (error) {
        console.error({ event: "sorrinbot_session_resume_resolve_error", message: error?.message || "unknown" });
        return jsonResponse(request, { ok: false, resumed: false, code: "session_resume_error", error: "Conversation continuity could not be checked." }, 500);
      }
    }

    if (request.method === "POST" && url.pathname === "/internal/sorrinbot/session-resume/advance") {
      if (!sorrinbotQuoteInternalAuthorized(request, env)) {
        return jsonResponse(request, { ok: false, code: "internal_auth_failed", error: "Internal session-resume access denied" }, 401);
      }
      let body;
      try { body = await request.json(); } catch {
        return jsonResponse(request, { ok: false, code: "invalid_json", error: "Session-resume request must be valid JSON" }, 400);
      }
      try {
        const result = await advanceSorrinbotSessionResume(env, {
          previousResumeToken: body.previousResumeToken,
          newResponseId: body.newResponseId,
          nextTurnNumber: body.nextTurnNumber,
        });
        const { httpStatus = 200, ...payload } = result;
        return jsonResponse(request, payload, httpStatus);
      } catch (error) {
        console.error({ event: "sorrinbot_session_resume_advance_error", message: error?.message || "unknown" });
        return jsonResponse(request, { ok: false, code: "session_resume_error", error: "Conversation continuity could not be updated." }, 500);
      }
    }

    if (request.method === "POST" && url.pathname === "/internal/sorrinbot/session-resume/revoke") {
      if (!sorrinbotQuoteInternalAuthorized(request, env)) {
        return jsonResponse(request, { ok: false, code: "internal_auth_failed", error: "Internal session-resume access denied" }, 401);
      }
      let body;
      try { body = await request.json(); } catch {
        return jsonResponse(request, { ok: false, code: "invalid_json", error: "Session-resume request must be valid JSON" }, 400);
      }
      try {
        const result = await revokeSorrinbotSessionResume(env, body.resumeToken);
        const { httpStatus = 200, ...payload } = result;
        return jsonResponse(request, payload, httpStatus);
      } catch (error) {
        console.error({ event: "sorrinbot_session_resume_revoke_error", message: error?.message || "unknown" });
        return jsonResponse(request, { ok: false, code: "session_resume_error", error: "Conversation continuity could not be revoked." }, 500);
      }
    }

    if (request.method === "POST" && url.pathname === "/internal/sorrinbot/business-profile/resolve") {
      if (!sorrinbotQuoteInternalAuthorized(request, env)) {
        return jsonResponse(request, { ok: false, code: "internal_auth_failed", error: "Internal business profile access denied" }, 401);
      }
      let body;
      try { body = await request.json(); } catch {
        return jsonResponse(request, { ok: false, code: "invalid_json", error: "Business profile request must be valid JSON" }, 400);
      }
      try {
        const result = await resolveSorrinbotBusinessProfile(env, body.responseId);
        const { httpStatus = 200, ...payload } = result;
        return jsonResponse(request, payload, httpStatus);
      } catch (error) {
        console.error({ event: "sorrinbot_business_profile_resolve_error", message: error?.message || "unknown" });
        return jsonResponse(request, { ok: false, code: "business_profile_error", error: "Business profile context could not be checked." }, 500);
      }
    }

    if (request.method === "POST" && url.pathname === "/internal/sorrinbot/business-profile/store") {
      if (!sorrinbotQuoteInternalAuthorized(request, env)) {
        return jsonResponse(request, { ok: false, code: "internal_auth_failed", error: "Internal business profile access denied" }, 401);
      }
      let body;
      try { body = await request.json(); } catch {
        return jsonResponse(request, { ok: false, code: "invalid_json", error: "Business profile request must be valid JSON" }, 400);
      }
      try {
        const result = await storeSorrinbotBusinessProfile(env, body.responseId, body.profile);
        const { httpStatus = 200, ...payload } = result;
        return jsonResponse(request, payload, httpStatus);
      } catch (error) {
        console.error({ event: "sorrinbot_business_profile_store_error", message: error?.message || "unknown" });
        return jsonResponse(request, { ok: false, stored: false, code: "business_profile_error", error: "Business profile context could not be stored." }, 500);
      }
    }

    if (request.method === "POST" && url.pathname === "/internal/sorrinbot/usc/registration/start") {
      if (!sorrinbotQuoteInternalAuthorized(request, env)) {
        return jsonResponse(request, {
          ok: false, started: false, code: "internal_auth_failed", error: "Internal USC registration access denied",
        }, 401);
      }
      let body;
      try { body = await request.json(); } catch {
        return jsonResponse(request, { ok: false, started: false, code: "invalid_json", error: "USC registration request must be valid JSON" }, 400);
      }
      try {
        const result = await startSorrinbotUscRegistration(env, body);
        const { httpStatus = 200, ...payload } = result;
        return jsonResponse(request, payload, httpStatus);
      } catch (error) {
        console.error({ event: "sorrinbot_usc_registration_start_error", message: error?.message || "unknown" });
        return jsonResponse(request, { ok: false, started: false, code: "usc_registration_error", error: "USC registration could not be started." }, 500);
      }
    }

    if (request.method === "POST" && url.pathname === "/internal/sorrinbot/usc/registration/complete") {
      if (!sorrinbotQuoteInternalAuthorized(request, env)) {
        return jsonResponse(request, {
          ok: false, registered: false, code: "internal_auth_failed", error: "Internal USC registration access denied",
        }, 401);
      }
      let body;
      try { body = await request.json(); } catch {
        return jsonResponse(request, { ok: false, registered: false, code: "invalid_json", error: "USC registration completion must be valid JSON" }, 400);
      }
      try {
        const result = await completeSorrinbotUscRegistration(env, body);
        const { httpStatus = 200, ...payload } = result;
        return jsonResponse(request, payload, httpStatus);
      } catch (error) {
        console.error({ event: "sorrinbot_usc_registration_complete_error", message: error?.message || "unknown" });
        return jsonResponse(request, { ok: false, registered: false, code: "usc_registration_error", error: "USC registration could not be completed." }, 500);
      }
    }

    if (request.method === "POST" && url.pathname === "/internal/sorrinbot/usc/authenticate") {
      if (!sorrinbotQuoteInternalAuthorized(request, env)) {
        return jsonResponse(request, {
          ok: false,
          authenticated: false,
          code: "internal_auth_failed",
          error: "Internal USC authentication access denied",
        }, 401);
      }

      let body;
      try {
        body = await request.json();
      } catch {
        return jsonResponse(request, {
          ok: false,
          authenticated: false,
          code: "invalid_json",
          error: "USC authentication request must be valid JSON",
        }, 400);
      }

      try {
        const result = await authenticateUscCredentials(env, body);
        const { httpStatus, ...payload } = result;
        return jsonResponse(request, payload, httpStatus);
      } catch (error) {
        console.error({
          event: "sorrinbot_usc_authentication_error",
          message: error?.message || "unknown",
        });
        return jsonResponse(request, {
          ok: false,
          authenticated: false,
          code: "usc_authentication_error",
          error: "USC authentication could not be completed.",
        }, 500);
      }
    }

    if (request.method === "POST" && url.pathname === "/internal/sorrinbot/repeat-jobs/search") {
      if (!sorrinbotQuoteInternalAuthorized(request, env)) {
        return jsonResponse(request, { ok: false, found: false, code: "unauthorized", error: "Unauthorized." }, 401);
      }
      try {
        const body = await requestBody(request);
        const result = await findSorrinbotRepeatJobs(env, {
          responseId: body?.responseId,
          query: body?.query,
          limit: body?.limit,
        });
        return jsonResponse(request, result, result.httpStatus || (result.ok ? 200 : 400));
      } catch (error) {
        console.error({ event: "sorrinbot_repeat_job_lookup_error", message: error?.message || "unknown" });
        return jsonResponse(request, { ok: false, found: false, code: "repeat_job_lookup_error", error: "Repeat-job history could not be retrieved." }, 500);
      }
    }

    if (request.method === "POST" && url.pathname === "/internal/sorrinbot/live-jobs/lookup") {
      if (!sorrinbotQuoteInternalAuthorized(request, env)) {
        return jsonResponse(request, { ok: false, found: false, code: "unauthorized", error: "Unauthorized." }, 401);
      }
      try {
        const body = await requestBody(request);
        const result = await findSorrinbotLiveJobs(env, {
          responseId: body?.responseId,
          query: body?.query,
          limit: body?.limit,
        });
        return jsonResponse(request, result, result.httpStatus || (result.ok ? 200 : 400));
      } catch (error) {
        console.error({ event: "sorrinbot_live_job_lookup_error", message: error?.message || "unknown" });
        return jsonResponse(request, { ok: false, found: false, code: "live_job_lookup_error", error: "Current-job information could not be retrieved." }, 500);
      }
    }

    if (request.method === "POST" && url.pathname === "/internal/sorrinbot/pod/retrieve") {
      if (!sorrinbotQuoteInternalAuthorized(request, env)) {
        return jsonResponse(request, { ok: false, found: false, code: "unauthorized", error: "Unauthorized." }, 401);
      }
      try {
        const body = await requestBody(request);
        const result = await retrieveSorrinbotProofOfDelivery(env, {
          responseId: body?.responseId,
          query: body?.query,
          limit: body?.limit,
        });
        return jsonResponse(request, result, result.httpStatus || (result.ok ? 200 : 400));
      } catch (error) {
        console.error({ event: "sorrinbot_pod_retrieval_error", message: error?.message || "unknown" });
        return jsonResponse(request, {
          ok: false,
          found: false,
          code: "pod_retrieval_error",
          error: "Proof of delivery could not be retrieved.",
        }, 500);
      }
    }

    if (request.method === "POST" && url.pathname === "/internal/sorrinbot/finance/lookup") {
      if (!sorrinbotQuoteInternalAuthorized(request, env)) {
        return jsonResponse(request, { ok: false, found: false, code: "unauthorized", error: "Unauthorized." }, 401);
      }
      try {
        const body = await requestBody(request);
        const result = await lookupSorrinbotFinance(env, {
          responseId: body?.responseId,
          query: body?.query,
          limit: body?.limit,
        });
        return jsonResponse(request, result, result.httpStatus || (result.ok ? 200 : 400));
      } catch (error) {
        console.error({ event: "sorrinbot_finance_lookup_error", message: error?.message || "unknown" });
        return jsonResponse(request, { ok: false, found: false, code: "finance_lookup_error", error: "Invoice/payment information could not be retrieved." }, 500);
      }
    }

    if (request.method === "POST" && url.pathname === "/internal/sorrinbot/finance/payment-link") {
      if (!sorrinbotQuoteInternalAuthorized(request, env)) {
        return jsonResponse(request, { ok: false, created: false, code: "unauthorized", error: "Unauthorized." }, 401);
      }
      try {
        const body = await requestBody(request);
        const result = await createSorrinbotPaymentLink(env, {
          responseId: body?.responseId,
          reference: body?.reference,
        });
        return jsonResponse(request, result, result.httpStatus || (result.ok ? 200 : 400));
      } catch (error) {
        console.error({ event: "sorrinbot_payment_link_error", message: error?.message || "unknown" });
        return jsonResponse(request, { ok: false, created: false, code: "payment_link_error", error: "A secure payment link could not be created." }, 500);
      }
    }

    if (request.method === "POST" && url.pathname === "/internal/sorrinbot/job-change/prepare") {
      if (!sorrinbotQuoteInternalAuthorized(request, env)) {
        return jsonResponse(request, { ok: false, prepared: false, code: "unauthorized", error: "Unauthorized." }, 401);
      }
      try {
        const body = await requestBody(request);
        const result = await prepareSorrinbotJobChangeRequest(env, {
          responseId: body?.responseId,
          reference: body?.reference,
          requestType: body?.requestType,
          requestDetails: body?.requestDetails,
        });
        return jsonResponse(request, result, result.httpStatus || (result.ok ? 200 : 400));
      } catch (error) {
        console.error({ event: "sorrinbot_job_change_prepare_error", message: error?.message || "unknown" });
        return jsonResponse(request, { ok: false, prepared: false, code: "job_change_prepare_error", error: "The current-job request could not be prepared." }, 500);
      }
    }

    if (request.method === "POST" && url.pathname === "/internal/sorrinbot/job-change/confirm") {
      if (!sorrinbotQuoteInternalAuthorized(request, env)) {
        return jsonResponse(request, { ok: false, submitted: false, code: "unauthorized", error: "Unauthorized." }, 401);
      }
      try {
        const body = await requestBody(request);
        const result = await confirmSorrinbotJobChangeRequest(env, {
          responseId: body?.responseId,
          requestId: body?.requestId,
        });
        return jsonResponse(request, result, result.httpStatus || (result.ok ? 200 : 400));
      } catch (error) {
        console.error({ event: "sorrinbot_job_change_confirm_error", message: error?.message || "unknown" });
        return jsonResponse(request, { ok: false, submitted: false, code: "job_change_confirm_error", error: "The current-job request could not be submitted." }, 500);
      }
    }

    if (request.method === "POST" && url.pathname === "/internal/sorrinbot/booking/prepare") {
      if (!sorrinbotQuoteInternalAuthorized(request, env)) {
        return jsonResponse(request, {
          ok: false,
          prepared: false,
          code: "internal_auth_failed",
          error: "Internal booking preparation access denied",
        }, 401);
      }
      let body;
      try {
        body = await request.json();
      } catch {
        return jsonResponse(request, {
          ok: false,
          prepared: false,
          code: "invalid_json",
          error: "Booking preparation request must be valid JSON",
        }, 400);
      }
      try {
        const result = await prepareSorrinbotCourierBooking(env, body);
        const { httpStatus = 200, ...payload } = result;
        return jsonResponse(request, payload, httpStatus);
      } catch (error) {
        console.error({ event: "sorrinbot_booking_prepare_error", message: error?.message || "unknown" });
        return jsonResponse(request, {
          ok: false,
          prepared: false,
          code: "booking_prepare_error",
          error: "The courier booking could not be prepared.",
        }, 500);
      }
    }

    if (request.method === "POST" && url.pathname === "/internal/sorrinbot/booking/confirm") {
      if (!sorrinbotQuoteInternalAuthorized(request, env)) {
        return jsonResponse(request, {
          ok: false,
          submitted: false,
          code: "internal_auth_failed",
          error: "Internal booking confirmation access denied",
        }, 401);
      }
      let body;
      try {
        body = await request.json();
      } catch {
        return jsonResponse(request, {
          ok: false,
          submitted: false,
          code: "invalid_json",
          error: "Booking confirmation request must be valid JSON",
        }, 400);
      }
      try {
        const result = await confirmSorrinbotCourierBooking(env, body);
        const { httpStatus = 200, ...payload } = result;
        return jsonResponse(request, payload, httpStatus);
      } catch (error) {
        console.error({ event: "sorrinbot_booking_confirm_error", message: error?.message || "unknown" });
        return jsonResponse(request, {
          ok: false,
          submitted: false,
          code: "booking_confirm_error",
          error: "The prepared courier booking could not be submitted.",
        }, 500);
      }
    }

    if (request.method === "POST" && url.pathname === "/internal/sorrinbot/cargo/assess") {
      if (!sorrinbotQuoteInternalAuthorized(request, env)) {
        return jsonResponse(request, {
          ok: false,
          code: "internal_auth_failed",
          error: "Internal cargo assessment access denied",
        }, 401);
      }

      let body;
      try {
        body = await request.json();
      } catch {
        return jsonResponse(request, {
          ok: false,
          code: "invalid_json",
          error: "Cargo assessment request must be valid JSON",
        }, 400);
      }

      try {
        const result = assessSorrinbotCargoSuitability(body);
        return jsonResponse(request, result, 200);
      } catch (error) {
        console.error({
          event: "sorrinbot_cargo_engine_error",
          message: error?.message || "unknown",
          engineVersion: SORRINBOT_CARGO_ENGINE_VERSION,
        });
        return jsonResponse(request, {
          ok: false,
          code: "cargo_engine_error",
          error: "The courier cargo suitability check could not be completed.",
          assessmentVersion: SORRINBOT_CARGO_ENGINE_VERSION,
        }, 500);
      }
    }

    if (request.method === "POST" && url.pathname === "/internal/sorrinbot/quote/calculate") {
      if (!sorrinbotQuoteInternalAuthorized(request, env)) {
        return jsonResponse(request, {
          ok: false,
          code: "internal_auth_failed",
          error: "Internal quote access denied",
        }, 401);
      }

      let body;
      try {
        body = await request.json();
      } catch {
        return jsonResponse(request, {
          ok: false,
          code: "invalid_json",
          error: "Quote request must be valid JSON",
        }, 400);
      }

      try {
        const result = await calculateSorrinbotCourierQuote(body, env);
        return jsonResponse(request, result, result.ok ? 200 : 400);
      } catch (error) {
        console.error({
          event: "sorrinbot_quote_engine_error",
          message: error?.message || "unknown",
          engineVersion: SORRINBOT_QUOTE_ENGINE_VERSION,
        });
        return jsonResponse(request, {
          ok: false,
          code: "quote_engine_error",
          error: "The live courier quote could not be calculated.",
          engineVersion: SORRINBOT_QUOTE_ENGINE_VERSION,
        }, 500);
      }
    }

    if (
      request.method === "GET" &&
      (url.pathname === "/" || url.pathname === "/health")
    ) {
      try {
        const databaseCheck = await env.DB.prepare(
          "SELECT 1 AS connected",
        ).first();

        return jsonResponse(request, {
          service: "sorrin-courier-api",
          status: "online",
          database:
            databaseCheck?.connected === 1 ? "connected" : "unavailable",
          sorrinbotQuoteEngineVersion: SORRINBOT_QUOTE_ENGINE_VERSION,
          sorrinbotCargoEngineVersion: SORRINBOT_CARGO_ENGINE_VERSION,
          sorrinbotBookingPreparationEngineVersion: SORRINBOT_BOOKING_PREPARATION_ENGINE_VERSION,
          sorrinbotUscRegistrationVersion: SORRINBOT_USC_REGISTRATION_VERSION,
          sorrinbotRepeatJobVersion: SORRINBOT_REPEAT_JOB_VERSION,
          sorrinbotMembershipMailingListVersion: SORRINBOT_MEMBERSHIP_MAILING_LIST_VERSION,
          sorrinbotConsultationRequestVersion: SORRINBOT_CONSULTATION_REQUEST_VERSION,
          sorrinbotBookingPreparationSeconds: sorrinbotBookingPreparationSeconds(env),
          sorrinbotQuoteInternalKeyConfigured: Boolean(env.SORRINBOT_INTERNAL_KEY),
          mapboxConfigured: Boolean(env.MAPBOX_ACCESS_TOKEN),
        });
      } catch {
        return jsonResponse(
          request,
          {
            service: "sorrin-courier-api",
            status: "error",
            database: "unavailable",
          },
          500,
        );
      }
    }

    if (request.method === "POST" && url.pathname === "/verification/request") {
      let body;

      try {
        body = await request.json();
      } catch {
        return jsonResponse(
          request,
          {
            sent: false,
            error: "Invalid request",
          },
          400,
        );
      }

      const email = normalizeEmail(body.email);

      if (!validEmail(email)) {
        return jsonResponse(
          request,
          {
            sent: false,
            error: "Enter a valid email address",
          },
          400,
        );
      }

      const clientIp = request.headers.get("CF-Connecting-IP") || "unknown";
      const ipHash = await hashValue(`sorrin-ip:${clientIp}`);

      const limits = await env.DB.prepare(
        `
        SELECT
          (
            SELECT COUNT(*)
            FROM email_verifications
            WHERE email = ? COLLATE NOCASE
              AND created_at >= datetime('now', '-15 minutes')
          ) AS email_count,
          (
            SELECT COUNT(*)
            FROM email_verifications
            WHERE request_ip_hash = ?
              AND created_at >= datetime('now', '-15 minutes')
          ) AS ip_count
      `,
      )
        .bind(email, ipHash)
        .first();

      if (
        Number(limits?.email_count || 0) >= 3 ||
        Number(limits?.ip_count || 0) >= 10
      ) {
        return jsonResponse(
          request,
          {
            sent: false,
            error: "Too many verification requests. Try again later.",
          },
          429,
        );
      }

      const verificationId = crypto.randomUUID();
      const code = generateCode();
      const codeHash = await hashValue(`${verificationId}:${code}`);

      await env.DB.prepare(
        `
        INSERT INTO email_verifications (
          id,
          email,
          code_hash,
          request_ip_hash,
          expires_at
        ) VALUES (
          ?,
          ?,
          ?,
          ?,
          datetime('now', '+10 minutes')
        )
      `,
      )
        .bind(verificationId, email, codeHash, ipHash)
        .run();

      try {
        await sendEmail(env, {
          to: email,
          subject: "Your Sorrin verification code",
          text:
            `Your Sorrin verification code is ${code}. ` +
            "It expires in 10 minutes. If you did not request this code, ignore this email.",
          html: `
            <div style="font-family:Arial,sans-serif;max-width:560px;margin:auto;padding:32px;color:#111;">
              <h1 style="margin:0 0 22px;">SORRIN COURIER</h1>
              <p>Enter this code to verify your email address:</p>
              <div style="font-size:34px;font-weight:700;letter-spacing:8px;margin:26px 0;">
                ${code}
              </div>
              <p>This code expires in 10 minutes.</p>
              <p style="color:#666;font-size:13px;margin-top:28px;">
                If you did not request this code, you can safely ignore this email.
              </p>
            </div>
          `,
        });
      } catch (error) {
        await env.DB.prepare(
          `
          DELETE FROM email_verifications
          WHERE id = ?
        `,
        )
          .bind(verificationId)
          .run();

        return jsonResponse(
          request,
          {
            sent: false,
            error: error.message,
          },
          502,
        );
      }

      return jsonResponse(request, {
        sent: true,
        verificationId,
        expiresInSeconds: 600,
      });
    }

    if (request.method === "POST" && url.pathname === "/verification/confirm") {
      let body;

      try {
        body = await request.json();
      } catch {
        return jsonResponse(
          request,
          {
            valid: false,
            error: "Invalid request",
          },
          400,
        );
      }

      const verificationId = String(body.verificationId || "").trim();
      const email = normalizeEmail(body.email);
      const code = String(body.code || "").trim();

      if (!verificationId || !validEmail(email) || !/^\d{6}$/.test(code)) {
        return jsonResponse(
          request,
          {
            valid: false,
            error: "Verification details are invalid",
          },
          400,
        );
      }

      const verification = await env.DB.prepare(
        `
        SELECT
          id,
          code_hash,
          attempts,
          status,
          CASE
            WHEN expires_at <= datetime('now') THEN 1
            ELSE 0
          END AS expired
        FROM email_verifications
        WHERE id = ?
          AND email = ? COLLATE NOCASE
        LIMIT 1
      `,
      )
        .bind(verificationId, email)
        .first();

      if (!verification || verification.status !== "pending") {
        return jsonResponse(
          request,
          {
            valid: false,
            error: "Verification code is invalid or unavailable",
          },
          400,
        );
      }

      if (Number(verification.expired) === 1) {
        await env.DB.prepare(
          `
          UPDATE email_verifications
          SET status = 'expired'
          WHERE id = ?
        `,
        )
          .bind(verificationId)
          .run();

        return jsonResponse(
          request,
          {
            valid: false,
            error: "Verification code has expired",
          },
          400,
        );
      }

      const suppliedHash = await hashValue(`${verificationId}:${code}`);

      if (suppliedHash !== verification.code_hash) {
        const attempts = Number(verification.attempts || 0) + 1;
        const status = attempts >= 5 ? "locked" : "pending";

        await env.DB.prepare(
          `
          UPDATE email_verifications
          SET attempts = ?, status = ?
          WHERE id = ?
        `,
        )
          .bind(attempts, status, verificationId)
          .run();

        return jsonResponse(
          request,
          {
            valid: false,
            error:
              attempts >= 5
                ? "Too many incorrect attempts. Request a new code."
                : "Verification code is incorrect",
          },
          400,
        );
      }

      const verificationToken = generateToken();
      const tokenHash = await hashValue(verificationToken);

      await env.DB.prepare(
        `
        UPDATE email_verifications
        SET
          status = 'verified',
          verified_at = datetime('now'),
          token_hash = ?,
          token_expires_at = datetime('now', '+30 minutes')
        WHERE id = ?
          AND status = 'pending'
      `,
      )
        .bind(tokenHash, verificationId)
        .run();

      return jsonResponse(request, {
        valid: true,
        verificationToken,
        expiresInSeconds: 1800,
      });
    }

    if (request.method === "POST" && url.pathname === "/usc/claim") {
      let body;

      try {
        body = await request.json();
      } catch {
        return jsonResponse(
          request,
          { claimed: false, error: "Invalid request" },
          400,
        );
      }

      const usc = normaliseUsc(body.usc);
      const email = normalizeEmail(body.email);
      const phone = normalizePhone(body.phone);
      const contactName = cleanText(body.contactName, 200) || null;
      const verificationId = cleanText(body.verificationId, 100);
      const verificationToken = cleanText(body.verificationToken, 200);

      if (!usc || !validEmail(email) || !validPhone(phone)) {
        return jsonResponse(
          request,
          {
            claimed: false,
            error: "USC, a valid official email and a valid official mobile are required",
          },
          400,
        );
      }

      const verification = await verifiedEmailRecord(
        env,
        email,
        verificationId,
        verificationToken,
      );
      if (!verification) {
        return jsonResponse(
          request,
          { claimed: false, error: "Email verification is invalid or has expired" },
          401,
        );
      }

      const business = await env.DB.prepare(
        `SELECT
           id, business_name, usc, authorised_email, authorised_phone,
           contact_name, status, account_state, invoice_eligible,
           completed_prepaid_deliveries, first_two_jobs_free
         FROM businesses
         WHERE usc = ? COLLATE NOCASE
         LIMIT 1`,
      )
        .bind(usc)
        .first();

      if (!business) {
        return jsonResponse(
          request,
          { claimed: false, error: "That USC is not registered" },
          404,
        );
      }
      if (business.status === "suspended" || business.account_state === "suspended") {
        return jsonResponse(
          request,
          { claimed: false, error: "This USC account is suspended" },
          409,
        );
      }

      const currentEmail = normalizeEmail(business.authorised_email);
      const currentPhone = normalizePhone(business.authorised_phone);
      const hasEmail = validEmail(currentEmail);
      const hasPhone = validPhone(currentPhone);

      if (hasEmail && hasPhone) {
        return jsonResponse(
          request,
          {
            claimed: false,
            error: "This USC already has official contact details",
            alreadyClaimed: true,
          },
          409,
        );
      }
      if (hasEmail && currentEmail !== email) {
        return jsonResponse(
          request,
          { claimed: false, error: "The verified email does not match this USC's existing official email" },
          409,
        );
      }
      if (hasPhone && currentPhone !== phone) {
        return jsonResponse(
          request,
          { claimed: false, error: "The supplied mobile does not match this USC's existing official mobile" },
          409,
        );
      }

      const savedEmail = hasEmail ? currentEmail : email;
      const savedPhone = hasPhone ? currentPhone : phone;
      const savedContactName = contactName || cleanText(business.contact_name, 200) || business.business_name;
      const update = await env.DB.prepare(
        `UPDATE businesses
         SET authorised_email = ?, authorised_phone = ?, contact_name = ?,
             updated_at = datetime('now')
         WHERE id = ?
           AND authorised_email = ?
           AND authorised_phone = ?`,
      )
        .bind(
          savedEmail,
          savedPhone,
          savedContactName,
          business.id,
          business.authorised_email || "",
          business.authorised_phone || "",
        )
        .run();

      if (d1Changes(update) === 0) {
        return jsonResponse(
          request,
          { claimed: false, error: "This USC changed while it was being claimed. Please check it again." },
          409,
        );
      }

      await env.DB.prepare(
        `INSERT INTO business_events (id, business_id, event_type, event_data)
         VALUES (?, ?, 'updated', ?)`,
      )
        .bind(
          crypto.randomUUID(),
          business.id,
          JSON.stringify({
            updatedBy: "customer_first_use_claim",
            fields: ["official email", "official mobile", "contact name"],
            source: "website_usc_claim",
          }),
        )
        .run();

      const freeDeliveriesRemaining = await firstTwoJobsFreeRemaining(
        env,
        business.id,
        Boolean(business.first_two_jobs_free),
      );

      return jsonResponse(request, {
        claimed: true,
        valid: true,
        businessName: business.business_name,
        usc: business.usc,
        accountStatus: business.status,
        officialEmail: savedEmail,
        officialPhone: savedPhone,
        contactName: savedContactName,
        firstTwoJobsFree: Boolean(business.first_two_jobs_free),
        freeDeliveriesRemaining,
        completedPrepaidDeliveries: Number(business.completed_prepaid_deliveries || 0),
        invoiceEligible:
          Boolean(business.invoice_eligible) ||
          business.status === "invoice_eligible" ||
          business.status === "invoicing",
        verificationMode: "usc_only",
        uscOnlyBooking: true,
        uscVerificationToken: verificationToken,
      });
    }

    if (request.method === "POST" && url.pathname === "/usc/verify") {
      let body;

      try {
        body = await request.json();
      } catch {
        return jsonResponse(
          request,
          { valid: false, error: "Invalid request" },
          400,
        );
      }

      const usc = normaliseUsc(body.usc);
      const suppliedEmail = normalizeEmail(body.email);
      const suppliedPhone = normalizePhone(body.phone);
      const uscOnlyWebsiteFlow = Boolean(usc && !suppliedEmail && !suppliedPhone);

      if (uscOnlyWebsiteFlow) {
        const business = await env.DB.prepare(
          `
          SELECT
            id,
            business_name,
            usc,
            authorised_email,
            authorised_phone,
            status,
            account_state,
            invoice_eligible,
            completed_prepaid_deliveries,
            first_two_jobs_free
          FROM businesses
          WHERE usc = ? COLLATE NOCASE
          LIMIT 1
        `,
        )
          .bind(usc)
          .first();

        if (!business) {
          return jsonResponse(
            request,
            { valid: false, error: "That USC is not registered" },
            401,
          );
        }

        if (business.status === "suspended" || business.account_state === "suspended") {
          return jsonResponse(
            request,
            { valid: false, error: "This USC account is suspended" },
            401,
          );
        }

        const contactSetupRequired =
          !validEmail(normalizeEmail(business.authorised_email)) ||
          !validPhone(normalizePhone(business.authorised_phone));
        const freeDeliveriesRemaining = await firstTwoJobsFreeRemaining(
          env,
          business.id,
          Boolean(business.first_two_jobs_free),
        );

        if (contactSetupRequired) {
          return jsonResponse(
            request,
            {
              valid: false,
              claimRequired: true,
              contactSetupRequired: true,
              businessName: business.business_name,
              usc: business.usc,
              firstTwoJobsFree: Boolean(business.first_two_jobs_free),
              freeDeliveriesRemaining,
              error: "This USC is ready to use once its official email and mobile are set",
            },
            409,
          );
        }

        return jsonResponse(request, {
          valid: true,
          businessName: business.business_name,
          accountStatus: business.status,
          completedPrepaidDeliveries: Number(business.completed_prepaid_deliveries || 0),
          firstTwoJobsFree: Boolean(business.first_two_jobs_free),
          freeDeliveriesRemaining,
          contactSetupRequired: false,
          invoiceEligible:
            Boolean(business.invoice_eligible) ||
            business.status === "invoice_eligible" ||
            business.status === "invoicing",
          verificationMode: "usc_only",
          uscOnlyBooking: true,
        });
      }

      const result = await authenticateUscCredentials(env, {
        usc,
        email: suppliedEmail,
        phone: suppliedPhone,
      });

      if (!result.authenticated) {
        return jsonResponse(
          request,
          { valid: false, error: result.error },
          result.httpStatus,
        );
      }

      return jsonResponse(request, {
        valid: true,
        businessName: result.businessName,
        accountStatus: result.accountStatus,
        completedPrepaidDeliveries: result.completedPrepaidDeliveries,
        firstTwoJobsFree: Boolean(result.firstTwoJobsFree),
        freeDeliveriesRemaining: Number(result.freeDeliveriesRemaining || 0),
        invoiceEligible: result.invoiceEligible,
        verificationMode: "authorised_contacts",
        uscOnlyBooking: false,
      });
    }

    if (request.method === "POST" && url.pathname === "/quote/email") {
      let body;

      try {
        body = await request.json();
      } catch {
        return jsonResponse(
          request,
          {
            sent: false,
            error: "Invalid request",
          },
          400,
        );
      }

      const email = normalizeEmail(body.to);
      const verificationId = cleanText(body.verificationId, 100);
      const verificationToken = cleanText(body.verificationToken, 200);
      const quote = body.summary;

      if (!validEmail(email) || !quote || typeof quote !== "object") {
        return jsonResponse(
          request,
          {
            sent: false,
            error: "Verified email and quote details are required",
          },
          400,
        );
      }

      const verification = await verifiedEmailRecord(
        env,
        email,
        verificationId,
        verificationToken,
      );

      if (!verification) {
        return jsonResponse(
          request,
          {
            sent: false,
            error: "Email verification is invalid or has expired",
          },
          401,
        );
      }

      const details = quoteText(quote);

      try {
        await sendEmail(env, {
          to: email,
          subject: "Your Sorrin courier quote details",
          text: `Thanks for supporting another aussie.\n\n${details}\n\nThis quote is indicative until reviewed and approved by Sorrin.`,
          html: `
            <div style="font-family:Arial,sans-serif;max-width:680px;margin:auto;padding:32px;color:#111;line-height:1.5;">
              <h1 style="margin:0 0 22px;">SORRIN COURIER</h1>
              <p>Thanks for supporting another aussie.</p>
              <pre style="white-space:pre-wrap;font:14px/1.5 Arial,sans-serif;background:#f5f5f5;padding:20px;border-radius:8px;">${escapeHtml(details)}</pre>
              <p><strong>This quote is indicative until reviewed and approved by Sorrin.</strong></p>
            </div>
          `,
        });
      } catch (error) {
        return jsonResponse(
          request,
          {
            sent: false,
            error: error.message,
          },
          502,
        );
      }

      return jsonResponse(request, { sent: true });
    }

    if (request.method === "POST" && url.pathname === "/booking") {
      let body;

      try {
        body = await request.json();
      } catch {
        return jsonResponse(
          request,
          {
            submitted: false,
            error: "Invalid request",
          },
          400,
        );
      }

      const requester = body.requester || {};
      const quote = body.quote || {};
      const bookingType = cleanText(requester.bookingType, 20).toLowerCase();
      const businessNameOrUsc = cleanText(requester.businessNameOrUsc, 250);
      const suppliedUsc = normaliseUsc(
        requester.uscCode || requester.usc || businessNameOrUsc || body.usc,
      );
      let requesterName = cleanText(requester.requesterName, 200);
      let requesterEmail = normalizeEmail(requester.requesterEmail);
      let requesterPhone = normalizePhone(requester.requesterPhone);
      const paymentMethod = cleanText(requester.paymentMethod, 100) || null;
      const verificationId = cleanText(
        body.verificationId || requester.emailVerificationId,
        100,
      );
      const verificationToken = cleanText(
        body.verificationToken || requester.emailVerificationToken,
        200,
      );
      const serviceLevel = cleanText(quote.service, 150);
      const pickupAddress = cleanText(quote.pickup?.address, 500);
      const primaryDropoffAddress = cleanText(
        Array.isArray(quote.dropoffs) ? quote.dropoffs[0]?.address : "",
        500,
      );
      const explicitUscOnlyBooking =
        body.uscOnlyBooking === true ||
        requester.uscOnlyBooking === true ||
        cleanText(requester.verificationMode, 40).toLowerCase() === "usc_only" ||
        cleanText(requester.authenticationSource, 60).toLowerCase() === "usc_only";
      const implicitUscOnlyBooking = Boolean(
        bookingType === "business" &&
          suppliedUsc &&
          !requesterEmail &&
          !requesterPhone &&
          !verificationId &&
          !verificationToken,
      );
      const uscOnlyBooking = Boolean(
        bookingType === "business" &&
          suppliedUsc &&
          (explicitUscOnlyBooking || implicitUscOnlyBooking),
      );

      if (!["business", "guest"].includes(bookingType)) {
        return jsonResponse(
          request,
          {
            submitted: false,
            error: "Choose a valid booking type",
          },
          400,
        );
      }

      if (!serviceLevel || !pickupAddress || !primaryDropoffAddress) {
        return jsonResponse(
          request,
          {
            submitted: false,
            error: "Required booking details are missing or invalid",
          },
          400,
        );
      }

      let businessId = null;
      let uscVerified = 0;
      let registeredBusinessName = null;
      let registeredUsc = null;
      let emailVerified = 0;
      let bookingEmailVerificationId = null;

      if (uscOnlyBooking) {
        const business = await env.DB.prepare(
          `
          SELECT
            id,
            business_name,
            usc,
            authorised_email,
            authorised_phone,
            contact_name,
            status,
            account_state
          FROM businesses
          WHERE usc = ? COLLATE NOCASE
          LIMIT 1
        `,
        )
          .bind(suppliedUsc)
          .first();

        if (!business) {
          return jsonResponse(
            request,
            { submitted: false, error: "That USC is not registered" },
            401,
          );
        }
        if (business.status === "suspended" || business.account_state === "suspended") {
          return jsonResponse(
            request,
            { submitted: false, error: "This USC account is suspended" },
            401,
          );
        }

        requesterName =
          cleanText(business.contact_name, 200) ||
          cleanText(business.business_name, 200);
        requesterEmail = normalizeEmail(business.authorised_email);
        requesterPhone = normalizePhone(business.authorised_phone);

        if (!requesterName || !validEmail(requesterEmail) || !validPhone(requesterPhone)) {
          return jsonResponse(
            request,
            {
              submitted: false,
              error: "This USC account's stored contact details need to be updated before booking",
            },
            409,
          );
        }

        businessId = business.id;
        registeredBusinessName = business.business_name;
        registeredUsc = business.usc;
        uscVerified = 1;
        bookingEmailVerificationId = `usc-only:${business.id}:${crypto.randomUUID()}`;
      } else {
        if (
          !requesterName ||
          !validEmail(requesterEmail) ||
          !validPhone(requesterPhone)
        ) {
          return jsonResponse(
            request,
            {
              submitted: false,
              error: "Required booking details are missing or invalid",
            },
            400,
          );
        }

        const verification = await verifiedEmailRecord(
          env,
          requesterEmail,
          verificationId,
          verificationToken,
        );

        if (!verification) {
          return jsonResponse(
            request,
            {
              submitted: false,
              error: "Email verification is invalid or has expired",
            },
            401,
          );
        }

        emailVerified = 1;
        bookingEmailVerificationId = verification.id;

        if (suppliedUsc) {
          const business = await env.DB.prepare(
            `
            SELECT
              id,
              business_name,
              usc,
              authorised_email,
              authorised_phone,
              status,
              account_state
            FROM businesses
            WHERE usc = ? COLLATE NOCASE
            LIMIT 1
          `,
          )
            .bind(suppliedUsc)
            .first();

          if (!business) {
            return jsonResponse(
              request,
              { submitted: false, error: "That USC is not registered" },
              401,
            );
          }
          const matches =
            normalizeEmail(business.authorised_email) === requesterEmail &&
            normalizePhone(business.authorised_phone) === requesterPhone &&
            business.status !== "suspended" &&
            business.account_state !== "suspended";

          if (!matches) {
            return jsonResponse(
              request,
              {
                submitted: false,
                error: "USC or authorised contact details do not match",
              },
              401,
            );
          }

          businessId = business.id;
          registeredBusinessName = business.business_name;
          registeredUsc = business.usc;
          uscVerified = 1;
        }
      }

      // PATCH30 website-only USC bookings may use an active registered USC alone.
      // The Worker resolves the stored authorised contact details server-side and
      // bypasses email_verifications only for that narrow booking path. This does
      // not alter SorrinBot USC authentication or new/non-USC registration rules.

      const id = crypto.randomUUID();
      const numbering = await nextJobNumbers(env, businessId);
      const quotedTotal = numberOrNull(quote.total);
      const quotedTotalCents =
        quotedTotal == null ? null : Math.max(0, Math.round(quotedTotal * 100));
      const freeAdjustment = await firstTwoJobsFreeAdjustment(
        env,
        businessId,
        numbering.uscJobNumber,
        quotedTotalCents,
      );
      applyFirstTwoJobsFreeToQuote(quote, freeAdjustment);
      const reference = bookingReference(
        quote,
        pickupAddress,
        primaryDropoffAddress,
        {
          usc: registeredUsc,
          globalJobNumber: numbering.globalJobNumber,
          uscJobNumber: numbering.uscJobNumber,
        },
      );
      const routeKm = numberOrNull(quote.routeKm);
      const indicativeTotalCents = freeAdjustment.effectiveTotalCents;
      const clientIp = request.headers.get("CF-Connecting-IP") || "unknown";
      const ipHash = await hashValue(`sorrin-ip:${clientIp}`);
      const resolvedBusinessNameOrUsc = businessNameOrUsc || registeredUsc || null;
      const resolvedRequester = {
        ...requester,
        bookingType,
        businessNameOrUsc: resolvedBusinessNameOrUsc,
        uscCode: registeredUsc || suppliedUsc || null,
        requesterName,
        requesterEmail,
        requesterPhone,
        paymentMethod,
        authenticationSource: uscOnlyBooking
          ? "website_usc_only"
          : requester.authenticationSource || null,
      };
      const payloadJson = JSON.stringify({ requester: resolvedRequester, quote });

      if (payloadJson.length > 100000) {
        return jsonResponse(
          request,
          {
            submitted: false,
            error: "Booking details are too large",
          },
          413,
        );
      }

      try {
        await env.DB.prepare(
          `
          INSERT INTO booking_requests (
            id,
            reference,
            global_job_number,
            usc_job_number,
            booking_type,
            business_id,
            business_name_or_usc,
            requester_name,
            requester_email,
            requester_phone,
            payment_method,
            email_verification_id,
            email_verified,
            usc_verified,
            service_level,
            manual_quote,
            route_km,
            indicative_total_cents,
            pickup_address,
            primary_dropoff_address,
            status,
            payload_json,
            request_ip_hash
          ) VALUES (
            ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending', ?, ?
          )
        `,
        )
          .bind(
            id,
            reference,
            numbering.globalJobNumber,
            numbering.uscJobNumber,
            bookingType,
            businessId,
            resolvedBusinessNameOrUsc,
            requesterName,
            requesterEmail,
            requesterPhone,
            paymentMethod,
            bookingEmailVerificationId,
            emailVerified,
            uscVerified,
            serviceLevel,
            booleanInteger(quote.manualQuote),
            routeKm,
            indicativeTotalCents,
            pickupAddress,
            primaryDropoffAddress,
            payloadJson,
            ipHash,
          )
          .run();

        await syncRequestToOrganisedJob(env, {
          id,
          reference,
          booking_type: bookingType,
          business_id: businessId,
          business_name_or_usc: resolvedBusinessNameOrUsc,
          requester_name: requesterName,
          requester_email: requesterEmail,
          requester_phone: requesterPhone,
          payment_method: paymentMethod,
          service_level: serviceLevel,
          indicative_total_cents: indicativeTotalCents,
          pickup_address: pickupAddress,
          primary_dropoff_address: primaryDropoffAddress,
          payload_json: payloadJson,
          usc_verified: uscVerified,
          usc_used: registeredUsc,
        });
      } catch (error) {
        return jsonResponse(
          request,
          {
            submitted: false,
            error: "Booking could not be saved",
            detail: error.message,
          },
          500,
        );
      }

      const details = quoteText(quote);
      const requesterDetails = [
        `Reference: ${reference}`,
        `Booking type: ${bookingType}`,
        `Business / USC: ${resolvedBusinessNameOrUsc || "Not supplied"}`,
        `Registered business: ${registeredBusinessName || "Not verified"}`,
        `Linked USC account: ${registeredUsc || "Not linked"}`,
        `USC verified: ${uscVerified ? "Yes" : "No"}`,
        `Name: ${requesterName}`,
        `Email: ${requesterEmail}`,
        `Phone: ${requesterPhone}`,
        `Payment method: ${paymentMethod || "Not selected"}`,
      ].join("\n");

      let notificationWarning = null;

      try {
        await sendEmail(env, {
          to: "courier@sorrin.com.au",
          subject: `${bookingType === "guest" ? "Guest" : "Business"} booking request ${reference}`,
          text: `${requesterDetails}\n\n${details}`,
          html: `
            <div style="font-family:Arial,sans-serif;max-width:720px;margin:auto;padding:32px;color:#111;line-height:1.5;">
              <h1 style="margin:0 0 22px;">NEW SORRIN BOOKING</h1>
              <pre style="white-space:pre-wrap;font:14px/1.5 Arial,sans-serif;background:#f5f5f5;padding:20px;border-radius:8px;">${escapeHtml(`${requesterDetails}\n\n${details}`)}</pre>
            </div>
          `,
        });

        const customerMessage =
          bookingType === "guest"
            ? `Your guest booking has been submitted for manual approval. It is not guaranteed until Sorrin confirms it, and pre-payment may be required.`
            : `Your business booking request has been submitted for approval. It is not confirmed until Sorrin reviews and accepts it.`;

        await sendEmail(env, {
          to: requesterEmail,
          subject: `Sorrin booking request received - ${reference}`,
          text: `Hi ${requesterName},\n\n${customerMessage}\n\nReference: ${reference}\n\n${details}\n\nKind regards,\nSorrin`,
          html: `
            <div style="font-family:Arial,sans-serif;max-width:680px;margin:auto;padding:32px;color:#111;line-height:1.5;">
              <h1 style="margin:0 0 22px;">SORRIN COURIER</h1>
              <p>Hi ${escapeHtml(requesterName)},</p>
              <p>${escapeHtml(customerMessage)}</p>
              <p><strong>Reference: ${escapeHtml(reference)}</strong></p>
              <pre style="white-space:pre-wrap;font:14px/1.5 Arial,sans-serif;background:#f5f5f5;padding:20px;border-radius:8px;">${escapeHtml(details)}</pre>
              <p>Kind regards,<br>Sorrin</p>
            </div>
          `,
        });
      } catch (error) {
        notificationWarning = error.message;
      }

      return jsonResponse(
        request,
        {
          submitted: true,
          reference,
          notificationSent: !notificationWarning,
          notificationWarning,
        },
        notificationWarning ? 202 : 201,
      );
    }

    return jsonResponse(request, { error: "Not found" }, 404);
  },
};