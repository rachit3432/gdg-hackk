(function (global) {
  'use strict';

  const Scrub = (global.Scrub = global.Scrub || {});

  // 46 lines mixing support ticket, server log, resume, and clinical note styles.
  // All data is synthetic; Aadhaar and Card check digits were verified mathematically.
  const SAMPLE_TEXT = [
    '=== [1/4] SUPPORT TICKET #884920 :: BILLING ESCALATION ===',
    'Created: 2026-11-27T09:14:22Z | SLA Window: 2026-11-28 | Release: v1.2.3.4',
    'Customer: Priya Sharma <Priya.Sharma+billing@AcmeCorp.example>',
    'Follow-up cc: priya.sharma+billing@acmecorp.example (duplicate casing test)',
    'Primary Phone: +91-98765-43210 | Alternate: 98765 43210 | Alt-2: 98765-43210',
    'Support Callback (US): +1 (415) 555-0192 | UK Desk: +44 20 7946 0958',
    'Order ID 1234567890123456 failed gateway settlement; retry ref 4012345678.',
    'Primary Visa used: 4111 1111 1111 1111 (re-entered as 4111-1111-1111-1111).',
    'Backup Mastercard: 5555 5555 5555 4444 | Corp Amex: 378282246310005',
    'Domestic RuPay: 6070 9500 0000 0016 | Discover: 6011 0009 9013 9424',
    'Declined card decoy: 4111 1111 1111 1112 | Non-PII ref: 5551234567, 123456789012.',
    'Escalation owner note: refund approved after duplicate invoice verification.',
    '',
    '=== [2/4] EDGE GATEWAY ACCESS LOG :: NODE EU-WEST-04 ===',
    '2026-11-27 14:32:09 INFO  auth_ok user=devops.alerts+prod@eu-west.svc.example.org src=192.168.10.42',
    '2026-11-27 14:32:11 WARN  rate_limit peer=10.0.48.201 fw_ver=v1.2.3.4 latency=42ms',
    '2026-11-27 14:32:14 INFO  egress relay reached public host 203.0.113.77.',
    '2026-11-27 14:32:19 INFO  ipv6_tunnel src=2001:0db8:85a3::8a2e:0370:7334 port=443',
    '2026-11-27 14:32:25 ERROR malformed_header bad_ip=999.300.1.1 build=20261127',
    '2026-11-27 14:32:30 INFO  repeat_login user=PRIYA.SHARMA+billing@ACMECORP.EXAMPLE src=192.168.10.42',
    '2026-11-27 14:32:34 INFO  healthcheck status=200 uptime=99.98% region=eu-west-1',
    '',
    '=== [3/4] CANDIDATE RESUME & KYC SNAPSHOT ===',
    'Name: Aarav Kulkarni | DOB: 15/08/1994 | City: Bengaluru',
    'Email: aarav.kulkarni+jobs@mail.example.in',
    'Mobile: 09876543210 | Emergency Contact: 0091-91234-56789',
    'Tax Identifier (PAN): ABCPE1234F (submitted lowercase on form 2: abcpe1234f)',
    'Corporate Entity PAN: BKCPC9876L | Internal Badge Decoy: XYZQE4512K',
    'Aadhaar KYC: 2345 6789 0124 (verified copy: 2345-6789-0124)',
    'Secondary Guardian Aadhaar: 7845-1236-9013 | Direct: 543219876545',
    'Courier Tracking Decoys (invalid Verhoeff): 2345 6789 0120, 7845 1236 9010',
    'Previous Experience: Platform Security Engineer (2021-04-01 to 2026-10-31)',
    '',
    '=== [4/4] OUTPATIENT CLINICAL NOTE :: SYNTHETIC RECORD ===',
    'Visit Date: 2026-11-27 | Attending: dr.mehta+clinic@medportal.example.in',
    'Clinic Portal: portal.health.example.org | Chart Ref: 987654321019',
    'Vitals: BP 118/76 mmHg | Temp 98.6 F | Pulse 72 bpm | SpO2 99%',
    'Lab Panel: HbA1c 5.4% | LDL 92 mg/dL | Fasting Glucose 88 mg/dL',
    'Patient Callback: +91 98201 55432 | Insurer Portal IP: 198.51.100.14.',
    'Co-pay Card on File: 4111 1111 1111 1111 | Pharmacy Auth: 2026-11-27T16:05:00Z',
    'Follow-up Scheduler: 2026-12-15 10:30:00 | Room: OPD-04',
    'Discharge Status: Stable — outpatient prescription issued locally.',
    'End of synthetic audit payload — zero live personal records included.'
  ].join('\n');

  Scrub.sample = {
    TEXT: SAMPLE_TEXT
  };
})(typeof window !== 'undefined' ? window : globalThis);
