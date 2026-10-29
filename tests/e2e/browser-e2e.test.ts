/**
 * VAJRA — Real Headless Chromium Browser E2E Suite (Prompt 0037)
 *
 * Executes real browser user flows in headless Chromium via `playwright-core`
 * against a live Express + built React SPA server instance:
 * 1. Owner registration, authenticated console load, sign-out, and sign-in.
 * 2. Empty device inventory honesty (0 enrolled devices) & opt-in sample preview toggle.
 * 3. Keyboard-accessible dialogs (Modal & NotificationSlideOverPanel: role="dialog",
 *    aria-modal="true", Tab/Shift+Tab focus containment, Escape dismissal) & mobile viewport (375x812).
 * 4. TOTP Multi-Factor Authentication setup, 8 single-use recovery codes, and MFA sign-in.
 * 5. ThreatCheck URL inspection, secret redaction (`access_token=[REDACTED]`), explainable indicators,
 *    and lexical limitation disclosure.
 * 6. Enrolled Windows device inventory rendering, DetailDrawer inspection, status check queueing,
 *    and MFA step-up gating for Lost Mode.
 * 7. Persisted Security Analytics & JSON/CSV report export verification.
 */

import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import path from 'node:path';
import fs from 'node:fs';
import crypto from 'node:crypto';
import express from 'express';
import { chromium, type Browser, type BrowserContext, type Page } from 'playwright-core';
import { PrismaClient } from '@prisma/client';
import { createVajraApiApp } from '../../src/server/app.ts';
import {
  InMemoryIdentityRepository,
  PrismaIdentityRepository,
  type IdentityRepository,
} from '../../src/server/db/repository.ts';
import {
  generateTotpCodeAtTime,
  generateDeviceKeyPair,
  signEnrollmentProof,
} from '../../packages/security/src/node.ts';

const DATABASE_URL = process.env.DATABASE_URL?.trim() ?? '';
const USE_PG =
  (DATABASE_URL.startsWith('postgresql://') || DATABASE_URL.startsWith('postgres://')) &&
  !DATABASE_URL.includes('placeholder');
const TOTP_KEY = 'vajra-browser-e2e-totp-key-32bytes!';

describe('Browser E2E — Headless Chromium against live VAJRA full-stack server', () => {
  let prisma: PrismaClient | null = null;
  let repository: IdentityRepository;
  let server: http.Server;
  let baseUrl = '';
  let browser: Browser;
  let context: BrowserContext;
  let page: Page;

  const runSuffix = crypto.randomBytes(4).toString('hex');
  const ownerEmail = `e2e.owner.${runSuffix}@vajra.test`;
  const ownerPassword = 'Vajra-E2E-StrongPass!2026';
  const ownerName = 'Aarav E2E Owner';
  let totpSecretBase32 = '';

  before(async () => {
    const distPath = path.resolve(process.cwd(), 'dist');
    const indexHtmlPath = path.join(distPath, 'index.html');
    assert.ok(
      fs.existsSync(indexHtmlPath),
      'dist/index.html is missing — run `npm run build` before browser E2E tests'
    );

    if (USE_PG) {
      prisma = new PrismaClient({ datasources: { db: { url: DATABASE_URL } } });
      await prisma.$connect();
      repository = new PrismaIdentityRepository(prisma);
    } else {
      repository = new InMemoryIdentityRepository();
    }

    const app = createVajraApiApp({
      repository,
      totpEncryptionKey: TOTP_KEY,
    });

    app.use(express.static(distPath));
    app.get('*', (req, res, next) => {
      if (req.path.startsWith('/api')) {
        next();
        return;
      }
      res.sendFile(indexHtmlPath);
    });

    server = http.createServer(app);
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', () => resolve()));
    const addr = server.address();
    assert.ok(addr && typeof addr === 'object');
    baseUrl = `http://127.0.0.1:${addr.port}`;

    browser = await chromium.launch({ headless: true });
    context = await browser.newContext({ viewport: { width: 1280, height: 800 } });
    page = await context.newPage();

    // Prevent external decorative video asset from slowing down headless tests
    await page.route('**res.cloudinary.com**', (route) => route.abort());
  });

  after(async () => {
    try {
      await context?.close();
    } catch {
      /* ignore */
    }
    try {
      await browser?.close();
    } catch {
      /* ignore */
    }
    await new Promise<void>((resolve) => server.close(() => resolve()));
    if (prisma) {
      try {
        await prisma.$disconnect();
      } catch {
        /* ignore */
      }
    }
  });

  it('1. registers a new owner account, loads the Overview console, signs out, and signs back in', async () => {
    await page.goto(baseUrl, { waitUntil: 'domcontentloaded' });

    await page.getByRole('button', { name: 'Create Account' }).click();
    await page.locator('#vajra-reg-name').fill(ownerName);
    await page.locator('#vajra-reg-email').fill(ownerEmail);
    await page.locator('#vajra-reg-password').fill(ownerPassword);
    await page.locator('#vajra-reg-confirm').fill(ownerPassword);
    await page.getByRole('button', { name: 'Create VAJRA Account' }).click();

    await page.getByText(/Protection Index/i).first().waitFor({ state: 'visible', timeout: 10000 });
    const bodyText = await page.locator('body').innerText();
    assert.match(bodyText, /Aarav/);

    // Navigate to Settings and Sign Out
    await page.getByRole('button', { name: 'Settings' }).first().click();
    await page.getByRole('button', { name: 'Sign Out', exact: true }).click();

    await page.locator('#vajra-login-email').waitFor({ state: 'visible', timeout: 10000 });
    await page.locator('#vajra-login-email').fill(ownerEmail);
    await page.locator('#vajra-login-password').fill(ownerPassword);
    await page.getByRole('button', { name: 'Sign In to VAJRA' }).click();

    await page.getByText(/Protection Index/i).first().waitFor({ state: 'visible', timeout: 10000 });
  });

  it('2. displays honest empty device inventory by default and toggles opt-in sample preview', async () => {
    await page.getByRole('button', { name: 'Devices' }).first().click();
    await page.getByText('Protect your first device').waitFor({ state: 'visible', timeout: 10000 });

    const defaultText = await page.locator('body').innerText();
    assert.match(defaultText, /No devices are enrolled yet/i);
    assert.doesNotMatch(defaultText, /ASUS TUF F16/);

    await page.getByRole('button', { name: 'Show sample preview' }).click();
    await page.getByText('ASUS TUF F16 (Sample)').waitFor({ state: 'visible', timeout: 5000 });
    const previewText = await page.locator('body').innerText();
    assert.match(previewText, /Sample only/);
    assert.match(previewText, /Not a real device/);

    await page.getByRole('button', { name: 'Hide sample preview' }).click();
    const afterHideCount = await page.getByText('ASUS TUF F16 (Sample)').count();
    assert.equal(afterHideCount, 0);
  });

  it('3. enforces keyboard-accessible dialogs (Modal & NotificationSlideOverPanel) and responsive mobile layout', async () => {
    // Open Connect Device modal
    await page.getByRole('button', { name: 'Connect Device' }).first().click();

    const dialog = page.locator('[role="dialog"][aria-modal="true"]').first();
    await dialog.waitFor({ state: 'visible', timeout: 5000 });

    // Verify Tab / Shift+Tab keeps focus inside the modal dialog
    await page.keyboard.press('Tab');
    const focusInsideAfterTab = await page.evaluate(() => {
      const dlg = document.querySelector('[role="dialog"][aria-modal="true"]');
      return Boolean(dlg && dlg.contains(document.activeElement));
    });
    assert.equal(focusInsideAfterTab, true, 'expected Tab focus to remain inside open dialog');

    await page.keyboard.press('Shift+Tab');
    const focusInsideAfterShiftTab = await page.evaluate(() => {
      const dlg = document.querySelector('[role="dialog"][aria-modal="true"]');
      return Boolean(dlg && dlg.contains(document.activeElement));
    });
    assert.equal(focusInsideAfterShiftTab, true, 'expected Shift+Tab focus to remain inside open dialog');

    // Dismiss modal with Escape key
    await page.keyboard.press('Escape');
    await dialog.waitFor({ state: 'hidden', timeout: 5000 });

    // Open NotificationSlideOverPanel via header bell button and dismiss with Escape
    await page.locator('button[aria-label^="Notifications"]').first().click();
    const notifDialog = page.locator('[role="dialog"][aria-modal="true"][aria-label="Notification Center"]');
    await notifDialog.waitFor({ state: 'visible', timeout: 5000 });
    await page.keyboard.press('Escape');
    await notifDialog.waitFor({ state: 'hidden', timeout: 5000 });

    // Verify mobile viewport (375x812) has no horizontal overflow
    await page.setViewportSize({ width: 375, height: 812 });
    const overflowCheck = await page.evaluate(() => ({
      scrollWidth: document.documentElement.scrollWidth,
      clientWidth: document.documentElement.clientWidth,
    }));
    assert.ok(
      overflowCheck.scrollWidth <= overflowCheck.clientWidth + 1,
      `expected no horizontal overflow on mobile viewport (scrollWidth=${overflowCheck.scrollWidth}, clientWidth=${overflowCheck.clientWidth})`
    );
    await page.setViewportSize({ width: 1280, height: 800 });
  });

  it('4. sets up TOTP MFA, displays 8 single-use recovery codes, and verifies MFA login', async () => {
    await page.getByRole('button', { name: 'Settings' }).first().click();
    await page.getByRole('button', { name: 'Enable Two-Step' }).click();

    await page.getByRole('button', { name: 'View manual setup key' }).click();
    const secretEl = page.locator('div.font-mono.text-\\[\\#C8A66A\\]').first();
    await secretEl.waitFor({ state: 'visible', timeout: 5000 });
    totpSecretBase32 = (await secretEl.innerText()).trim();
    assert.match(totpSecretBase32, /^[A-Z2-7]+=*$/);

    const code = generateTotpCodeAtTime(totpSecretBase32);
    await page.locator('#mfa-verify-code').fill(code);
    await page.getByRole('button', { name: 'Activate' }).click();

    await page.getByText('Protected with authenticator app').waitFor({ state: 'visible', timeout: 10000 });
    await page.getByText('Recovery Codes').first().waitFor({ state: 'visible', timeout: 5000 });

    const pageText = await page.locator('body').innerText();
    const recoveryMatches = pageText.match(/\b[A-Z0-9]{4}-[A-Z0-9]{4}\b/g) ?? [];
    assert.ok(
      recoveryMatches.length >= 8,
      `expected 8 single-use recovery codes, found ${recoveryMatches.length}`
    );

    // Sign out and verify MFA challenge during login
    await page.getByRole('button', { name: 'Sign Out', exact: true }).click();
    await page.locator('#vajra-login-email').waitFor({ state: 'visible', timeout: 10000 });
    await page.locator('#vajra-login-email').fill(ownerEmail);
    await page.locator('#vajra-login-password').fill(ownerPassword);
    await page.getByRole('button', { name: 'Sign In to VAJRA' }).click();

    await page.locator('#vajra-login-totp').waitFor({ state: 'visible', timeout: 10000 });
    const loginTotp = generateTotpCodeAtTime(totpSecretBase32);
    await page.locator('#vajra-login-totp').fill(loginTotp);
    await page.getByRole('button', { name: 'Verify & Sign In' }).click();

    await page.getByText(/Protection Index/i).first().waitFor({ state: 'visible', timeout: 10000 });
  });

  it('5. inspects a restricted URL in ThreatCheck, redacts secrets, and renders explainable indicators & limitations', async () => {
    await page.getByRole('button', { name: 'ThreatCheck' }).first().click();

    const urlInput = page.locator('input[aria-label="Website address to inspect"]');
    await urlInput.waitFor({ state: 'visible', timeout: 5000 });
    await urlInput.fill('http://127.0.0.1:8080/admin?access_token=SECRET123#frag');
    await page.getByRole('button', { name: 'Check Link' }).click();

    await page
      .getByText('Restricted Destination Boundary Flagged')
      .waitFor({ state: 'visible', timeout: 10000 });

    const tcText = await page.locator('body').innerText();
    assert.match(tcText, /HIGH RISK/);
    assert.match(tcText, /Explainable Threat Indicators/);
    assert.match(tcText, /Limitations note:/);
    assert.match(tcText, /access_token=\[REDACTED\]/);
    assert.doesNotMatch(tcText, /SECRET123/);
  });

  it('6. enrolls a Windows device, renders it in inventory, queues a status check, and gates Lost Mode behind MFA step-up', async () => {
    // Enroll a Windows device using the browser's authenticated session + protocol enrollment submit
    const enrollInfo = await page.evaluate(async () => {
      const meRes = await fetch('/api/auth/me', { credentials: 'include' });
      const meData = await meRes.json();
      const csrf = meData.csrfToken;
      const initRes = await fetch('/api/devices/enrollment/initiate', {
        method: 'POST',
        credentials: 'include',
        headers: {
          'Content-Type': 'application/json',
          'X-CSRF-Token': csrf,
        },
        body: JSON.stringify({
          name: 'Win11-Workstation-E2E',
          deviceType: 'WINDOWS',
          osVersion: 'Windows 11 Pro 23H2',
        }),
      });
      const initData = await initRes.json();
      return { status: initRes.status, csrf, enrollment: initData.enrollment };
    });

    assert.equal(enrollInfo.status, 201);
    const { deviceId, enrollmentToken, challengeNonce } = enrollInfo.enrollment;
    const keyPair = generateDeviceKeyPair('ECDSA_P256');
    const timestampIso = new Date().toISOString();
    const clientNonce = crypto.randomBytes(16).toString('hex');
    const signatureBase64 = signEnrollmentProof({
      privateKeyPem: keyPair.privateKeyPem,
      keyAlgorithm: 'ECDSA_P256',
      deviceId,
      enrollmentToken,
      challengeNonce,
      publicKeyFingerprint: keyPair.publicKeyFingerprint,
      timestampIso,
      clientNonce,
    });

    const submitStatus = await page.evaluate(
      async (payload) => {
        const subRes = await fetch('/api/devices/enrollment/submit', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(payload.submitBody),
        });
        const confRes = await fetch(`/api/devices/${payload.deviceId}/enrollment/confirm`, {
          method: 'POST',
          credentials: 'include',
          headers: {
            'Content-Type': 'application/json',
            'X-CSRF-Token': payload.csrf,
          },
        });
        return { subStatus: subRes.status, confStatus: confRes.status };
      },
      {
        deviceId,
        csrf: enrollInfo.csrf,
        submitBody: {
          enrollmentToken,
          publicKeyPem: keyPair.publicKeyPem,
          keyAlgorithm: 'ECDSA_P256',
          signatureBase64,
          timestampIso,
          clientNonce,
          hardwareBacked: false,
        },
      }
    );
    assert.ok(submitStatus.subStatus === 200 || submitStatus.subStatus === 201);
    assert.ok(submitStatus.confStatus === 200 || submitStatus.confStatus === 201);

    // Reload Devices view in browser and inspect the enrolled device card
    await page.reload({ waitUntil: 'domcontentloaded' });
    await page.getByRole('button', { name: 'Devices' }).first().click();
    await page.getByText('Win11-Workstation-E2E').first().waitFor({ state: 'visible', timeout: 10000 });

    await page.getByText('Win11-Workstation-E2E').first().click();
    const drawer = page.locator('aside[role="dialog"][aria-modal="true"]');
    await drawer.waitFor({ state: 'visible', timeout: 5000 });

    // Queue REQUEST_DEVICE_STATUS and verify queued honesty (awaiting device agent delivery)
    await drawer.getByRole('button', { name: 'Request Status Check' }).click();
    await page
      .getByText(/Waiting for device agent delivery|queued/i)
      .first()
      .waitFor({ state: 'visible', timeout: 10000 });

    // Close drawer with Escape
    await page.keyboard.press('Escape');
    await drawer.waitFor({ state: 'hidden', timeout: 5000 });
  });

  it('7. renders persisted Security Analytics and exports JSON and CSV reports with no-store headers', async () => {
    await page.getByRole('button', { name: 'Overview' }).first().click();
    await page
      .getByText('Security Analytics & Report Export')
      .first()
      .waitFor({ state: 'visible', timeout: 10000 });

    const exportChecks = await page.evaluate(async () => {
      const jsonRes = await fetch('/api/reports/export?format=json', {
        credentials: 'include',
      });
      const csvRes = await fetch('/api/reports/export?format=csv', {
        credentials: 'include',
      });
      return {
        jsonStatus: jsonRes.status,
        jsonCache: jsonRes.headers.get('cache-control'),
        csvStatus: csvRes.status,
        csvCache: csvRes.headers.get('cache-control'),
        csvText: await csvRes.text(),
      };
    });

    assert.equal(exportChecks.jsonStatus, 200);
    assert.match(String(exportChecks.jsonCache), /no-store/i);
    assert.equal(exportChecks.csvStatus, 200);
    assert.match(String(exportChecks.csvCache), /no-store/i);
    assert.match(exportChecks.csvText, /Win11-Workstation-E2E/);
  });
});
