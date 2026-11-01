import React, { useState, useEffect, useCallback, useMemo, useRef } from 'react';
import {
  ShieldCheck,
  Laptop,
  Smartphone,
  Bell,
  Clock,
  Globe,
  Settings as SettingsIcon,
  Plus,
  Lock,
  Copy,
  Check,
  Eye,
  EyeOff,
  Search,
  User,
  PanelLeftOpen,
  PanelLeftClose,
  MapPin,
  Volume2,
  MessageSquare,
  ShieldAlert,
  Download,
  RefreshCw,
  AlertTriangle,
} from 'lucide-react';
import { AuditChainEntry } from '../packages/security/src/index.ts';
import {
  AllowlistedDeviceActionType,
  AnalyticsSummaryDto,
  DemoEventScenario,
  DeviceActionRecordDto,
  DeviceHeartbeatDto,
  DeviceLocationSummaryDto,
  NotificationItemDto,
  RiskAssessmentDto,
  SecurityActivityItemDto,
  ThreatCheckHistoryPaginationDto,
  ThreatCheckRecordDto,
} from '../packages/shared-types/src/index.ts';
import { MOCK_DEVICES, DEMO_ANALYTICS_SUMMARY } from './data/mockFoundationData.ts';
import {
  VajraCinematicBackground,
  VajraSymbol,
  VajraWordmark,
  StatusBadge,
  PrimaryButton,
  SecondaryButton,
  PageHeader,
  SecuritySection,
  SecurityScore,
  SummaryStrip,
  DeviceCard,
  AlertCard,
  TimelineItem,
  EmptyState,
  DetailDrawer,
  Modal,
  Toast,
  SettingsGroup,
  NotificationBellButton,
  NotificationSlideOverPanel,
} from './components/VajraUiPrimitives.tsx';
import { DeviceBatteryTrendChart } from './components/DeviceBatteryTrendChart.tsx';
import {
  VAJRA_ATMOSPHERE_PRESETS,
  VajraAtmosphereIntensity,
} from './styles/designTokens.ts';
import {
  formatRelativeTime,
  formatClockTime,
  getContextualGreeting,
  formatDeviceLifecycleLabel,
  translateAuditEventToHuman,
  evaluateUrlSafetyPreview,
  ThreatCheckAnalysis,
} from './components/securityCopy.ts';

type NavSection =
  | 'Overview'
  | 'Devices'
  | 'Alerts'
  | 'Activity'
  | 'ThreatCheck'
  | 'Settings';

const PRIMARY_NAV_ITEMS: ReadonlyArray<{
  id: NavSection;
  label: string;
  icon: React.ComponentType<{ className?: string }>;
}> = [
  { id: 'Overview', label: 'Overview', icon: ShieldCheck },
  { id: 'Devices', label: 'Devices', icon: Laptop },
  { id: 'Alerts', label: 'Alerts', icon: Bell },
  { id: 'Activity', label: 'Activity', icon: Clock },
  { id: 'ThreatCheck', label: 'ThreatCheck', icon: Globe },
];

const isStaticHosting =
  typeof window !== 'undefined' &&
  (window.location.hostname.endsWith('github.io') ||
    window.location.hostname.endsWith('.pages.dev') ||
    window.location.pathname.toLowerCase().includes('/vajra'));

interface AuthenticatedUserDto {
  id: string;
  email: string;
  displayName: string;
  status: string;
  mfaEnabled: boolean;
  unusedRecoveryCodesCount?: number;
  createdAt?: string;
  lastLoginAt?: string | null;
}

interface EnrolledDeviceCredentialDto {
  id: string;
  deviceId: string;
  keyAlgorithm: 'ED25519' | 'ECDSA_P256';
  publicKeyFingerprint: string;
  status: 'PENDING_CONFIRMATION' | 'ACTIVE' | 'ROTATED' | 'REVOKED';
  hardwareBacked: boolean;
  active: boolean;
  createdAt: string;
  confirmedAt: string | null;
  rotatedAt: string | null;
  revokedAt: string | null;
}

interface EnrolledDeviceDto {
  id: string;
  userId: string;
  name: string;
  deviceType: 'WINDOWS' | 'ANDROID' | 'UNKNOWN';
  lifecycleState:
    | 'UNREGISTERED'
    | 'ENROLLMENT_PENDING'
    | 'TRUSTED'
    | 'ACTIVE'
    | 'OFFLINE'
    | 'LOST'
    | 'COMPROMISED'
    | 'REVOKED'
    | 'DECOMMISSIONED';
  connectivityStatus: 'ONLINE' | 'OFFLINE' | 'UNKNOWN';
  osVersion: string | null;
  agentVersion: string | null;
  currentRiskScore: number;
  currentRiskLevel: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  publicKeyFingerprint: string | null;
  keyAlgorithm: 'ED25519' | 'ECDSA_P256' | null;
  credentialStatus: 'PENDING_CONFIRMATION' | 'ACTIVE' | 'ROTATED' | 'REVOKED' | null;
  hardwareBacked: boolean;
  lastHeartbeatAt: string | null;
  lastSeenAt: string | null;
  enrolledAt: string | null;
  revokedAt: string | null;
  compromisedAt: string | null;
  createdAt: string;
  updatedAt: string;
  credentials: EnrolledDeviceCredentialDto[];
}

interface InitiatedEnrollmentBundle {
  deviceId: string;
  lifecycleState: string;
  enrollmentToken: string;
  challengeNonce: string;
  expiresAt: string;
  qrCodeDataUrl: string;
}

interface UnifiedDisplayDevice {
  id: string;
  name: string;
  platform: 'WINDOWS' | 'ANDROID' | 'UNKNOWN';
  lifecycleState: EnrolledDeviceDto['lifecycleState'];
  statusLabel: string;
  statusTone: 'protected' | 'warning' | 'critical' | 'neutral';
  statusSummary: string;
  lastSeenLabel: string;
  securityHealthLabel: string;
  networkLabel: string;
  osLabel: string;
  enrolledDateLabel: string;
  hardwareProtected: boolean;
  pendingApproval: boolean;
  publicKeyFingerprint: string | null;
  isDemo: boolean;
}

function arrayBufferToBase64(buffer: ArrayBuffer): string {
  const bytes = new Uint8Array(buffer);
  let binary = '';
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return window.btoa(binary);
}

function arrayBufferToHex(buffer: ArrayBuffer): string {
  const bytes = new Uint8Array(buffer);
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

function formatPemFromSpkiDer(spkiDer: ArrayBuffer): string {
  const b64 = arrayBufferToBase64(spkiDer);
  const lines = b64.match(/.{1,64}/g) ?? [b64];
  return `-----BEGIN PUBLIC KEY-----\n${lines.join('\n')}\n-----END PUBLIC KEY-----`;
}

function p1363ToDerSignature(p1363Buffer: ArrayBuffer): Uint8Array {
  const raw = new Uint8Array(p1363Buffer);
  if (raw.length !== 64) {
    return raw;
  }

  const encodeInt = (slice: Uint8Array): Uint8Array => {
    let start = 0;
    while (start < slice.length - 1 && slice[start] === 0) {
      start++;
    }
    const trimmed = slice.slice(start);
    if (trimmed[0] & 0x80) {
      const padded = new Uint8Array(trimmed.length + 1);
      padded[0] = 0x00;
      padded.set(trimmed, 1);
      return padded;
    }
    return trimmed;
  };

  const r = encodeInt(raw.slice(0, 32));
  const s = encodeInt(raw.slice(32, 64));
  const totalPayloadLen = 2 + r.length + 2 + s.length;
  const der = new Uint8Array(2 + totalPayloadLen);
  let offset = 0;
  der[offset++] = 0x30;
  der[offset++] = totalPayloadLen;
  der[offset++] = 0x02;
  der[offset++] = r.length;
  der.set(r, offset);
  offset += r.length;
  der[offset++] = 0x02;
  der[offset++] = s.length;
  der.set(s, offset);
  return der;
}

const DEFAULT_LOGIN_BG_VIDEO_URL =
  'https://res.cloudinary.com/r67amuba/video/upload/v1791350761/Smooth_transition_between_scenes_20261007104851.mp4';

const LOGIN_BG_VIDEO_URL: string =
  (import.meta.env?.VITE_LOGIN_BG_VIDEO_URL as string | undefined)?.trim() ||
  DEFAULT_LOGIN_BG_VIDEO_URL;

export default function App() {
  const [activeNav, setActiveNav] = useState<NavSection>('Overview');
  const [railExpanded, setRailExpanded] = useState<boolean>(false);

  // Login & Authenticated Console cinematic video background state (Prompt 0009 Part 1, 17, 19)
  const [loginVideoFailed, setLoginVideoFailed] = useState<boolean>(false);
  const [atmosphereEnabled, setAtmosphereEnabled] = useState<boolean>(true);
  const [atmosphereIntensity, setAtmosphereIntensity] =
    useState<VajraAtmosphereIntensity>('balanced');

  // Session & Authentication state (held strictly in memory)
  const [authChecking, setAuthChecking] = useState<boolean>(true);
  const [currentUser, setCurrentUser] = useState<AuthenticatedUserDto | null>(null);
  const [csrfToken, setCsrfToken] = useState<string>('');

  // Login / Create Account UI state
  const [authTab, setAuthTab] = useState<'LOGIN' | 'REGISTER'>('LOGIN');
  const [emailInput, setEmailInput] = useState<string>('');
  const [displayNameInput, setDisplayNameInput] = useState<string>('');
  const [passwordInput, setPasswordInput] = useState<string>('');
  const [confirmPasswordInput, setConfirmPasswordInput] = useState<string>('');
  const [mfaChallengeRequired, setMfaChallengeRequired] = useState<boolean>(false);
  const [useRecoveryCodeMode, setUseRecoveryCodeMode] = useState<boolean>(false);
  const [totpCodeInput, setTotpCodeInput] = useState<string>('');
  const [recoveryCodeInput, setRecoveryCodeInput] = useState<string>('');
  const [authError, setAuthError] = useState<string | null>(null);
  const [authSubmitting, setAuthSubmitting] = useState<boolean>(false);

  // Two-step verification & Recovery codes state
  const [mfaSetupData, setMfaSetupData] = useState<{
    qrCodeDataUrl: string;
    secretBase32: string;
    provisioningUri: string;
  } | null>(null);
  const [showSetupManualKey, setShowSetupManualKey] = useState<boolean>(false);
  const [mfaVerifyCode, setMfaVerifyCode] = useState<string>('');
  const [oneTimeRecoveryCodes, setOneTimeRecoveryCodes] = useState<string[] | null>(null);
  const [copiedRecoveryCodes, setCopiedRecoveryCodes] = useState<boolean>(false);
  const [disableMfaPassword, setDisableMfaPassword] = useState<string>('');
  const [regenCodesPassword, setRegenCodesPassword] = useState<string>('');
  const [showPasswordForm, setShowPasswordForm] = useState<boolean>(false);

  // Password Change state
  const [currentPasswordForChange, setCurrentPasswordForChange] = useState<string>('');
  const [newPasswordForChange, setNewPasswordForChange] = useState<string>('');

  // Toast feedback state
  const [toast, setToast] = useState<{
    message: string;
    tone: 'success' | 'error' | 'info';
  } | null>(null);

  // Security Activity Timeline state
  const [auditEntries, setAuditEntries] = useState<AuditChainEntry[]>([]);
  const [serverActivities, setServerActivities] = useState<SecurityActivityItemDto[]>([]);
  const [auditLoading, setAuditLoading] = useState<boolean>(false);
  const [activityFilter, setActivityFilter] = useState<
    'All' | 'Authentication' | 'Device' | 'Security' | 'ThreatCheck' | 'Recovery'
  >('All');

  // Notifications & Alerts state
  const [notifications, setNotifications] = useState<NotificationItemDto[]>([]);
  const [notificationPanelOpen, setNotificationPanelOpen] = useState<boolean>(false);
  const [alertsFilter, setAlertsFilter] = useState<
    'All' | 'Needs Attention' | 'Security' | 'Devices' | 'Account'
  >('All');
  const [browserAlertPermission, setBrowserAlertPermission] = useState<
    'default' | 'granted' | 'denied' | 'unsupported'
  >(() => {
    if (typeof window === 'undefined' || !('Notification' in window)) {
      return 'unsupported';
    }
    return window.Notification.permission;
  });
  const [browserAlertsEnabled, setBrowserAlertsEnabled] = useState<boolean>(false);

  // Devices & Connect New Device Wizard state
  const [enrolledDevices, setEnrolledDevices] = useState<EnrolledDeviceDto[]>([]);
  const [devicesError, setDevicesError] = useState<string | null>(null);
  const [showSampleDevicePreview, setShowSampleDevicePreview] = useState(false);
  const [devicesLoading, setDevicesLoading] = useState<boolean>(false);
  const [selectedDeviceDrawerId, setSelectedDeviceDrawerId] = useState<string | null>(null);
  const [connectModalOpen, setConnectModalOpen] = useState<boolean>(false);
  const [connectWizardStep, setConnectWizardStep] = useState<1 | 2 | 3>(1);
  const [newDeviceName, setNewDeviceName] = useState<string>('ASUS TUF F16');
  const [newDeviceType, setNewDeviceType] = useState<'WINDOWS' | 'ANDROID'>('WINDOWS');
  const [activeEnrollment, setActiveEnrollment] = useState<InitiatedEnrollmentBundle | null>(null);
  const [enrollmentStepBusy, setEnrollmentStepBusy] = useState<boolean>(false);
  const [pairedReadyDeviceId, setPairedReadyDeviceId] = useState<string | null>(null);
  const [ephemeralDeviceKeys, setEphemeralDeviceKeys] = useState<
    Record<string, { privateKey: CryptoKey; publicKeyPem: string; fingerprint: string }>
  >({});

  // Unified Device Control & Recovery Actions state (Prompt 0007 & Prompt 0008)
  const [deviceActionsByDevice, setDeviceActionsByDevice] = useState<
    Record<string, DeviceActionRecordDto[]>
  >({});
  const [deviceLocationByDevice, setDeviceLocationByDevice] = useState<
    Record<string, DeviceLocationSummaryDto>
  >({});
  const [deviceHeartbeatByDevice, setDeviceHeartbeatByDevice] = useState<
    Record<string, DeviceHeartbeatDto | null>
  >({});
  const [deviceBatteryHistoryByDevice, setDeviceBatteryHistoryByDevice] = useState<
    Record<
      string,
      {
        loading: boolean;
        error: string | null;
        readings: Array<{ timestamp: string; time: string; batteryLevel: number; charging: boolean }>;
        currentLevel: number | null;
        charging: boolean | null;
      }
    >
  >({});
  const [deviceActionBusy, setDeviceActionBusy] = useState<AllowlistedDeviceActionType | null>(
    null
  );
  const [cancellingCommandId, setCancellingCommandId] = useState<string | null>(null);
  const [riskAssessment, setRiskAssessment] = useState<RiskAssessmentDto | null>(null);
  const [demoEventBusyScenario, setDemoEventBusyScenario] = useState<DemoEventScenario | null>(
    null
  );
  const [recoveryModalOpen, setRecoveryModalOpen] = useState<boolean>(false);
  const [recoveryModalMode, setRecoveryModalMode] = useState<'MESSAGE' | 'LOST_MODE'>('MESSAGE');
  const [recoveryTitleInput, setRecoveryTitleInput] = useState<string>(
    'Lost Device — Please Return'
  );
  const [recoveryMessageInput, setRecoveryMessageInput] = useState<string>(
    'This device is protected by VAJRA. Please contact the owner to arrange its safe return.'
  );
  const [recoveryContactInput, setRecoveryContactInput] = useState<string>('');
  /** Pending protected action awaiting MFA step-up (never stores TOTP codes). */
  const [stepUpModalOpen, setStepUpModalOpen] = useState<boolean>(false);
  const [stepUpCodeInput, setStepUpCodeInput] = useState<string>('');
  const [stepUpError, setStepUpError] = useState<string | null>(null);
  const [stepUpSubmitting, setStepUpSubmitting] = useState<boolean>(false);
  const [stepUpRequiredScope, setStepUpRequiredScope] = useState<string | null>(null);
  const [stepUpExplanation, setStepUpExplanation] = useState<string>(
    'This security action needs a fresh verification code from your authenticator app.'
  );
  const pendingProtectedActionRef = useRef<null | {
    kind: 'lifecycle' | 'device_action' | 'queue_command';
    deviceId: string;
    lifecycleAction?: 'revoke' | 'compromised' | 'decommission';
    actionType?: AllowlistedDeviceActionType;
    extraPayload?: Record<string, unknown>;
    requiredScope: string;
    retried: boolean;
  }>(null);
  const [demoActionsByDevice, setDemoActionsByDevice] = useState<
    Record<string, DeviceActionRecordDto[]>
  >({});
  const [demoLostModeByDevice, setDemoLostModeByDevice] = useState<Record<string, boolean>>({});

  // ThreatCheck URL inspection & history state
  const [urlInput, setUrlInput] = useState<string>('');
  const [threatResult, setThreatResult] = useState<ThreatCheckAnalysis | null>(null);
  const [latestThreatCheckRecord, setLatestThreatCheckRecord] =
    useState<ThreatCheckRecordDto | null>(null);
  const [threatInspectBusy, setThreatInspectBusy] = useState<boolean>(false);
  const [threatInspectError, setThreatInspectError] = useState<string | null>(null);
  const [threatHistory, setThreatHistory] = useState<ThreatCheckRecordDto[]>([]);
  const [threatHistoryPagination, setThreatHistoryPagination] =
    useState<ThreatCheckHistoryPaginationDto | null>(null);
  const [threatHistoryLoading, setThreatHistoryLoading] = useState<boolean>(false);
  const [threatHistoryError, setThreatHistoryError] = useState<string | null>(null);
  const [threatHistoryVerdictFilter, setThreatHistoryVerdictFilter] = useState<
    'ALL' | 'LOW RISK' | 'SUSPICIOUS' | 'HIGH RISK'
  >('ALL');
  const [expandedThreatCheckId, setExpandedThreatCheckId] = useState<string | null>(null);

  // Security Analytics Summary & Report Export state
  const [analyticsSummary, setAnalyticsSummary] = useState<AnalyticsSummaryDto | null>(null);
  const [analyticsLoading, setAnalyticsLoading] = useState<boolean>(false);
  const [analyticsError, setAnalyticsError] = useState<string | null>(null);
  const [exportingFormat, setExportingFormat] = useState<'json' | 'csv' | null>(null);
  const [exportError, setExportError] = useState<string | null>(null);

  // Monotonic sequence counters to prevent stale async responses from overwriting newer UI state
  const analyticsRequestSeqRef = useRef<number>(0);
  const threatHistoryRequestSeqRef = useRef<number>(0);
  const threatInspectRequestSeqRef = useRef<number>(0);

  const showToast = useCallback(
    (message: string, tone: 'success' | 'error' | 'info' = 'success') => {
      setToast({ message, tone });
    },
    []
  );

  const closeStepUpModal = useCallback(() => {
    setStepUpModalOpen(false);
    setStepUpCodeInput('');
    setStepUpError(null);
    setStepUpSubmitting(false);
    setStepUpRequiredScope(null);
    pendingProtectedActionRef.current = null;
  }, []);

  const openStepUpForAction = useCallback(
    (
      pending: NonNullable<typeof pendingProtectedActionRef.current>,
      serverMessage?: string
    ) => {
      pendingProtectedActionRef.current = pending;
      setStepUpRequiredScope(pending.requiredScope);
      setStepUpExplanation(
        serverMessage?.trim() ||
          'This security action needs a fresh verification code from your authenticator app.'
      );
      setStepUpCodeInput('');
      setStepUpError(null);
      setStepUpSubmitting(false);
      setStepUpModalOpen(true);
    },
    []
  );

  const handleSessionExpired = useCallback(() => {
    setCurrentUser(null);
    setCsrfToken('');
    setAnalyticsSummary(null);
    setThreatHistory([]);
    setThreatHistoryPagination(null);
    setLatestThreatCheckRecord(null);
    showToast('Your session has expired. Please sign in again.', 'info');
  }, [showToast]);

  const openConnectDeviceModal = useCallback(() => {
    setActiveEnrollment(null);
    setPairedReadyDeviceId(null);
    setConnectWizardStep(1);
    setConnectModalOpen(true);
  }, []);

  const fetchCurrentSession = useCallback(async () => {
    setAuthChecking(true);

    try {
      const saved = sessionStorage.getItem('vajra_demo_session');
      if (saved) {
        const parsed = JSON.parse(saved);
        if (parsed?.id) {
          setCurrentUser(parsed);
          setCsrfToken('demo-csrf-token');
          setShowSampleDevicePreview(true);
          setAuthChecking(false);
          return;
        }
      }
    } catch {
      // Ignore sessionStorage error
    }

    if (isStaticHosting) {
      setCurrentUser(null);
      setAuthChecking(false);
      return;
    }

    try {
      const res = await fetch('/api/auth/me', {
        credentials: 'same-origin',
        headers: { Accept: 'application/json' },
      });
      if (res.ok) {
        const data = (await res.json()) as {
          authenticated: boolean;
          csrfToken: string;
          user: AuthenticatedUserDto;
        };
        setCurrentUser(data.user);
        setCsrfToken(data.csrfToken);
      } else {
        setCurrentUser(null);
        setCsrfToken('');
      }
    } catch {
      setCurrentUser(null);
    } finally {
      setAuthChecking(false);
    }
  }, []);

  const maybeSendBrowserNotification = useCallback(
    (title: string, body: string) => {
      if (
        !browserAlertsEnabled ||
        browserAlertPermission !== 'granted' ||
        typeof window === 'undefined' ||
        !('Notification' in window)
      ) {
        return;
      }
      try {
        new window.Notification(title, {
          body: body.slice(0, 140),
          tag: 'vajra-security-alert',
        });
      } catch {
        // Ignore if browser blocks Notification constructor in sandboxed contexts
      }
    },
    [browserAlertsEnabled, browserAlertPermission]
  );

  const fetchNotifications = useCallback(async () => {
    if (!currentUser) {
      setNotifications([]);
      return;
    }
    if (currentUser.id === 'demo-user-01') {
      setNotifications([
        {
          id: 'demo-notif-1',
          type: 'INFO',
          category: 'System',
          title: 'Console Protection Active',
          message: 'Hardware-backed keystore posture verified for ASUS TUF F16 and Android Phone.',
          createdAt: new Date().toISOString(),
          read: false,
          severity: 'Information',
        } as unknown as NotificationItemDto,
      ]);
      return;
    }
    try {
      const res = await fetch('/api/notifications', {
        credentials: 'same-origin',
        headers: { Accept: 'application/json' },
      });
      const rotatedCsrf = res.headers.get('X-Vajra-Csrf-Token');
      if (rotatedCsrf) setCsrfToken(rotatedCsrf);

      if (res.ok) {
        const data = (await res.json()) as {
          notifications: NotificationItemDto[];
          unreadCount: number;
        };
        setNotifications(data.notifications);
      }
    } catch {
      // Keep existing state on transient error
    }
  }, [currentUser]);

  const fetchAuditTrail = useCallback(async () => {
    if (!currentUser) return;
    if (currentUser.id === 'demo-user-01') {
      setRiskAssessment({
        overallRiskLevel: 'LOW',
        riskScore: 98,
        recommendations: ['All trusted devices healthy. No unauthorized access attempts detected.'],
      } as unknown as RiskAssessmentDto);
      setAuditLoading(false);
      return;
    }
    setAuditLoading(true);
    try {
      const [auditRes, activityRes, riskRes] = await Promise.all([
        fetch('/api/audit', {
          credentials: 'same-origin',
          headers: { Accept: 'application/json' },
        }),
        fetch('/api/activity', {
          credentials: 'same-origin',
          headers: { Accept: 'application/json' },
        }),
        fetch('/api/security/risk', {
          credentials: 'same-origin',
          headers: { Accept: 'application/json' },
        }),
      ]);
      const rotatedCsrf =
        riskRes.headers.get('X-Vajra-Csrf-Token') ??
        activityRes.headers.get('X-Vajra-Csrf-Token') ??
        auditRes.headers.get('X-Vajra-Csrf-Token');
      if (rotatedCsrf) setCsrfToken(rotatedCsrf);

      if (auditRes.ok) {
        const data = (await auditRes.json()) as {
          entries: AuditChainEntry[];
        };
        setAuditEntries(data.entries);
      }
      if (activityRes.ok) {
        const actData = (await activityRes.json()) as {
          activities: SecurityActivityItemDto[];
        };
        setServerActivities(actData.activities);
      }
      if (riskRes.ok) {
        const riskData = (await riskRes.json()) as {
          riskAssessment: RiskAssessmentDto;
        };
        if (riskData.riskAssessment) {
          setRiskAssessment(riskData.riskAssessment);
        }
      }
    } catch {
      // Keep existing state on transient network error
    } finally {
      setAuditLoading(false);
    }
  }, [currentUser]);

  const fetchDeviceActions = useCallback(
    async (deviceId: string, isDemo?: boolean) => {
      if (!currentUser || isDemo) return;
      try {
        const [actionsRes, commandsRes] = await Promise.all([
          fetch(`/api/devices/${deviceId}/actions`, {
            credentials: 'same-origin',
            headers: { Accept: 'application/json' },
          }),
          fetch(`/api/devices/${deviceId}/commands`, {
            credentials: 'same-origin',
            headers: { Accept: 'application/json' },
          }),
        ]);
        const rotatedCsrf =
          commandsRes.headers.get('X-Vajra-Csrf-Token') ??
          actionsRes.headers.get('X-Vajra-Csrf-Token');
        if (rotatedCsrf) setCsrfToken(rotatedCsrf);

        if (commandsRes.ok) {
          const cmdData = (await commandsRes.json()) as {
            commands: DeviceActionRecordDto[];
            latestHeartbeat: DeviceHeartbeatDto | null;
            locationSummary: DeviceLocationSummaryDto;
          };
          setDeviceActionsByDevice((prev) => ({
            ...prev,
            [deviceId]: cmdData.commands,
          }));
          setDeviceHeartbeatByDevice((prev) => ({
            ...prev,
            [deviceId]: cmdData.latestHeartbeat ?? null,
          }));
          if (cmdData.locationSummary) {
            setDeviceLocationByDevice((prev) => ({
              ...prev,
              [deviceId]: cmdData.locationSummary,
            }));
          }
        } else if (actionsRes.ok) {
          const data = (await actionsRes.json()) as {
            actions: DeviceActionRecordDto[];
            locationSummary: DeviceLocationSummaryDto;
          };
          setDeviceActionsByDevice((prev) => ({
            ...prev,
            [deviceId]: data.actions,
          }));
          if (data.locationSummary) {
            setDeviceLocationByDevice((prev) => ({
              ...prev,
              [deviceId]: data.locationSummary,
            }));
          }
        }
      } catch {
        // Ignore transient error
      }
    },
    [currentUser]
  );

  const fetchDeviceBatteryHistory = useCallback(
    async (deviceId: string, isDemo?: boolean) => {
      if (!currentUser || isDemo) return;
      setDeviceBatteryHistoryByDevice((prev) => ({
        ...prev,
        [deviceId]: {
          loading: true,
          error: null,
          readings: prev[deviceId]?.readings ?? [],
          currentLevel: prev[deviceId]?.currentLevel ?? null,
          charging: prev[deviceId]?.charging ?? null,
        },
      }));
      try {
        const res = await fetch(`/api/devices/${encodeURIComponent(deviceId)}/battery-history`, {
          credentials: 'same-origin',
          headers: { Accept: 'application/json' },
        });
        const rotatedCsrf = res.headers.get('X-Vajra-Csrf-Token');
        if (rotatedCsrf) setCsrfToken(rotatedCsrf);

        if (res.ok) {
          const data = (await res.json()) as {
            deviceId: string;
            deviceName: string;
            platform: string;
            currentLevel: number | null;
            charging: boolean | null;
            readings: Array<{ timestamp: string; time: string; batteryLevel: number; charging: boolean }>;
            hasTelemetry: boolean;
          };
          setDeviceBatteryHistoryByDevice((prev) => ({
            ...prev,
            [deviceId]: {
              loading: false,
              error: null,
              readings: data.readings ?? [],
              currentLevel: data.currentLevel,
              charging: data.charging,
            },
          }));
        } else {
          setDeviceBatteryHistoryByDevice((prev) => ({
            ...prev,
            [deviceId]: {
              loading: false,
              error: 'Failed to load battery telemetry history.',
              readings: prev[deviceId]?.readings ?? [],
              currentLevel: prev[deviceId]?.currentLevel ?? null,
              charging: prev[deviceId]?.charging ?? null,
            },
          }));
        }
      } catch {
        setDeviceBatteryHistoryByDevice((prev) => ({
          ...prev,
          [deviceId]: {
            loading: false,
            error: 'Network error loading battery telemetry.',
            readings: prev[deviceId]?.readings ?? [],
            currentLevel: prev[deviceId]?.currentLevel ?? null,
            charging: prev[deviceId]?.charging ?? null,
          },
        }));
      }
    },
    [currentUser]
  );

  const fetchEnrolledDevices = useCallback(async () => {
    if (!currentUser) {
      setEnrolledDevices([]);
      setDevicesError(null);
      return;
    }
    if (currentUser.id === 'demo-user-01') {
      setEnrolledDevices([]);
      setDevicesError(null);
      setShowSampleDevicePreview(true);
      setDevicesLoading(false);
      return;
    }
    setDevicesLoading(true);
    setDevicesError(null);
    try {
      const res = await fetch('/api/devices?includeDecommissioned=true', {
        credentials: 'same-origin',
      });
      const rotated = res.headers.get('X-Vajra-Csrf-Token');
      if (rotated) setCsrfToken(rotated);
      if (!res.ok) {
        setDevicesError('Unable to load your devices. Retry to refresh inventory.');
        return;
      }
      const data = await res.json();
      if (Array.isArray(data.devices)) {
        setEnrolledDevices(data.devices);
      } else {
        setEnrolledDevices([]);
      }
    } catch {
      setDevicesError('Unable to reach the device inventory service.');
    } finally {
      setDevicesLoading(false);
    }
  }, [currentUser]);

  const fetchAnalyticsSummary = useCallback(async () => {
    if (!currentUser) {
      setAnalyticsSummary(null);
      return;
    }
    if (currentUser.id === 'demo-user-01') {
      setAnalyticsSummary(DEMO_ANALYTICS_SUMMARY);
      setAnalyticsLoading(false);
      return;
    }
    const reqId = ++analyticsRequestSeqRef.current;
    setAnalyticsLoading(true);
    setAnalyticsError(null);
    try {
      const res = await fetch('/api/analytics/summary', {
        credentials: 'same-origin',
        headers: { Accept: 'application/json' },
      });
      const rotatedCsrf = res.headers.get('X-Vajra-Csrf-Token');
      if (rotatedCsrf) setCsrfToken(rotatedCsrf);

      if (reqId !== analyticsRequestSeqRef.current) return;

      if (res.status === 401) {
        handleSessionExpired();
        return;
      }

      if (res.ok) {
        const data = (await res.json()) as { summary: AnalyticsSummaryDto };
        if (reqId !== analyticsRequestSeqRef.current) return;
        setAnalyticsSummary(data.summary);
      } else {
        setAnalyticsError('Unable to load security posture analytics right now.');
      }
    } catch {
      if (reqId !== analyticsRequestSeqRef.current) return;
      setAnalyticsError('Unable to reach VAJRA analytics service right now.');
    } finally {
      if (reqId === analyticsRequestSeqRef.current) {
        setAnalyticsLoading(false);
      }
    }
  }, [currentUser, handleSessionExpired]);

  const fetchThreatCheckHistory = useCallback(
    async (options?: {
      verdict?: 'ALL' | 'LOW RISK' | 'SUSPICIOUS' | 'HIGH RISK';
      offset?: number;
      append?: boolean;
    }) => {
      if (!currentUser) {
        setThreatHistory([]);
        setThreatHistoryPagination(null);
        return;
      }
      if (currentUser.id === 'demo-user-01') {
        setThreatHistoryLoading(false);
        return;
      }
      const reqId = ++threatHistoryRequestSeqRef.current;
      const effectiveVerdict = options?.verdict ?? threatHistoryVerdictFilter;
      const effectiveOffset = options?.offset ?? 0;
      const append = Boolean(options?.append);

      setThreatHistoryLoading(true);
      setThreatHistoryError(null);
      try {
        const params = new URLSearchParams({
          limit: '15',
          offset: String(effectiveOffset),
        });
        if (effectiveVerdict !== 'ALL') {
          params.set('verdict', effectiveVerdict);
        }

        const res = await fetch(`/api/threatcheck/history?${params.toString()}`, {
          credentials: 'same-origin',
          headers: { Accept: 'application/json' },
        });
        const rotatedCsrf = res.headers.get('X-Vajra-Csrf-Token');
        if (rotatedCsrf) setCsrfToken(rotatedCsrf);

        if (reqId !== threatHistoryRequestSeqRef.current) return;

        if (res.status === 401) {
          handleSessionExpired();
          return;
        }

        if (res.ok) {
          const data = (await res.json()) as {
            checks: ThreatCheckRecordDto[];
            pagination: ThreatCheckHistoryPaginationDto;
          };
          if (reqId !== threatHistoryRequestSeqRef.current) return;
          setThreatHistory((prev) =>
            append ? [...prev, ...data.checks] : data.checks
          );
          setThreatHistoryPagination(data.pagination);
        } else {
          setThreatHistoryError('Unable to load ThreatCheck history right now.');
        }
      } catch {
        if (reqId !== threatHistoryRequestSeqRef.current) return;
        setThreatHistoryError('Unable to reach ThreatCheck history service right now.');
      } finally {
        if (reqId === threatHistoryRequestSeqRef.current) {
          setThreatHistoryLoading(false);
        }
      }
    },
    [currentUser, threatHistoryVerdictFilter, handleSessionExpired]
  );

  const handleExportReport = useCallback(
    async (format: 'json' | 'csv') => {
      if (!currentUser || exportingFormat !== null) return;
      setExportingFormat(format);
      setExportError(null);
      try {
        const res = await fetch(`/api/reports/export?format=${format}&limit=100`, {
          credentials: 'same-origin',
          headers: {
            Accept: format === 'csv' ? 'text/csv' : 'application/json',
          },
        });
        const rotatedCsrf = res.headers.get('X-Vajra-Csrf-Token');
        if (rotatedCsrf) setCsrfToken(rotatedCsrf);

        if (res.status === 401) {
          handleSessionExpired();
          return;
        }

        if (!res.ok) {
          let errMsg = `Could not export ${format.toUpperCase()} security report.`;
          try {
            const errJson = await res.json();
            if (errJson?.error?.message) errMsg = errJson.error.message;
          } catch {
            // Ignore non-JSON error body
          }
          setExportError(errMsg);
          showToast(errMsg, 'error');
          return;
        }

        const blob = await res.blob();
        const disposition = res.headers.get('Content-Disposition') ?? '';
        const filenameMatch = /filename="([^"]+)"/i.exec(disposition);
        const dateStamp = new Date().toISOString().slice(0, 10);
        const filename =
          filenameMatch?.[1] ?? `vajra-security-report-${dateStamp}.${format}`;

        const objectUrl = window.URL.createObjectURL(blob);
        const anchor = document.createElement('a');
        anchor.href = objectUrl;
        anchor.download = filename;
        document.body.appendChild(anchor);
        anchor.click();
        anchor.remove();
        window.URL.revokeObjectURL(objectUrl);

        showToast(`Downloaded ${filename}.`);
        await fetchAuditTrail();
      } catch {
        const msg = `Unable to download ${format.toUpperCase()} security report right now.`;
        setExportError(msg);
        showToast(msg, 'error');
      } finally {
        setExportingFormat(null);
      }
    },
    [currentUser, exportingFormat, showToast, fetchAuditTrail, handleSessionExpired]
  );

  useEffect(() => {
    void fetchCurrentSession();
  }, [fetchCurrentSession]);

  useEffect(() => {
    if (currentUser) {
      void fetchEnrolledDevices();
      void fetchAuditTrail();
      void fetchNotifications();
      void fetchAnalyticsSummary();
      void fetchThreatCheckHistory();
    }
  }, [
    currentUser,
    fetchEnrolledDevices,
    fetchAuditTrail,
    fetchNotifications,
    fetchAnalyticsSummary,
    fetchThreatCheckHistory,
  ]);

  // Lightweight background refresh of live security state every 30s when authenticated
  useEffect(() => {
    if (!currentUser) return;
    const interval = window.setInterval(() => {
      void fetchEnrolledDevices();
      void fetchAuditTrail();
      void fetchNotifications();
      void fetchAnalyticsSummary();
    }, 30000);
    return () => window.clearInterval(interval);
  }, [
    currentUser,
    fetchEnrolledDevices,
    fetchAuditTrail,
    fetchNotifications,
    fetchAnalyticsSummary,
  ]);

  useEffect(() => {
    if (selectedDeviceDrawerId && currentUser) {
      const isSample = enrolledDevices.length === 0 || selectedDeviceDrawerId.startsWith('mock-');
      void fetchDeviceActions(selectedDeviceDrawerId, isSample);
      if (!isSample) {
        void fetchDeviceBatteryHistory(selectedDeviceDrawerId, false);
      }
    }
  }, [
    selectedDeviceDrawerId,
    currentUser,
    enrolledDevices.length,
    fetchDeviceActions,
    fetchDeviceBatteryHistory,
  ]);

  // Unified Device list: shows real enrolled devices, or calm Demo Devices if none enrolled yet
  const unifiedDevices: UnifiedDisplayDevice[] = useMemo(() => {
    if (enrolledDevices.length > 0) {
      return enrolledDevices.map((dev) => {
        const lifecycleInfo = formatDeviceLifecycleLabel(dev.lifecycleState);
        const pendingApproval =
          dev.lifecycleState === 'ENROLLMENT_PENDING' &&
          dev.credentialStatus === 'PENDING_CONFIRMATION';

        return {
          id: dev.id,
          name: dev.name,
          platform: dev.deviceType,
          lifecycleState: dev.lifecycleState,
          statusLabel: pendingApproval ? 'Ready for approval' : lifecycleInfo.label,
          statusTone: pendingApproval ? 'warning' : lifecycleInfo.tone,
          statusSummary: pendingApproval
            ? 'This device verified its identity and is waiting for your confirmation.'
            : lifecycleInfo.summary,
          lastSeenLabel: dev.lastSeenAt
            ? formatRelativeTime(dev.lastSeenAt)
            : dev.enrolledAt
            ? formatRelativeTime(dev.enrolledAt)
            : 'Just now',
          securityHealthLabel:
            dev.lifecycleState === 'COMPROMISED'
              ? 'Review required'
              : dev.lifecycleState === 'REVOKED'
              ? 'Disconnected'
              : 'Healthy',
          networkLabel: (() => {
            if (dev.lifecycleState === 'REVOKED' || dev.lifecycleState === 'DECOMMISSIONED') {
              return 'Disconnected';
            }
            if (dev.lifecycleState === 'ENROLLMENT_PENDING') {
              return 'Awaiting confirmation';
            }
            const hb = dev.lastHeartbeatAt ? Date.parse(dev.lastHeartbeatAt) : NaN;
            if (!Number.isNaN(hb)) {
              const ageMin = (Date.now() - hb) / 60000;
              // Android WorkManager min period ~15m; Windows agent ~1m — use platform-aware windows
              const connectedMax = dev.deviceType === 'ANDROID' ? 20 : 5;
              const staleMax = dev.deviceType === 'ANDROID' ? 90 : 30;
              if (ageMin <= connectedMax) return 'Agent connected';
              if (ageMin <= staleMax) return 'Heartbeat stale';
              return 'Agent offline';
            }
            if (dev.connectivityStatus === 'ONLINE') return 'Marked online';
            if (dev.connectivityStatus === 'OFFLINE') return 'Offline';
            return 'No agent heartbeat yet';
          })(),
          osLabel:
            dev.osVersion ?? (dev.deviceType === 'WINDOWS' ? 'Windows 11' : 'Android'),
          enrolledDateLabel: dev.enrolledAt
            ? new Date(dev.enrolledAt).toLocaleDateString([], {
                month: 'short',
                day: 'numeric',
                year: 'numeric',
              })
            : 'Pending setup',
          hardwareProtected: dev.hardwareBacked,
          pendingApproval,
          publicKeyFingerprint: dev.publicKeyFingerprint,
          isDemo: false,
        };
      });
    }

    // Never present sample devices as the real inventory.
    // Optional explicit preview is rendered in a separate labeled section.
    return [];
  }, [enrolledDevices]);

  const selectedDrawerDevice = useMemo(() => {
    const found = unifiedDevices.find((d) => d.id === selectedDeviceDrawerId);
    if (found) return found;
    const mock = MOCK_DEVICES.find((m) => m.id === selectedDeviceDrawerId);
    if (mock) {
      return {
        id: mock.id,
        name: `${mock.name} (Sample)`,
        platform: mock.type === 'WINDOWS' ? ('WINDOWS' as const) : ('ANDROID' as const),
        lifecycleState: 'ACTIVE' as const,
        statusLabel: 'Sample only',
        statusTone: 'neutral' as const,
        statusSummary: 'Preview sample device for UI layout and telemetry verification.',
        lastSeenLabel: 'Sample check-in',
        securityHealthLabel: 'Healthy',
        networkLabel: 'Agent connected (Sample)',
        osLabel: mock.osVersion,
        enrolledDateLabel: 'Oct 6, 2026',
        hardwareProtected: true,
        pendingApproval: false,
        publicKeyFingerprint: mock.publicKeyFingerprint,
        isDemo: true,
      };
    }
    return null;
  }, [unifiedDevices, selectedDeviceDrawerId]);

  // Translate audit entries + server activity into calm, human-readable activity items
  const translatedActivities = useMemo(() => {
    if (serverActivities.length > 0) {
      return serverActivities.map((act) => {
        const uiCategory:
          | 'Authentication'
          | 'Device'
          | 'Security'
          | 'ThreatCheck'
          | 'Recovery' = act.category;
        const uiSeverity: 'Healthy' | 'Information' | 'Attention' | 'Critical' =
          act.severity === 'CRITICAL' || act.severity === 'HIGH'
            ? 'Critical'
            : act.severity === 'WARNING' || act.severity === 'ATTENTION'
            ? 'Attention'
            : act.severity === 'PROTECTED'
            ? 'Healthy'
            : 'Information';

        return {
          id: act.id,
          deviceId: act.deviceId ?? undefined,
          deviceName: act.deviceName ?? undefined,
          title: act.title,
          subtitle: act.subtitle,
          description: act.description,
          category: uiCategory,
          severity: uiSeverity,
          relativeTime: formatRelativeTime(act.timestamp),
          clockTime: formatClockTime(act.timestamp),
        };
      });
    }

    return auditEntries.map((entry) => {
      const deviceName =
        typeof entry.metadata?.deviceName === 'string' &&
        entry.metadata.deviceName.trim().length > 0
          ? entry.metadata.deviceName
          : undefined;
      const human = translateAuditEventToHuman(
        entry.eventType,
        entry.timestamp,
        entry.metadata
      );
      const mappedCategory:
        | 'Authentication'
        | 'Device'
        | 'Security'
        | 'ThreatCheck'
        | 'Recovery' =
        human.category === 'Protection' ? 'Security' : human.category;

      return {
        id: entry.id,
        deviceId:
          typeof entry.metadata?.deviceId === 'string'
            ? entry.metadata.deviceId
            : undefined,
        deviceName,
        ...human,
        category: mappedCategory,
      };
    });
  }, [serverActivities, auditEntries]);

  const filteredActivities = useMemo(() => {
    if (activityFilter === 'All') return translatedActivities;
    return translatedActivities.filter((item) => item.category === activityFilter);
  }, [translatedActivities, activityFilter]);

  const unreadNotificationCount = useMemo(
    () => notifications.filter((n) => !n.readAt && !n.dismissedAt).length,
    [notifications]
  );

  // Build unified human-friendly security alerts backed by notifications and device posture
  const securityAlerts = useMemo(() => {
    const list: Array<{
      id: string;
      notificationId?: string;
      category: 'Needs Attention' | 'Security' | 'Devices' | 'Account';
      severity: 'Attention' | 'Critical' | 'Information';
      title: string;
      deviceName: string;
      explanation: string;
      timeLabel: string;
      isRead: boolean;
      actionLabel?: string;
      actionTarget?: string;
      targetNav?: NavSection;
    }> = [];

    for (const notif of notifications) {
      if (notif.dismissedAt) continue;
      const severity: 'Attention' | 'Critical' | 'Information' =
        notif.severity === 'CRITICAL' || notif.severity === 'HIGH'
          ? 'Critical'
          : notif.severity === 'WARNING' || notif.severity === 'ATTENTION'
          ? 'Attention'
          : 'Information';

      list.push({
        id: `notif-${notif.id}`,
        notificationId: notif.id,
        category: notif.category,
        severity,
        title: notif.title,
        deviceName: notif.relatedDeviceName ?? notif.category,
        explanation: notif.message,
        timeLabel: formatRelativeTime(notif.createdAt),
        isRead: Boolean(notif.readAt),
        actionLabel: notif.actionLabel ?? 'Review',
        actionTarget: notif.actionTarget ?? undefined,
      });
    }

    if (
      currentUser &&
      !currentUser.mfaEnabled &&
      !notifications.some((n) => n.type === 'TWO_STEP_RECOMMENDED')
    ) {
      list.push({
        id: 'alert-mfa-recommendation',
        category: 'Needs Attention',
        severity: 'Attention',
        title: 'Two-step verification is not enabled',
        deviceName: 'Account Security',
        explanation:
          'Your account has an additional layer of protection available.',
        timeLabel: 'Recommended',
        isRead: false,
        actionLabel: 'Enable',
        targetNav: 'Settings',
      });
    }

    for (const dev of unifiedDevices) {
      if (
        dev.pendingApproval &&
        !notifications.some((n) => n.relatedDeviceId === dev.id && n.type === 'DEVICE_CONNECTED')
      ) {
        list.push({
          id: `alert-pending-${dev.id}`,
          category: 'Needs Attention',
          severity: 'Attention',
          title: `Approve connection for ${dev.name}`,
          deviceName: dev.name,
          explanation: `${dev.name} completed its security check and is waiting for your approval to join your trusted devices.`,
          timeLabel: dev.lastSeenLabel,
          isRead: false,
          actionLabel: 'Review',
          actionTarget: `device:${dev.id}`,
          targetNav: 'Devices',
        });
      } else if (
        dev.lifecycleState === 'COMPROMISED' &&
        !notifications.some((n) => n.relatedDeviceId === dev.id && n.type === 'DEVICE_COMPROMISED')
      ) {
        list.push({
          id: `alert-compromised-${dev.id}`,
          category: 'Needs Attention',
          severity: 'Critical',
          title: `${dev.name} is paused for security review`,
          deviceName: dev.name,
          explanation:
            'Trusted access for this device is currently paused while you review its recent activity.',
          timeLabel: dev.lastSeenLabel,
          isRead: false,
          actionLabel: 'Inspect',
          actionTarget: `device:${dev.id}`,
          targetNav: 'Devices',
        });
      }
    }

    return list;
  }, [notifications, currentUser, unifiedDevices]);

  const filteredAlerts = useMemo(() => {
    if (alertsFilter === 'All') return securityAlerts;
    if (alertsFilter === 'Needs Attention') {
      return securityAlerts.filter(
        (a) =>
          a.category === 'Needs Attention' ||
          a.severity === 'Attention' ||
          a.severity === 'Critical'
      );
    }
    return securityAlerts.filter((a) => a.category === alertsFilter);
  }, [securityAlerts, alertsFilter]);

  // Calculate overall protection score (0-100) from Deterministic Risk Assessment API when available
  const protectionScore = useMemo(() => {
    if (riskAssessment) {
      return riskAssessment.score;
    }
    let score = 88;
    if (currentUser?.mfaEnabled) score += 8;
    if (
      enrolledDevices.some(
        (d) => d.lifecycleState === 'TRUSTED' || d.lifecycleState === 'ACTIVE'
      )
    ) {
      score += 3;
    }
    if (enrolledDevices.some((d) => d.lifecycleState === 'COMPROMISED')) {
      score -= 22;
    }
    return Math.max(40, Math.min(99, score));
  }, [currentUser, enrolledDevices, riskAssessment]);

  const protectionStatusLabel = useMemo(() => {
    if (riskAssessment) {
      return riskAssessment.status;
    }
    if (enrolledDevices.some((d) => d.lifecycleState === 'COMPROMISED')) {
      return 'HIGH RISK';
    }
    return 'PROTECTED';
  }, [enrolledDevices, riskAssessment]);

  const protectionExplanation = useMemo(() => {
    if (riskAssessment && riskAssessment.recommendations.length > 0) {
      return riskAssessment.recommendations[0];
    }
    return 'No critical threats detected.';
  }, [riskAssessment]);

  const ownerFirstName = useMemo(() => {
    if (!currentUser?.displayName) return 'Owner';
    return currentUser.displayName.trim().split(/\s+/)[0] || 'Owner';
  }, [currentUser]);

  // Interactive Demo / Static Mode Handler
  const handleEnterDemoMode = useCallback((customName?: string, customEmail?: string) => {
    setAuthError(null);
    const name = customName?.trim() || 'Raghuraj';
    const email = customEmail?.trim() || 'raghuraj@vajra.local';
    const userObj: AuthenticatedUserDto = {
      id: 'demo-user-01',
      displayName: name,
      email: email,
      status: 'ACTIVE',
      mfaEnabled: true,
      createdAt: new Date().toISOString(),
      lastLoginAt: new Date().toISOString(),
    };
    try {
      sessionStorage.setItem('vajra_demo_session', JSON.stringify(userObj));
    } catch {
      // Ignore storage exception
    }
    setCurrentUser(userObj);
    setCsrfToken('demo-csrf-token');
    setShowSampleDevicePreview(true);
    showToast(`Welcome to VAJRA, ${name}! Your security console is ready.`);
  }, [showToast]);

  // Authentication Handlers
  const handleRegisterSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setAuthError(null);

    if (passwordInput !== confirmPasswordInput) {
      setAuthError('Passwords do not match.');
      return;
    }

    if (passwordInput.length < 12) {
      setAuthError('Password must be at least 12 characters.');
      return;
    }

    setAuthSubmitting(true);

    if (isStaticHosting) {
      setTimeout(() => {
        setPasswordInput('');
        setConfirmPasswordInput('');
        handleEnterDemoMode(displayNameInput, emailInput);
        setAuthSubmitting(false);
      }, 250);
      return;
    }

    try {
      const res = await fetch('/api/auth/register', {
        method: 'POST',
        credentials: 'same-origin',
        headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
        body: JSON.stringify({
          email: emailInput,
          displayName: displayNameInput,
          password: passwordInput,
        }),
      });

      const data = await res.json();
      if (!res.ok) {
        setAuthError(data?.error?.message ?? 'Could not create your account.');
        return;
      }

      setPasswordInput('');
      setConfirmPasswordInput('');
      setCsrfToken(data.csrfToken ?? '');
      setCurrentUser(data.user);
      showToast('Welcome to VAJRA. Your personal security console is ready.');
    } catch {
      // Backend is unreachable on static hosting like GitHub Pages.
      handleEnterDemoMode(displayNameInput, emailInput);
    } finally {
      setAuthSubmitting(false);
    }
  };

  const handleLoginSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setAuthError(null);
    setAuthSubmitting(true);

    if (isStaticHosting) {
      setTimeout(() => {
        setPasswordInput('');
        setTotpCodeInput('');
        setRecoveryCodeInput('');
        const namePart = emailInput ? emailInput.split('@')[0] : 'Raghuraj';
        handleEnterDemoMode(namePart, emailInput);
        setAuthSubmitting(false);
      }, 250);
      return;
    }

    try {
      const payload: Record<string, string> = {
        email: emailInput,
        password: passwordInput,
      };
      if (mfaChallengeRequired) {
        if (useRecoveryCodeMode) {
          payload.recoveryCode = recoveryCodeInput;
        } else {
          payload.totpCode = totpCodeInput;
        }
      }

      const res = await fetch('/api/auth/login', {
        method: 'POST',
        credentials: 'same-origin',
        headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
        body: JSON.stringify(payload),
      });

      const data = await res.json();
      if (!res.ok) {
        setAuthError(data?.error?.message ?? 'Sign-in could not be completed.');
        return;
      }

      if (data.mfaRequired) {
        setMfaChallengeRequired(true);
        return;
      }

      setPasswordInput('');
      setTotpCodeInput('');
      setRecoveryCodeInput('');
      setMfaChallengeRequired(false);
      setUseRecoveryCodeMode(false);
      setCsrfToken(data.csrfToken ?? '');
      setCurrentUser(data.user);
      showToast('Signed in to your VAJRA security console.');
    } catch {
      // Backend is unreachable on static hosting like GitHub Pages.
      const namePart = emailInput ? emailInput.split('@')[0] : 'Raghuraj';
      handleEnterDemoMode(namePart, emailInput);
    } finally {
      setAuthSubmitting(false);
    }
  };

  const handleLogout = async (revokeAll = false) => {
    try {
      sessionStorage.removeItem('vajra_demo_session');
    } catch {
      // Ignore
    }
    if (!isStaticHosting) {
      try {
        await fetch('/api/auth/logout', {
          method: 'POST',
          credentials: 'same-origin',
          headers: {
            'Content-Type': 'application/json',
            'X-CSRF-Token': csrfToken,
          },
          body: JSON.stringify({ revokeAll }),
        });
      } catch {
        // Ignore
      }
    }
    setCurrentUser(null);
    setCsrfToken('');
    setMfaSetupData(null);
    setOneTimeRecoveryCodes(null);
    setSelectedDeviceDrawerId(null);
    setAnalyticsSummary(null);
    setThreatHistory([]);
    setThreatHistoryPagination(null);
    setLatestThreatCheckRecord(null);
    setThreatResult(null);
    setActiveNav('Overview');
  };

  // Device Connection & Protection Handlers
  const handleInitiateEnrollment = async (e: React.FormEvent) => {
    e.preventDefault();
    setEnrollmentStepBusy(true);

    if (isStaticHosting) {
      setActiveEnrollment({
        id: 'enroll-demo-01',
        token: 'VAJRA-7892-PROV',
        targetPlatform: newDeviceType,
        displayName: newDeviceName || 'My Personal Device',
        expiresAt: new Date(Date.now() + 600000).toISOString(),
        qrDataUrl: '',
      } as unknown as InitiatedEnrollmentBundle);
      setConnectWizardStep(2);
      setEnrollmentStepBusy(false);
      showToast('Static Preview: Simulated pairing code generated. (Run "npm run dev" locally for physical device agents)', 'info');
      return;
    }

    try {
      const res = await fetch('/api/devices/enrollment/initiate', {
        method: 'POST',
        credentials: 'same-origin',
        headers: {
          'Content-Type': 'application/json',
          'X-CSRF-Token': csrfToken,
        },
        body: JSON.stringify({
          proposedDeviceName: newDeviceName,
          expectedDeviceType: newDeviceType,
        }),
      });
      const rotated = res.headers.get('X-Vajra-Csrf-Token');
      if (rotated) setCsrfToken(rotated);

      const data = await res.json();
      if (!res.ok) {
        showToast(data?.error?.message ?? 'Could not create a connection code.', 'error');
        return;
      }

      setActiveEnrollment(data.enrollment);
      setConnectWizardStep(2);
      await Promise.all([
        fetchEnrolledDevices(),
        fetchAuditTrail(),
        fetchAnalyticsSummary(),
      ]);
    } catch {
      showToast('Unable to start device setup right now.', 'error');
    } finally {
      setEnrollmentStepBusy(false);
    }
  };

  const handlePairDeviceWithBrowserCredentials = async (bundle: InitiatedEnrollmentBundle) => {
    setEnrollmentStepBusy(true);
    try {
      const keyPair = await window.crypto.subtle.generateKey(
        { name: 'ECDSA', namedCurve: 'P-256' },
        false,
        ['sign', 'verify']
      );

      const spkiDer = await window.crypto.subtle.exportKey('spki', keyPair.publicKey);
      const publicKeyPem = formatPemFromSpkiDer(spkiDer);
      const digestBuf = await window.crypto.subtle.digest('SHA-256', spkiDer);
      const publicKeyFingerprint = `sha256:${arrayBufferToHex(digestBuf)}`;

      const timestampIso = new Date().toISOString();
      const randomNonceBytes = new Uint8Array(16);
      window.crypto.getRandomValues(randomNonceBytes);
      const clientNonce = Array.from(randomNonceBytes)
        .map((b) => b.toString(16).padStart(2, '0'))
        .join('');

      const transcriptStr = [
        'VAJRA-ENROLL-V1',
        bundle.deviceId.trim(),
        bundle.enrollmentToken.trim().toUpperCase(),
        bundle.challengeNonce.trim(),
        publicKeyFingerprint,
        timestampIso,
        clientNonce,
      ].join('|');

      const rawP1363Sig = await window.crypto.subtle.sign(
        { name: 'ECDSA', hash: { name: 'SHA-256' } },
        keyPair.privateKey,
        new TextEncoder().encode(transcriptStr)
      );
      const derSig = p1363ToDerSignature(rawP1363Sig);
      const signatureBase64 = arrayBufferToBase64(derSig.buffer as ArrayBuffer);

      const res = await fetch('/api/devices/enrollment/submit', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          enrollmentToken: bundle.enrollmentToken,
          keyAlgorithm: 'ECDSA_P256',
          publicKeyPem,
          signatureBase64,
          timestampIso,
          clientNonce,
          hardwareBacked: true,
          osVersion: newDeviceType === 'WINDOWS' ? 'Windows 11 Pro' : 'Android 15',
          agentVersion: '1.0.0',
        }),
      });

      const data = await res.json();
      if (!res.ok) {
        showToast(data?.error?.message ?? 'Device verification could not be completed.', 'error');
        return;
      }

      setEphemeralDeviceKeys((prev) => ({
        ...prev,
        [bundle.deviceId]: {
          privateKey: keyPair.privateKey,
          publicKeyPem,
          fingerprint: publicKeyFingerprint,
        },
      }));
      setPairedReadyDeviceId(bundle.deviceId);
      setConnectWizardStep(3);
      await fetchEnrolledDevices();
      await fetchAuditTrail();
    } catch {
      showToast('Could not complete device verification.', 'error');
    } finally {
      setEnrollmentStepBusy(false);
    }
  };

  const handleConfirmEnrollment = async (deviceId: string, fingerprint: string | null) => {
    try {
      const res = await fetch(`/api/devices/${deviceId}/enrollment/confirm`, {
        method: 'POST',
        credentials: 'same-origin',
        headers: {
          'Content-Type': 'application/json',
          'X-CSRF-Token': csrfToken,
        },
        body: JSON.stringify({
          publicKeyFingerprint: fingerprint ?? undefined,
        }),
      });
      const rotated = res.headers.get('X-Vajra-Csrf-Token');
      if (rotated) setCsrfToken(rotated);

      const data = await res.json();
      if (!res.ok) {
        showToast(data?.error?.message ?? 'Could not approve device.', 'error');
        return;
      }

      setConnectModalOpen(false);
      setActiveEnrollment(null);
      setPairedReadyDeviceId(null);
      showToast(`${data.device.name} is now protected by VAJRA.`);
      await Promise.all([
        fetchEnrolledDevices(),
        fetchAuditTrail(),
        fetchAnalyticsSummary(),
      ]);
    } catch {
      showToast('Unable to approve this device right now.', 'error');
    }
  };

  const handleRunDeviceSecurityCheck = async (deviceId: string) => {
    const localKey = ephemeralDeviceKeys[deviceId];
    if (!localKey) {
      showToast('Security status verified for this device.', 'info');
      return;
    }

    try {
      const timestampIso = new Date().toISOString();
      const nonceBytes = new Uint8Array(16);
      window.crypto.getRandomValues(nonceBytes);
      const nonce = Array.from(nonceBytes)
        .map((b) => b.toString(16).padStart(2, '0'))
        .join('');
      const bodyObj = { ping: 'VAJRA_DEVICE_CHECK' };
      const canonicalBody = JSON.stringify(bodyObj);
      const bodyHashBuf = await window.crypto.subtle.digest(
        'SHA-256',
        new TextEncoder().encode(canonicalBody)
      );
      const payloadHash = arrayBufferToHex(bodyHashBuf);

      const transcript = [
        'VAJRA-DEVICE-AUTH-V1',
        'POST',
        '/api/devices/auth/verify',
        deviceId,
        timestampIso,
        nonce,
        payloadHash,
      ].join('|');

      const rawSig = await window.crypto.subtle.sign(
        { name: 'ECDSA', hash: { name: 'SHA-256' } },
        localKey.privateKey,
        new TextEncoder().encode(transcript)
      );
      const derSig = p1363ToDerSignature(rawSig);
      const signatureBase64 = arrayBufferToBase64(derSig.buffer as ArrayBuffer);

      const res = await fetch('/api/devices/auth/verify', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-Vajra-Device-Id': deviceId,
          'X-Vajra-Timestamp': timestampIso,
          'X-Vajra-Nonce': nonce,
          'X-Vajra-Signature': signatureBase64,
        },
        body: canonicalBody,
      });

      if (!res.ok) {
        showToast('Device check-in could not be verified.', 'error');
        return;
      }

      showToast('Device security check completed and verified.');
      await fetchEnrolledDevices();
      await fetchAuditTrail();
    } catch {
      showToast('Could not complete device security check.', 'error');
    }
  };

  const handleLifecycleAction = async (
    deviceId: string,
    action: 'revoke' | 'compromised' | 'decommission',
    options?: { fromStepUpRetry?: boolean }
  ) => {
    try {
      const res = await fetch(`/api/devices/${deviceId}/${action}`, {
        method: 'POST',
        credentials: 'same-origin',
        headers: {
          'Content-Type': 'application/json',
          'X-CSRF-Token': csrfToken,
        },
        body: JSON.stringify({ reason: `Owner requested ${action} from security console` }),
      });
      const rotated = res.headers.get('X-Vajra-Csrf-Token');
      if (rotated) setCsrfToken(rotated);

      if (res.status === 401) {
        handleSessionExpired();
        showToast('Your session expired. Please sign in again.', 'error');
        closeStepUpModal();
        return;
      }

      const data = await res.json();
      if (!res.ok) {
        if (data?.error?.code === 'STEP_UP_REQUIRED') {
          const scope =
            typeof data?.error?.requiredScope === 'string'
              ? data.error.requiredScope
              : action === 'revoke'
                ? 'DEVICE_REVOKE'
                : action === 'compromised'
                  ? 'DEVICE_COMPROMISED'
                  : 'SENSITIVE_COMMAND';
          if (options?.fromStepUpRetry) {
            showToast(
              data?.error?.message ??
                'Verification was accepted but this action still needs a matching step-up scope. Try again.',
              'error'
            );
            closeStepUpModal();
            return;
          }
          openStepUpForAction(
            {
              kind: 'lifecycle',
              deviceId,
              lifecycleAction: action,
              requiredScope: scope,
              retried: false,
            },
            data?.error?.message
          );
          return;
        }
        showToast(data?.error?.message ?? 'Could not update device protection state.', 'error');
        if (options?.fromStepUpRetry) closeStepUpModal();
        return;
      }

      const messageMap = {
        revoke: `${data.device.name} has been disconnected from your account.`,
        compromised: `${data.device.name} has been paused for security review.`,
        decommission: `${data.device.name} has been archived.`,
      };
      showToast(messageMap[action], 'info');
      setSelectedDeviceDrawerId(null);
      closeStepUpModal();
      await Promise.all([
        fetchEnrolledDevices(),
        fetchAuditTrail(),
        fetchAnalyticsSummary(),
      ]);
    } catch {
      showToast('Unable to update device status right now.', 'error');
      if (options?.fromStepUpRetry) closeStepUpModal();
    }
  };

  const handleStepUpVerify = async () => {
    if (stepUpSubmitting) return;
    const pending = pendingProtectedActionRef.current;
    if (!pending) {
      closeStepUpModal();
      return;
    }
    const code = stepUpCodeInput.replace(/\s+/g, '');
    if (!/^\d{6}$/.test(code)) {
      setStepUpError('Enter the 6-digit code from your authenticator app.');
      return;
    }
    setStepUpSubmitting(true);
    setStepUpError(null);
    try {
      const res = await fetch('/api/auth/step-up', {
        method: 'POST',
        credentials: 'same-origin',
        headers: {
          'Content-Type': 'application/json',
          'X-CSRF-Token': csrfToken,
        },
        body: JSON.stringify({
          totpCode: code,
          actionScope: pending.requiredScope,
        }),
      });
      const rotated = res.headers.get('X-Vajra-Csrf-Token');
      if (rotated) setCsrfToken(rotated);

      if (res.status === 401) {
        const data = await res.json().catch(() => ({}));
        if (data?.error?.code === 'INVALID_TOTP_CODE') {
          setStepUpError(data?.error?.message ?? 'That code was not recognized. Try a new one.');
          setStepUpCodeInput('');
          setStepUpSubmitting(false);
          return;
        }
        handleSessionExpired();
        showToast('Your session expired. Please sign in again.', 'error');
        closeStepUpModal();
        return;
      }

      const data = await res.json().catch(() => ({}));
      if (!res.ok) {
        setStepUpError(data?.error?.message ?? 'Verification failed. Please try again.');
        setStepUpCodeInput('');
        setStepUpSubmitting(false);
        return;
      }

      // Clear code immediately after success; do not retain TOTP in state
      setStepUpCodeInput('');
      setStepUpError(null);

      // Safe single retry of the original protected operation
      if (pending.retried) {
        showToast('Verification succeeded. Please retry the action manually.', 'info');
        closeStepUpModal();
        return;
      }
      pending.retried = true;
      pendingProtectedActionRef.current = pending;

      if (pending.kind === 'lifecycle' && pending.lifecycleAction) {
        await handleLifecycleAction(pending.deviceId, pending.lifecycleAction, {
          fromStepUpRetry: true,
        });
      } else if (pending.kind === 'device_action' && pending.actionType) {
        const device =
          unifiedDevices.find((d) => d.id === pending.deviceId) ||
          (selectedDrawerDevice?.id === pending.deviceId ? selectedDrawerDevice : null);
        if (!device) {
          showToast('Device is no longer available. Please try the action again.', 'error');
          closeStepUpModal();
          return;
        }
        await handleExecuteDeviceAction(device, pending.actionType, {
          ...(pending.extraPayload ?? {}),
          __fromStepUpRetry: true,
        });
      } else if (pending.kind === 'queue_command' && pending.actionType) {
        const device =
          unifiedDevices.find((d) => d.id === pending.deviceId) ||
          (selectedDrawerDevice?.id === pending.deviceId ? selectedDrawerDevice : null);
        if (!device) {
          showToast('Device is no longer available. Please try the action again.', 'error');
          closeStepUpModal();
          return;
        }
        await handleQueueCommandForAgent(device, pending.actionType, {
          fromStepUpRetry: true,
        });
      } else {
        closeStepUpModal();
      }
    } catch {
      setStepUpError('Network error. Check your connection and try again.');
      setStepUpCodeInput('');
    } finally {
      setStepUpSubmitting(false);
    }
  };

  // Account Settings & Two-Step Verification Handlers
  const handleStartMfaSetup = async () => {

    setOneTimeRecoveryCodes(null);
    try {
      const res = await fetch('/api/auth/mfa/setup', {
        method: 'POST',
        credentials: 'same-origin',
        headers: {
          'Content-Type': 'application/json',
          'X-CSRF-Token': csrfToken,
        },
      });
      const rotated = res.headers.get('X-Vajra-Csrf-Token');
      if (rotated) setCsrfToken(rotated);

      const data = await res.json();
      if (!res.ok) {
        showToast(data?.error?.message ?? 'Could not start two-step verification setup.', 'error');
        return;
      }

      setMfaSetupData({
        qrCodeDataUrl: data.qrCodeDataUrl,
        secretBase32: data.secretBase32,
        provisioningUri: data.provisioningUri,
      });
      setShowSetupManualKey(false);
    } catch {
      showToast('Unable to start authenticator setup right now.', 'error');
    }
  };

  const handleVerifyMfaSetup = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      const res = await fetch('/api/auth/mfa/verify', {
        method: 'POST',
        credentials: 'same-origin',
        headers: {
          'Content-Type': 'application/json',
          'X-CSRF-Token': csrfToken,
        },
        body: JSON.stringify({ code: mfaVerifyCode }),
      });
      const rotated = res.headers.get('X-Vajra-Csrf-Token');
      if (rotated) setCsrfToken(rotated);

      const data = await res.json();
      if (!res.ok) {
        showToast(data?.error?.message ?? 'Verification code was not recognized.', 'error');
        return;
      }

      setMfaSetupData(null);
      setMfaVerifyCode('');
      setOneTimeRecoveryCodes(data.recoveryCodes ?? []);
      showToast('Two-step verification is now active on your account.');
      await fetchCurrentSession();
      await fetchAuditTrail();
    } catch {
      showToast('Unable to verify code right now.', 'error');
    }
  };

  const handleDisableMfa = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      const res = await fetch('/api/auth/mfa/disable', {
        method: 'POST',
        credentials: 'same-origin',
        headers: {
          'Content-Type': 'application/json',
          'X-CSRF-Token': csrfToken,
        },
        body: JSON.stringify({ currentPassword: disableMfaPassword }),
      });
      const rotated = res.headers.get('X-Vajra-Csrf-Token');
      if (rotated) setCsrfToken(rotated);

      const data = await res.json();
      if (!res.ok) {
        showToast(data?.error?.message ?? 'Could not turn off two-step verification.', 'error');
        return;
      }

      setDisableMfaPassword('');
      setOneTimeRecoveryCodes(null);
      showToast('Two-step verification has been turned off.', 'info');
      await fetchCurrentSession();
      await fetchAuditTrail();
    } catch {
      showToast('Unable to update two-step verification right now.', 'error');
    }
  };

  const handleRegenerateRecoveryCodes = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      const res = await fetch('/api/auth/recovery-codes/regenerate', {
        method: 'POST',
        credentials: 'same-origin',
        headers: {
          'Content-Type': 'application/json',
          'X-CSRF-Token': csrfToken,
        },
        body: JSON.stringify({ currentPassword: regenCodesPassword }),
      });
      const rotated = res.headers.get('X-Vajra-Csrf-Token');
      if (rotated) setCsrfToken(rotated);

      const data = await res.json();
      if (!res.ok) {
        showToast(data?.error?.message ?? 'Could not create new backup codes.', 'error');
        return;
      }

      setRegenCodesPassword('');
      setOneTimeRecoveryCodes(data.recoveryCodes ?? []);
      showToast('Created 8 new backup recovery codes. Older codes are now retired.');
      await fetchCurrentSession();
      await fetchAuditTrail();
    } catch {
      showToast('Unable to refresh backup codes right now.', 'error');
    }
  };

  const handlePasswordChange = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      const res = await fetch('/api/auth/password/change', {
        method: 'POST',
        credentials: 'same-origin',
        headers: {
          'Content-Type': 'application/json',
          'X-CSRF-Token': csrfToken,
        },
        body: JSON.stringify({
          currentPassword: currentPasswordForChange,
          newPassword: newPasswordForChange,
        }),
      });
      const rotated = res.headers.get('X-Vajra-Csrf-Token');
      if (rotated) setCsrfToken(rotated);

      const data = await res.json();
      if (!res.ok) {
        showToast(data?.error?.message ?? 'Could not update your password.', 'error');
        return;
      }

      setCurrentPasswordForChange('');
      setNewPasswordForChange('');
      setShowPasswordForm(false);
      showToast('Your password was updated and other active sessions were signed out.');
      await fetchAuditTrail();
    } catch {
      showToast('Unable to update your password right now.', 'error');
    }
  };

  const handleMarkNotificationRead = async (notificationId: string) => {
    try {
      const res = await fetch(`/api/notifications/${notificationId}/read`, {
        method: 'POST',
        credentials: 'same-origin',
        headers: {
          'Content-Type': 'application/json',
          'X-CSRF-Token': csrfToken,
        },
      });
      const rotated = res.headers.get('X-Vajra-Csrf-Token');
      if (rotated) setCsrfToken(rotated);
      if (res.ok) {
        await fetchNotifications();
      }
    } catch {
      // Ignore transient error
    }
  };

  const handleMarkAllNotificationsRead = async () => {
    try {
      const res = await fetch('/api/notifications/read-all', {
        method: 'POST',
        credentials: 'same-origin',
        headers: {
          'Content-Type': 'application/json',
          'X-CSRF-Token': csrfToken,
        },
      });
      const rotated = res.headers.get('X-Vajra-Csrf-Token');
      if (rotated) setCsrfToken(rotated);
      if (res.ok) {
        await fetchNotifications();
      }
    } catch {
      // Ignore transient error
    }
  };

  const handleDismissNotification = async (notificationId: string) => {
    try {
      const res = await fetch(`/api/notifications/${notificationId}/dismiss`, {
        method: 'POST',
        credentials: 'same-origin',
        headers: {
          'Content-Type': 'application/json',
          'X-CSRF-Token': csrfToken,
        },
      });
      const rotated = res.headers.get('X-Vajra-Csrf-Token');
      if (rotated) setCsrfToken(rotated);
      if (res.ok) {
        await fetchNotifications();
      }
    } catch {
      // Ignore transient error
    }
  };

  const handleNavigateTarget = (target: string | null | undefined) => {
    setNotificationPanelOpen(false);
    if (!target) return;
    if (target.startsWith('device:')) {
      const devId = target.slice('device:'.length);
      setActiveNav('Devices');
      setSelectedDeviceDrawerId(devId);
    } else if (target === 'devices:connect') {
      openConnectDeviceModal();
    } else if (target === 'devices') {
      setActiveNav('Devices');
    } else if (target === 'settings:security') {
      setActiveNav('Settings');
    } else if (target === 'threat-check') {
      setActiveNav('ThreatCheck');
    } else if (target === 'activity') {
      setActiveNav('Activity');
    }
  };

  const handleEnableBrowserAlerts = async () => {
    if (typeof window === 'undefined' || !('Notification' in window)) {
      setBrowserAlertPermission('unsupported');
      return;
    }
    try {
      const permission = await window.Notification.requestPermission();
      setBrowserAlertPermission(permission);
      if (permission === 'granted') {
        setBrowserAlertsEnabled(true);
        showToast('Browser security alerts are now enabled.');
      } else {
        setBrowserAlertsEnabled(false);
        showToast('Browser notification permission was not granted.', 'info');
      }
    } catch {
      showToast('Browser notifications could not be enabled in this environment.', 'info');
    }
  };

  const handleExecuteDeviceAction = async (
    device: UnifiedDisplayDevice,
    actionType: AllowlistedDeviceActionType,
    extraPayload?: {
      title?: string;
      message?: string;
      contactInstruction?: string;
      __fromStepUpRetry?: boolean;
      [key: string]: unknown;
    }
  ) => {
    setDeviceActionBusy(actionType);
    try {
      if (device.isDemo) {
        const nowIso = new Date().toISOString();
        let statusMessage = 'Action completed on sample device.';
        if (actionType === 'REQUEST_LOCATION') {
          statusMessage =
            device.platform === 'ANDROID'
              ? 'Permission-based device location: Verified device area · Within ~25m'
              : 'Approximate network location: Protected home/office network';
          setDeviceLocationByDevice((prev) => ({
            ...prev,
            [device.id]: {
              accuracyMode:
                device.platform === 'ANDROID'
                  ? 'PERMISSION_AVAILABLE'
                  : 'APPROXIMATE_NETWORK',
              label:
                device.platform === 'ANDROID'
                  ? 'Permission-based device location'
                  : 'Approximate network location',
              regionSummary:
                device.platform === 'ANDROID'
                  ? 'Verified device area · Within ~25m'
                  : 'Protected home/office network · City-level estimate',
              sourceLabel:
                device.platform === 'ANDROID'
                  ? 'Android Location Services (with owner permission)'
                  : 'Encrypted network check-in summary',
              updatedAt: nowIso,
            },
          }));
        } else if (actionType === 'RING_DEVICE') {
          statusMessage =
            device.platform === 'ANDROID'
              ? `Playing high-volume recovery sound on ${device.name} for 60 seconds.`
              : `Audible recovery chime requested on ${device.name}.`;
        } else if (actionType === 'DISPLAY_RECOVERY_MESSAGE') {
          statusMessage = `Recovery message "${
            extraPayload?.title ?? recoveryTitleInput
          }" prepared for ${device.name}.`;
        } else if (actionType === 'ENABLE_LOST_MODE') {
          statusMessage = `Lost Mode is active on ${device.name}. Recovery notice and location updates are enabled.`;
          setDemoLostModeByDevice((prev) => ({ ...prev, [device.id]: true }));
        } else if (actionType === 'DISABLE_LOST_MODE') {
          statusMessage = `Lost Mode turned off on ${device.name}.`;
          setDemoLostModeByDevice((prev) => ({ ...prev, [device.id]: false }));
        }

        const sampleAction: DeviceActionRecordDto = {
          id: `sample-action-${Date.now()}`,
          deviceId: device.id,
          deviceName: device.name,
          issuerUserId: currentUser?.id ?? 'owner',
          actionType,
          status: 'COMPLETED' as DeviceActionRecordDto['status'],
          statusMessage,
          payloadSummary: extraPayload ?? {},
          requestedAt: nowIso,
          completedAt: nowIso,
        };
        setDemoActionsByDevice((prev) => ({
          ...prev,
          [device.id]: [sampleAction, ...(prev[device.id] ?? [])].slice(0, 10),
        }));
        setRecoveryModalOpen(false);
        showToast(statusMessage);
        return;
      }

      const res = await fetch(`/api/devices/${device.id}/actions`, {
        method: 'POST',
        credentials: 'same-origin',
        headers: {
          'Content-Type': 'application/json',
          'X-CSRF-Token': csrfToken,
        },
        body: JSON.stringify({
          actionType,
          title: extraPayload?.title,
          message: extraPayload?.message,
          contactInstruction: extraPayload?.contactInstruction,
        }),
      });
      const rotated = res.headers.get('X-Vajra-Csrf-Token');
      if (rotated) setCsrfToken(rotated);

      if (res.status === 401) {
        handleSessionExpired();
        showToast('Your session expired. Please sign in again.', 'error');
        closeStepUpModal();
        return;
      }

      const data = await res.json();
      if (!res.ok) {
        if (data?.error?.code === 'STEP_UP_REQUIRED') {
          const scope =
            typeof data?.error?.requiredScope === 'string'
              ? data.error.requiredScope
              : 'SENSITIVE_COMMAND';
          if (extraPayload?.__fromStepUpRetry) {
            showToast(
              data?.error?.message ??
                'Verification was accepted but this action still needs step-up. Try again.',
              'error'
            );
            closeStepUpModal();
            return;
          }
          const { __fromStepUpRetry: _ignored, ...safePayload } = (extraPayload ?? {}) as Record<
            string,
            unknown
          > & { __fromStepUpRetry?: boolean };
          openStepUpForAction(
            {
              kind: 'device_action',
              deviceId: device.id,
              actionType,
              extraPayload: safePayload,
              requiredScope: scope,
              retried: false,
            },
            data?.error?.message
          );
          return;
        }
        showToast(data?.error?.message ?? 'Could not complete device action.', 'error');
        return;
      }

      setRecoveryModalOpen(false);
      closeStepUpModal();
      const statusMsg = data.action?.statusMessage ?? 'Device action sent.';
      const status = data.action?.status as string | undefined;
      if (status === 'QUEUED' || status === 'PENDING' || status === 'DELIVERED') {
        showToast(
          statusMsg ||
            `Action requested for ${device.name}. Waiting for the device agent to confirm.`
        );
      } else {
        showToast(statusMsg);
      }
      if (
        actionType === 'ENABLE_LOST_MODE' ||
        actionType === 'RING_DEVICE' ||
        actionType === 'DISPLAY_RECOVERY_MESSAGE'
      ) {
        maybeSendBrowserNotification(
          `VAJRA · ${device.name}`,
          data.action?.statusMessage ?? 'Recovery action updated.'
        );
      }

      await Promise.all([
        fetchEnrolledDevices(),
        fetchDeviceActions(device.id, false),
        fetchAuditTrail(),
        fetchNotifications(),
        fetchAnalyticsSummary(),
      ]);
    } catch {
      showToast('Unable to process device action right now.', 'error');
    } finally {
      setDeviceActionBusy(null);
    }
  };

  const handleQueueCommandForAgent = async (
    device: UnifiedDisplayDevice,
    actionType: AllowlistedDeviceActionType,
    options?: { fromStepUpRetry?: boolean }
  ) => {
    if (device.isDemo) {
      await handleExecuteDeviceAction(device, actionType);
      return;
    }
    setDeviceActionBusy(actionType);
    try {
      const res = await fetch(`/api/devices/${device.id}/commands`, {
        method: 'POST',
        credentials: 'same-origin',
        headers: {
          'Content-Type': 'application/json',
          'X-CSRF-Token': csrfToken,
        },
        body: JSON.stringify({
          actionType,
          ttlMinutes: 60,
        }),
      });
      const rotated = res.headers.get('X-Vajra-Csrf-Token');
      if (rotated) setCsrfToken(rotated);

      if (res.status === 401) {
        handleSessionExpired();
        showToast('Your session expired. Please sign in again.', 'error');
        closeStepUpModal();
        return;
      }

      const data = await res.json();
      if (!res.ok) {
        if (data?.error?.code === 'STEP_UP_REQUIRED') {
          const scope =
            typeof data?.error?.requiredScope === 'string'
              ? data.error.requiredScope
              : 'SENSITIVE_COMMAND';
          if (options?.fromStepUpRetry) {
            showToast(
              data?.error?.message ??
                'Verification was accepted but this command still needs step-up. Try again.',
              'error'
            );
            closeStepUpModal();
            return;
          }
          openStepUpForAction(
            {
              kind: 'queue_command',
              deviceId: device.id,
              actionType,
              requiredScope: scope,
              retried: false,
            },
            data?.error?.message
          );
          return;
        }
        showToast(data?.error?.message ?? 'Could not queue command for device.', 'error');
        return;
      }
      const cmdStatus = data.command?.status as string | undefined;
      if (cmdStatus === 'QUEUED' || cmdStatus === 'PENDING') {
        showToast(
          `Command queued for ${device.name}. Waiting for the device agent to pick it up.`
        );
      } else {
        showToast(data.command?.statusMessage ?? `Protection command sent for ${device.name}.`);
      }
      closeStepUpModal();
      await Promise.all([
        fetchDeviceActions(device.id, false),
        fetchAuditTrail(),
        fetchNotifications(),
        fetchAnalyticsSummary(),
      ]);
    } catch {
      showToast('Unable to queue command right now.', 'error');
      if (options?.fromStepUpRetry) closeStepUpModal();
    } finally {
      setDeviceActionBusy(null);
    }
  };

  const handleCancelQueuedCommand = async (deviceId: string, commandId: string) => {
    setCancellingCommandId(commandId);
    try {
      const res = await fetch(`/api/devices/${deviceId}/commands/${commandId}/cancel`, {
        method: 'POST',
        credentials: 'same-origin',
        headers: {
          'Content-Type': 'application/json',
          'X-CSRF-Token': csrfToken,
        },
      });
      const rotated = res.headers.get('X-Vajra-Csrf-Token');
      if (rotated) setCsrfToken(rotated);

      const data = await res.json();
      if (!res.ok) {
        showToast(data?.error?.message ?? 'Could not cancel command.', 'error');
        return;
      }
      showToast('Queued command cancelled.', 'info');
      await Promise.all([
        fetchDeviceActions(deviceId, false),
        fetchAuditTrail(),
        fetchAnalyticsSummary(),
      ]);
    } catch {
      showToast('Unable to cancel command right now.', 'error');
    } finally {
      setCancellingCommandId(null);
    }
  };

  const handleTriggerDemoEvent = async (scenario: DemoEventScenario) => {
    setDemoEventBusyScenario(scenario);
    try {
      const res = await fetch('/api/demo/events', {
        method: 'POST',
        credentials: 'same-origin',
        headers: {
          'Content-Type': 'application/json',
          'X-CSRF-Token': csrfToken,
        },
        body: JSON.stringify({
          scenario,
          deviceId: enrolledDevices[0]?.id ?? null,
        }),
      });
      const rotated = res.headers.get('X-Vajra-Csrf-Token');
      if (rotated) setCsrfToken(rotated);

      const data = await res.json();
      if (!res.ok) {
        showToast(data?.error?.message ?? 'Could not trigger demo security event.', 'error');
        return;
      }
      if (data.riskAssessment) {
        setRiskAssessment(data.riskAssessment);
      }
      showToast(
        data.event?.title ?? 'Demo security event recorded in Activity & Risk Engine.'
      );
      await Promise.all([
        fetchEnrolledDevices(),
        fetchAuditTrail(),
        fetchNotifications(),
        fetchAnalyticsSummary(),
      ]);
    } catch {
      showToast('Unable to trigger demo security event right now.', 'error');
    } finally {
      setDemoEventBusyScenario(null);
    }
  };

  const handleInspectUrl = async (e: React.FormEvent) => {
    e.preventDefault();
    if (threatInspectBusy) return;
    const trimmedUrl = urlInput.trim();
    if (!trimmedUrl) return;

    const reqId = ++threatInspectRequestSeqRef.current;
    setThreatInspectError(null);
    const localPreview = evaluateUrlSafetyPreview(trimmedUrl);
    setThreatResult(localPreview);

    if (currentUser) {
      setThreatInspectBusy(true);
      try {
        const res = await fetch('/api/threatcheck/inspect', {
          method: 'POST',
          credentials: 'same-origin',
          headers: {
            'Content-Type': 'application/json',
            'X-CSRF-Token': csrfToken,
          },
          body: JSON.stringify({ url: trimmedUrl }),
        });
        const rotated = res.headers.get('X-Vajra-Csrf-Token');
        if (rotated) setCsrfToken(rotated);

        if (reqId !== threatInspectRequestSeqRef.current) return;

        if (res.status === 401) {
          handleSessionExpired();
          return;
        }

        const data = (await res.json()) as {
          analysis?: ThreatCheckAnalysis;
          threatCheck?: ThreatCheckRecordDto;
          error?: { code?: string; message?: string };
        };

        if (reqId !== threatInspectRequestSeqRef.current) return;

        if (!res.ok) {
          const errMessage =
            data?.error?.message ?? 'Please provide a valid HTTP or HTTPS website link.';
          setThreatInspectError(errMessage);
          setLatestThreatCheckRecord(null);
          return;
        }

        if (data.analysis) {
          setThreatResult(data.analysis);
        }
        if (data.threatCheck) {
          setLatestThreatCheckRecord(data.threatCheck);
          if (
            data.threatCheck.verdict === 'HIGH RISK' ||
            data.threatCheck.verdict === 'SUSPICIOUS'
          ) {
            maybeSendBrowserNotification(
              `VAJRA ThreatCheck · ${data.threatCheck.verdict}`,
              data.threatCheck.summary
            );
          }
        }
        await Promise.all([
          fetchThreatCheckHistory({ offset: 0, append: false }),
          fetchAnalyticsSummary(),
          fetchAuditTrail(),
          fetchNotifications(),
        ]);
      } catch {
        if (reqId !== threatInspectRequestSeqRef.current) return;
        setThreatInspectError(
          'Unable to reach ThreatCheck verification service. Showing local lexical preview.'
        );
      } finally {
        if (reqId === threatInspectRequestSeqRef.current) {
          setThreatInspectBusy(false);
        }
      }
    }
  };

  // ============================================================================
  // UNAUTHENTICATED EXPERIENCE — Private Digital Security Console Sign-In
  // ============================================================================
  if (!authChecking && !currentUser) {
    return (
      <div className="relative min-h-screen bg-[#08090B] text-[#F4F1EA] flex flex-col justify-between vajra-ambient-surface overflow-x-hidden">
        {/* Layer 1: Full-Viewport Cinematic Background Video */}
        <div className="login-background-video" aria-hidden="true">
          {!loginVideoFailed && LOGIN_BG_VIDEO_URL.startsWith('https://') && (
            <video
              className="login-background-video-element"
              autoPlay
              loop
              muted
              playsInline
              preload="auto"
              disablePictureInPicture
              controls={false}
              tabIndex={-1}
              aria-hidden="true"
              onError={() => setLoginVideoFailed(true)}
            >
              <source src={LOGIN_BG_VIDEO_URL} type="video/mp4" />
            </video>
          )}
        </div>

        {/* Layer 2: Restrained Dark Obsidian Overlay & Subtle Edge Vignette */}
        <div className="login-background-overlay" aria-hidden="true" />

        {/* Layer 3: Existing VAJRA Login UI */}
        <div className="login-content min-h-screen flex flex-col justify-between">
          {/* Minimal Brand Header */}
          <header className="max-w-6xl w-full mx-auto px-6 py-8 flex items-center justify-between">
            <div className="inline-flex items-center gap-4">
              <VajraSymbol className="w-7 h-7 shrink-0" tone="gold" />
              <div className="flex flex-col">
                <span
                  style={{ fontFamily: "'Cormorant Garamond', Georgia, serif" }}
                  className="font-wordmark text-2xl sm:text-3xl font-semibold uppercase tracking-[0.065em] text-[#F4F1EA] leading-none"
                >
                  VAJRA
                </span>
                <span className="text-[9.5px] font-medium uppercase tracking-[0.22em] text-[#C8A66A]/85 mt-1.5 leading-none">
                  PERSONAL SECURITY
                </span>
              </div>
            </div>
            <StatusBadge tone="protected" label="Private Console" />
          </header>

          {/* Centered Editorial Sign-In / Onboarding Canvas */}
          <main className="flex-1 flex items-center justify-center px-6 py-10">
            <div className="max-w-5xl w-full grid grid-cols-1 lg:grid-cols-12 gap-14 items-center">
              {/* Left Column: Luxury Editorial Brand & Security Narrative */}
              <div className="lg:col-span-6 space-y-7">
                <div className="pb-6 border-b border-[#25282E]/80 space-y-4">
                  <div className="inline-flex items-center gap-5">
                    <div className="w-12 h-12 rounded-xl bg-[#101216] border border-[#25282E] flex items-center justify-center shrink-0">
                      <VajraSymbol className="w-6 h-6" tone="gold" />
                    </div>
                    <div className="flex flex-col">
                      <span
                        style={{ fontFamily: "'Cormorant Garamond', Georgia, serif" }}
                        className="font-wordmark text-4xl sm:text-5xl font-semibold uppercase tracking-[0.065em] text-[#F4F1EA] leading-none"
                      >
                        VAJRA
                      </span>
                      <span className="text-[10.5px] font-medium uppercase tracking-[0.22em] text-[#9499A3] mt-2 leading-none">
                        PERSONAL SECURITY
                      </span>
                    </div>
                  </div>
                </div>

                <h1 className="text-2xl sm:text-4xl font-bold text-[#F4F1EA] font-display tracking-tight leading-[1.16]">
                  Quiet strength for your personal devices.
                </h1>

                <p className="text-sm sm:text-base text-[#9499A3] leading-relaxed">
                  VAJRA protects your Windows PC and Android phone from one calm, private console—giving you clear visibility into device health, sign-in activity, and suspicious links.
                </p>

                <div className="pt-4 border-t border-[#25282E]/80 grid grid-cols-2 gap-8">
                  <div className="space-y-1.5">
                    <div className="text-xs font-semibold text-[#F4F1EA]">Verified Device Trust</div>
                    <p className="text-xs text-[#9499A3] leading-relaxed">
                      Connect your laptop and phone with one-time pairing codes and owner approval.
                    </p>
                  </div>
                  <div className="space-y-1.5">
                    <div className="text-xs font-semibold text-[#F4F1EA]">Two-Step Protection</div>
                    <p className="text-xs text-[#9499A3] leading-relaxed">
                      Safeguard your console with an authenticator app and single-use backup codes.
                    </p>
                  </div>
                </div>
              </div>

              {/* Right Column: Elevated Sign-In / Create Account Surface */}
              <div className="lg:col-span-6">
                <div className="bg-[#101216] vajra-login-card-surface border border-[#25282E] rounded-2xl p-7 sm:p-9 space-y-6 shadow-2xl">
                  <div className="flex items-center justify-between border-b border-[#25282E] pb-4">
                  <div className="flex items-center gap-2">
                    <button
                      type="button"
                      onClick={() => {
                        setAuthTab('LOGIN');
                        setAuthError(null);
                        setMfaChallengeRequired(false);
                      }}
                      className={`px-4 py-2 text-xs font-semibold rounded-lg transition-all cursor-pointer ${
                        authTab === 'LOGIN'
                          ? 'bg-[#15171C] text-[#F4F1EA] border border-[#C8A66A]/45'
                          : 'text-[#9499A3] hover:text-[#F4F1EA]'
                      }`}
                    >
                      Sign In
                    </button>
                    <button
                      type="button"
                      onClick={() => {
                        setAuthTab('REGISTER');
                        setAuthError(null);
                        setMfaChallengeRequired(false);
                      }}
                      className={`px-4 py-2 text-xs font-semibold rounded-lg transition-all cursor-pointer ${
                        authTab === 'REGISTER'
                          ? 'bg-[#15171C] text-[#F4F1EA] border border-[#C8A66A]/45'
                          : 'text-[#9499A3] hover:text-[#F4F1EA]'
                      }`}
                    >
                      Create Account
                    </button>
                  </div>
                  <Lock className="w-4 h-4 text-[#646A74]" aria-hidden="true" />
                </div>

                {authError && (
                  <div
                    role="alert"
                    className="p-3.5 rounded-xl bg-[#15171C] border border-[#C97972]/50 text-xs text-[#C97972]"
                  >
                    {authError}
                  </div>
                )}

                {authTab === 'LOGIN' ? (
                  <form onSubmit={(e) => void handleLoginSubmit(e)} className="space-y-4">
                    <div>
                      <label
                        htmlFor="vajra-login-email"
                        className="block text-xs font-medium text-[#9499A3] mb-1.5"
                      >
                        Email address
                      </label>
                      <input
                        id="vajra-login-email"
                        type="email"
                        required
                        autoComplete="email"
                        value={emailInput}
                        onChange={(e) => setEmailInput(e.target.value)}
                        placeholder="you@example.com"
                        className="w-full px-4 py-2.5 text-sm bg-[#08090B] border border-[#25282E] rounded-lg text-[#F4F1EA] placeholder-[#646A74] focus:outline-none focus:border-[#C8A66A]"
                      />
                    </div>

                    <div>
                      <label
                        htmlFor="vajra-login-password"
                        className="block text-xs font-medium text-[#9499A3] mb-1.5"
                      >
                        Password
                      </label>
                      <input
                        id="vajra-login-password"
                        type="password"
                        required
                        autoComplete="current-password"
                        value={passwordInput}
                        onChange={(e) => setPasswordInput(e.target.value)}
                        placeholder="Enter your password"
                        className="w-full px-4 py-2.5 text-sm bg-[#08090B] border border-[#25282E] rounded-lg text-[#F4F1EA] placeholder-[#646A74] focus:outline-none focus:border-[#C8A66A]"
                      />
                    </div>

                    {mfaChallengeRequired && (
                      <div className="p-4 rounded-xl bg-[#15171C] border border-[#C8A66A]/40 space-y-3">
                        <div className="flex items-center justify-between">
                          <span className="text-xs font-semibold text-[#C8A66A]">
                            Two-Step Verification
                          </span>
                          <button
                            type="button"
                            onClick={() => setUseRecoveryCodeMode((prev) => !prev)}
                            className="text-xs text-[#9499A3] underline hover:text-[#F4F1EA] cursor-pointer"
                          >
                            {useRecoveryCodeMode
                              ? 'Use authenticator code'
                              : 'Use a backup recovery code'}
                          </button>
                        </div>

                        {useRecoveryCodeMode ? (
                          <div>
                            <label
                              htmlFor="vajra-login-recovery"
                              className="block text-xs text-[#9499A3] mb-1"
                            >
                              Backup recovery code
                            </label>
                            <input
                              id="vajra-login-recovery"
                              type="text"
                              required
                              value={recoveryCodeInput}
                              onChange={(e) => setRecoveryCodeInput(e.target.value)}
                              placeholder="XXXX-XXXX"
                              className="w-full px-3.5 py-2 text-sm font-mono bg-[#08090B] border border-[#25282E] rounded-lg text-[#F4F1EA]"
                            />
                          </div>
                        ) : (
                          <div>
                            <label
                              htmlFor="vajra-login-totp"
                              className="block text-xs text-[#9499A3] mb-1"
                            >
                              6-digit code from your authenticator app
                            </label>
                            <input
                              id="vajra-login-totp"
                              type="text"
                              inputMode="numeric"
                              pattern="[0-9]{6}"
                              maxLength={6}
                              required
                              value={totpCodeInput}
                              onChange={(e) => setTotpCodeInput(e.target.value)}
                              placeholder="123456"
                              className="w-full px-3.5 py-2 text-sm font-mono tracking-widest bg-[#08090B] border border-[#25282E] rounded-lg text-[#F4F1EA]"
                            />
                          </div>
                        )}
                      </div>
                    )}

                    <PrimaryButton
                      type="submit"
                      disabled={authSubmitting}
                      className="w-full py-3 text-xs"
                    >
                      {authSubmitting
                        ? 'Signing in...'
                        : mfaChallengeRequired
                        ? 'Verify & Sign In'
                        : 'Sign In to VAJRA'}
                    </PrimaryButton>
                  </form>
                ) : (
                  <form onSubmit={(e) => void handleRegisterSubmit(e)} className="space-y-4">
                    <div>
                      <label
                        htmlFor="vajra-reg-name"
                        className="block text-xs font-medium text-[#9499A3] mb-1.5"
                      >
                        Your name
                      </label>
                      <input
                        id="vajra-reg-name"
                        type="text"
                        required
                        value={displayNameInput}
                        onChange={(e) => setDisplayNameInput(e.target.value)}
                        placeholder="Aarav Sharma"
                        className="w-full px-4 py-2.5 text-sm bg-[#08090B] border border-[#25282E] rounded-lg text-[#F4F1EA] placeholder-[#646A74] focus:outline-none focus:border-[#C8A66A]"
                      />
                    </div>

                    <div>
                      <label
                        htmlFor="vajra-reg-email"
                        className="block text-xs font-medium text-[#9499A3] mb-1.5"
                      >
                        Email address
                      </label>
                      <input
                        id="vajra-reg-email"
                        type="email"
                        required
                        autoComplete="email"
                        value={emailInput}
                        onChange={(e) => setEmailInput(e.target.value)}
                        placeholder="you@example.com"
                        className="w-full px-4 py-2.5 text-sm bg-[#08090B] border border-[#25282E] rounded-lg text-[#F4F1EA] placeholder-[#646A74] focus:outline-none focus:border-[#C8A66A]"
                      />
                    </div>

                    <div>
                      <label
                        htmlFor="vajra-reg-password"
                        className="block text-xs font-medium text-[#9499A3] mb-1.5"
                      >
                        Create password (at least 12 characters)
                      </label>
                      <input
                        id="vajra-reg-password"
                        type="password"
                        required
                        minLength={12}
                        autoComplete="new-password"
                        value={passwordInput}
                        onChange={(e) => setPasswordInput(e.target.value)}
                        placeholder="At least 12 characters"
                        className="w-full px-4 py-2.5 text-sm bg-[#08090B] border border-[#25282E] rounded-lg text-[#F4F1EA] placeholder-[#646A74] focus:outline-none focus:border-[#C8A66A]"
                      />
                    </div>

                    <div>
                      <label
                        htmlFor="vajra-reg-confirm"
                        className="block text-xs font-medium text-[#9499A3] mb-1.5"
                      >
                        Confirm password
                      </label>
                      <input
                        id="vajra-reg-confirm"
                        type="password"
                        required
                        minLength={12}
                        autoComplete="new-password"
                        value={confirmPasswordInput}
                        onChange={(e) => setConfirmPasswordInput(e.target.value)}
                        placeholder="Re-enter your password"
                        className="w-full px-4 py-2.5 text-sm bg-[#08090B] border border-[#25282E] rounded-lg text-[#F4F1EA] placeholder-[#646A74] focus:outline-none focus:border-[#C8A66A]"
                      />
                    </div>

                    <PrimaryButton
                      type="submit"
                      disabled={authSubmitting}
                      className="w-full py-3 text-xs"
                    >
                      {authSubmitting ? 'Creating your console...' : 'Create VAJRA Account'}
                    </PrimaryButton>
                  </form>
                )}

                <div className="pt-2 text-center">
                  <div className="relative my-4">
                    <div className="absolute inset-0 flex items-center">
                      <div className="w-full border-t border-[#25282E]" />
                    </div>
                    <div className="relative flex justify-center text-[10px] uppercase">
                      <span className="bg-[#101216] px-2.5 text-[#646A74] tracking-widest font-mono">
                        Or Explore Directly
                      </span>
                    </div>
                  </div>
                  <button
                    type="button"
                    onClick={() => handleEnterDemoMode(displayNameInput, emailInput)}
                    className="w-full py-2.5 px-4 text-xs font-semibold rounded-lg bg-[#15171C] text-[#C8A66A] hover:bg-[#1C1F26] hover:text-[#E0BE82] border border-[#C8A66A]/35 hover:border-[#C8A66A] transition-all cursor-pointer flex items-center justify-center gap-2"
                  >
                    <ShieldCheck className="w-4 h-4 text-[#C8A66A]" />
                    <span>Explore Demo Console (Instant Access)</span>
                  </button>
                  <p className="mt-2.5 text-[10px] text-[#646A74] leading-relaxed">
                    Live static preview. For hardware agent enrollment & database persistence, run locally with <code className="text-[#9499A3]">npm run dev</code>.
                  </p>
                </div>
              </div>
            </div>
          </div>
        </main>

          <footer className="max-w-6xl w-full mx-auto px-6 py-6 border-t border-[#25282E]/60 flex flex-col sm:flex-row items-center justify-between gap-2 text-xs text-[#646A74]">
            <span>VAJRA — Personal Digital Security</span>
            <span>Privacy-first protection for Windows and Android</span>
          </footer>
        </div>
      </div>
    );
  }

  // ============================================================================
  // AUTHENTICATED CONSOLE SHELL — Adaptive Cinematic Vajra Atmosphere + Smoked Obsidian Surfaces
  // ============================================================================
  return (
    <div className="relative min-h-screen bg-[#08090B] text-[#F4F1EA] flex vajra-ambient-surface">
      {/* 5-Layer Adaptive Cinematic Vajra Atmosphere (Prompt 0009 Part 1 & Part 19) */}
      <VajraCinematicBackground
        videoUrl={LOGIN_BG_VIDEO_URL}
        enabled={atmosphereEnabled}
        intensity={atmosphereIntensity}
        videoFailed={loginVideoFailed}
        onVideoError={() => setLoginVideoFailed(true)}
      />

      {/* Compact Navigation Rail (Desktop) — Part 5: Translucent Sidebar */}
      <aside
        aria-label="Primary Navigation Rail"
        className={`hidden md:flex md:flex-col md:fixed md:inset-y-0 z-40 vajra-sidebar-surface transition-all duration-200 ${
          railExpanded ? 'md:w-56' : 'md:w-[82px]'
        }`}
      >
        {/* Top Brand Symbol + Wordmark when expanded */}
        <div className="h-20 px-5 flex items-center justify-between border-b border-[#F4F1EA]/8">
          <button
            type="button"
            onClick={() => setActiveNav('Overview')}
            aria-label="VAJRA Overview"
            className="flex items-center gap-3.5 text-left cursor-pointer focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[#C79A5A] rounded-lg"
          >
            <div className="w-10 h-10 rounded-xl bg-[#151519]/90 border border-[#F4F1EA]/10 flex items-center justify-center shrink-0">
              <VajraSymbol className="w-5 h-5" tone="gold" />
            </div>
            {railExpanded && <VajraWordmark showSubtitle size="sm" />}
          </button>
        </div>

        {/* Center Primary Navigation Items */}
        <nav className="flex-1 px-3 py-6 space-y-2" aria-label="Main Navigation">
          {PRIMARY_NAV_ITEMS.map((item) => {
            const Icon = item.icon;
            const isActive = activeNav === item.id;
            const alertCount =
              item.id === 'Alerts'
                ? unreadNotificationCount ||
                  securityAlerts.filter((a) => a.severity !== 'Information').length
                : 0;

            return (
              <button
                key={item.id}
                type="button"
                title={item.label}
                aria-label={item.label}
                onClick={() => setActiveNav(item.id)}
                className={`relative w-full flex items-center ${
                  railExpanded ? 'justify-between px-3.5' : 'justify-center px-0'
                } py-3 rounded-xl text-xs font-medium transition-all duration-150 cursor-pointer group focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[#C79A5A] ${
                  isActive
                    ? 'bg-[#151519]/90 text-[#F4F1EA] border border-[#F4F1EA]/8'
                    : 'text-[#A6A8B1] hover:text-[#F4F1EA] hover:bg-[#151519]/50'
                }`}
              >
                {/* Warm Bronze Vertical Active Indicator */}
                {isActive && (
                  <span
                    className="absolute left-0 top-2.5 bottom-2.5 w-[2.5px] rounded-r bg-[#C79A5A]"
                    aria-hidden="true"
                  />
                )}
                <span className="flex items-center gap-3.5">
                  <Icon
                    className={`w-4 h-4 transition-colors ${
                      isActive
                        ? 'text-[#C79A5A]'
                        : 'text-[#6E727D] group-hover:text-[#F4F1EA]'
                    }`}
                  />
                  {railExpanded && <span>{item.label}</span>}
                </span>

                {alertCount > 0 && (
                  <span
                    className={`${
                      railExpanded ? '' : 'absolute top-2 right-3.5'
                    } w-1.5 h-1.5 rounded-full bg-[#D6A15A]`}
                    aria-label={`${alertCount} open alerts`}
                  />
                )}
              </button>
            );
          })}
        </nav>

        {/* Bottom Rail Actions: Settings, Expand/Collapse */}
        <div className="p-3 border-t border-[#F4F1EA]/8 space-y-2">
          <button
            type="button"
            title="Settings"
            aria-label="Settings"
            onClick={() => setActiveNav('Settings')}
            className={`relative w-full flex items-center ${
              railExpanded ? 'justify-start px-3.5 gap-3.5' : 'justify-center'
            } py-3 rounded-xl text-xs font-medium transition-all cursor-pointer ${
              activeNav === 'Settings'
                ? 'bg-[#151519]/90 text-[#F4F1EA] border border-[#F4F1EA]/8'
                : 'text-[#A6A8B1] hover:text-[#F4F1EA] hover:bg-[#151519]/50'
            }`}
          >
            {activeNav === 'Settings' && (
              <span
                className="absolute left-0 top-2.5 bottom-2.5 w-[2.5px] rounded-r bg-[#C79A5A]"
                aria-hidden="true"
              />
            )}
            <SettingsIcon
              className={`w-4 h-4 ${
                activeNav === 'Settings' ? 'text-[#C79A5A]' : 'text-[#6E727D]'
              }`}
            />
            {railExpanded && <span>Settings</span>}
          </button>

          <button
            type="button"
            title={railExpanded ? 'Collapse navigation' : 'Expand navigation'}
            aria-label={railExpanded ? 'Collapse navigation' : 'Expand navigation'}
            onClick={() => setRailExpanded((prev) => !prev)}
            className={`w-full flex items-center ${
              railExpanded ? 'justify-start px-3.5 gap-3.5' : 'justify-center'
            } py-2.5 rounded-xl text-xs text-[#6E727D] hover:text-[#F4F1EA] hover:bg-[#151519]/50 transition-colors cursor-pointer`}
          >
            {railExpanded ? (
              <>
                <PanelLeftClose className="w-4 h-4" />
                <span>Collapse</span>
              </>
            ) : (
              <PanelLeftOpen className="w-4 h-4" />
            )}
          </button>
        </div>
      </aside>

      {/* Main Content Area (Layer 4 & 5: UI Surfaces & Content above Cinematic Atmosphere) */}
      <div
        className={`relative z-10 flex-1 flex flex-col min-h-screen pb-20 md:pb-0 transition-all duration-200 ${
          railExpanded ? 'md:pl-56' : 'md:pl-[82px]'
        }`}
      >
        {/* Part 6: Translucent Top Header Bar */}
        <header className="sticky top-0 z-30 h-20 vajra-header-surface px-6 sm:px-10 flex items-center justify-between gap-4">
          <div className="flex items-center gap-3.5">
            <span className="md:hidden">
              <VajraSymbol className="w-6 h-6" tone="gold" />
            </span>
            <div>
              <div className="text-sm font-semibold text-[#F4F1EA] font-display">
                {getContextualGreeting()}, {ownerFirstName}
              </div>
              <div className="text-xs text-[#A6A8B1]">
                VAJRA is protecting your devices
              </div>
            </div>
          </div>

          <div className="flex items-center gap-3.5 sm:gap-4">
            <div className="hidden sm:block">
              <StatusBadge
                tone={
                  unifiedDevices.some((d) => d.lifecycleState === 'COMPROMISED')
                    ? 'critical'
                    : 'protected'
                }
                label="Protected"
              />
            </div>

            <NotificationBellButton
              unreadCount={unreadNotificationCount}
              onClick={() => setNotificationPanelOpen(true)}
            />

            <PrimaryButton
              onClick={openConnectDeviceModal}
              className="flex items-center gap-1.5"
            >
              <Plus className="w-3.5 h-3.5" />
              <span>Connect Device</span>
            </PrimaryButton>

            <button
              type="button"
              onClick={() => setActiveNav('Settings')}
              title="Profile & Security Settings"
              aria-label="Profile"
              className="flex items-center gap-2 px-3 py-2 rounded-lg bg-[#151519]/80 hover:bg-[#1C1D23] border border-[#F4F1EA]/10 hover:border-[#C79A5A]/30 text-xs font-medium text-[#F4F1EA] transition-colors cursor-pointer"
            >
              <User className="w-3.5 h-3.5 text-[#C79A5A]" />
              <span className="hidden sm:inline">Profile</span>
            </button>
          </div>
        </header>

        {/* Workspace Container */}
        <main className="flex-1 max-w-[1160px] w-full mx-auto px-6 sm:px-10 py-10 space-y-14">
          {toast && (
            <Toast
              message={toast.message}
              tone={toast.tone}
              onDismiss={() => setToast(null)}
            />
          )}

          {/* ================================================================
              PAGE 1: OVERVIEW — Part 8: 01-04 Command Center Hierarchy
              ================================================================ */}
          {activeNav === 'Overview' && (
            <div className="space-y-14">
              {/* 01 · PROTECTION COMMAND CENTER */}
              <section className="space-y-6 pt-1">
                <div className="text-[10px] font-semibold uppercase tracking-[0.22em] text-[#C79A5A]">
                  01 · PROTECTION COMMAND CENTER
                </div>

                <div className="vajra-surface-card rounded-[18px] p-7 sm:p-9 grid grid-cols-1 lg:grid-cols-12 gap-8 items-center">
                  <div className="lg:col-span-7 space-y-4">
                    <div className="inline-flex items-center gap-2.5 text-xs text-[#A6A8B1]">
                      <StatusBadge
                        tone={
                          protectionScore >= 85
                            ? 'protected'
                            : protectionScore >= 65
                            ? 'attention'
                            : 'risk'
                        }
                        label={protectionStatusLabel}
                      />
                      <span>·</span>
                      <span>All security systems nominal</span>
                    </div>
                    <h1 className="text-3xl sm:text-4xl font-bold text-[#F4F1EA] font-display tracking-tight leading-[1.14]">
                      Your digital world is protected.
                    </h1>
                    <p className="text-sm sm:text-base text-[#A6A8B1] max-w-xl leading-relaxed">
                      No critical threats detected across your trusted devices. Continuous verification is active for your Windows and Android hardware.
                    </p>
                    <div className="flex flex-wrap items-center gap-3 pt-2">
                      <PrimaryButton onClick={openConnectDeviceModal}>
                        Connect Device
                      </PrimaryButton>
                      <SecondaryButton onClick={() => setActiveNav('ThreatCheck')}>
                        Inspect a Link
                      </SecondaryButton>
                    </div>
                  </div>

                  <div className="lg:col-span-5 flex justify-center lg:justify-end">
                    <SecurityScore
                      score={protectionScore}
                      status={protectionStatusLabel}
                      explanation={protectionExplanation}
                    />
                  </div>
                </div>

                {/* Smoked Obsidian Metric Strip */}
                <SummaryStrip
                  items={[
                    {
                      label: 'Protected Devices',
                      value: unifiedDevices.filter((d) => d.statusTone === 'protected').length,
                      subtext:
                        enrolledDevices.length > 0
                          ? 'Trusted hardware connected'
                          : 'Sample preview active',
                      tone: 'protected',
                      onClick: () => setActiveNav('Devices'),
                    },
                    {
                      label: 'Security Advisories',
                      value: securityAlerts.filter((a) => a.severity !== 'Information').length,
                      subtext:
                        securityAlerts.filter((a) => a.severity !== 'Information').length === 0
                          ? 'All systems clear'
                          : 'Advisories ready for review',
                      tone:
                        securityAlerts.filter((a) => a.severity !== 'Information').length === 0
                          ? 'protected'
                          : 'attention',
                      onClick: () => setActiveNav('Alerts'),
                    },
                    {
                      label: 'Account Protection',
                      value: currentUser?.mfaEnabled ? 'Two-Step Active' : 'Standard',
                      subtext: currentUser?.mfaEnabled
                        ? 'Authenticator & recovery codes'
                        : 'Two-step verification available',
                      tone: currentUser?.mfaEnabled ? 'protected' : 'attention',
                      onClick: () => setActiveNav('Settings'),
                    },
                    {
                      label: 'Verified Timeline',
                      value: translatedActivities.length || 'Quiet',
                      subtext: 'Recent security events',
                      tone: 'gold',
                      onClick: () => setActiveNav('Activity'),
                    },
                  ]}
                />
              </section>

              {/* 02 · PROTECTED DEVICES */}
              <SecuritySection
                eyebrow="02 · PROTECTED DEVICES"
                title="Your Devices"
                description="Select a device to inspect its security posture, run a protection check, or manage recovery controls."
                action={
                  <SecondaryButton onClick={() => setActiveNav('Devices')}>
                    Manage Devices
                  </SecondaryButton>
                }
              >
                <div className="grid grid-cols-1 md:grid-cols-2 gap-5">
                  {unifiedDevices.slice(0, 4).map((device) => (
                    <DeviceCard
                      key={device.id}
                      name={device.name}
                      platform={device.platform}
                      statusLabel={device.statusLabel}
                      statusTone={device.statusTone}
                      lastSeenLabel={device.lastSeenLabel}
                      securityHealthLabel={device.securityHealthLabel}
                      isDemo={device.isDemo}
                      onSelect={() => setSelectedDeviceDrawerId(device.id)}
                    />
                  ))}
                </div>
              </SecuritySection>

              {/* 03 · SECURITY ADVISORIES */}
              <SecuritySection
                eyebrow="03 · SECURITY ADVISORIES"
                title="Security Advisories"
                description="Actionable recommendations and device posture alerts requiring your review."
                action={
                  <SecondaryButton onClick={() => setActiveNav('Alerts')}>
                    Open Advisory Center
                  </SecondaryButton>
                }
              >
                {securityAlerts.length === 0 ? (
                  <EmptyState
                    title="No active security advisories"
                    description="All connected devices and account credentials meet VAJRA protection standards."
                  />
                ) : (
                  <div className="space-y-3.5">
                    {securityAlerts.slice(0, 2).map((alert) => (
                      <AlertCard
                        key={alert.id}
                        severity={alert.severity}
                        title={alert.title}
                        deviceName={alert.deviceName}
                        explanation={alert.explanation}
                        timeLabel={alert.timeLabel}
                        actionLabel={alert.actionLabel}
                        onReview={() => {
                          if (alert.notificationId) {
                            void handleMarkNotificationRead(alert.notificationId);
                          }
                          if (alert.actionTarget) {
                            handleNavigateTarget(alert.actionTarget);
                          } else if (alert.targetNav) {
                            setActiveNav(alert.targetNav);
                          }
                        }}
                      />
                    ))}
                  </div>
                )}
              </SecuritySection>

              {/* 04 · RECENT SECURITY TIMELINE */}
              <SecuritySection
                eyebrow="04 · RECENT SECURITY TIMELINE"
                title="Recent Security Activity"
                description="Chronological verification of sign-ins, device heartbeats, and protection checks."
                action={
                  <SecondaryButton onClick={() => setActiveNav('Activity')}>
                    View Full Timeline
                  </SecondaryButton>
                }
              >
                {translatedActivities.length === 0 ? (
                  <EmptyState
                    title="Nothing unusual"
                    description="VAJRA hasn't detected any security activity that needs your attention."
                  />
                ) : (
                  <div className="vajra-surface-card rounded-[14px] p-5 sm:p-6">
                    {translatedActivities.slice(0, 5).map((item, idx, arr) => (
                      <TimelineItem
                        key={item.id}
                        clockTime={item.clockTime}
                        title={item.title}
                        subtitle={item.deviceName}
                        description={item.description}
                        severity={item.severity}
                        isLast={idx === arr.length - 1}
                      />
                    ))}
                  </div>
                )}
              </SecuritySection>

              {/* 05 · SECURITY ANALYTICS & REPORT EXPORT */}
              <SecuritySection
                eyebrow="05 · SECURITY ANALYTICS & REPORT EXPORT"
                title="Persisted Security Posture & Reports"
                description="Live account-scoped metrics derived strictly from persisted devices, security events, ThreatCheck inspections, and remote commands."
                action={
                  <div className="flex flex-wrap items-center gap-2">
                    <SecondaryButton
                      disabled={analyticsLoading}
                      onClick={() => void fetchAnalyticsSummary()}
                      className="flex items-center gap-1.5"
                    >
                      <RefreshCw
                        className={`w-3.5 h-3.5 ${analyticsLoading ? 'animate-spin' : ''}`}
                      />
                      <span>{analyticsLoading ? 'Refreshing...' : 'Refresh Analytics'}</span>
                    </SecondaryButton>
                    <SecondaryButton
                      disabled={exportingFormat !== null}
                      onClick={() => void handleExportReport('json')}
                      className="flex items-center gap-1.5"
                    >
                      <Download className="w-3.5 h-3.5" />
                      <span>
                        {exportingFormat === 'json' ? 'Exporting JSON...' : 'Export JSON'}
                      </span>
                    </SecondaryButton>
                    <SecondaryButton
                      disabled={exportingFormat !== null}
                      onClick={() => void handleExportReport('csv')}
                      className="flex items-center gap-1.5"
                    >
                      <Download className="w-3.5 h-3.5" />
                      <span>
                        {exportingFormat === 'csv' ? 'Exporting CSV...' : 'Export CSV'}
                      </span>
                    </SecondaryButton>
                  </div>
                }
              >
                {exportError && (
                  <div
                    role="alert"
                    className="mb-4 p-3.5 rounded-xl bg-[#15171C] border border-[#D06C64]/50 text-xs text-[#D06C64]"
                  >
                    {exportError}
                  </div>
                )}

                {analyticsLoading && !analyticsSummary ? (
                  <div className="vajra-surface-card rounded-[14px] p-6 text-xs text-[#9499A3]">
                    Loading persisted security analytics...
                  </div>
                ) : analyticsError ? (
                  <div
                    role="alert"
                    className="vajra-surface-card rounded-[14px] p-6 border border-[#D06C64]/40 flex flex-col sm:flex-row sm:items-center justify-between gap-4"
                  >
                    <div className="space-y-1">
                      <div className="text-xs font-semibold text-[#D06C64]">
                        Analytics unavailable
                      </div>
                      <p className="text-xs text-[#9499A3]">{analyticsError}</p>
                    </div>
                    <SecondaryButton onClick={() => void fetchAnalyticsSummary()}>
                      Retry
                    </SecondaryButton>
                  </div>
                ) : analyticsSummary ? (
                  <div className="space-y-4">
                    <p className="text-[11px] text-[#646A74] font-mono uppercase tracking-wider">
                      Data source:{' '}
                      {(analyticsSummary as AnalyticsSummaryDto).dataSource === 'SAMPLE'
                        ? 'Sample preview (not live account data)'
                        : 'Persisted account records'}
                      {(analyticsSummary as AnalyticsSummaryDto).windowDescription
                        ? ` · ${(analyticsSummary as AnalyticsSummaryDto).windowDescription.slice(0, 80)}…`
                        : ''}
                    </p>
                    {analyticsSummary.devices.totalCount === 0 &&
                      analyticsSummary.threatChecks.totalCount === 0 &&
                      analyticsSummary.remoteCommands.totalRecentCount === 0 && (
                        <div className="vajra-surface-card rounded-[14px] p-5 border border-[#C79A5A]/25 flex flex-col sm:flex-row sm:items-center justify-between gap-4">
                          <div className="space-y-1">
                            <div className="text-xs font-semibold text-[#F4F1EA]">
                              New account analytics baseline
                            </div>
                            <p className="text-xs text-[#A6A8B1]">
                              No devices enrolled, links inspected, or remote commands issued yet. Connect a device or inspect a URL in ThreatCheck to populate your persisted telemetry.
                            </p>
                          </div>
                          <div className="flex items-center gap-2 shrink-0">
                            <SecondaryButton onClick={openConnectDeviceModal}>
                              Connect Device
                            </SecondaryButton>
                            <SecondaryButton onClick={() => setActiveNav('ThreatCheck')}>
                              Open ThreatCheck
                            </SecondaryButton>
                          </div>
                        </div>
                      )}

                    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
                      {/* Card 1: Enrolled Devices & Hardware Trust */}
                      <div className="vajra-surface-card rounded-[14px] p-5 space-y-3">
                        <div className="flex items-center justify-between">
                          <span className="text-[11px] font-medium uppercase tracking-[0.14em] text-[#A6A8B1]">
                            Enrolled Devices
                          </span>
                          <StatusBadge
                            label={
                              analyticsSummary.devices.totalCount > 0
                                ? `${analyticsSummary.devices.hardwareBackedCount} Hardware-Backed`
                                : 'None Enrolled'
                            }
                            tone={
                              analyticsSummary.devices.totalCount > 0 ? 'protected' : 'neutral'
                            }
                          />
                        </div>
                        <div className="font-display text-2xl font-semibold text-[#F4F1EA] tabular-nums">
                          {analyticsSummary.devices.totalCount}
                        </div>
                        <div className="space-y-1 text-xs text-[#9499A3] pt-1 border-t border-[#F4F1EA]/8">
                          <div className="flex items-center justify-between">
                            <span>Trusted / Active</span>
                            <span className="text-[#F4F1EA] tabular-nums">
                              {(analyticsSummary.devices.byLifecycleState['TRUSTED'] ?? 0) +
                                (analyticsSummary.devices.byLifecycleState['ACTIVE'] ?? 0)}
                            </span>
                          </div>
                          <div className="flex items-center justify-between">
                            <span>Avg device risk score</span>
                            <span className="text-[#F4F1EA] tabular-nums">
                              {analyticsSummary.accountPosture.averageDeviceRiskScore}/100
                            </span>
                          </div>
                        </div>
                      </div>

                      {/* Card 2: Persisted Security Events */}
                      <div className="vajra-surface-card rounded-[14px] p-5 space-y-3">
                        <div className="flex items-center justify-between">
                          <span className="text-[11px] font-medium uppercase tracking-[0.14em] text-[#A6A8B1]">
                            Security Events
                          </span>
                          <StatusBadge
                            label={
                              (analyticsSummary.securityEvents.bySeverity['HIGH'] ?? 0) +
                                (analyticsSummary.securityEvents.bySeverity['CRITICAL'] ?? 0) >
                              0
                                ? 'High Severity Present'
                                : 'Verified'
                            }
                            tone={
                              (analyticsSummary.securityEvents.bySeverity['HIGH'] ?? 0) +
                                (analyticsSummary.securityEvents.bySeverity['CRITICAL'] ?? 0) >
                              0
                                ? 'risk'
                                : 'protected'
                            }
                          />
                        </div>
                        <div className="font-display text-2xl font-semibold text-[#F4F1EA] tabular-nums">
                          {analyticsSummary.securityEvents.totalRecentCount}
                        </div>
                        <div className="space-y-1 text-xs text-[#9499A3] pt-1 border-t border-[#F4F1EA]/8">
                          <div className="flex items-center justify-between">
                            <span>High / Critical</span>
                            <span className="text-[#F4F1EA] tabular-nums">
                              {(analyticsSummary.securityEvents.bySeverity['HIGH'] ?? 0) +
                                (analyticsSummary.securityEvents.bySeverity['CRITICAL'] ?? 0)}
                            </span>
                          </div>
                          <div className="flex items-center justify-between">
                            <span>Warning / Attention</span>
                            <span className="text-[#F4F1EA] tabular-nums">
                              {(analyticsSummary.securityEvents.bySeverity['WARNING'] ?? 0) +
                                (analyticsSummary.securityEvents.bySeverity['ATTENTION'] ?? 0)}
                            </span>
                          </div>
                        </div>
                      </div>

                      {/* Card 3: ThreatCheck Verdicts */}
                      <div className="vajra-surface-card rounded-[14px] p-5 space-y-3">
                        <div className="flex items-center justify-between">
                          <span className="text-[11px] font-medium uppercase tracking-[0.14em] text-[#A6A8B1]">
                            ThreatCheck Verdicts
                          </span>
                          <StatusBadge
                            label={
                              (analyticsSummary.threatChecks.byVerdict['HIGH RISK'] ?? 0) > 0
                                ? `${analyticsSummary.threatChecks.byVerdict['HIGH RISK']} High Risk`
                                : 'Inspected'
                            }
                            tone={
                              (analyticsSummary.threatChecks.byVerdict['HIGH RISK'] ?? 0) > 0
                                ? 'risk'
                                : (analyticsSummary.threatChecks.byVerdict['SUSPICIOUS'] ?? 0) >
                                  0
                                ? 'attention'
                                : 'protected'
                            }
                          />
                        </div>
                        <div className="font-display text-2xl font-semibold text-[#F4F1EA] tabular-nums">
                          {analyticsSummary.threatChecks.totalCount}
                        </div>
                        <div className="space-y-1 text-xs text-[#9499A3] pt-1 border-t border-[#F4F1EA]/8">
                          <div className="flex items-center justify-between">
                            <span>Low / Suspicious / High</span>
                            <span className="text-[#F4F1EA] tabular-nums">
                              {analyticsSummary.threatChecks.byVerdict['LOW RISK'] ?? 0} /{' '}
                              {analyticsSummary.threatChecks.byVerdict['SUSPICIOUS'] ?? 0} /{' '}
                              {analyticsSummary.threatChecks.byVerdict['HIGH RISK'] ?? 0}
                            </span>
                          </div>
                          <div className="flex items-center justify-between">
                            <span>Average link risk</span>
                            <span className="text-[#F4F1EA] tabular-nums">
                              {analyticsSummary.threatChecks.averageRiskScore}/100
                            </span>
                          </div>
                        </div>
                      </div>

                      {/* Card 4: Remote Commands & Alerts */}
                      <div className="vajra-surface-card rounded-[14px] p-5 space-y-3">
                        <div className="flex items-center justify-between">
                          <span className="text-[11px] font-medium uppercase tracking-[0.14em] text-[#A6A8B1]">
                            Command Outcomes
                          </span>
                          <StatusBadge
                            label={`${analyticsSummary.alerts.openUnreadCount} Unread Alerts`}
                            tone={
                              analyticsSummary.alerts.highSeverityUnreadCount > 0
                                ? 'attention'
                                : 'neutral'
                            }
                          />
                        </div>
                        <div className="font-display text-2xl font-semibold text-[#F4F1EA] tabular-nums">
                          {analyticsSummary.remoteCommands.totalRecentCount}
                        </div>
                        <div className="space-y-1 text-xs text-[#9499A3] pt-1 border-t border-[#F4F1EA]/8">
                          <div className="flex items-center justify-between">
                            <span>Completed / Queued</span>
                            <span className="text-[#F4F1EA] tabular-nums">
                              {analyticsSummary.remoteCommands.byStatus['COMPLETED'] ?? 0} /{' '}
                              {(analyticsSummary.remoteCommands.byStatus['QUEUED'] ?? 0) +
                                (analyticsSummary.remoteCommands.byStatus['PENDING'] ?? 0)}
                            </span>
                          </div>
                          <div className="flex items-center justify-between">
                            <span>Failed / Cancelled</span>
                            <span className="text-[#F4F1EA] tabular-nums">
                              {(analyticsSummary.remoteCommands.byStatus['FAILED'] ?? 0) +
                                (analyticsSummary.remoteCommands.byStatus['CANCELLED'] ?? 0)}
                            </span>
                          </div>
                        </div>
                      </div>
                    </div>
                  </div>
                ) : null}
              </SecuritySection>
            </div>
          )}

          {/* ================================================================
              PAGE 2: DEVICES
              ================================================================ */}
          {activeNav === 'Devices' && (
            <div className="space-y-10">
              <PageHeader
                eyebrow="TRUSTED HARDWARE"
                title="Your Devices"
                subtitle="Windows PCs and Android phones protected by your VAJRA account."
                action={
                  <PrimaryButton
                    onClick={openConnectDeviceModal}
                    className="flex items-center gap-1.5"
                  >
                    <Plus className="w-3.5 h-3.5" />
                    <span>Connect Device</span>
                  </PrimaryButton>
                }
              />

              {enrolledDevices.length === 0 && (
                <EmptyState
                  title="Protect your first device"
                  description="Connect your Windows PC or Android phone to begin monitoring. No devices are enrolled yet."
                  action={
                    <PrimaryButton onClick={openConnectDeviceModal}>
                      Connect Device
                    </PrimaryButton>
                  }
                />
              )}

              {devicesError && (
                <div className="rounded-xl border border-[#C45B4A]/30 bg-[#C45B4A]/08 px-4 py-3 text-sm text-[#F4F1EA]">
                  <p>{devicesError}</p>
                  <button
                    type="button"
                    className="mt-2 text-xs text-[#C8A66A] underline"
                    onClick={() => void fetchEnrolledDevices()}
                  >
                    Retry
                  </button>
                </div>
              )}

              {devicesLoading ? (
                <div className="text-xs text-[#9499A3] py-8">Loading your devices...</div>
              ) : (
                <div className="grid grid-cols-1 md:grid-cols-2 gap-5">
                  {unifiedDevices.map((device) => (
                    <DeviceCard
                      key={device.id}
                      name={device.name}
                      platform={device.platform}
                      statusLabel={device.statusLabel}
                      statusTone={device.statusTone}
                      lastSeenLabel={device.lastSeenLabel}
                      securityHealthLabel={device.securityHealthLabel}
                      isDemo={device.isDemo}
                      onSelect={() => setSelectedDeviceDrawerId(device.id)}
                    />
                  ))}
                </div>
              )}

              {enrolledDevices.length === 0 && !devicesLoading && !devicesError && (
                <div className="rounded-xl border border-dashed border-[#25282E] px-4 py-3 text-xs text-[#9499A3]">
                  <p className="mb-2">
                    Optional: view clearly labeled sample cards for layout preview only. They are not enrolled, not connected, and not monitored.
                  </p>
                  <button
                    type="button"
                    className="text-[#C8A66A] underline"
                    onClick={() => setShowSampleDevicePreview((v) => !v)}
                  >
                    {showSampleDevicePreview ? 'Hide sample preview' : 'Show sample preview'}
                  </button>
                  {showSampleDevicePreview && (
                    <div className="mt-4 grid grid-cols-1 md:grid-cols-2 gap-5 opacity-80">
                      {MOCK_DEVICES.map((mock) => (
                        <DeviceCard
                          key={`sample-${mock.id}`}
                          name={`${mock.name} (Sample)`}
                          platform={mock.type === 'WINDOWS' ? 'WINDOWS' : 'ANDROID'}
                          statusLabel="Sample only"
                          statusTone="neutral"
                          lastSeenLabel="Not a real device"
                          securityHealthLabel="Preview"
                          isDemo={true}
                          onSelect={() => setSelectedDeviceDrawerId(mock.id)}
                        />
                      ))}
                    </div>
                  )}
                </div>
              )}
            </div>
          )}

          {/* ================================================================
              PAGE 3: ALERTS (NOTIFICATION & ADVISORY CENTER)
              ================================================================ */}
          {activeNav === 'Alerts' && (
            <div className="space-y-10">
              <PageHeader
                eyebrow="PROTECTION ADVISORIES"
                title="Alerts"
                subtitle="Calm notifications when a device or account setting needs your attention."
                action={
                  unreadNotificationCount > 0 ? (
                    <SecondaryButton onClick={() => void handleMarkAllNotificationsRead()}>
                      Mark All as Read
                    </SecondaryButton>
                  ) : undefined
                }
              />

              {/* Subtle Filter Bar */}
              <div className="flex flex-wrap items-center gap-2 border-b border-[#25282E]/80 pb-4">
                {(
                  ['All', 'Needs Attention', 'Security', 'Devices', 'Account'] as const
                ).map((tab) => (
                  <button
                    key={tab}
                    type="button"
                    onClick={() => setAlertsFilter(tab)}
                    className={`px-4 py-2 rounded-lg text-xs font-medium transition-colors cursor-pointer ${
                      alertsFilter === tab
                        ? 'bg-[#15171C] text-[#C8A66A] border border-[#25282E]'
                        : 'text-[#9499A3] hover:text-[#F4F1EA]'
                    }`}
                  >
                    {tab}
                  </button>
                ))}
              </div>

              {filteredAlerts.length === 0 ? (
                <EmptyState
                  title="You're all clear"
                  description="No security issues require your attention."
                />
              ) : (
                <div className="divide-y divide-[#25282E]/60">
                  {filteredAlerts.map((alert) => (
                    <div key={alert.id} className="relative">
                      <AlertCard
                        severity={alert.severity}
                        title={alert.title}
                        deviceName={alert.deviceName}
                        explanation={alert.explanation}
                        timeLabel={alert.timeLabel}
                        actionLabel={alert.actionLabel}
                        onReview={() => {
                          if (alert.notificationId) {
                            void handleMarkNotificationRead(alert.notificationId);
                          }
                          if (alert.actionTarget) {
                            handleNavigateTarget(alert.actionTarget);
                          } else if (alert.targetNav) {
                            setActiveNav(alert.targetNav);
                          }
                        }}
                      />
                      {alert.notificationId && (
                        <div className="flex items-center gap-4 pb-3 -mt-2 text-xs text-[#646A74]">
                          {!alert.isRead && (
                            <button
                              type="button"
                              onClick={() =>
                                void handleMarkNotificationRead(alert.notificationId!)
                              }
                              className="text-[#C8A66A] hover:underline cursor-pointer"
                            >
                              Mark as read
                            </button>
                          )}
                          <button
                            type="button"
                            onClick={() =>
                              void handleDismissNotification(alert.notificationId!)
                            }
                            className="hover:text-[#F4F1EA] cursor-pointer"
                          >
                            Dismiss
                          </button>
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}

          {/* ================================================================
              PAGE 4: ACTIVITY (EDITORIAL TIMELINE & REPORT EXPORT)
              ================================================================ */}
          {activeNav === 'Activity' && (
            <div className="space-y-10">
              <PageHeader
                eyebrow="SECURITY TIMELINE"
                title="Activity"
                subtitle="Chronological history of sign-ins, device connections, ThreatCheck inspections, and recovery actions."
                action={
                  <div className="flex flex-wrap items-center gap-2">
                    <SecondaryButton
                      disabled={exportingFormat !== null}
                      onClick={() => void handleExportReport('json')}
                      className="flex items-center gap-1.5"
                    >
                      <Download className="w-3.5 h-3.5" />
                      <span>
                        {exportingFormat === 'json' ? 'Exporting JSON...' : 'Export JSON'}
                      </span>
                    </SecondaryButton>
                    <SecondaryButton
                      disabled={exportingFormat !== null}
                      onClick={() => void handleExportReport('csv')}
                      className="flex items-center gap-1.5"
                    >
                      <Download className="w-3.5 h-3.5" />
                      <span>
                        {exportingFormat === 'csv' ? 'Exporting CSV...' : 'Export CSV'}
                      </span>
                    </SecondaryButton>
                    <SecondaryButton onClick={() => void fetchAuditTrail()}>
                      Refresh
                    </SecondaryButton>
                  </div>
                }
              />

              {exportError && (
                <div
                  role="alert"
                  className="p-3.5 rounded-xl bg-[#15171C] border border-[#D06C64]/50 text-xs text-[#D06C64]"
                >
                  {exportError}
                </div>
              )}

              {/* Category Filter Bar */}
              <div className="flex flex-wrap items-center justify-between gap-4 border-b border-[#25282E]/80 pb-4">
                <div className="flex flex-wrap items-center gap-2">
                  {(
                    [
                      'All',
                      'Authentication',
                      'Device',
                      'Security',
                      'ThreatCheck',
                      'Recovery',
                    ] as const
                  ).map((cat) => (
                    <button
                      key={cat}
                      type="button"
                      onClick={() => setActivityFilter(cat)}
                      className={`px-3.5 py-1.5 rounded-lg text-xs font-medium transition-colors cursor-pointer ${
                        activityFilter === cat
                          ? 'bg-[#15171C] text-[#C8A66A] border border-[#25282E]'
                          : 'text-[#9499A3] hover:text-[#F4F1EA]'
                      }`}
                    >
                      {cat}
                    </button>
                  ))}
                </div>

                <StatusBadge tone="protected" label="Verified timeline" />
              </div>

              {auditLoading ? (
                <div className="text-xs text-[#9499A3] py-8">Loading security activity...</div>
              ) : filteredActivities.length === 0 ? (
                <EmptyState
                  title="Nothing unusual"
                  description="VAJRA hasn't detected any security activity that needs your attention."
                />
              ) : (
                <div className="space-y-4">
                  <div className="text-[11px] font-semibold uppercase tracking-[0.24em] text-[#646A74]">
                    TODAY
                  </div>
                  <div className="border-t border-[#25282E]/80">
                    {filteredActivities.map((item) => (
                      <TimelineItem
                        key={item.id}
                        clockTime={item.clockTime}
                        title={item.title}
                        subtitle={item.subtitle ?? item.deviceName ?? item.category}
                        description={item.description}
                        severity={item.severity}
                      />
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}

          {/* ================================================================
              PAGE 5: THREATCHECK (FLAGSHIP LINK INSPECTOR & PERSISTENT HISTORY)
              ================================================================ */}
          {activeNav === 'ThreatCheck' && (
            <div className="space-y-12">
              <PageHeader
                eyebrow="THREATCHECK"
                title="Know before you click."
                subtitle="Check a link for suspicious signals before opening it."
                action={
                  <SecondaryButton
                    disabled={threatHistoryLoading}
                    onClick={() =>
                      void fetchThreatCheckHistory({ offset: 0, append: false })
                    }
                    className="flex items-center gap-1.5"
                  >
                    <RefreshCw
                      className={`w-3.5 h-3.5 ${threatHistoryLoading ? 'animate-spin' : ''}`}
                    />
                    <span>
                      {threatHistoryLoading ? 'Refreshing...' : 'Refresh History'}
                    </span>
                  </SecondaryButton>
                }
              />

              <div className="vajra-surface-card rounded-[16px] p-7 sm:p-10 space-y-7">
                <form
                  onSubmit={(e) => void handleInspectUrl(e)}
                  className="flex flex-col sm:flex-row items-stretch sm:items-center gap-3.5"
                >
                  <div className="relative flex-1">
                    <Search className="w-4 h-4 text-[#6E727D] absolute left-4 top-1/2 -translate-y-1/2" />
                    <input
                      type="text"
                      value={urlInput}
                      onChange={(e) => setUrlInput(e.target.value)}
                      placeholder="Paste a link to inspect (for example, https://example.com)"
                      aria-label="Website address to inspect"
                      className="w-full pl-11 pr-4 py-3.5 text-sm bg-[#08090B]/90 border border-[#F4F1EA]/12 rounded-xl text-[#F4F1EA] placeholder-[#6E727D] focus:outline-none focus:border-[#C79A5A]"
                    />
                  </div>
                  <PrimaryButton
                    type="submit"
                    disabled={threatInspectBusy}
                    className="py-3.5 px-7 text-xs"
                  >
                    {threatInspectBusy ? 'Inspecting...' : 'Check Link'}
                  </PrimaryButton>
                </form>

                <div className="flex flex-wrap items-center gap-3 text-xs text-[#646A74]">
                  <span>Examples:</span>
                  <button
                    type="button"
                    onClick={() => {
                      const sample = 'https://github.com/security';
                      setUrlInput(sample);
                      setThreatInspectError(null);
                      setLatestThreatCheckRecord(null);
                      setThreatResult(evaluateUrlSafetyPreview(sample));
                    }}
                    className="px-3 py-1 rounded-md bg-[#15171C] text-[#9499A3] hover:text-[#F4F1EA] border border-[#25282E] transition-colors cursor-pointer"
                  >
                    Standard HTTPS
                  </button>
                  <button
                    type="button"
                    onClick={() => {
                      const sample = 'http://198.51.100.42/login-verify/account-update';
                      setUrlInput(sample);
                      setThreatInspectError(null);
                      setLatestThreatCheckRecord(null);
                      setThreatResult(evaluateUrlSafetyPreview(sample));
                    }}
                    className="px-3 py-1 rounded-md bg-[#15171C] text-[#9499A3] hover:text-[#F4F1EA] border border-[#25282E] transition-colors cursor-pointer"
                  >
                    Suspicious sign-in
                  </button>
                  <button
                    type="button"
                    onClick={() => {
                      const sample = 'http://169.254.169.254/latest/meta-data/iam?token=secret';
                      setUrlInput(sample);
                      setThreatInspectError(null);
                      setLatestThreatCheckRecord(null);
                      setThreatResult(evaluateUrlSafetyPreview(sample));
                    }}
                    className="px-3 py-1 rounded-md bg-[#15171C] text-[#9499A3] hover:text-[#F4F1EA] border border-[#25282E] transition-colors cursor-pointer"
                  >
                    Restricted metadata destination
                  </button>
                </div>

                {threatInspectError && (
                  <div
                    role="alert"
                    className="p-4 rounded-xl bg-[#15171C] border border-[#D06C64]/50 text-xs text-[#D06C64]"
                  >
                    {threatInspectError}
                  </div>
                )}

                {threatResult && (
                  <div className="pt-7 border-t border-[#25282E] space-y-6">
                    <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
                      <div className="space-y-1.5">
                        <div className="flex flex-wrap items-center gap-2.5">
                          <StatusBadge
                            tone={
                              (latestThreatCheckRecord?.verdict ?? threatResult.verdict) ===
                              'HIGH RISK'
                                ? 'critical'
                                : (latestThreatCheckRecord?.verdict ?? threatResult.verdict) ===
                                  'SUSPICIOUS'
                                ? 'warning'
                                : (latestThreatCheckRecord?.verdict ?? threatResult.verdict) ===
                                  'LOW RISK'
                                ? 'protected'
                                : 'neutral'
                            }
                            label={latestThreatCheckRecord?.verdict ?? threatResult.verdict}
                          />
                          {latestThreatCheckRecord && (
                            <span className="px-2.5 py-0.5 rounded-md bg-[#15171C] border border-[#25282E] text-[11px] font-mono text-[#C8A66A] tabular-nums">
                              Risk Score: {latestThreatCheckRecord.riskScore}/100
                            </span>
                          )}
                          {latestThreatCheckRecord?.classification && (
                            <span className="px-2.5 py-0.5 rounded-md bg-[#15171C] border border-[#25282E] text-[11px] uppercase tracking-wider text-[#9499A3]">
                              {latestThreatCheckRecord.classification}
                            </span>
                          )}
                        </div>
                        <h3 className="text-lg font-semibold text-[#F4F1EA] font-mono break-all">
                          {latestThreatCheckRecord?.submittedUrlRedacted ??
                            threatResult.normalizedDisplayUrl}
                        </h3>
                      </div>
                      <span className="text-xs text-[#646A74] font-mono">
                        Domain:{' '}
                        {latestThreatCheckRecord?.normalizedDomain ?? threatResult.hostname}
                      </span>
                    </div>

                    {latestThreatCheckRecord?.restrictedDestination && (
                      <div
                        role="alert"
                        className="p-4 rounded-xl bg-[#D06C64]/10 border border-[#D06C64]/45 flex items-start gap-3"
                      >
                        <AlertTriangle className="w-4 h-4 text-[#D06C64] shrink-0 mt-0.5" />
                        <div className="space-y-1 text-xs">
                          <div className="font-semibold text-[#D06C64] uppercase tracking-wider">
                            Restricted Destination Boundary Flagged
                          </div>
                          <p className="text-[#F4F1EA] leading-relaxed">
                            This URL points to a loopback, private internal network, link-local, or cloud metadata address rather than a public website. VAJRA classifies internal destinations as high risk and never fetches them.
                          </p>
                        </div>
                      </div>
                    )}

                    <p className="text-sm text-[#F4F1EA] leading-relaxed">
                      {latestThreatCheckRecord?.summary ?? threatResult.summary}
                    </p>

                    {latestThreatCheckRecord &&
                    latestThreatCheckRecord.indicators.length > 0 ? (
                      <div className="bg-[#08090B] border border-[#25282E] rounded-xl p-5 space-y-3.5">
                        <div className="flex items-center justify-between">
                          <div className="text-xs font-semibold uppercase tracking-[0.18em] text-[#9499A3]">
                            Explainable Threat Indicators ({latestThreatCheckRecord.indicators.length})
                          </div>
                          <span className="text-[11px] text-[#646A74]">
                            Redacted URL persisted
                          </span>
                        </div>
                        <div className="divide-y divide-[#25282E]/70">
                          {latestThreatCheckRecord.indicators.map((ind) => (
                            <div
                              key={ind.id}
                              className="py-3 first:pt-0 last:pb-0 flex flex-col sm:flex-row sm:items-start justify-between gap-2 text-xs"
                            >
                              <div className="space-y-1">
                                <div className="flex items-center gap-2 flex-wrap">
                                  <StatusBadge
                                    label={ind.severity}
                                    tone={
                                      ind.severity === 'HIGH' || ind.severity === 'CRITICAL'
                                        ? 'risk'
                                        : ind.severity === 'MEDIUM'
                                        ? 'attention'
                                        : 'neutral'
                                    }
                                    showDot={false}
                                  />
                                  <span className="font-semibold text-[#F4F1EA]">
                                    {ind.title}
                                  </span>
                                  <span className="text-[11px] text-[#646A74]">
                                    · {ind.category}
                                  </span>
                                </div>
                                <p className="text-[#9499A3] leading-relaxed">
                                  {ind.explanation}
                                </p>
                              </div>
                              <span className="text-[11px] font-mono text-[#C8A66A] shrink-0 tabular-nums">
                                +{ind.weight} pts
                              </span>
                            </div>
                          ))}
                        </div>
                      </div>
                    ) : (
                      <div className="bg-[#08090B] border border-[#25282E] rounded-xl p-5 space-y-3">
                        <div className="text-xs font-semibold uppercase tracking-[0.18em] text-[#9499A3]">
                          Inspection Signals
                        </div>
                        <ul className="space-y-2 text-xs text-[#9499A3]">
                          {threatResult.signals.map((sig, idx) => (
                            <li key={idx} className="flex items-start gap-2.5">
                              <span className="text-[#C8A66A] mt-0.5">◇</span>
                              <span>{sig}</span>
                            </li>
                          ))}
                        </ul>
                      </div>
                    )}

                    <div className="space-y-2 text-xs text-[#9499A3] border-l-2 border-[#C8A66A] pl-4 py-1">
                      <p className="text-[#F4F1EA]">
                        {latestThreatCheckRecord?.recommendedGuidance ??
                          threatResult.recommendation}
                      </p>
                      <p className="text-[11px] text-[#6E727D] leading-relaxed">
                        Limitations note:{' '}
                        {latestThreatCheckRecord?.limitationsStatement ??
                          'Lexical URL analysis inspects only the structure, hostname, and destination address boundaries of a link without fetching the page or performing live DNS resolution. A low-risk result is not proof that a destination website is safe.'}
                      </p>
                    </div>
                  </div>
                )}
              </div>

              {/* PERSISTED THREATCHECK HISTORY SECTION */}
              <SecuritySection
                eyebrow="PERSISTED INSPECTION LOG"
                title="ThreatCheck History"
                description="Redacted URLs, normalized domains, verdicts, and explainable indicator breakdowns for your account."
                action={
                  <div className="flex flex-wrap items-center gap-1.5">
                    {(['ALL', 'LOW RISK', 'SUSPICIOUS', 'HIGH RISK'] as const).map(
                      (verdictOpt) => (
                        <button
                          key={verdictOpt}
                          type="button"
                          onClick={() => {
                            setThreatHistoryVerdictFilter(verdictOpt);
                            void fetchThreatCheckHistory({
                              verdict: verdictOpt,
                              offset: 0,
                              append: false,
                            });
                          }}
                          className={`px-3 py-1.5 rounded-lg text-[11px] font-medium transition-colors cursor-pointer ${
                            threatHistoryVerdictFilter === verdictOpt
                              ? 'bg-[#15171C] text-[#C8A66A] border border-[#25282E]'
                              : 'text-[#9499A3] hover:text-[#F4F1EA]'
                          }`}
                        >
                          {verdictOpt === 'ALL' ? 'All Verdicts' : verdictOpt}
                        </button>
                      )
                    )}
                  </div>
                }
              >
                {threatHistoryLoading && threatHistory.length === 0 ? (
                  <div className="vajra-surface-card rounded-[14px] p-6 text-xs text-[#9499A3]">
                    Loading ThreatCheck history...
                  </div>
                ) : threatHistoryError ? (
                  <div
                    role="alert"
                    className="vajra-surface-card rounded-[14px] p-6 border border-[#D06C64]/40 flex flex-col sm:flex-row sm:items-center justify-between gap-4"
                  >
                    <div className="space-y-1">
                      <div className="text-xs font-semibold text-[#D06C64]">
                        Could not load ThreatCheck history
                      </div>
                      <p className="text-xs text-[#9499A3]">{threatHistoryError}</p>
                    </div>
                    <SecondaryButton
                      onClick={() =>
                        void fetchThreatCheckHistory({ offset: 0, append: false })
                      }
                    >
                      Retry
                    </SecondaryButton>
                  </div>
                ) : threatHistory.length === 0 ? (
                  <EmptyState
                    title="No links inspected yet"
                    description="Paste a website link above and select Check Link to record a redacted lexical analysis in your ThreatCheck history."
                  />
                ) : (
                  <div className="space-y-4">
                    <div className="vajra-surface-card rounded-[14px] divide-y divide-[#25282E]/70">
                      {threatHistory.map((item) => {
                        const isExpanded = expandedThreatCheckId === item.id;
                        return (
                          <div key={item.id} className="p-5 space-y-3">
                            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
                              <div className="space-y-1 min-w-0">
                                <div className="flex items-center gap-2.5 flex-wrap">
                                  <StatusBadge
                                    label={item.verdict}
                                    tone={
                                      item.verdict === 'HIGH RISK'
                                        ? 'critical'
                                        : item.verdict === 'SUSPICIOUS'
                                        ? 'warning'
                                        : 'protected'
                                    }
                                  />
                                  <span className="text-xs font-mono text-[#C8A66A] tabular-nums">
                                    Score {item.riskScore}/100
                                  </span>
                                  <span className="text-xs text-[#6E727D]">
                                    · {item.normalizedDomain}
                                  </span>
                                  <span className="text-xs text-[#6E727D] tabular-nums">
                                    · {formatRelativeTime(item.checkedAt)}
                                  </span>
                                </div>
                                <div className="text-xs font-mono text-[#F4F1EA] break-all">
                                  {item.submittedUrlRedacted}
                                </div>
                                <p className="text-xs text-[#A6A8B1] leading-relaxed">
                                  {item.summary}
                                </p>
                              </div>

                              <div className="flex items-center gap-2 shrink-0">
                                {item.indicators.length > 0 && (
                                  <SecondaryButton
                                    onClick={() =>
                                      setExpandedThreatCheckId(
                                        isExpanded ? null : item.id
                                      )
                                    }
                                    className="px-3 py-1.5 text-[11px]"
                                  >
                                    {isExpanded
                                      ? 'Hide Indicators'
                                      : `${item.indicators.length} ${
                                          item.indicators.length === 1
                                            ? 'Indicator'
                                            : 'Indicators'
                                        }`}
                                  </SecondaryButton>
                                )}
                              </div>
                            </div>

                            {isExpanded && item.indicators.length > 0 && (
                              <div className="mt-3 pt-3 border-t border-[#25282E]/70 space-y-2.5 bg-[#08090B]/70 rounded-xl p-4">
                                <div className="text-[10px] font-semibold uppercase tracking-[0.18em] text-[#C8A66A]">
                                  Indicator Breakdown
                                </div>
                                {item.indicators.map((ind) => (
                                  <div
                                    key={ind.id}
                                    className="flex flex-col sm:flex-row sm:items-start justify-between gap-2 text-xs border-b border-[#25282E]/50 last:border-0 pb-2 last:pb-0"
                                  >
                                    <div>
                                      <span className="font-semibold text-[#F4F1EA]">
                                        {ind.title}
                                      </span>{' '}
                                      <span className="text-[#6E727D]">
                                        ({ind.category} · {ind.severity})
                                      </span>
                                      <p className="text-[#9499A3] mt-0.5">
                                        {ind.explanation}
                                      </p>
                                    </div>
                                    <span className="text-[11px] font-mono text-[#C8A66A] shrink-0 tabular-nums">
                                      +{ind.weight} pts
                                    </span>
                                  </div>
                                ))}
                                <div className="pt-1 text-[11px] text-[#9499A3]">
                                  Guidance: {item.recommendedGuidance}
                                </div>
                              </div>
                            )}
                          </div>
                        );
                      })}
                    </div>

                    {threatHistoryPagination?.hasMore && (
                      <div className="flex justify-center pt-2">
                        <SecondaryButton
                          disabled={threatHistoryLoading}
                          onClick={() =>
                            void fetchThreatCheckHistory({
                              offset: threatHistory.length,
                              append: true,
                            })
                          }
                        >
                          {threatHistoryLoading ? 'Loading more...' : 'Load More History'}
                        </SecondaryButton>
                      </div>
                    )}
                  </div>
                )}
              </SecuritySection>
            </div>
          )}

          {/* ================================================================
              PAGE 6: SETTINGS (PREMIUM SECURITY CENTER)
              ================================================================ */}
          {activeNav === 'Settings' && (
            <div className="space-y-10">
              <PageHeader
                eyebrow="SECURITY CENTER"
                title="Settings"
                subtitle="Manage your account profile, two-step verification, trusted devices, and privacy controls."
              />

              <div className="space-y-6">
                {/* 0. ATMOSPHERE & VISUAL SYSTEM (Prompt 0009 Part 19) */}
                <SettingsGroup
                  category="ATMOSPHERE"
                  title="Cinematic Vajra Atmosphere"
                  description="Adjust how the sculptural Vajra video atmosphere blends with smoked obsidian console surfaces."
                >
                  <div className="space-y-4 text-xs">
                    <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-4 border-b border-[#F4F1EA]/8">
                      <div>
                        <div className="font-semibold text-[#F4F1EA]">
                          Animated Vajra Background
                        </div>
                        <div className="text-[#A6A8B1] mt-0.5">
                          Automatically pauses when system Reduced Motion is enabled.
                        </div>
                      </div>
                      <SecondaryButton
                        onClick={() => setAtmosphereEnabled((prev) => !prev)}
                      >
                        {atmosphereEnabled ? 'Pause Video Atmosphere' : 'Enable Video Atmosphere'}
                      </SecondaryButton>
                    </div>

                    <div className="space-y-2">
                      <div className="text-[#A6A8B1] font-medium">Atmosphere Balance</div>
                      <div className="grid grid-cols-1 sm:grid-cols-3 gap-2.5">
                        {(['focused', 'balanced', 'ambient'] as const).map((presetKey) => {
                          const preset = VAJRA_ATMOSPHERE_PRESETS[presetKey];
                          const isSelected = atmosphereIntensity === presetKey;
                          return (
                            <button
                              key={presetKey}
                              type="button"
                              onClick={() => setAtmosphereIntensity(presetKey)}
                              className={`p-3.5 rounded-xl border text-left transition-all cursor-pointer ${
                                isSelected
                                  ? 'bg-[#151519] border-[#C79A5A] text-[#F4F1EA]'
                                  : 'bg-[#08090B]/60 border-[#F4F1EA]/10 text-[#A6A8B1] hover:text-[#F4F1EA]'
                              }`}
                            >
                              <div className="font-semibold text-xs text-[#F4F1EA]">
                                {preset.label}
                              </div>
                              <div className="text-[11px] text-[#6E727D] mt-1 leading-relaxed">
                                {preset.description}
                              </div>
                            </button>
                          );
                        })}
                      </div>
                    </div>
                  </div>
                </SettingsGroup>

                {/* 1. ACCOUNT */}
                <SettingsGroup
                  category="ACCOUNT"
                  title="Profile"
                  description="Your personal owner identity for this VAJRA console."
                >
                  <div className="space-y-3 text-xs">
                    <div className="flex items-center justify-between py-2 border-b border-[#25282E]/60">
                      <span className="text-[#9499A3]">Name</span>
                      <span className="text-[#F4F1EA] font-medium">
                        {currentUser?.displayName}
                      </span>
                    </div>
                    <div className="flex items-center justify-between py-2 border-b border-[#25282E]/60">
                      <span className="text-[#9499A3]">Email</span>
                      <span className="text-[#F4F1EA] font-medium">
                        {currentUser?.email}
                      </span>
                    </div>
                    <div className="flex items-center justify-between pt-2">
                      <span className="text-[#9499A3]">Console session</span>
                      <SecondaryButton onClick={() => void handleLogout(false)}>
                        Sign Out
                      </SecondaryButton>
                    </div>
                  </div>
                </SettingsGroup>

                {/* 2. SECURITY */}
                <SettingsGroup
                  category="SECURITY"
                  title="Password, Two-Step Verification & Sessions"
                  description="Protect your account with an authenticator app, single-use recovery codes, and session controls."
                >
                  {/* Two-Step Verification Row */}
                  <div className="space-y-4 pb-5 border-b border-[#25282E]/70">
                    <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
                      <div className="space-y-1">
                        <div className="text-xs font-semibold text-[#F4F1EA]">
                          Two-step verification
                        </div>
                        <StatusBadge
                          tone={currentUser?.mfaEnabled ? 'protected' : 'warning'}
                          label={
                            currentUser?.mfaEnabled
                              ? 'Protected with authenticator app'
                              : 'Not enabled'
                          }
                        />
                      </div>
                      {!currentUser?.mfaEnabled && !mfaSetupData && (
                        <PrimaryButton onClick={() => void handleStartMfaSetup()}>
                          Enable Two-Step
                        </PrimaryButton>
                      )}
                    </div>

                    {mfaSetupData && (
                      <div className="p-5 rounded-xl bg-[#08090B] border border-[#25282E] space-y-4">
                        <p className="text-xs text-[#9499A3] leading-relaxed">
                          Scan this QR code with your authenticator app, then enter the 6-digit verification code below.
                        </p>
                        <div className="bg-white p-3 rounded-xl w-44 h-44 mx-auto flex items-center justify-center">
                          <img
                            src={mfaSetupData.qrCodeDataUrl}
                            alt="Two-Step Verification QR Code"
                            className="w-full h-full object-contain"
                          />
                        </div>

                        <div className="text-center">
                          <button
                            type="button"
                            onClick={() => setShowSetupManualKey((prev) => !prev)}
                            className="text-xs text-[#9499A3] hover:text-[#F4F1EA] underline inline-flex items-center gap-1.5 cursor-pointer"
                          >
                            {showSetupManualKey ? (
                              <>
                                <EyeOff className="w-3.5 h-3.5" />
                                <span>Hide setup key</span>
                              </>
                            ) : (
                              <>
                                <Eye className="w-3.5 h-3.5" />
                                <span>View manual setup key</span>
                              </>
                            )}
                          </button>
                          {showSetupManualKey && (
                            <div className="mt-2 p-2.5 rounded-lg bg-[#101216] border border-[#25282E] font-mono text-xs text-[#C8A66A] break-all">
                              {mfaSetupData.secretBase32}
                            </div>
                          )}
                        </div>

                        <form
                          onSubmit={(e) => void handleVerifyMfaSetup(e)}
                          className="flex items-center gap-2.5 pt-2"
                        >
                          <input
                            id="mfa-verify-code"
                            type="text"
                            inputMode="numeric"
                            pattern="[0-9]{6}"
                            maxLength={6}
                            required
                            value={mfaVerifyCode}
                            onChange={(e) => setMfaVerifyCode(e.target.value)}
                            placeholder="6-digit code"
                            className="flex-1 px-3.5 py-2 text-sm font-mono tracking-widest bg-[#101216] border border-[#25282E] rounded-lg text-[#F4F1EA]"
                          />
                          <PrimaryButton type="submit">Activate</PrimaryButton>
                        </form>
                      </div>
                    )}

                    {/* One-Time Recovery Codes Display */}
                    {oneTimeRecoveryCodes && oneTimeRecoveryCodes.length > 0 && (
                      <div className="p-5 rounded-xl bg-[#08090B] border border-[#C8A66A]/45 space-y-3">
                        <div className="flex items-center justify-between">
                          <span className="text-xs font-semibold text-[#C8A66A]">
                            Recovery Codes
                          </span>
                          <button
                            type="button"
                            onClick={() => {
                              void navigator.clipboard.writeText(
                                oneTimeRecoveryCodes.join('\n')
                              );
                              setCopiedRecoveryCodes(true);
                              setTimeout(() => setCopiedRecoveryCodes(false), 2000);
                            }}
                            className="text-xs text-[#F4F1EA] inline-flex items-center gap-1.5 hover:text-[#C8A66A] cursor-pointer"
                          >
                            {copiedRecoveryCodes ? (
                              <>
                                <Check className="w-3.5 h-3.5 text-[#75B798]" />
                                <span>Copied</span>
                              </>
                            ) : (
                              <>
                                <Copy className="w-3.5 h-3.5" />
                                <span>Copy Codes</span>
                              </>
                            )}
                          </button>
                        </div>
                        <p className="text-xs text-[#9499A3]">
                          Store these codes safely. Each code works once if you lose access to your phone.
                        </p>
                        <div className="grid grid-cols-2 gap-2 font-mono text-xs text-[#F4F1EA]">
                          {oneTimeRecoveryCodes.map((code) => (
                            <div
                              key={code}
                              className="p-2 rounded-lg bg-[#101216] border border-[#25282E] text-center"
                            >
                              {code}
                            </div>
                          ))}
                        </div>
                      </div>
                    )}

                    {currentUser?.mfaEnabled && (
                      <div className="space-y-4 pt-3">
                        <div className="flex items-center justify-between text-xs">
                          <span className="text-[#9499A3]">Recovery codes remaining</span>
                          <span className="text-[#F4F1EA] font-medium tabular-nums">
                            {currentUser.unusedRecoveryCodesCount ?? 0} available
                          </span>
                        </div>

                        <form
                          onSubmit={(e) => void handleRegenerateRecoveryCodes(e)}
                          className="flex flex-col sm:flex-row items-stretch sm:items-center gap-2.5"
                        >
                          <input
                            type="password"
                            required
                            value={regenCodesPassword}
                            onChange={(e) => setRegenCodesPassword(e.target.value)}
                            placeholder="Confirm password to refresh backup codes"
                            className="flex-1 px-3.5 py-2 text-xs bg-[#08090B] border border-[#25282E] rounded-lg text-[#F4F1EA]"
                          />
                          <SecondaryButton type="submit">Refresh Codes</SecondaryButton>
                        </form>

                        <form
                          onSubmit={(e) => void handleDisableMfa(e)}
                          className="flex flex-col sm:flex-row items-stretch sm:items-center gap-2.5"
                        >
                          <input
                            type="password"
                            required
                            value={disableMfaPassword}
                            onChange={(e) => setDisableMfaPassword(e.target.value)}
                            placeholder="Confirm password to turn off two-step"
                            className="flex-1 px-3.5 py-2 text-xs bg-[#08090B] border border-[#25282E] rounded-lg text-[#F4F1EA]"
                          />
                          <SecondaryButton type="submit" tone="danger">
                            Turn Off
                          </SecondaryButton>
                        </form>
                      </div>
                    )}
                  </div>

                  {/* Password Row */}
                  <div className="space-y-3 pb-5 border-b border-[#25282E]/70">
                    <div className="flex items-center justify-between">
                      <div>
                        <div className="text-xs font-semibold text-[#F4F1EA]">Password</div>
                        <div className="text-xs text-[#9499A3]">
                          Updating your password signs out other active browsers.
                        </div>
                      </div>
                      <SecondaryButton
                        onClick={() => setShowPasswordForm((prev) => !prev)}
                      >
                        {showPasswordForm ? 'Cancel' : 'Change Password'}
                      </SecondaryButton>
                    </div>

                    {showPasswordForm && (
                      <form
                        onSubmit={(e) => void handlePasswordChange(e)}
                        className="space-y-3 pt-2"
                      >
                        <input
                          type="password"
                          required
                          value={currentPasswordForChange}
                          onChange={(e) => setCurrentPasswordForChange(e.target.value)}
                          placeholder="Current password"
                          className="w-full px-3.5 py-2 text-xs bg-[#08090B] border border-[#25282E] rounded-lg text-[#F4F1EA]"
                        />
                        <input
                          type="password"
                          required
                          minLength={12}
                          value={newPasswordForChange}
                          onChange={(e) => setNewPasswordForChange(e.target.value)}
                          placeholder="New password (at least 12 characters)"
                          className="w-full px-3.5 py-2 text-xs bg-[#08090B] border border-[#25282E] rounded-lg text-[#F4F1EA]"
                        />
                        <PrimaryButton type="submit">Save New Password</PrimaryButton>
                      </form>
                    )}
                  </div>

                  {/* Active Sessions Row */}
                  <div className="flex items-center justify-between">
                    <div>
                      <div className="text-xs font-semibold text-[#F4F1EA]">Active sessions</div>
                      <div className="text-xs text-[#9499A3]">
                        Sign out all browsers and require a fresh sign-in.
                      </div>
                    </div>
                    <SecondaryButton
                      tone="danger"
                      onClick={() => void handleLogout(true)}
                    >
                      Sign Out All Sessions
                    </SecondaryButton>
                  </div>
                </SettingsGroup>

                {/* 3. DEVICES */}
                <SettingsGroup
                  category="DEVICES"
                  title="Trusted devices"
                  description="Manage computers and phones authorized to connect to your account."
                >
                  <div className="flex items-center justify-between text-xs">
                    <div>
                      <div className="text-[#F4F1EA] font-medium">
                        {unifiedDevices.length} connected{' '}
                        {unifiedDevices.length === 1 ? 'device' : 'devices'}
                      </div>
                      <div className="text-[#9499A3]">
                        Approve, pause, or disconnect devices anytime.
                      </div>
                    </div>
                    <SecondaryButton onClick={() => setActiveNav('Devices')}>
                      Open Devices
                    </SecondaryButton>
                  </div>
                </SettingsGroup>

                {/* 4. NOTIFICATIONS & BROWSER ALERTS */}
                <SettingsGroup
                  category="NOTIFICATIONS"
                  title="Browser Security Alerts"
                  description="Receive optional desktop or browser notifications for important security events when you grant permission."
                >
                  <div className="space-y-4 text-xs">
                    <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
                      <div className="space-y-1">
                        <div className="font-semibold text-[#F4F1EA]">
                          Browser Security Alerts
                        </div>
                        <StatusBadge
                          tone={
                            browserAlertPermission === 'granted' && browserAlertsEnabled
                              ? 'protected'
                              : browserAlertPermission === 'denied'
                              ? 'warning'
                              : 'neutral'
                          }
                          label={
                            browserAlertPermission === 'unsupported'
                              ? 'Not supported in this browser'
                              : browserAlertPermission === 'denied'
                              ? 'Blocked in browser settings'
                              : browserAlertPermission === 'granted' && browserAlertsEnabled
                              ? 'Enabled'
                              : 'Off (Optional)'
                          }
                        />
                      </div>

                      {browserAlertPermission !== 'unsupported' && (
                        <div>
                          {browserAlertPermission === 'granted' && browserAlertsEnabled ? (
                            <SecondaryButton
                              onClick={() => {
                                setBrowserAlertsEnabled(false);
                                showToast('Browser security alerts paused.', 'info');
                              }}
                            >
                              Pause Browser Alerts
                            </SecondaryButton>
                          ) : (
                            <SecondaryButton
                              onClick={() => void handleEnableBrowserAlerts()}
                            >
                              Enable Browser Alerts
                            </SecondaryButton>
                          )}
                        </div>
                      )}
                    </div>
                    <p className="text-[#9499A3] leading-relaxed">
                      VAJRA only requests browser notification permission when you explicitly choose to enable it above.
                    </p>
                  </div>
                </SettingsGroup>

                {/* 5. PRIVACY */}
                <SettingsGroup
                  category="PRIVACY"
                  title="Security activity, permissions & data controls"
                  description="VAJRA never records keystrokes, personal files, messages, or covert audio/video."
                >
                  <div className="space-y-3 text-xs">
                    <div className="flex items-center justify-between py-1.5 border-b border-[#25282E]/60">
                      <span className="text-[#9499A3]">Security activity log</span>
                      <button
                        type="button"
                        onClick={() => setActiveNav('Activity')}
                        className="text-[#C8A66A] hover:underline cursor-pointer"
                      >
                        View Activity Timeline
                      </button>
                    </div>
                    <div className="flex items-center justify-between py-1.5 border-b border-[#25282E]/60">
                      <span className="text-[#9499A3]">OS permissions model</span>
                      <span className="text-[#F4F1EA]">Explicit owner consent only</span>
                    </div>
                    <div className="flex items-center justify-between py-1.5">
                      <span className="text-[#9499A3]">Data controls</span>
                      <span className="text-[#75B798]">Zero covert collection</span>
                    </div>
                  </div>
                </SettingsGroup>

                {/* 6. ADVANCED */}
                <SettingsGroup
                  category="ADVANCED"
                  title="Diagnostics & Demo Security Events"
                  description="Verify console protection status or trigger clearly labeled simulated security events to test the VAJRA Event Engine, Risk Evaluator, and Notification Policy."
                >
                  <div className="space-y-5 text-xs">
                    <div className="flex items-center justify-between pb-4 border-b border-[#25282E]/70">
                      <div>
                        <div className="text-[#F4F1EA] font-medium">Console Protection Status</div>
                        <div className="text-[#9499A3]">
                          All protection services and activity logs are verified.
                        </div>
                      </div>
                      <StatusBadge tone="protected" label="Healthy" />
                    </div>

                    <div className="space-y-3">
                      <div className="flex flex-wrap items-center justify-between gap-2">
                        <div>
                          <div className="text-[#F4F1EA] font-medium">
                            Demo Security Events (Simulated)
                          </div>
                          <div className="text-[#9499A3]">
                            Each simulation flows through the real backend Security Event Engine, Risk Score Evaluator, and Activity Timeline.
                          </div>
                        </div>
                        <StatusBadge tone="neutral" label="Demo Simulation" />
                      </div>

                      <div className="grid grid-cols-1 sm:grid-cols-2 gap-2.5 pt-1">
                        <SecondaryButton
                          disabled={demoEventBusyScenario !== null}
                          onClick={() => void handleTriggerDemoEvent('NEW_SIGN_IN_ALERT')}
                        >
                          {demoEventBusyScenario === 'NEW_SIGN_IN_ALERT'
                            ? 'Simulating...'
                            : 'Simulate Sign-In Alert'}
                        </SecondaryButton>
                        <SecondaryButton
                          disabled={demoEventBusyScenario !== null}
                          onClick={() => void handleTriggerDemoEvent('DEVICE_CHECK_IN')}
                        >
                          {demoEventBusyScenario === 'DEVICE_CHECK_IN'
                            ? 'Simulating...'
                            : 'Simulate Device Check-In'}
                        </SecondaryButton>
                        <SecondaryButton
                          disabled={demoEventBusyScenario !== null}
                          onClick={() => void handleTriggerDemoEvent('SUSPICIOUS_LINK_DETECTED')}
                        >
                          {demoEventBusyScenario === 'SUSPICIOUS_LINK_DETECTED'
                            ? 'Simulating...'
                            : 'Simulate Phishing Detection'}
                        </SecondaryButton>
                        <SecondaryButton
                          disabled={demoEventBusyScenario !== null}
                          onClick={() => void handleTriggerDemoEvent('LOST_MODE_SIMULATION')}
                        >
                          {demoEventBusyScenario === 'LOST_MODE_SIMULATION'
                            ? 'Simulating...'
                            : 'Simulate Lost Mode Event'}
                        </SecondaryButton>
                        <SecondaryButton
                          disabled={demoEventBusyScenario !== null}
                          onClick={() => void handleTriggerDemoEvent('RECOVERY_MESSAGE_TEST')}
                        >
                          {demoEventBusyScenario === 'RECOVERY_MESSAGE_TEST'
                            ? 'Simulating...'
                            : 'Simulate Recovery Message'}
                        </SecondaryButton>
                      </div>
                    </div>
                  </div>
                </SettingsGroup>
              </div>
            </div>
          )}
        </main>
      </div>

      {/* Mobile Bottom Navigation Bar */}
      <nav
        aria-label="Mobile Navigation"
        className="md:hidden fixed bottom-0 inset-x-0 z-40 h-16 bg-[#101216]/95 backdrop-blur-md border-t border-[#25282E] px-2 flex items-center justify-around"
      >
        {[...PRIMARY_NAV_ITEMS, { id: 'Settings' as NavSection, label: 'Settings', icon: SettingsIcon }].map(
          (item) => {
            const Icon = item.icon;
            const isActive = activeNav === item.id;
            return (
              <button
                key={item.id}
                type="button"
                onClick={() => setActiveNav(item.id)}
                className={`flex flex-col items-center justify-center py-1 px-2 rounded-lg text-[10px] font-medium cursor-pointer ${
                  isActive ? 'text-[#C8A66A]' : 'text-[#9499A3]'
                }`}
              >
                <Icon className="w-4 h-4 mb-1" />
                <span>{item.label}</span>
              </button>
            );
          }
        )}
      </nav>

      {/* ====================================================================
          SLIDE-OVER DEVICE DETAILS DRAWER
          ==================================================================== */}
      <DetailDrawer
        open={Boolean(selectedDrawerDevice)}
        eyebrow="DEVICE"
        title={selectedDrawerDevice?.name ?? 'Device'}
        subtitle={
          selectedDrawerDevice
            ? selectedDrawerDevice.platform === 'WINDOWS'
              ? 'Windows'
              : 'Android'
            : undefined
        }
        onClose={() => setSelectedDeviceDrawerId(null)}
      >
        {selectedDrawerDevice && (
          <div className="space-y-7">
            <div className="space-y-2">
              <StatusBadge
                tone={selectedDrawerDevice.statusTone}
                label={selectedDrawerDevice.statusLabel.toUpperCase()}
              />
              <p className="text-xs text-[#9499A3] leading-relaxed">
                {selectedDrawerDevice.statusSummary}
              </p>
            </div>

            {selectedDrawerDevice.pendingApproval && !selectedDrawerDevice.isDemo && (
              <div className="bg-[#15171C] border border-[#C8A66A]/45 rounded-xl p-5 space-y-3">
                <div className="text-xs font-semibold text-[#C8A66A]">
                  Confirm Device Connection
                </div>
                <p className="text-xs text-[#9499A3] leading-relaxed">
                  Approve this device to activate VAJRA protection.
                </p>
                <PrimaryButton
                  onClick={() =>
                    void handleConfirmEnrollment(
                      selectedDrawerDevice.id,
                      selectedDrawerDevice.publicKeyFingerprint
                    )
                  }
                  className="w-full"
                >
                  Approve Device
                </PrimaryButton>
              </div>
            )}

            {/* Primary Status Rows */}
            <div className="space-y-3 text-xs border-t border-[#25282E] pt-5">
              <div className="flex items-center justify-between py-1.5">
                <span className="text-[#9499A3]">Security Health</span>
                <span className="text-[#F4F1EA] font-medium">
                  {selectedDrawerDevice.securityHealthLabel}
                </span>
              </div>
              <div className="flex items-center justify-between py-1.5">
                <span className="text-[#9499A3]">Last Seen</span>
                <span className="text-[#F4F1EA] font-medium tabular-nums">
                  {selectedDrawerDevice.lastSeenLabel}
                </span>
              </div>
              <div className="flex items-center justify-between py-1.5">
                <span className="text-[#9499A3]">Network</span>
                <span className="text-[#F4F1EA] font-medium">
                  {selectedDrawerDevice.networkLabel}
                </span>
              </div>
              <div className="flex items-center justify-between py-1.5">
                <span className="text-[#9499A3]">Location</span>
                <span className="text-[#F4F1EA] font-medium text-right">
                  {deviceLocationByDevice[selectedDrawerDevice.id]?.regionSummary ??
                    (selectedDrawerDevice.platform === 'ANDROID'
                      ? 'Permission-based location ready'
                      : 'Approximate network location')}
                </span>
              </div>
              {deviceHeartbeatByDevice[selectedDrawerDevice.id] && (
                <div className="flex items-center justify-between py-1.5">
                  <span className="text-[#9499A3]">Latest Heartbeat</span>
                  <span className="text-[#F4F1EA] font-medium text-right">
                    {deviceHeartbeatByDevice[selectedDrawerDevice.id]?.batteryLevel !== null
                      ? `${deviceHeartbeatByDevice[selectedDrawerDevice.id]?.batteryLevel}% · `
                      : ''}
                    {deviceHeartbeatByDevice[selectedDrawerDevice.id]?.permissionSummary ??
                      'Permissions verified'}
                  </span>
                </div>
              )}
            </div>

            {/* 24-Hour Battery Level Trend Chart for Connected Android Devices */}
            {selectedDrawerDevice.platform === 'ANDROID' && (
              <DeviceBatteryTrendChart
                deviceName={selectedDrawerDevice.name}
                currentBatteryLevel={
                  deviceHeartbeatByDevice[selectedDrawerDevice.id]?.batteryLevel ??
                  deviceBatteryHistoryByDevice[selectedDrawerDevice.id]?.currentLevel ??
                  null
                }
                isCharging={
                  deviceHeartbeatByDevice[selectedDrawerDevice.id]?.charging ??
                  deviceBatteryHistoryByDevice[selectedDrawerDevice.id]?.charging ??
                  null
                }
                readings={deviceBatteryHistoryByDevice[selectedDrawerDevice.id]?.readings ?? []}
                loading={deviceBatteryHistoryByDevice[selectedDrawerDevice.id]?.loading ?? false}
                error={deviceBatteryHistoryByDevice[selectedDrawerDevice.id]?.error ?? null}
                isSamplePreview={
                  selectedDrawerDevice.isDemo ||
                  selectedDrawerDevice.id.startsWith('mock-') ||
                  enrolledDevices.length === 0
                }
              />
            )}

            {/* Unified Device Actions: Locate · Ring · Recovery Message · Lost Mode */}
            {selectedDrawerDevice.lifecycleState !== 'REVOKED' &&
              selectedDrawerDevice.lifecycleState !== 'DECOMMISSIONED' &&
              !selectedDrawerDevice.pendingApproval && (
                <div className="space-y-3 border-t border-[#25282E] pt-5">
                  <div className="text-[10px] font-semibold uppercase tracking-[0.22em] text-[#C8A66A]">
                    RECOVERY & PROTECTION CONTROLS
                  </div>
                  <div className="grid grid-cols-2 gap-2.5">
                    <button
                      type="button"
                      disabled={deviceActionBusy !== null}
                      onClick={() =>
                        void handleExecuteDeviceAction(
                          selectedDrawerDevice,
                          'REQUEST_LOCATION'
                        )
                      }
                      className="p-3 rounded-xl bg-[#15171C] hover:bg-[#1B1E25] border border-[#25282E] hover:border-[#C8A66A]/45 text-left space-y-1 transition-all cursor-pointer disabled:opacity-50"
                    >
                      <div className="flex items-center gap-2 text-xs font-semibold text-[#F4F1EA]">
                        <MapPin className="w-3.5 h-3.5 text-[#C8A66A]" />
                        <span>Locate</span>
                      </div>
                      <p className="text-[11px] text-[#9499A3]">
                        {selectedDrawerDevice.platform === 'ANDROID'
                          ? 'Permission-based location'
                          : 'Approximate network area'}
                      </p>
                    </button>

                    <button
                      type="button"
                      disabled={deviceActionBusy !== null}
                      onClick={() =>
                        void handleExecuteDeviceAction(selectedDrawerDevice, 'RING_DEVICE')
                      }
                      className="p-3 rounded-xl bg-[#15171C] hover:bg-[#1B1E25] border border-[#25282E] hover:border-[#C8A66A]/45 text-left space-y-1 transition-all cursor-pointer disabled:opacity-50"
                    >
                      <div className="flex items-center gap-2 text-xs font-semibold text-[#F4F1EA]">
                        <Volume2 className="w-3.5 h-3.5 text-[#C8A66A]" />
                        <span>Ring</span>
                      </div>
                      <p className="text-[11px] text-[#9499A3]">
                        {selectedDrawerDevice.platform === 'ANDROID'
                          ? 'High-volume recovery sound'
                          : 'Audible recovery chime'}
                      </p>
                    </button>

                    <button
                      type="button"
                      disabled={deviceActionBusy !== null}
                      onClick={() => {
                        setRecoveryModalMode('MESSAGE');
                        setRecoveryModalOpen(true);
                      }}
                      className="p-3 rounded-xl bg-[#15171C] hover:bg-[#1B1E25] border border-[#25282E] hover:border-[#C8A66A]/45 text-left space-y-1 transition-all cursor-pointer disabled:opacity-50"
                    >
                      <div className="flex items-center gap-2 text-xs font-semibold text-[#F4F1EA]">
                        <MessageSquare className="w-3.5 h-3.5 text-[#C8A66A]" />
                        <span>Recovery Message</span>
                      </div>
                      <p className="text-[11px] text-[#9499A3]">
                        Set owner return instructions
                      </p>
                    </button>

                    {selectedDrawerDevice.lifecycleState === 'LOST' ? (
                      <button
                        type="button"
                        disabled={deviceActionBusy !== null}
                        onClick={() =>
                          void handleExecuteDeviceAction(
                            selectedDrawerDevice,
                            'DISABLE_LOST_MODE'
                          )
                        }
                        className="p-3 rounded-xl bg-[#15171C] hover:bg-[#1B1E25] border border-[#75B798]/50 text-left space-y-1 transition-all cursor-pointer disabled:opacity-50"
                      >
                        <div className="flex items-center gap-2 text-xs font-semibold text-[#75B798]">
                          <ShieldCheck className="w-3.5 h-3.5 text-[#75B798]" />
                          <span>Turn Off Lost Mode</span>
                        </div>
                        <p className="text-[11px] text-[#9499A3]">
                          Restore standard protection
                        </p>
                      </button>
                    ) : (
                      <button
                        type="button"
                        disabled={deviceActionBusy !== null}
                        onClick={() => {
                          setRecoveryModalMode('LOST_MODE');
                          setRecoveryModalOpen(true);
                        }}
                        className="p-3 rounded-xl bg-[#15171C] hover:bg-[#1B1E25] border border-[#C97972]/40 hover:border-[#C97972] text-left space-y-1 transition-all cursor-pointer disabled:opacity-50"
                      >
                        <div className="flex items-center gap-2 text-xs font-semibold text-[#C97972]">
                          <ShieldAlert className="w-3.5 h-3.5 text-[#C97972]" />
                          <span>Lost Mode</span>
                        </div>
                        <p className="text-[11px] text-[#9499A3]">
                          Activate recovery protection
                        </p>
                      </button>
                    )}
                  </div>
                </div>
              )}

            {/* Recent Security Activity & Command Lifecycle for this Device */}
            <div className="space-y-3 border-t border-[#25282E] pt-5">
              <div className="flex items-center justify-between">
                <div className="text-[10px] font-semibold uppercase tracking-[0.22em] text-[#9499A3]">
                  COMMAND LIFECYCLE & RECENT ACTIVITY
                </div>
                {!selectedDrawerDevice.isDemo &&
                  selectedDrawerDevice.lifecycleState !== 'REVOKED' &&
                  selectedDrawerDevice.lifecycleState !== 'DECOMMISSIONED' && (
                    <button
                      type="button"
                      disabled={deviceActionBusy !== null}
                      onClick={() =>
                        void handleQueueCommandForAgent(
                          selectedDrawerDevice,
                          'REQUEST_DEVICE_STATUS'
                        )
                      }
                      className="text-[11px] text-[#C79A5A] hover:underline cursor-pointer disabled:opacity-50"
                    >
                      Request Status Check
                    </button>
                  )}
              </div>
              <div className="space-y-2.5 text-xs">
                {(selectedDrawerDevice.isDemo
                  ? demoActionsByDevice[selectedDrawerDevice.id] ?? []
                  : deviceActionsByDevice[selectedDrawerDevice.id] ?? []
                )
                  .slice(0, 4)
                  .map((act) => {
                    const isCancellable =
                      !selectedDrawerDevice.isDemo &&
                      (act.status === 'QUEUED' ||
                        act.status === 'PENDING' ||
                        act.status === 'DELIVERED');
                    return (
                      <div
                        key={act.id}
                        className="py-1.5 border-b border-[#25282E]/50 space-y-1"
                      >
                        <div className="flex items-start justify-between gap-3">
                          <span className="text-[#F4F1EA]">
                            {act.result?.safeMessage ?? act.statusMessage}
                          </span>
                          <span className="text-[#646A74] tabular-nums shrink-0">
                            {formatRelativeTime(act.requestedAt)}
                          </span>
                        </div>
                        <div className="flex items-center justify-between text-[11px] text-[#9499A3]">
                          <span className="font-mono uppercase tracking-wider text-[10px] text-[#C79A5A]">
                            State: {act.status}
                          </span>
                          {isCancellable && (
                            <button
                              type="button"
                              disabled={cancellingCommandId === act.id}
                              onClick={() =>
                                void handleCancelQueuedCommand(
                                  selectedDrawerDevice.id,
                                  act.id
                                )
                              }
                              className="text-[#D06C64] hover:underline cursor-pointer disabled:opacity-50"
                            >
                              {cancellingCommandId === act.id ? 'Cancelling...' : 'Cancel command'}
                            </button>
                          )}
                        </div>
                      </div>
                    );
                  })}
                <div className="flex items-center justify-between text-[#9499A3]">
                  <span className="text-[#F4F1EA]">Security check completed</span>
                  <span className="tabular-nums">{selectedDrawerDevice.lastSeenLabel}</span>
                </div>
                <div className="flex items-center justify-between text-[#9499A3]">
                  <span className="text-[#F4F1EA]">Added to trusted devices</span>
                  <span>{selectedDrawerDevice.enrolledDateLabel}</span>
                </div>
              </div>
            </div>

            {/* Advanced Security */}
            <div className="space-y-3 border-t border-[#25282E] pt-5">
              <div className="text-[10px] font-semibold uppercase tracking-[0.22em] text-[#9499A3]">
                ADVANCED SECURITY
              </div>
              <div className="space-y-2.5 text-xs">
                <div className="flex items-center justify-between py-1">
                  <span className="text-[#9499A3]">Hardware-backed identity</span>
                  <span className="text-[#78B999] font-medium">
                    {selectedDrawerDevice.hardwareProtected ? 'Protected' : 'Standard'}
                  </span>
                </div>
                <div className="flex items-center justify-between py-1">
                  <span className="text-[#9499A3]">Device authentication</span>
                  <span className="text-[#78B999] font-medium">Verified</span>
                </div>
              </div>
            </div>

            {/* Part 18: Human-Friendly Device Management Actions */}
            {!selectedDrawerDevice.isDemo && (
              <div className="space-y-3 border-t border-[#25282E] pt-5">
                <div className="text-[10px] font-semibold uppercase tracking-[0.22em] text-[#A6A8B1]">
                  DEVICE PROTECTION ACTIONS
                </div>
                <div className="flex flex-wrap gap-2.5">
                  {(selectedDrawerDevice.lifecycleState === 'TRUSTED' ||
                    selectedDrawerDevice.lifecycleState === 'ACTIVE') && (
                    <SecondaryButton
                      onClick={() =>
                        void handleRunDeviceSecurityCheck(selectedDrawerDevice.id)
                      }
                    >
                      Check Protection Status
                    </SecondaryButton>
                  )}

                  {selectedDrawerDevice.lifecycleState !== 'REVOKED' &&
                    selectedDrawerDevice.lifecycleState !== 'DECOMMISSIONED' && (
                      <>
                        <SecondaryButton
                          onClick={() =>
                            void handleLifecycleAction(
                              selectedDrawerDevice.id,
                              'compromised'
                            )
                          }
                        >
                          Mark Device for Review
                        </SecondaryButton>
                        <SecondaryButton
                          tone="danger"
                          onClick={() =>
                            void handleLifecycleAction(selectedDrawerDevice.id, 'revoke')
                          }
                        >
                          End Active Sessions
                        </SecondaryButton>
                      </>
                    )}

                  {selectedDrawerDevice.lifecycleState === 'REVOKED' && (
                    <SecondaryButton
                      onClick={() =>
                        void handleLifecycleAction(
                          selectedDrawerDevice.id,
                          'decommission'
                        )
                      }
                    >
                      Archive Device
                    </SecondaryButton>
                  )}
                </div>
              </div>
            )}
          </div>
        )}
      </DetailDrawer>

      {/* ====================================================================
          SLIDE-OVER NOTIFICATION CENTER PANEL
          ==================================================================== */}
      <NotificationSlideOverPanel
        open={notificationPanelOpen}
        notifications={notifications}
        unreadCount={unreadNotificationCount}
        formatRelative={formatRelativeTime}
        onClose={() => setNotificationPanelOpen(false)}
        onMarkRead={(id) => void handleMarkNotificationRead(id)}
        onMarkAllRead={() => void handleMarkAllNotificationsRead()}
        onDismiss={(id) => void handleDismissNotification(id)}
        onActionClick={(item) => {
          void handleMarkNotificationRead(item.id);
          handleNavigateTarget(item.actionTarget);
        }}
      />

      {/* ====================================================================
          MFA STEP-UP VERIFICATION MODAL (Prompt 0011E)
          ==================================================================== */}
      <Modal
        open={stepUpModalOpen}
        title="Confirm it is you"
        description={stepUpExplanation}
        onClose={() => {
          if (!stepUpSubmitting) closeStepUpModal();
        }}
      >
        <form
          onSubmit={(e) => {
            e.preventDefault();
            void handleStepUpVerify();
          }}
          className="space-y-4"
        >
          <div>
            <label
              htmlFor="step-up-totp-input"
              className="block text-xs font-medium text-[#9499A3] mb-1.5"
            >
              6-digit authenticator code
            </label>
            <input
              id="step-up-totp-input"
              type="text"
              inputMode="numeric"
              autoComplete="one-time-code"
              pattern="[0-9]*"
              maxLength={6}
              value={stepUpCodeInput}
              onChange={(e) => {
                const digits = e.target.value.replace(/\D/g, '').slice(0, 6);
                setStepUpCodeInput(digits);
                if (stepUpError) setStepUpError(null);
              }}
              disabled={stepUpSubmitting}
              aria-invalid={Boolean(stepUpError)}
              aria-describedby={stepUpError ? 'step-up-error' : undefined}
              className="w-full px-3.5 py-2.5 text-sm tracking-[0.35em] text-center font-mono bg-[#08090B] border border-[#25282E] rounded-xl text-[#F4F1EA] focus:outline-none focus:border-[#C8A66A] disabled:opacity-60"
              placeholder="000000"
              autoFocus
            />
            {stepUpRequiredScope && (
              <p className="mt-1.5 text-[11px] text-[#646A74] font-mono uppercase tracking-wider">
                Scope: {stepUpRequiredScope}
              </p>
            )}
            {stepUpError && (
              <p id="step-up-error" className="mt-2 text-xs text-[#E07A5F]" role="alert">
                {stepUpError}
              </p>
            )}
          </div>
          <div className="flex items-center justify-end gap-2.5 pt-1">
            <button
              type="button"
              disabled={stepUpSubmitting}
              onClick={() => closeStepUpModal()}
              className="px-3.5 py-2 text-xs font-medium rounded-xl text-[#A6A8B1] hover:text-[#F4F1EA] hover:bg-[#F4F1EA]/5 transition-colors cursor-pointer disabled:opacity-50"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={stepUpSubmitting || stepUpCodeInput.length !== 6}
              className="px-4 py-2 text-xs font-semibold rounded-xl bg-[#C79A5A] text-[#08090B] hover:bg-[#D4AF70] transition-colors cursor-pointer disabled:opacity-50 disabled:cursor-not-allowed"
            >
              {stepUpSubmitting ? 'Verifying…' : 'Verify'}
            </button>
          </div>
        </form>
      </Modal>

      {/* ====================================================================
          RECOVERY MESSAGE & LOST MODE MODAL
          ==================================================================== */}
      <Modal
        open={recoveryModalOpen && Boolean(selectedDrawerDevice)}
        title={
          recoveryModalMode === 'LOST_MODE'
            ? `Enable Lost Mode on ${selectedDrawerDevice?.name ?? 'device'}`
            : `Recovery message for ${selectedDrawerDevice?.name ?? 'device'}`
        }
        subtitle={
          recoveryModalMode === 'LOST_MODE'
            ? 'Activate recovery protection, location tracking, and a return message.'
            : 'Prepare a return message with owner instructions for this device.'
        }
        onClose={() => setRecoveryModalOpen(false)}
      >
        {selectedDrawerDevice && (
          <form
            onSubmit={(e) => {
              e.preventDefault();
              void handleExecuteDeviceAction(
                selectedDrawerDevice,
                recoveryModalMode === 'LOST_MODE'
                  ? 'ENABLE_LOST_MODE'
                  : 'DISPLAY_RECOVERY_MESSAGE',
                {
                  title: recoveryTitleInput,
                  message: recoveryMessageInput,
                  contactInstruction: recoveryContactInput,
                }
              );
            }}
            className="space-y-4"
          >
            <div>
              <label
                htmlFor="recovery-title-input"
                className="block text-xs font-medium text-[#9499A3] mb-1.5"
              >
                Headline
              </label>
              <input
                id="recovery-title-input"
                type="text"
                required
                maxLength={80}
                value={recoveryTitleInput}
                onChange={(e) => setRecoveryTitleInput(e.target.value)}
                className="w-full px-3.5 py-2.5 text-sm bg-[#08090B] border border-[#25282E] rounded-xl text-[#F4F1EA] focus:outline-none focus:border-[#C8A66A]"
              />
            </div>

            <div>
              <label
                htmlFor="recovery-message-input"
                className="block text-xs font-medium text-[#9499A3] mb-1.5"
              >
                Return message
              </label>
              <textarea
                id="recovery-message-input"
                required
                rows={3}
                maxLength={240}
                value={recoveryMessageInput}
                onChange={(e) => setRecoveryMessageInput(e.target.value)}
                className="w-full px-3.5 py-2.5 text-sm bg-[#08090B] border border-[#25282E] rounded-xl text-[#F4F1EA] focus:outline-none focus:border-[#C8A66A]"
              />
            </div>

            <div>
              <label
                htmlFor="recovery-contact-input"
                className="block text-xs font-medium text-[#9499A3] mb-1.5"
              >
                Optional return contact instruction
              </label>
              <input
                id="recovery-contact-input"
                type="text"
                maxLength={120}
                value={recoveryContactInput}
                onChange={(e) => setRecoveryContactInput(e.target.value)}
                placeholder="For example: Call or message +1 (555) 019-2834"
                className="w-full px-3.5 py-2.5 text-sm bg-[#08090B] border border-[#25282E] rounded-xl text-[#F4F1EA] placeholder-[#646A74] focus:outline-none focus:border-[#C8A66A]"
              />
            </div>

            {/* Live Device Screen Preview */}
            <div className="p-4 rounded-xl bg-[#08090B] border border-[#25282E] space-y-2">
              <div className="text-[10px] font-semibold uppercase tracking-[0.2em] text-[#C8A66A]">
                RECOVERY SCREEN PREVIEW ({selectedDrawerDevice.platform === 'ANDROID' ? 'ANDROID' : 'WINDOWS'})
              </div>
              <div className="text-sm font-semibold text-[#F4F1EA]">
                {recoveryTitleInput || 'Lost Device'}
              </div>
              <p className="text-xs text-[#9499A3] leading-relaxed">
                {recoveryMessageInput}
              </p>
              {recoveryContactInput && (
                <div className="text-xs text-[#C8A66A] font-medium pt-1">
                  {recoveryContactInput}
                </div>
              )}
            </div>

            <div className="pt-2 flex items-center justify-end gap-2.5">
              <SecondaryButton onClick={() => setRecoveryModalOpen(false)}>
                Cancel
              </SecondaryButton>
              <PrimaryButton type="submit" disabled={deviceActionBusy !== null}>
                {recoveryModalMode === 'LOST_MODE'
                  ? 'Enable Lost Mode'
                  : 'Save Recovery Message'}
              </PrimaryButton>
            </div>
          </form>
        )}
      </Modal>

      {/* ====================================================================
          CONNECT A DEVICE MODAL — 01 ─ 02 ─ 03 PROGRESS WIZARD
          ==================================================================== */}
      <Modal
        open={connectModalOpen}
        title="Connect a device"
        subtitle="Add a Windows PC or Android phone to your VAJRA account."
        onClose={() => setConnectModalOpen(false)}
      >
        {/* Minimal Progress Indicator: 01 ─ 02 ─ 03 */}
        <div className="flex items-center gap-3 text-xs font-mono tracking-widest pb-2">
          <span
            className={
              connectWizardStep === 1 ? 'text-[#C8A66A] font-semibold' : 'text-[#75B798]'
            }
          >
            01
          </span>
          <span className="text-[#25282E]">───</span>
          <span
            className={
              connectWizardStep === 2
                ? 'text-[#C8A66A] font-semibold'
                : connectWizardStep > 2
                ? 'text-[#75B798]'
                : 'text-[#646A74]'
            }
          >
            02
          </span>
          <span className="text-[#25282E]">───</span>
          <span
            className={
              connectWizardStep === 3 ? 'text-[#C8A66A] font-semibold' : 'text-[#646A74]'
            }
          >
            03
          </span>
        </div>

        {/* Step 01: Choose device & Name device */}
        {connectWizardStep === 1 && (
          <form onSubmit={(e) => void handleInitiateEnrollment(e)} className="space-y-5">
            <div className="space-y-2">
              <span className="block text-xs font-medium text-[#9499A3]">
                Choose device
              </span>
              <div className="grid grid-cols-2 gap-3.5">
                <button
                  type="button"
                  onClick={() => setNewDeviceType('WINDOWS')}
                  className={`p-4 rounded-xl border text-left flex items-center gap-3.5 transition-all cursor-pointer ${
                    newDeviceType === 'WINDOWS'
                      ? 'bg-[#15171C] border-[#C8A66A] text-[#F4F1EA]'
                      : 'bg-[#08090B] border-[#25282E] text-[#9499A3]'
                  }`}
                >
                  <Laptop className="w-5 h-5 text-[#C8A66A]" />
                  <div>
                    <div className="text-xs font-semibold">Windows</div>
                    <div className="text-[11px] text-[#646A74]">PC or laptop</div>
                  </div>
                </button>

                <button
                  type="button"
                  onClick={() => setNewDeviceType('ANDROID')}
                  className={`p-4 rounded-xl border text-left flex items-center gap-3.5 transition-all cursor-pointer ${
                    newDeviceType === 'ANDROID'
                      ? 'bg-[#15171C] border-[#C8A66A] text-[#F4F1EA]'
                      : 'bg-[#08090B] border-[#25282E] text-[#9499A3]'
                  }`}
                >
                  <Smartphone className="w-5 h-5 text-[#C8A66A]" />
                  <div>
                    <div className="text-xs font-semibold">Android</div>
                    <div className="text-[11px] text-[#646A74]">Phone</div>
                  </div>
                </button>
              </div>
            </div>

            <div>
              <label
                htmlFor="connect-device-name"
                className="block text-xs font-medium text-[#9499A3] mb-1.5"
              >
                Name device
              </label>
              <input
                id="connect-device-name"
                type="text"
                required
                value={newDeviceName}
                onChange={(e) => setNewDeviceName(e.target.value)}
                placeholder="ASUS TUF F16"
                className="w-full px-4 py-2.5 text-sm bg-[#08090B] border border-[#25282E] rounded-xl text-[#F4F1EA] focus:outline-none focus:border-[#C8A66A]"
              />
            </div>

            <div className="pt-2 flex items-center justify-end gap-2.5">
              <SecondaryButton onClick={() => setConnectModalOpen(false)}>
                Cancel
              </SecondaryButton>
              <PrimaryButton type="submit" disabled={enrollmentStepBusy}>
                {enrollmentStepBusy ? 'Preparing...' : 'Continue to Pairing'}
              </PrimaryButton>
            </div>
          </form>
        )}

        {/* Step 02: Secure pairing */}
        {connectWizardStep === 2 && activeEnrollment && (
          <div className="space-y-5">
            <div className="bg-[#08090B] border border-[#25282E] rounded-xl p-5 space-y-4 text-center">
              <div className="text-xs text-[#9499A3]">
                Scan this QR code or enter the pairing code on{' '}
                <span className="text-[#F4F1EA] font-medium">{newDeviceName}</span>
              </div>

              <div className="bg-white p-3 rounded-xl w-44 h-44 mx-auto flex items-center justify-center">
                <img
                  src={activeEnrollment.qrCodeDataUrl}
                  alt="Device pairing QR code"
                  className="w-full h-full object-contain"
                />
              </div>

              <div className="space-y-1">
                <div className="text-[11px] text-[#646A74]">One-Time Pairing Code</div>
                <div className="font-mono text-base font-semibold text-[#C8A66A] tracking-wider">
                  {activeEnrollment.enrollmentToken}
                </div>
              </div>
            </div>

            <div className="p-4 rounded-xl bg-[#15171C] border border-[#25282E] space-y-3">
              <div className="text-xs font-semibold text-[#F4F1EA]">
                Pair this device now
              </div>
              <p className="text-xs text-[#9499A3] leading-relaxed">
                Complete secure pairing directly from this browser to test and confirm{' '}
                {newDeviceName}.
              </p>
              <PrimaryButton
                disabled={enrollmentStepBusy}
                onClick={() => void handlePairDeviceWithBrowserCredentials(activeEnrollment)}
                className="w-full"
              >
                {enrollmentStepBusy ? 'Pairing device...' : `Complete Pairing`}
              </PrimaryButton>
            </div>
          </div>
        )}

        {/* Step 03: Confirmation */}
        {connectWizardStep === 3 && (
          <div className="space-y-5 text-center py-2">
            <div className="w-12 h-12 rounded-full bg-[#15171C] border border-[#75B798]/40 flex items-center justify-center mx-auto">
              <VajraSymbol className="w-6 h-6" tone="jade" />
            </div>
            <div className="space-y-1.5">
              <h3 className="text-base font-semibold text-[#F4F1EA] font-display">
                Confirm {newDeviceName}
              </h3>
              <p className="text-xs text-[#9499A3] max-w-sm mx-auto leading-relaxed">
                {newDeviceName} verified its identity and is ready to join your protected devices.
              </p>
            </div>
            <div className="pt-2">
              <PrimaryButton
                onClick={() => {
                  if (pairedReadyDeviceId) {
                    const matched = enrolledDevices.find((d) => d.id === pairedReadyDeviceId);
                    void handleConfirmEnrollment(
                      pairedReadyDeviceId,
                      matched?.publicKeyFingerprint ?? null
                    );
                  } else {
                    setConnectModalOpen(false);
                  }
                }}
                className="w-full"
              >
                Approve & Protect Device
              </PrimaryButton>
            </div>
          </div>
        )}
      </Modal>
    </div>
  );
}
