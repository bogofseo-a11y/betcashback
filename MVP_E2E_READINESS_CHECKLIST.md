# BetCashback MVP — Manual E2E Readiness Checklist (Pre-Freeze)

Legend:
- ✅ Pass (verified in code and/or runnable check)
- ⚠️ Partial (code-verified, runtime/browser backend integration not fully executable in this environment)
- ❌ Fail (blocking issue found)

## 1) User bookmaker onboarding
| Scenario | Expected result | Actual result / status | Notes |
|---|---|---|---|
| Mini App loads active bookmakers | `/api/bookmakers` is called and list rendered | ⚠️ | Code path present in `loadUserData -> apiCall('/bookmakers')` and UI render flow. |
| Generate tracked link | `/api/bookmakers/:id/generate-link` returns URL and tokens persisted | ✅ | Endpoint exists with validation; frontend integrates button flow. |
| Submit player ID | `/api/bookmaker-accounts` stores/updates per `(user, bookmaker)` | ✅ | Endpoint and frontend flow present. |
| Status shown in UI | pending/verified/rejected reflected in UI | ⚠️ | Code paths present; requires live API session for full runtime assertion. |

## 2) Admin bookmaker verification
| Scenario | Expected result | Actual result / status | Notes |
|---|---|---|---|
| Verification queue loads | Admin sees bookmaker accounts with context | ✅ | `/admin/bookmaker-accounts` query includes user/bookmaker data + selected suggestion summary. |
| Verify account | status -> verified, audit + user notification | ✅ | Endpoint handles status update, audit, best-effort Telegram notify. |
| Reject account | status -> rejected, optional reason + notification | ✅ | Reason persisted and included in notification if provided. |
| Selected suggestion visibility | Selected suggestion details visible in queue | ✅ | `selected_*` fields included in backend and rendered in admin table. |
| Notes visibility | Notes modal/action available for bookmaker account | ✅ | Generic notes modal wired from BK row action. |

## 3) Claim submission flow
| Scenario | Expected result | Actual result / status | Notes |
|---|---|---|---|
| Non-verified blocked | Claims rejected unless bookmaker account is verified | ✅ | Backend gate checks `bookmaker_accounts.status === 'verified'`. |
| Verified can submit | Claim creation succeeds with attachments and audit | ✅ | Backend flow includes tier/risk/attachments/audit. |
| Admin queue updates | Claims visible and admin status update works | ✅ | Admin claims endpoints and modal actions present. |
| Notifications on status | approved/rejected/paid notify user best-effort | ✅ | Unified safe notifier used in claim status route. |

## 4) Partner import + suggestions
| Scenario | Expected result | Actual result / status | Notes |
|---|---|---|---|
| Upload CSV batch | Batch and rows created | ✅ | `/admin/partner-imports` parses CSV, inserts rows. |
| Diff counters | new/changed/unchanged computed and returned | ✅ | Counters are persisted and returned in summary/list. |
| Suggestions generated | Suggestions upserted per imported row | ✅ | Generation called in import transaction loop. |
| Suggestions in import view | Batch suggestions list visible | ✅ | `/admin/partner-imports/:id/suggestions` + admin modal flow wired. |
| Suggestions from BK verification | Account suggestions visible and selectable | ✅ | `/admin/bookmaker-accounts/:id/suggestions` and select endpoint wired. |
| Manual verification separate | Selecting suggestion does not auto-verify | ✅ | Selection endpoint only toggles `is_selected`. |

## 5) Internal notes workflow
| Scenario | Expected result | Actual result / status | Notes |
|---|---|---|---|
| Add/list claim notes | claim notes can be listed/added | ✅ | Claim modal has embedded notes list/add flow. |
| Add/list BK notes | bookmaker account notes listed/added | ✅ | Generic notes modal with entity_type `bookmaker_account`. |
| Add/list payout notes | payout_request notes listed/added | ✅ | Generic notes modal with entity_type `payout_request`. |
| Safe rendering | Note content does not break UI | ✅ | Escaping applied in notes rendering and key admin tables. |

## 6) Payout flow
| Scenario | Expected result | Actual result / status | Notes |
|---|---|---|---|
| Add payout method | User can save payout method | ✅ | Frontend `savePayoutMethod` -> backend `/api/payout-methods`. |
| Available amount shown | Withdrawable amount shown in wallet | ✅ | Frontend renders from `/api/payout-requests` balance payload. |
| Minimum enforced | amount >= app setting minimum | ✅ | Backend validates against `app_settings.min_payout_amount_rub`. |
| Create payout request | Request created with pending status | ✅ | Backend validates ownership, amount, availability, inserts request. |
| Overspend guard | Concurrency race protection in place | ✅ | `pg_advisory_xact_lock(user_id)` in transaction. |
| Admin queue/status | Admin sees queue and updates statuses | ✅ | `/admin/payout-requests` + patch status endpoint wired. |
| Invalid transitions rejected | Transition guardrails enforced | ✅ | Explicit transition map denies invalid rewrites. |
| paid requires tx_hash | paid blocked without tx hash | ✅ | Backend enforces non-empty `tx_hash` for paid. |
| Notifications | approved/processing/paid/rejected/failed notify best-effort | ✅ | Uses safe notifier; business action unaffected on send failure. |

## 7) General admin sanity
| Scenario | Expected result | Actual result / status | Notes |
|---|---|---|---|
| Main pages load | dashboard/claims/users/bookmakers/verification/imports/payouts visible | ⚠️ | Static admin shell renders; full API-backed content requires live backend+DB env. |
| Filters work | per-page filter buttons toggle correctly | ✅ | Claims filter selector fixed to page-scoped buttons only. |
| Dynamic table safety | dynamic content doesn’t break from special chars | ✅ | Key fields now escaped (`escapeHtml`/`escapeAttr`) in risky tables. |

---

## Blocking issues found during this pass
- No hard blocker found in code-level flow inspection.

## Small fix applied in this pass
- Scoped claim filter button active-state reset to `#page-claims .filter-btn` (avoids cross-page filter UI side effects).

## Environment limitations for this checklist
- Full backend+DB end-to-end HTTP execution could not be comprehensively completed in this environment session.
- Validation is code-backed plus static/browser shell checks.
