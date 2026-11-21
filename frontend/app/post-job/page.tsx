"use client";

import {
  buildPostJobArgs,
  getActiveContractId,
  getDescPayloadMax,
  postJob,
  storeDescriptionCid,
} from "@/lib/contract";
import { estimateTransactionFee, type FeeEstimate } from "@/lib/fee-estimator";
import TransactionPreview, {
  feeEstimateToSimulation,
  type PayloadScope,
} from "@/components/TransactionPreview";
import SigningOriginWarning from "@/components/SigningOriginWarning";
import { uploadToIpfs } from "@/lib/ipfs-service";
import ErrorBanner from "@/components/ErrorBanner";
import ContractRetryBanner from "@/components/ContractRetryBanner";
import dynamic from "next/dynamic";
import { getExplorerTxUrl, isValidStellarAddress, parseContractError, getNativeBalance, retryQueuedWrites, getCurrentOriginResult, type OriginValidationResult } from "@/lib/stellar";
import { useWallet } from "@/lib/wallet-context";
import { useRouter } from "next/navigation";
import { useEffect, useId, useRef, useState } from "react";
import {
  getRateLimitStatus,
  recordPostJob,
  formatCooldown,
  type RateLimitStatus,
} from "@/lib/rate-limiter";
import {
  validateAmount,
  validateAmountMin,
  validateDeadline,
  validateTokenAddress,
  MIN_JOB_AMOUNT_STROOPS,
} from "@/lib/sanitize";
import { JobCategorySelect } from "@/components/JobCategorySelect";
import { embedLanguage } from "@/lib/language";
import { StrKey } from "@stellar/stellar-sdk";

const MIN_JOB_AMOUNT_XLM = 0.5;
const DRAFT_STORAGE_KEY_PREFIX = "stellarwork:post-job-draft:";
const REDIRECT_DELAY_MS = 1500;

interface JobFormErrors {
  amount?: string;
  description?: string;
  deadline?: string;
  tokenAddress?: string;
  title?: string;
}

interface JobFormInput {
  amountStroops: string;
  bonusAmountStroops: string;
  hashHex: string;
  descriptionPayloadLen: number;
  deadlineUnix: string;
  htmlContent: string;
}

/**
 * Validate the post-job form and, when valid, derive the exact inputs used for
 * both the fee estimate and the on-chain submission. Kept in one place so the
 * simulated transaction always matches the transaction that gets submitted.
 */
async function validateAndBuildJobInput(params: {
  amount: string;
  bonusAmount: string;
  description: string;
  deadline: string;
  tokenAddress: string;
  title: string;
  language: string;
  maxDescPayloadBytes: number;
}): Promise<{ errors: JobFormErrors; input: JobFormInput | null }> {
  const {
    amount,
    bonusAmount,
    description,
    deadline,
    tokenAddress,
    title,
    language,
    maxDescPayloadBytes,
  } = params;
  const errors: JobFormErrors = {};

  const amountResult = validateAmount(amount);
  const amountStroops = amountResult.stroops;
  if (amountResult.error) {
    errors.amount = amountResult.error;
  } else if (amountStroops) {
    const minError = validateAmountMin(
      amountStroops,
      MIN_JOB_AMOUNT_STROOPS,
      `${MIN_JOB_AMOUNT_XLM} XLM`,
    );
    if (minError) errors.amount = minError;
  }

  const bonusAmountResult = validateAmount(bonusAmount || "0");
  const bonusAmountStroops = bonusAmountResult.stroops;
  if (bonusAmountResult.error) {
    errors.amount = bonusAmountResult.error;
  }

  const plainDescription = htmlToPlainText(description);
  const descriptionBytes = new TextEncoder().encode(plainDescription).length;
  if (!plainDescription) {
    errors.description = "Job description cannot be empty.";
  } else if (descriptionBytes > maxDescPayloadBytes) {
    errors.description = `Description must be at most ${maxDescPayloadBytes} bytes (currently ${descriptionBytes}).`;
  }

  if (deadline) {
    const deadlineError = validateDeadline(deadline);
    if (deadlineError) errors.deadline = deadlineError;
  }

  if (!tokenAddress.trim()) {
    errors.tokenAddress = "Token address is required.";
  } else {
    const tokenError = validateTokenAddress(tokenAddress);
    if (tokenError) {
      errors.tokenAddress = tokenError;
    } else if (
      !StrKey.isValidContract(tokenAddress.trim()) &&
      !StrKey.isValidEd25519PublicKey(tokenAddress.trim())
    ) {
      errors.tokenAddress = "Invalid Stellar address or contract ID.";
    } else if (!isValidStellarAddress(tokenAddress)) {
      errors.tokenAddress =
        "Enter a valid Stellar address (G... or C..., 56 characters).";
    }
  }

  if (!title.trim()) {
    errors.title = "Job title is required.";
  } else if (new TextEncoder().encode(title).length > 64) {
    errors.title = `Title must be at most 64 bytes (currently ${new TextEncoder().encode(title).length}).`;
  }

  if (Object.keys(errors).length > 0) {
    return { errors, input: null };
  }

  const rawDescription = description.trim();
  const htmlContent = embedLanguage(rawDescription, language);
  const plainContent = htmlToPlainText(rawDescription);
  const hashHex = await sha256Hex(plainContent);
  const descriptionPayloadLen = new TextEncoder().encode(plainContent).length;
  const deadlineUnix = deadline
    ? Math.floor(new Date(deadline).getTime() / 1000).toString()
    : "0";

  return {
    errors,
    input: {
      amountStroops: amountStroops!,
      bonusAmountStroops: bonusAmountStroops || "0",
      hashHex,
      descriptionPayloadLen,
      deadlineUnix,
      htmlContent,
    },
  };
}

function getErrorMessage(error: unknown): string {
  if (error instanceof Error) return error.message;
  if (typeof error === "string") return error;
  return "";
}

function formatContractError(error: unknown, fallback: string): string {
  const message = getErrorMessage(error);
  const normalized = message.toLowerCase();

  if (
    normalized.startsWith("stellar rejected the transaction") ||
    normalized.startsWith("transaction was cancelled") ||
    normalized.startsWith("freighter is locked") ||
    normalized.startsWith("the transaction was submitted") ||
    normalized.startsWith("connect freighter before")
  ) {
    return message;
  }

  if (normalized.includes("user rejected") || normalized.includes("cancelled")) {
    return "Transaction was cancelled in Freighter.";
  }

  if (normalized.includes("wallet locked")) {
    return "Freighter is locked. Unlock your wallet and try again.";
  }

  if (
    normalized.includes("sendtransaction") ||
    normalized.includes("contract invocation failed") ||
    normalized.includes("transaction failed") ||
    normalized.includes("tx_bad") ||
    normalized.includes("op_")
  ) {
    return "Stellar rejected the transaction. Check your wallet network, balance, and token address, then try again.";
  }

  if (normalized.includes("timed out")) {
    return "The transaction was submitted but confirmation timed out. Check your wallet activity or the Stellar explorer before retrying.";
  }

  if (normalized.includes("connect freighter")) {
    return "Connect Freighter before posting a job.";
  }

  return fallback;
}

async function withContractErrorHandling<T>(
  call: () => Promise<T>,
  fallback: string,
): Promise<T> {
  try {
    return await call();
  } catch (error) {
    throw new Error(formatContractError(error, fallback));
  }
}
const RichTextEditor = dynamic(
  () => import("@/components/RichTextEditor"),
  { ssr: false, loading: () => <p className="text-sm text-slate-500">Loading editor…</p> },
);


interface DraftData {
  amount: string;
  bonusAmount: string;
  description: string;
  deadline: string;
  tokenAddress: string;
  title: string;
  category: string;
  language: string;
  savedAt: number;
}

function getDraftKey(walletAddress: string | null): string {
  return `${DRAFT_STORAGE_KEY_PREFIX}${walletAddress ?? "anonymous"}`;
}

function loadDraft(walletAddress: string | null): DraftData | null {
  try {
    const raw = localStorage.getItem(getDraftKey(walletAddress));
    if (!raw) return null;
    const draft = JSON.parse(raw) as DraftData;
    return { ...draft, bonusAmount: draft.bonusAmount ?? "0" };
  } catch {
    return null;
  }
}

function saveDraft(walletAddress: string | null, data: DraftData): void {
  try {
    localStorage.setItem(getDraftKey(walletAddress), JSON.stringify(data));
  } catch {
    // Storage quota exceeded — ignore silently.
  }
}

function clearDraft(walletAddress: string | null): void {
  try {
    localStorage.removeItem(getDraftKey(walletAddress));
  } catch {
    // Ignore.
  }
}

import { sha256Hex, htmlToPlainText } from "@/lib/crypto";

export default function PostJobPage() {
  const router = useRouter();
  const { wallet, walletNetwork, connectWallet } = useWallet();
  const [amount, setAmount] = useState("");
  const [bonusAmount, setBonusAmount] = useState("");
  const [description, setDescription] = useState("");
  const [deadline, setDeadline] = useState("");
  const [title, setTitle] = useState("");
  const [category, setCategory] = useState("development");
  const [language, setLanguage] = useState("en");
  const descriptionLabelId = useId();
  const [tokenAddress, setTokenAddress] = useState(
    process.env.NEXT_PUBLIC_NATIVE_TOKEN ?? "",
  );
  const [termsAcknowledged, setTermsAcknowledged] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);
  const [warning, setWarning] = useState<string | null>(null);
  const [lastAnnouncedSuccess, setLastAnnouncedSuccess] = useState<string | null>(null);
  const [txHash, setTxHash] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);
  const [feeEstimate, setFeeEstimate] = useState<FeeEstimate | null>(null);
  const [estimating, setEstimating] = useState(false);
  const [estimateError, setEstimateError] = useState<string | null>(null);
  const [maxDescPayloadBytes, setMaxDescPayloadBytes] = useState(4096);
  const [fieldErrors, setFieldErrors] = useState<{
    amount?: string;
    description?: string;
    deadline?: string;
    tokenAddress?: string;
    title?: string;
  }>({});
  const [rateLimit, setRateLimit] = useState<RateLimitStatus>({
    remaining: 5,
    cooldownEndsAt: null,
    isLimited: false,
  });
  // Origin validation — computed once on mount so the SigningOriginWarning
  // banner can be displayed before the user clicks Confirm.
  const [originResult, setOriginResult] = useState<OriginValidationResult | null>(null);
  const [tags, setTags] = useState<string[]>([]);
  const [advancedOpen, setAdvancedOpen] = useState(() => {
    if (typeof window === "undefined") return false;
    return sessionStorage.getItem("stellarwork:advanced-open") === "true";
  });

  // Draft saving state
  const [draftSavedAt, setDraftSavedAt] = useState<number | null>(null);
  const [hasDraft, setHasDraft] = useState(false);
  const debounceTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const redirectTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const prevWalletRef = useRef<string | null>(null);

  useEffect(() => {
    return () => {
      if (redirectTimerRef.current) clearTimeout(redirectTimerRef.current);
    };
  }, []);

  // Restore draft on mount and on wallet change
  useEffect(() => {
    const draft = loadDraft(wallet);
    if (draft) {
      // eslint-disable-next-line react-hooks/set-state-in-effect
      setAmount(draft.amount);
      setBonusAmount(draft.bonusAmount);
      setDescription(draft.description);
      setDeadline(draft.deadline);
      setTokenAddress(
        draft.tokenAddress || process.env.NEXT_PUBLIC_NATIVE_TOKEN || "",
      );
      setTitle(draft.title || "");
      setCategory(draft.category || "development");
      setLanguage(draft.language || "en");
      setDraftSavedAt(draft.savedAt);
      setHasDraft(true);
    } else {
      setHasDraft(false);
      setDraftSavedAt(null);
    }
    prevWalletRef.current = wallet;
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // When wallet address changes, clear current form and load draft for new wallet
  useEffect(() => {
    if (prevWalletRef.current === wallet) return;
    prevWalletRef.current = wallet;
    setAmount("");
    setBonusAmount("");
    setDescription("");
    setDeadline("");
    setTokenAddress(process.env.NEXT_PUBLIC_NATIVE_TOKEN ?? "");
    setTitle("");
    setCategory("development");
    setDraftSavedAt(null);
    setHasDraft(false);
    const draft = loadDraft(wallet);
    if (draft) {
      // eslint-disable-next-line react-hooks/set-state-in-effect
      setAmount(draft.amount);
      setBonusAmount(draft.bonusAmount);
      setDescription(draft.description);
      setDeadline(draft.deadline);
      setTokenAddress(
        draft.tokenAddress || process.env.NEXT_PUBLIC_NATIVE_TOKEN || "",
      );
      setTitle(draft.title || "");
      setCategory(draft.category || "development");
      setDraftSavedAt(draft.savedAt);
      setHasDraft(true);
    }
  }, [wallet]);

  // BUG-28: token addresses differ per network, so drop a stale one on switch.
  const prevNetworkRef = useRef(walletNetwork);
  useEffect(() => {
    if (prevNetworkRef.current === walletNetwork) return;
    prevNetworkRef.current = walletNetwork;
    setTokenAddress(process.env.NEXT_PUBLIC_NATIVE_TOKEN ?? "");
  }, [walletNetwork]);

  useEffect(() => {
    if (!wallet) {
      // eslint-disable-next-line react-hooks/set-state-in-effect
      setError(null);
      setSuccess(null);
      setWarning(null);
      setTxHash(null);
      setFeeEstimate(null);
      setEstimateError(null);
      setEstimating(false);
    }
  }, [wallet]);

  // Compute the origin validation result once on mount (client-side only).
  // This is synchronous and does not touch the wallet or network.
  useEffect(() => {
    // eslint-disable-next-line react-hooks/set-state-in-effect
    setOriginResult(getCurrentOriginResult());
  }, []);

  useEffect(() => {
    void getDescPayloadMax()
      .then((maxBytes) => {
        if (maxBytes > 0) {
          setMaxDescPayloadBytes(maxBytes);
        }
      })
      .catch((err) => {
        setWarning(
          formatContractError(
            err,
            "Could not verify the contract description limit. The default limit will be used.",
          ),
        );
      });
  }, []);

  useEffect(() => {
    // eslint-disable-next-line react-hooks/set-state-in-effect
    setRateLimit(getRateLimitStatus());
    const interval = setInterval(() => {
      setRateLimit(getRateLimitStatus());
    }, 1000);
    return () => clearInterval(interval);
  }, []);

  // Debounced auto-save draft on form value changes
  useEffect(() => {
    if (debounceTimerRef.current) {
      clearTimeout(debounceTimerRef.current);
    }
    const isEmpty =
      !amount.trim() && !htmlToPlainText(description).trim() && !deadline;
    if (isEmpty) return;

    debounceTimerRef.current = setTimeout(() => {
      const now = Date.now();
      saveDraft(wallet, {
        amount,
        bonusAmount,
        description,
        deadline,
        tokenAddress,
        title,
        category,
        language,
        savedAt: now,
      });
      setDraftSavedAt(now);
      setHasDraft(true);
    }, 800);

    return () => {
      if (debounceTimerRef.current) {
        clearTimeout(debounceTimerRef.current);
      }
    };
  }, [
    amount,
    bonusAmount,
    description,
    deadline,
    tokenAddress,
    title,
    category,
    language,
    wallet,
  ]);

  // Warn on navigation away when unsaved changes exist
  useEffect(() => {
    const hasContent =
      amount.trim() || htmlToPlainText(description).trim() || deadline;
    if (!hasContent) return;

    const handleBeforeUnload = (event: BeforeUnloadEvent) => {
      event.preventDefault();
      event.returnValue = "";
    };
    window.addEventListener("beforeunload", handleBeforeUnload);
    return () => window.removeEventListener("beforeunload", handleBeforeUnload);
  }, [amount, description, deadline]);

  function handleClearDraft() {
    clearDraft(wallet);
    setAmount("");
    setBonusAmount("");
    setDescription("");
    setDeadline("");
    setTokenAddress(process.env.NEXT_PUBLIC_NATIVE_TOKEN ?? "");
    setTitle("");
    setCategory("development");
    setDraftSavedAt(null);
    setHasDraft(false);
    setFieldErrors({});
  }

  /**
   * Phase 1 — validate the form, then simulate the transaction on the RPC to
   * estimate its fee before anything is submitted. The estimate (XLM + USD,
   * breakdown, recent-fee comparison, high-fee warning) is shown in the
   * TransactionPreview panel; the user then confirms to actually post.
   */
  async function handleSubmit(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (submitting || estimating) return;
    setError(null);
    setSuccess(null);
    setWarning(null);
    setTxHash(null);
    setFieldErrors({});
    setEstimateError(null);
    setFeeEstimate(null);

    if (!wallet) {
      try {
        await connectWallet();
      } catch {
        setError("Failed to connect wallet. Is Freighter installed?");
      }
      return;
    }

    const { errors, input } = await validateAndBuildJobInput({
      amount,
      bonusAmount,
      description,
      deadline,
      tokenAddress,
      title,
      language,
      maxDescPayloadBytes,
    });
    if (Object.keys(errors).length > 0) {
      setFieldErrors(errors);
      return;
    }
    if (!input) return;

    const limitStatus = getRateLimitStatus();
    if (limitStatus.isLimited) {
      setError(
        `Rate limit reached. You can post at most 5 jobs per hour. Try again in ${formatCooldown(limitStatus.cooldownEndsAt!)}.`,
      );
      setRateLimit(limitStatus);
      return;
    }

    // Simulate the exact transaction the user will submit (same args).
    const args = buildPostJobArgs(
      wallet,
      input.amountStroops,
      input.bonusAmountStroops,
      input.hashHex,
      input.descriptionPayloadLen,
      input.deadlineUnix,
      tokenAddress.trim(),
      title.trim(),
      category,
    );

    setEstimating(true);
    try {
      const estimate = await estimateTransactionFee(
        getActiveContractId(),
        "post_job",
        args,
        { walletAddress: wallet },
      );
      setFeeEstimate(estimate);
    } catch (e) {
      // Estimation is best-effort: surface the reason but never block posting.
      setEstimateError(
        formatContractError(
          e,
          "Could not estimate the transaction fee. You can still post the job.",
        ),
      );
    } finally {
      setEstimating(false);
    }
  }

  /**
   * Phase 2 — the user confirmed the fee estimate: submit the job for real.
   * Re-validates from the current form state so the posted job always matches
   * what the user sees (the estimate itself is advisory and re-runnable).
   */
  async function handleConfirmPost() {
    if (submitting || !wallet) return;
    setError(null);
    setSuccess(null);
    setWarning(null);
    setTxHash(null);
    setFieldErrors({});

    const limitStatus = getRateLimitStatus();
    if (limitStatus.isLimited) {
      setError(
        `Rate limit reached. You can post at most 5 jobs per hour. Try again in ${formatCooldown(limitStatus.cooldownEndsAt!)}.`,
      );
      setRateLimit(limitStatus);
      return;
    }

    const { errors, input } = await validateAndBuildJobInput({
      amount,
      bonusAmount,
      description,
      deadline,
      tokenAddress,
      title,
      language,
      maxDescPayloadBytes,
    });
    if (Object.keys(errors).length > 0 || !input) {
      setFieldErrors(errors);
      // The estimate may be stale after edits — require a fresh one.
      setFeeEstimate(null);
      setEstimateError(null);
      return;
    }

    setSubmitting(true);
    try {
      localStorage.setItem(`job-desc:${input.hashHex}`, input.htmlContent);
      const cid = await uploadToIpfs(input.htmlContent);

      const result = await withContractErrorHandling(
        () =>
          postJob(
            wallet,
            input.amountStroops,
            input.hashHex,
            input.descriptionPayloadLen,
            input.deadlineUnix,
            tokenAddress.trim(),
            title.trim(),
            category,
          ),
        "Could not post the job to the contract. Please check your wallet and try again.",
      );
      if (result.status !== "SUCCESS") {
        throw new Error(result.errorResult ?? "Job transaction failed.");
      }
      const rawJobId = result.data;
      if (
        typeof rawJobId !== "bigint" &&
        typeof rawJobId !== "number" &&
        typeof rawJobId !== "string"
      ) {
        throw new Error("The job was posted, but its ID was not returned.");
      }
      const jobId = String(rawJobId);

      if (cid && !cid.startsWith("fallback:")) {
        try {
          await withContractErrorHandling(
            () => storeDescriptionCid(wallet, input.hashHex, cid),
            "Job posted, but the description CID could not be saved on-chain.",
          );
        } catch (cidError) {
          setWarning(getErrorMessage(cidError));
        }
      }
      if (result.hash) {
        setTxHash(result.hash);
      }
      recordPostJob();
      setRateLimit(getRateLimitStatus());
      const successMessage = `Job #${jobId} created successfully. Redirecting...`;
      setSuccess(successMessage);
      if (successMessage !== lastAnnouncedSuccess) {
        setLastAnnouncedSuccess(successMessage);
      }

      // Clear form and draft after successful submission.
      clearDraft(wallet);
      setAmount("");
      setBonusAmount("");
      setDescription("");
      setDeadline("");
      setTitle("");
      setCategory("development");
      setDraftSavedAt(null);
      setHasDraft(false);
      setFeeEstimate(null);
      setEstimateError(null);

      redirectTimerRef.current = setTimeout(() => {
        router.push(`/job/${encodeURIComponent(jobId)}`);
      }, REDIRECT_DELAY_MS);
    } catch (e) {
      let balance: string | undefined;
      if (wallet) {
        try {
          balance = await getNativeBalance(wallet);
        } catch {
          // Balance fetch failed — parseContractError will omit the balance detail
        }
      }
      setError(parseContractError(e, balance));
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <section className="mx-auto max-w-2xl space-y-6">
      <h1 className="text-2xl font-semibold">Post Job</h1>

      <ContractRetryBanner
        onRetryQueue={async () => {
          const { succeeded, failed } = await retryQueuedWrites();
          if (succeeded > 0) {
            setSuccess(`Retried ${succeeded} queued write${succeeded === 1 ? "" : "s"}.`);
          }
          if (failed > 0) {
            setError(`${failed} queued write${failed === 1 ? "" : "s"} still failed.`);
          }
        }}
      />

      {hasDraft && draftSavedAt && (
        <div className="flex items-center justify-between rounded-md border border-amber-200 bg-amber-50 px-4 py-2 text-sm text-amber-800">
          <span>
            Draft saved{" "}
            {new Date(draftSavedAt).toLocaleTimeString([], {
              hour: "2-digit",
              minute: "2-digit",
            })}
          </span>
          <button
            type="button"
            onClick={handleClearDraft}
            className="ml-4 rounded px-2 py-0.5 text-xs font-medium text-amber-700 hover:bg-amber-100"
          >
            Clear draft
          </button>
        </div>
      )}

      <form
        className="space-y-4 rounded-lg border border-slate-200 bg-white p-5"
        onSubmit={handleSubmit}
      >
        {(fieldErrors.amount ||
          fieldErrors.description ||
          fieldErrors.deadline ||
          fieldErrors.tokenAddress ||
          fieldErrors.title) && (
          <div
            id="post-job-errors"
            role="alert"
            aria-live="assertive"
            aria-atomic="true"
            className="rounded-md border border-red-200 bg-red-50 p-3 text-sm text-red-700"
          >
            <p className="font-medium">Please correct the highlighted fields:</p>
            <ul className="mt-2 list-disc pl-5">
              {fieldErrors.amount && <li>{fieldErrors.amount}</li>}
              {fieldErrors.description && <li>{fieldErrors.description}</li>}
              {fieldErrors.deadline && <li>{fieldErrors.deadline}</li>}
              {fieldErrors.tokenAddress && <li>{fieldErrors.tokenAddress}</li>}
              {fieldErrors.title && <li>{fieldErrors.title}</li>}
            </ul>
          </div>
        )}

        <label className="block text-sm font-medium">
          Amount (XLM)
          <input
            className="mt-1 w-full rounded-md border border-slate-300 px-3 py-2"
            type="number"
            min="0"
            step="0.0000001"
            value={amount}
            onChange={(e) => {
              const nextValue = e.target.value;
              if (nextValue.includes("-")) {
                return;
              }
              setAmount(nextValue);
              setFieldErrors((current) => ({ ...current, amount: undefined }));
            }}
            aria-invalid={Boolean(fieldErrors.amount)}
            aria-describedby={fieldErrors.amount ? "post-job-amount-error" : "post-job-amount-helper"}
            required
          />
          <p id="post-job-amount-helper" className="mt-1 text-xs text-slate-500">
            Enter amount in XLM with up to 7 decimal places (e.g., 10.5 or 0.0000001). Minimum: {MIN_JOB_AMOUNT_XLM} XLM.
          </p>
          {fieldErrors.amount && (
            <p id="post-job-amount-error" className="mt-1 text-xs text-red-600">
              {fieldErrors.amount}
            </p>
          )}
        </label>

        <label className="block text-sm font-medium">
          Job Title
          <input
            className="mt-1 w-full rounded-md border border-slate-300 px-3 py-2"
            type="text"
            maxLength={64}
            value={title}
            onChange={(e) => {
              setTitle(e.target.value);
              setFieldErrors((current) => ({ ...current, title: undefined }));
            }}
            aria-invalid={Boolean(fieldErrors.title)}
            aria-describedby={fieldErrors.title ? "post-job-title-error" : undefined}
            placeholder="e.g. Build a landing page"
            required
          />
          {fieldErrors.title && (
            <p id="post-job-title-error" className="mt-1 text-xs text-red-600">
              {fieldErrors.title}
            </p>
          )}
        </label>

        <div className="block text-sm font-medium">
          <JobCategorySelect
            category={category}
            tags={tags}
            onCategoryChange={setCategory}
            onTagsChange={setTags}
          />
        </div>

        <div className="block text-sm font-medium">
          <span id={descriptionLabelId}>Job Description</span>
          <div className="mt-1">
            <RichTextEditor
              value={description}
              onChange={(html) => {
                setDescription(html);
                setFieldErrors((current) => ({ ...current, description: undefined }));
              }}
              maxBytes={maxDescPayloadBytes}
              error={fieldErrors.description}
              errorId={fieldErrors.description ? "post-job-description-error" : undefined}
              labelId={descriptionLabelId}
              required
            />
          </div>
          {fieldErrors.description && (
            <p id="post-job-description-error" className="mt-1 text-xs text-red-600">
              {fieldErrors.description}
            </p>
          )}
        </div>

        <details
          open={advancedOpen}
          onToggle={(e) => {
            const open = (e.currentTarget as HTMLDetailsElement).open;
            setAdvancedOpen(open);
            try {
              sessionStorage.setItem(
                "stellarwork:advanced-open",
                String(open),
              );
            } catch {
              // ignore
            }
          }}
          className="rounded-md border border-slate-200 bg-slate-50"
        >
          <summary className="cursor-pointer select-none px-4 py-3 text-sm font-medium text-slate-700 hover:bg-slate-100">
            Advanced options
          </summary>
          <div className="space-y-4 px-4 pb-4">
            <label className="block text-sm font-medium">
              Bonus Amount (XLM)
              <input
                className="mt-1 w-full rounded-md border border-slate-300 px-3 py-2"
                type="number"
                min="0"
                step="0.0000001"
                value={bonusAmount}
                onChange={(e) => {
                  const nextValue = e.target.value;
                  if (nextValue.includes("-")) {
                    return;
                  }
                  setBonusAmount(nextValue);
                }}
                placeholder="Optional early completion bonus"
              />
            </label>

            <label className="block text-sm font-medium">
              Deadline (optional)
              <input
                className="mt-1 w-full rounded-md border border-slate-300 px-3 py-2"
                type="date"
                value={deadline}
                onChange={(e) => {
                  setDeadline(e.target.value);
                  setFieldErrors((current) => ({
                    ...current,
                    deadline: undefined,
                  }));
                }}
                aria-invalid={Boolean(fieldErrors.deadline)}
                aria-describedby={
                  fieldErrors.deadline ? "post-job-deadline-error" : undefined
                }
              />
              {fieldErrors.deadline && (
                <p
                  id="post-job-deadline-error"
                  className="mt-1 text-xs text-red-600"
                >
                  {fieldErrors.deadline}
                </p>
              )}
            </label>

            <label className="block text-sm font-medium">
              Token Address
              <input
                className={`mt-1 w-full rounded-md border px-3 py-2 font-mono text-xs ${
                  fieldErrors.tokenAddress
                    ? "border-red-400 focus:border-red-500 focus:outline-red-500"
                    : "border-slate-300"
                }`}
                type="text"
                value={tokenAddress}
                onChange={(e) => {
                  setTokenAddress(e.target.value);
                  setFieldErrors((current) => ({
                    ...current,
                    tokenAddress: undefined,
                  }));
                }}
                onBlur={(e) => {
                  const trimmed = e.currentTarget.value.trim();
                  if (!trimmed) return;
                  if (!isValidStellarAddress(trimmed)) {
                    setFieldErrors((current) => ({
                      ...current,
                      tokenAddress:
                        "Enter a valid Stellar address (G... or C..., 56 characters).",
                    }));
                  }
                }}
                placeholder="G... or C... (56 characters)"
                spellCheck={false}
                autoComplete="off"
                aria-invalid={Boolean(fieldErrors.tokenAddress)}
                aria-describedby={
                  fieldErrors.tokenAddress
                    ? "post-job-token-address-error"
                    : undefined
                }
                required
              />
              {fieldErrors.tokenAddress && (
                <p
                  id="post-job-token-address-error"
                  className="mt-1 text-xs text-red-600"
                >
                  {fieldErrors.tokenAddress}
                </p>
              )}
            </label>
          </div>
        </details>

        {rateLimit.cooldownEndsAt && (
          <div
            className="rounded-md bg-blue-50 p-3 text-sm text-blue-700"
            role="status"
            aria-live="polite"
          >
            {rateLimit.isLimited
              ? `Rate limit: You can post again in ${formatCooldown(rateLimit.cooldownEndsAt)}`
              : `${rateLimit.remaining} job post${rateLimit.remaining === 1 ? "" : "s"} remaining this hour`}
          </div>
        )}

        {(estimating || feeEstimate || estimateError) && (
          <div className="space-y-3">
            <TransactionPreview
              operation="Post job"
              details={`${amount || "0"} XLM escrow + 2.5% platform fee on completion`}
              simulation={feeEstimate ? feeEstimateToSimulation(feeEstimate) : null}
              simulating={estimating}
              simulationError={estimateError ?? undefined}
              allowSubmitWithoutSimulation
              payloadScope={{
                operation: "Post job",
                contractMethod: "post_job",
                jobTitle: title.trim() || undefined,
                amount: amount ? `${amount} XLM` : undefined,
                recipient: wallet ?? undefined,
                deadline: deadline || undefined,
              }}
            />
            {originResult && (
              <SigningOriginWarning
                originResult={originResult}
                suppress={originResult.isPlatformOrigin}
              />
            )}
            <div className="flex items-center gap-2">
              <button
                type="button"
                onClick={handleConfirmPost}
                disabled={submitting || estimating}
                className="rounded-md bg-emerald-600 px-4 py-2 text-sm font-medium text-white hover:bg-emerald-700 disabled:cursor-not-allowed disabled:opacity-60"
                aria-busy={submitting}
              >
                {submitting ? "Posting..." : "Confirm & Post Job"}
              </button>
              {(feeEstimate || estimateError) && (
                <button
                  type="button"
                  onClick={() => {
                    setFeeEstimate(null);
                    setEstimateError(null);
                  }}
                  disabled={submitting || estimating}
                  className="rounded-md border border-slate-300 px-4 py-2 text-sm font-medium text-slate-700 hover:bg-slate-50 disabled:cursor-not-allowed disabled:opacity-60"
                >
                  Edit details
                </button>
              )}
            </div>
            <p className="text-xs text-slate-500">
              The fee is estimated by simulating your transaction on the network —
              nothing is submitted until you confirm.
            </p>
          </div>
        )}

        <label className="flex items-start gap-2 text-xs text-slate-600">
          <input type="checkbox" checked={termsAcknowledged} onChange={(e) => setTermsAcknowledged(e.target.checked)} className="mt-0.5" />
          I confirm the platform fee, payment token, deadline, and cancellation policy.
        </label>

        <button
          type="submit"
          className="rounded-md bg-slate-900 px-4 py-2 text-sm font-medium text-white disabled:cursor-not-allowed disabled:opacity-60"
          disabled={!termsAcknowledged || submitting || estimating || rateLimit.isLimited}
          aria-busy={submitting || estimating}
        >
          {submitting
            ? "Posting..."
            : estimating
              ? "Estimating fee…"
              : "Post Job"}
        </button>
        <p className="mt-2 text-xs text-slate-500">
          A 2.5% platform fee applies on job completion.{" "}
          <a
            href="https://github.com/anoncon/Stellar-work-/blob/main/docs/TOKENOMICS.md"
            target="_blank"
            rel="noopener noreferrer"
            className="text-blue-600 hover:underline"
          >
            Learn more about fees
          </a>
        </p>
      </form>

      {error && <ErrorBanner message={error} onDismiss={() => setError(null)} />}
      {warning && <ErrorBanner message={warning} onDismiss={() => setWarning(null)} />}
      {success && (
        <p role="status" aria-live="polite" aria-atomic="true" className="rounded-md bg-green-100 p-3 text-sm text-green-700">
          {success}
        </p>
      )}
      {txHash && (
        <p className="text-sm text-slate-700">
          Transaction:{" "}
          <a
            href={getExplorerTxUrl(txHash)}
            target="_blank"
            rel="noreferrer"
            className="text-blue-600 hover:underline"
          >
            {txHash}
          </a>
        </p>
      )}
    </section>
  );
}
