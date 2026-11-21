import React from "react";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import PostJobPage from "@/app/post-job/page";

vi.mock("next/navigation", () => ({
  useRouter: () => ({ push: vi.fn() }),
}));

const mockPostJob = vi.fn();
const mockGetDescPayloadMax = vi.fn();

vi.mock("@/lib/contract", () => ({
  getDescPayloadMax: (...args: unknown[]) => mockGetDescPayloadMax(...args),
  postJob: (...args: unknown[]) => mockPostJob(...args),
  freelancerCancelJob: vi.fn(),
  getDescriptionCid: vi.fn(),
  storeDescriptionCid: vi.fn(),
}));

vi.mock("@/lib/ipfs-service", () => ({
  uploadToIpfs: vi.fn().mockResolvedValue("Qm123"),
  fetchFromIpfs: vi.fn(),
}));

vi.mock("@/lib/wallet-context", () => ({
  useWallet: () => ({
    wallet: "GWALLET000000000000000000000000000000000000000000000000000",
    connectWallet: vi.fn(),
  }),
}));

vi.mock("@/lib/stellar", () => ({
  getExplorerTxUrl: (hash: string) => `https://example.test/tx/${hash}`,
  isValidStellarAddress: (address: string) =>
    /^[GC][A-Z2-7]{55}$/.test(address.trim()),
  getCurrentOriginResult: () => null,
}));

describe("Post-job form: draft saving (FE-71)", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    localStorage.clear();
    mockGetDescPayloadMax.mockResolvedValue(4096);
    vi.stubGlobal("crypto", {
      subtle: {
        digest: vi.fn().mockResolvedValue(new Uint8Array(32).buffer),
      },
    });
  });

  it("shows 'Clear draft' button when a draft is restored from localStorage", () => {
    const walletKey =
      "stellarwork:post-job-draft:GWALLET000000000000000000000000000000000000000000000000000";
    localStorage.setItem(
      walletKey,
      JSON.stringify({
        amount: "5",
        description: "<p>Draft description</p>",
        deadline: "",
        tokenAddress: "GNATIVE",
        savedAt: Date.now(),
      }),
    );

    render(<PostJobPage />);

    expect(screen.getByText("Clear draft")).toBeInTheDocument();
    expect(screen.getByLabelText(/Bonus Amount/)).toHaveProperty("value", "0");
  });

  it("autosaves bonus-only edits and restores the saved bonus", async () => {
    const walletKey =
      "stellarwork:post-job-draft:GWALLET000000000000000000000000000000000000000000000000000";
    localStorage.setItem(
      walletKey,
      JSON.stringify({
        amount: "5",
        bonusAmount: "1",
        description: "<p>Draft description</p>",
        deadline: "",
        tokenAddress: "GNATIVE",
        savedAt: Date.now(),
      }),
    );

    const { unmount } = render(<PostJobPage />);
    const bonusInput = screen.getByLabelText(/Bonus Amount/);
    expect(bonusInput).toHaveProperty("value", "1");
    fireEvent.change(bonusInput, { target: { value: "2.5" } });

    await waitFor(() => {
      expect(JSON.parse(localStorage.getItem(walletKey)!).bonusAmount).toBe("2.5");
    });

    unmount();
    render(<PostJobPage />);
    expect(screen.getByLabelText(/Bonus Amount/)).toHaveProperty("value", "2.5");
  });

  it("clears draft and resets form when 'Clear draft' is clicked", async () => {
    const walletKey =
      "stellarwork:post-job-draft:GWALLET000000000000000000000000000000000000000000000000000";
    localStorage.setItem(
      walletKey,
      JSON.stringify({
        amount: "5",
        description: "<p>Draft description</p>",
        deadline: "",
        tokenAddress: "GNATIVE",
        savedAt: Date.now(),
      }),
    );

    render(<PostJobPage />);

    const clearBtn = screen.getByText("Clear draft");
    fireEvent.click(clearBtn);

    await waitFor(() => {
      expect(screen.queryByText("Clear draft")).not.toBeInTheDocument();
    });

    expect(localStorage.getItem(walletKey)).toBeNull();
    expect(screen.getByLabelText(/Bonus Amount/)).toHaveProperty("value", "");
  });

  it("does not show draft banner when no draft exists", () => {
    render(<PostJobPage />);
    expect(screen.queryByText("Clear draft")).not.toBeInTheDocument();
  });
});
