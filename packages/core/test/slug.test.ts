import { describe, expect, it } from "vitest";
import { normalizeSlug, validateSlug } from "../src/index.js";

describe("slug", () => {
  it("normalizes slugs", () => {
    expect(normalizeSlug("Wallet")).toBe("wallet");
    expect(normalizeSlug("  My Note  ")).toBe("my-note");
    expect(normalizeSlug("hello---world")).toBe("hello-world");
  });

  it("validates slug format", () => {
    expect(validateSlug("wallet")).toEqual({ ok: true });
    expect(validateSlug("ab")).toEqual({ ok: false, error: "invalid_format" });
    expect(validateSlug("admin")).toEqual({ ok: false, error: "reserved_slug" });
  });
});
