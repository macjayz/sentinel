import { describe, expect, it } from "vitest";
import { generateSessionToken, hashPassword, hashToken, roleMeetsMinimum, verifyPassword } from "./auth.js";

describe("password hashing", () => {
  it("verifies a correct password against its hash", async () => {
    const hash = await hashPassword("correct horse battery staple");
    expect(await verifyPassword("correct horse battery staple", hash)).toBe(true);
  });

  it("rejects an incorrect password", async () => {
    const hash = await hashPassword("correct horse battery staple");
    expect(await verifyPassword("wrong password", hash)).toBe(false);
  });

  it("produces a different hash each time due to a random salt", async () => {
    const hashA = await hashPassword("same password");
    const hashB = await hashPassword("same password");
    expect(hashA).not.toBe(hashB);
  });

  it("rejects malformed stored hashes instead of throwing", async () => {
    expect(await verifyPassword("anything", "not-a-valid-hash")).toBe(false);
  });
});

describe("session tokens", () => {
  it("generates unique, hashable tokens", () => {
    const tokenA = generateSessionToken();
    const tokenB = generateSessionToken();
    expect(tokenA).not.toBe(tokenB);
    expect(hashToken(tokenA)).not.toBe(hashToken(tokenB));
  });

  it("hashes the same token to the same value", () => {
    const token = generateSessionToken();
    expect(hashToken(token)).toBe(hashToken(token));
  });
});

describe("roleMeetsMinimum", () => {
  it("allows a role that meets or exceeds the minimum", () => {
    expect(roleMeetsMinimum("owner", "admin")).toBe(true);
    expect(roleMeetsMinimum("admin", "admin")).toBe(true);
    expect(roleMeetsMinimum("developer", "developer")).toBe(true);
  });

  it("rejects a role below the minimum", () => {
    expect(roleMeetsMinimum("viewer", "developer")).toBe(false);
    expect(roleMeetsMinimum("developer", "admin")).toBe(false);
  });

  it("rejects a missing or unknown role", () => {
    expect(roleMeetsMinimum(null, "viewer")).toBe(false);
    expect(roleMeetsMinimum("not-a-role", "viewer")).toBe(false);
  });
});
