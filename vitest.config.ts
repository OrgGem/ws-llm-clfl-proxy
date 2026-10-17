import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    environment: "node",
    include: ["**/*.test.ts"],
    exclude: ["**/node_modules/**", "**/dist/**", "apps/identity/**", "integration/**"],
    restoreMocks: true,
    clearMocks: true,
  },
});
