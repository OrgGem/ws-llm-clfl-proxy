export function timestampMilliseconds(value) {
  if ((typeof value !== "string" && typeof value !== "number") || value === "") return Number.NaN;
  const numeric = typeof value === "number" ? value : /^\d+(?:\.\d+)?$/.test(value) ? Number(value) : Number.NaN;
  if (Number.isFinite(numeric)) return numeric < 10_000_000_000 ? numeric * 1000 : numeric;
  return Date.parse(value);
}

export function isTimestampExpired(value, now = Date.now()) {
  const milliseconds = timestampMilliseconds(value);
  return !Number.isFinite(milliseconds) || milliseconds <= now;
}
