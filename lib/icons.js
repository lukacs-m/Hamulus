export function iconPaths(level = "neutral") {
  return Object.fromEntries([16, 32, 48, 128].map((size) => [size, `icons/${level}-${size}.png`]));
}

export function scoreTitle(result) {
  const label = { safe: "Looks legitimate", caution: "Be careful", danger: "Likely phishing" }[result.level];
  return `Hamulus - Last scanned email: ${result.score}/100 - ${label}`;
}
