import "./shared.js";

export function iconPaths(level = "neutral") {
  return Object.fromEntries([16, 32, 48, 128].map((size) => [size, `icons/${level}-${size}.png`]));
}

export function scoreTitle(result) {
  return `Hamulus - Latest requested scan across tabs: ${result.score == null ? "Not scored" : `${result.score}/100`} - ${Hamulus.heading(result)}`;
}
