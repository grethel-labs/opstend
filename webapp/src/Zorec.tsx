export type ZorecGesture =
  | "neutral" | "listening" | "thinking" | "answered" | "missing-data" | "limit" | "offline"
  | "setup" | "verifying" | "scanning" | "selection" | "awaiting-download" | "failed" | "ready";

function imageUrl(theme: "light" | "dark", gesture: ZorecGesture) {
  const view = `${theme}-${gesture}`;
  // A distinct request URL also updates <picture> when only the SVG view changes.
  return `/brand/zorec.svg?view=${view}#${view}`;
}

export function Zorec({ gesture = "neutral", size = 56 }: { gesture?: ZorecGesture; size?: number }) {
  return (
    <picture className="zorec-mark" data-gesture={gesture}>
      <source media="(prefers-color-scheme: dark)" srcSet={imageUrl("dark", gesture)} />
      <img src={imageUrl("light", gesture)} width={size} height={size} alt="" />
    </picture>
  );
}
