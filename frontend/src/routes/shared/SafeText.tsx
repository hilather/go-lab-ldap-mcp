import { asText } from "../../lib/a11y";

export function SafeText({ value }: { value: string }) {
  return <>{asText(value)}</>;
}

export function LiveRegion({
  message,
  assertive = false,
}: {
  message?: string | undefined;
  assertive?: boolean;
}) {
  if (message === undefined || message === "") {
    return null;
  }
  return (
    <p role={assertive ? "alert" : "status"} aria-live={assertive ? "assertive" : "polite"}>
      {message}
    </p>
  );
}
