"use client";
export default function RemediationsPage() {
  return (
    <div>
      <h1 className="text-2xl font-bold mb-6">Remediations</h1>
      <p className="text-muted-foreground mb-4">View running and completed remediations. Click a row to see live logs.</p>
      <p className="text-sm text-muted-foreground">
        Trigger remediations from the <a href="/vulnerabilities" className="underline">Vulnerabilities</a> page.
      </p>
    </div>
  );
}
