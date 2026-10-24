import React from "react";

// Shown above the app in the mock-only SE build (MODE=se-mock) and nowhere else. The text comes from the server.
export default function HostedBanner({ banner }) {
  if (!banner) return null;
  return (
    <p role="note" className="hosted-banner" data-testid="hosted-banner">{banner}</p>
  );
}
