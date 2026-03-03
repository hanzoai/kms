// Stub for stripped EE secret scanning feature
export enum SecretScanningDataSource {
  GitHub = "github"
}

export enum SecretScanningScanStatus {
  Queued = "queued",
  Scanning = "scanning",
  Completed = "completed",
  Failed = "failed"
}

export enum SecretScanningFindingStatus {
  Unresolved = "unresolved",
  Resolved = "resolved"
}
