export const isHanzoCloud = () =>
  window.location.origin.includes("https://kms.hanzo.ai") ||
  window.location.origin.includes("https://us.kms.hanzo.ai") ||
  window.location.origin.includes("https://eu.kms.hanzo.ai") ||
  window.location.origin.includes("https://gamma.kms.hanzo.ai");
