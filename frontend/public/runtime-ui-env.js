// Runtime UI environment — injected at container startup or served as static file.
// __toCdnUrl: maps asset filenames to URLs. Default: serve from same origin.
window.__toCdnUrl = function(filename) {
  return "/" + filename;
};
// 20260409T004403
