import { Buffer } from "buffer";
globalThis.Buffer = globalThis.Buffer ?? Buffer;
// jsrp (SRP library) requires a global `process` object in the browser.
if (typeof globalThis.process === "undefined") {
  (globalThis as any).process = { env: {}, version: "v22.0.0", browser: true, nextTick: (fn: Function, ...args: any[]) => setTimeout(() => fn(...args), 0) };
}

import { StrictMode } from "react";
import ReactDOM from "react-dom/client";
import { createRouter, RouterProvider } from "@tanstack/react-router";
import NProgress from "nprogress";

import { queryClient } from "./hooks/api/reactQuery";
import { ErrorPage } from "./pages/public/ErrorPage/ErrorPage";
import { NotFoundPage } from "./pages/public/NotFoundPage/NotFoundPage";
// Import the generated route tree
import { routeTree } from "./routeTree.gen";

import "@fontsource/inter/400.css";
import "@fontsource/inter/500.css";
import "@xyflow/react/dist/style.css";
import "nprogress/nprogress.css";
import "react-toastify/dist/ReactToastify.css";
import "@fortawesome/fontawesome-svg-core/styles.css";
import "react-day-picker/dist/style.css";
import "./index.css";

import "./translation";

// Create a new router instance
NProgress.configure({ showSpinner: false });

window.addEventListener("vite:preloadError", async (event) => {
  const reloadCount = parseInt(sessionStorage.getItem("vitePreloadErrorCount") || "0", 10);

  if (reloadCount >= 2) {
    // Don't preventDefault — let the error propagate so the app shows a real error.
    console.warn("Vite preload has failed multiple times. Stopping automatic reload.");
    return;
  }
  event.preventDefault();

  try {
    if ("caches" in window) {
      const keys = await caches.keys();
      await Promise.all(keys.map((key) => caches.delete(key)));
    }
  } catch (cleanupError) {
    console.error(cleanupError);
  }
  //
  // Increment and save the counter
  sessionStorage.setItem("vitePreloadErrorCount", (reloadCount + 1).toString());

  console.log(`Reloading page (attempt ${reloadCount + 1} of 2)...`);
  window.location.reload(); // for example, refresh the page
});

const router = createRouter({
  routeTree,
  context: { serverConfig: null, queryClient },
  defaultPendingComponent: () => (
    <div className="flex h-screen w-screen items-center justify-center bg-bunker-800">
      <div className="h-10 w-10 animate-spin rounded-full border-4 border-mineshaft-500 border-t-primary" />
    </div>
  ),
  defaultNotFoundComponent: NotFoundPage,
  defaultErrorComponent: ErrorPage
});

router.subscribe("onBeforeLoad", ({ pathChanged }) => {
  if (pathChanged) {
    NProgress.start();
    const timer = setTimeout(() => {
      clearTimeout(timer);
      NProgress.done();
    }, 2000);
  }
});
router.subscribe("onLoad", () => NProgress.done());

// Register the router instance for type safety
declare module "@tanstack/react-router" {
  interface Register {
    router: typeof router;
  }
}

const rootElement = document.getElementById("root")!;
if (!rootElement.innerHTML) {
  const root = ReactDOM.createRoot(rootElement);
  root.render(
    <StrictMode>
      <RouterProvider router={router} />
    </StrictMode>
  );
}
