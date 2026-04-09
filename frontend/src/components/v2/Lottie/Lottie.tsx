import { forwardRef, ReactNode } from "react";

export type LottieProps = {
  children?: ReactNode;
  icon?: string;
  iconMode?: string;
  className?: string;
  isAutoPlay?: boolean;
};

// Replaced dotlottie WASM component with a simple CSS spinner.
// The WASM binary had version mismatches causing blank screens.
export const Lottie = forwardRef<HTMLDivElement, LottieProps>(
  ({ children, className, ...props }, ref): JSX.Element => {
    return (
      <div {...props} ref={ref} className={className}>
        <div
          style={{
            width: "100%",
            height: "100%",
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
          }}
        >
          <div
            style={{
              width: "2rem",
              height: "2rem",
              border: "2px solid rgba(255,255,255,0.2)",
              borderTopColor: "white",
              borderRadius: "50%",
              animation: "spin 0.8s linear infinite",
            }}
          />
          <style>{`@keyframes spin { to { transform: rotate(360deg) } }`}</style>
        </div>
        {children}
      </div>
    );
  }
);
