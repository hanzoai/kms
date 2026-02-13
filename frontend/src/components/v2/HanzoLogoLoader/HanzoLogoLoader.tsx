import { useEffect, useState } from "react";
import { AnimatePresence, motion } from "framer-motion";
import { twMerge } from "tailwind-merge";

type Props = {
  className?: string;
  size?: "sm" | "md" | "lg";
};

const sizeMap = {
  sm: "w-12 h-12",
  md: "w-24 h-24",
  lg: "w-32 h-32"
};

const logoVariants = {
  initial: {
    opacity: 0,
    rotateY: 180,
    scale: 0.6
  },
  animate: {
    opacity: 1,
    rotateY: 0,
    scale: 1,
    transition: {
      duration: 0.5,
      delay: 0.2,
      staggerChildren: 0.12,
      when: "beforeChildren" as const
    }
  },
  exit: {
    opacity: 0,
    scale: 0.6,
    transition: {
      duration: 0.3,
      staggerChildren: 0.05,
      staggerDirection: -1,
      when: "afterChildren" as const
    }
  }
};

const pathVariants = {
  initial: (custom: number) => ({
    opacity: 0,
    scale: 0.8,
    x: custom % 2 === 0 ? -15 : 15,
    y: custom % 3 === 0 ? -15 : 15,
    rotate: custom * 5
  }),
  animate: {
    opacity: 1,
    scale: 1,
    x: 0,
    y: 0,
    rotate: 0,
    transition: {
      type: "spring" as const,
      stiffness: 260,
      damping: 20
    }
  },
  exit: (custom: number) => ({
    opacity: 0,
    scale: 0.8,
    x: custom % 2 === 0 ? 15 : -15,
    y: custom % 3 === 0 ? 15 : -15,
    rotate: -custom * 5,
    transition: { duration: 0.2 }
  })
};

export const HanzoLogoLoader = ({ className, size = "lg" }: Props) => {
  const [cycle, setCycle] = useState(0);

  useEffect(() => {
    // After the entrance animation completes (~1.2s), hold for 0.6s, then restart
    const timer = setInterval(() => {
      setCycle((c) => c + 1);
    }, 2000);
    return () => clearInterval(timer);
  }, []);

  return (
    <div
      className={twMerge(sizeMap[size], className)}
      style={{ perspective: 800 }}
    >
      <AnimatePresence mode="wait">
        <motion.div
          key={cycle}
          initial="initial"
          animate="animate"
          exit="exit"
          variants={logoVariants}
          style={{ transformOrigin: "center center" }}
        >
          <svg
            viewBox="0 0 67 67"
            xmlns="http://www.w3.org/2000/svg"
            className="w-full h-full"
          >
            <motion.path
              custom={1}
              variants={pathVariants}
              d="M22.21 67V44.6369H0V67H22.21Z"
              fill="white"
            />
            <motion.path
              custom={1.5}
              variants={pathVariants}
              d="M0 44.6369L22.21 46.8285V44.6369H0Z"
              fill="#DDDDDD"
            />
            <motion.path
              custom={2}
              variants={pathVariants}
              d="M66.7038 22.3184H22.2534L0.0878906 44.6367H44.4634L66.7038 22.3184Z"
              fill="white"
            />
            <motion.path
              custom={3}
              variants={pathVariants}
              d="M22.21 0H0V22.3184H22.21V0Z"
              fill="white"
            />
            <motion.path
              custom={4}
              variants={pathVariants}
              d="M66.7198 0H44.5098V22.3184H66.7198V0Z"
              fill="white"
            />
            <motion.path
              custom={4.5}
              variants={pathVariants}
              d="M66.6753 22.3185L44.5098 20.0822V22.3185H66.6753Z"
              fill="#DDDDDD"
            />
            <motion.path
              custom={5}
              variants={pathVariants}
              d="M66.7198 67V44.6369H44.5098V67H66.7198Z"
              fill="white"
            />
          </svg>
        </motion.div>
      </AnimatePresence>
    </div>
  );
};
