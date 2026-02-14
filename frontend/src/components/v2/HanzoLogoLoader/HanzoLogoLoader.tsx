import { motion } from "framer-motion";
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

// Each path assembles in with stagger, then the whole logo gently pulses
const containerVariants = {
  initial: { opacity: 0, scale: 0.8 },
  assemble: {
    opacity: 1,
    scale: 1,
    transition: {
      duration: 0.4,
      staggerChildren: 0.08,
      when: "beforeChildren" as const
    }
  }
};

const pathVariants = {
  initial: (custom: number) => ({
    opacity: 0,
    y: custom % 2 === 0 ? -12 : 12,
    x: custom % 3 === 0 ? -8 : 8
  }),
  assemble: {
    opacity: 1,
    y: 0,
    x: 0,
    transition: {
      type: "spring" as const,
      stiffness: 300,
      damping: 22
    }
  }
};

// Diagonal bar does a subtle shimmer/slide after assembly
const diagonalVariants = {
  initial: { opacity: 0, x: -20 },
  assemble: {
    opacity: 1,
    x: 0,
    transition: {
      type: "spring" as const,
      stiffness: 300,
      damping: 22
    }
  }
};

export const HanzoLogoLoader = ({ className, size = "lg" }: Props) => {
  return (
    <div className={twMerge(sizeMap[size], className)}>
      <motion.div
        initial="initial"
        animate="assemble"
        variants={containerVariants}
      >
        {/* Gentle pulse on the whole logo once assembled */}
        <motion.svg
          viewBox="0 0 67 67"
          xmlns="http://www.w3.org/2000/svg"
          className="w-full h-full"
          animate={{
            opacity: [1, 0.7, 1],
            scale: [1, 0.97, 1]
          }}
          transition={{
            duration: 2,
            repeat: Infinity,
            ease: "easeInOut",
            delay: 0.8 // wait for assembly to finish
          }}
        >
          {/* Bottom-left square */}
          <motion.path
            custom={1}
            variants={pathVariants}
            d="M22.21 67V44.6369H0V67H22.21Z"
            fill="white"
          />
          {/* Bottom-left shadow accent */}
          <motion.path
            custom={1.5}
            variants={pathVariants}
            d="M0 44.6369L22.21 46.8285V44.6369H0Z"
            fill="#DDDDDD"
          />
          {/* Diagonal bar — the "signature" piece */}
          <motion.path
            variants={diagonalVariants}
            d="M66.7038 22.3184H22.2534L0.0878906 44.6367H44.4634L66.7038 22.3184Z"
            fill="white"
          />
          {/* Top-left square */}
          <motion.path
            custom={3}
            variants={pathVariants}
            d="M22.21 0H0V22.3184H22.21V0Z"
            fill="white"
          />
          {/* Top-right square */}
          <motion.path
            custom={4}
            variants={pathVariants}
            d="M66.7198 0H44.5098V22.3184H66.7198V0Z"
            fill="white"
          />
          {/* Top-right shadow accent */}
          <motion.path
            custom={4.5}
            variants={pathVariants}
            d="M66.6753 22.3185L44.5098 20.0822V22.3185H66.6753Z"
            fill="#DDDDDD"
          />
          {/* Bottom-right square */}
          <motion.path
            custom={5}
            variants={pathVariants}
            d="M66.7198 67V44.6369H44.5098V67H66.7198Z"
            fill="white"
          />
        </motion.svg>
      </motion.div>
    </div>
  );
};
