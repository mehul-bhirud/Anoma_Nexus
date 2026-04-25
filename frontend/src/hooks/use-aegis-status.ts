import { useState, useEffect } from "react";

export function useAegisStatus() {
  const [isConnected, setIsConnected] = useState(false);
  const [isVerified, setIsVerified] = useState(true);

  useEffect(() => {
    // Simulate initial connection delay for demo purposes
    const timer = setTimeout(() => {
      setIsConnected(true);
    }, 1500);

    return () => clearTimeout(timer);
  }, []);

  return { isConnected, isVerified };
}
