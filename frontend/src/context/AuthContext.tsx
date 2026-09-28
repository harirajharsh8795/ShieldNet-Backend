import { createContext, useContext, useState, useEffect, type ReactNode } from "react";
import { loginOAuth2, signupOAuth2, logoutOAuth2, fetchCurrentUserProfile } from "../data/api";

export interface UserProfile {
  username: string;
  display_name: string;
  role: string;
  clearance_level: number;
  clearance_label: string;
  department: string;
  permissions?: string[];
}

interface AuthContextType {
  user: UserProfile | null;
  token: string | null;
  isAuthenticated: boolean;
  isLoading: boolean;
  login: (username: string, password: string) => Promise<void>;
  signup: (details: {
    username: string;
    password: string;
    display_name: string;
    role?: string;
    department?: string;
  }) => Promise<void>;
  logout: () => void;
  authMode: "login" | "signup";
  setAuthMode: (mode: "login" | "signup") => void;
  targetPath: string | null;
  setTargetPath: (path: string | null) => void;
  openAuthModal: (mode?: "login" | "signup", targetPath?: string) => void;
  closeAuthModal: () => void;
  isAuthModalOpen: boolean;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<UserProfile | null>(() => {
    try {
      const saved = localStorage.getItem("shieldnet_user");
      return saved ? JSON.parse(saved) : null;
    } catch {
      return null;
    }
  });

  const [token, setToken] = useState<string | null>(() => {
    return localStorage.getItem("shieldnet_token") || null;
  });

  const [isLoading, setIsLoading] = useState(false);
  const [authMode, setAuthMode] = useState<"login" | "signup">("login");
  const [isAuthModalOpen, setIsAuthModalOpen] = useState(false);
  const [targetPath, setTargetPath] = useState<string | null>(null);

  useEffect(() => {
    // If token exists, verify/refresh user profile
    if (token && !user) {
      fetchCurrentUserProfile()
        .then((profile) => {
          if (profile) setUser(profile);
          else {
            setToken(null);
            localStorage.removeItem("shieldnet_token");
            localStorage.removeItem("shieldnet_user");
          }
        })
        .catch(() => {
          // Keep cached user if offline
        });
    }
  }, [token, user]);

  const login = async (username: string, password: string) => {
    setIsLoading(true);
    try {
      const res = await loginOAuth2(username, password);
      if (res && res.user) {
        setUser(res.user);
        setToken(res.access_token || localStorage.getItem("shieldnet_token"));
        setIsAuthModalOpen(false);
      }
    } finally {
      setIsLoading(false);
    }
  };

  const signup = async (details: {
    username: string;
    password: string;
    display_name: string;
    role?: string;
    department?: string;
  }) => {
    setIsLoading(true);
    try {
      const res = await signupOAuth2(details);
      if (res && res.user) {
        setUser(res.user);
        setToken(res.access_token || localStorage.getItem("shieldnet_token"));
        setIsAuthModalOpen(false);
      }
    } finally {
      setIsLoading(false);
    }
  };

  const logout = () => {
    logoutOAuth2();
    localStorage.removeItem("shieldnet_token");
    localStorage.removeItem("shieldnet_user");
    setUser(null);
    setToken(null);
    setAuthMode("login");
    setTargetPath(null);
  };

  const openAuthModal = (mode: "login" | "signup" = "login", path?: string) => {
    setAuthMode(mode);
    if (path) setTargetPath(path);
    setIsAuthModalOpen(true);
  };

  const closeAuthModal = () => {
    setIsAuthModalOpen(false);
    setTargetPath(null);
  };

  return (
    <AuthContext.Provider
      value={{
        user,
        token,
        isAuthenticated: !!user,
        isLoading,
        login,
        signup,
        logout,
        authMode,
        setAuthMode,
        targetPath,
        setTargetPath,
        openAuthModal,
        closeAuthModal,
        isAuthModalOpen
      }}
    >
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error("useAuth must be used within an AuthProvider");
  }
  return context;
}
