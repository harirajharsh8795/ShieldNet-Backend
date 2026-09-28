"""
ShieldNet Production-Grade Reference Baseline Scaler Guard.

Guarantees that regardless of attack density in the current window (whether 0% or 100% attacks),
features are standardized strictly against the frozen golden benign enterprise baseline:
    Z = clip((X - mu_ref) / (sigma_ref + eps), -5.0, 5.0)

Never computes mean or variance dynamically across the incoming batch (preventing
the fatal self-centering scaler bug).
"""

from pathlib import Path
from typing import Optional, Union
import numpy as np
import joblib


class FrozenReferenceScalerGuard:
    """
    Safeguards model inference against dynamic batch-centering distortion.
    Loads and freezes reference mean and scale vectors for the canonical 84 features.
    """
    def __init__(self, scaler_path: Optional[Union[str, Path]] = None,
                 mean: Optional[np.ndarray] = None,
                 scale: Optional[np.ndarray] = None):
        self.is_loaded = False
        
        if mean is not None and scale is not None:
            self.mean = np.array(mean[:84] if len(mean) >= 84 else np.pad(mean, (0, 84 - len(mean))), dtype=np.float32)
            self.scale = np.array(scale[:84] if len(scale) >= 84 else np.pad(scale, (0, 84 - len(scale)), constant_values=1.0), dtype=np.float32)
            self.is_loaded = True
        elif scaler_path is not None and Path(scaler_path).exists():
            p = Path(scaler_path)
            if p.suffix == ".npz":
                # Numpy archive with 'mean' and 'scale' keys (e.g. scaler_reference.npz)
                data = np.load(p)
                raw_mean = data["mean"]
                raw_scale = data["scale"]
                self.mean = np.array(raw_mean[:84] if len(raw_mean) >= 84 else np.pad(raw_mean, (0, 84 - len(raw_mean))), dtype=np.float32)
                self.scale = np.array(raw_scale[:84] if len(raw_scale) >= 84 else np.pad(raw_scale, (0, 84 - len(raw_scale)), constant_values=1.0), dtype=np.float32)
                self.is_loaded = True
            else:
                # Joblib-serialized sklearn StandardScaler with .mean_ and .scale_ attributes
                scaler = joblib.load(p)
                self.mean = np.array(scaler.mean_[:84] if len(scaler.mean_) >= 84 else np.pad(scaler.mean_, (0, 84 - len(scaler.mean_))), dtype=np.float32)
                self.scale = np.array(scaler.scale_[:84] if len(scaler.scale_) >= 84 else np.pad(scaler.scale_, (0, 84 - len(scaler.scale_)), constant_values=1.0), dtype=np.float32)
                self.is_loaded = True
        else:
            # Fallback search path in project models/checkpoints
            ckpt_dirs = [
                Path(__file__).resolve().parent.parent / "models" / "checkpoints",
                Path(__file__).resolve().parent.parent.parent / "models" / "checkpoints",
            ]
            for c_dir in ckpt_dirs:
                npz_file = c_dir / "scaler_params.npz"
                if npz_file.exists():
                    try:
                        data = np.load(npz_file)
                        self.mean = np.array(data["mean"][:84], dtype=np.float32)
                        self.scale = np.array(data["scale"][:84], dtype=np.float32)
                        self.is_loaded = True
                        break
                    except Exception:
                        pass

                joblib_file = c_dir / "scaler.joblib"
                if not self.is_loaded and joblib_file.exists():
                    try:
                        scaler = joblib.load(joblib_file)
                        self.mean = np.array(scaler.mean_[:84] if len(scaler.mean_) >= 84 else np.pad(scaler.mean_, (0, 84 - len(scaler.mean_))), dtype=np.float32)
                        self.scale = np.array(scaler.scale_[:84] if len(scaler.scale_) >= 84 else np.pad(scaler.scale_, (0, 84 - len(scaler.scale_)), constant_values=1.0), dtype=np.float32)
                        self.is_loaded = True
                        break
                    except Exception:
                        pass

    def transform(self, X: np.ndarray, clip_range: float = 5.0) -> np.ndarray:
        """
        Applies strict reference standardization: Z = (X - mu_ref) / (sigma_ref + eps).
        Never computes mean across the input X.
        
        Args:
            X: Array of shape (84,) or (N, 84)
            clip_range: Maximum absolute z-score limit (default 5.0)
            
        Returns:
            Standardized array matching input shape.
        """
        X_arr = np.asarray(X, dtype=np.float32)
        n_features = min(X_arr.shape[-1], 84)
        
        mean_slice = self.mean[:n_features]
        scale_slice = self.scale[:n_features] + 1e-6
        
        normalized = (X_arr[..., :n_features] - mean_slice) / scale_slice
        cleaned = np.nan_to_num(normalized, nan=0.0, posinf=clip_range, neginf=-clip_range)
        return np.clip(cleaned, -clip_range, clip_range).astype(np.float32)

    def guard_batch(self, X: np.ndarray, clip_range: float = 5.0) -> np.ndarray:
        """Standardizes live streaming telemetry batches of shape (B, 84) or (B, L, 84)."""
        X_arr = np.asarray(X, dtype=np.float32)
        if X_arr.ndim == 1:
            return self.transform(X_arr, clip_range=clip_range)
        elif X_arr.ndim == 2:
            return self.transform(X_arr, clip_range=clip_range)
        elif X_arr.ndim == 3:
            # (Batch, Seq_Len, Features)
            shape = X_arr.shape
            reshaped = X_arr.reshape(-1, shape[-1])
            norm = self.transform(reshaped, clip_range=clip_range)
            return norm.reshape(shape)
        return X_arr
