"""
Pad 62-dim tensors → 64-dim by inserting is_weekend=0, is_out_of_hours=0
at position 4 (after hour_cos_std, before session_duration_s).

Normal training data has 0.0 for both features — correct semantics.
Run once, then retrain.
"""
import torch
from pathlib import Path

DATA = Path(__file__).parent

for name in ["train_tensor.pt", "test_tensor.pt"]:
    p = DATA / name
    t = torch.load(p, weights_only=True)
    print(f"{name}: {list(t.shape)}")
    
    if t.shape[1] == 62:
        # Insert 2 zero columns at index 4
        zeros = torch.zeros(t.shape[0], 2, dtype=t.dtype)
        t_new = torch.cat([t[:, :4], zeros, t[:, 4:]], dim=1)
        print(f"  -> padded to {list(t_new.shape)}")
        
        # Backup original
        torch.save(t, DATA / f"{name}.bak62")
        torch.save(t_new, p)
        print(f"  -> saved (backup: {name}.bak62)")
    elif t.shape[1] == 64:
        print(f"  -> already 64-dim, skipping")
    else:
        print(f"  -> unexpected dim={t.shape[1]}, skipping")

print("\nDone. Ready for retrain.")
