"""
NetGuard AI: Two-Stage Hierarchical XGBoost Trainer (Binary + Multi-Class)
Make sure you change the Runtime Type to 'GPU' (T4 or A100)!
"""
import pandas as pd
import numpy as np
import joblib
import glob
import xgboost as xgb
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score
from imblearn.over_sampling import SMOTE
from sklearn.preprocessing import LabelEncoder

# 1. Mount Google Drive
try:
    from google.colab import drive
    drive.mount('/content/drive')
except ImportError:
    pass

import re

def normalize_feature(f_name: str) -> str:
    return re.sub(r'[^a-zA-Z0-9]', '', str(f_name)).lower()

FEATURES = [
    "Flow Duration", "Total Fwd Packets", "Total Backward Packets",
    "Fwd Packet Length Mean", "Bwd Packet Length Mean",
    "Flow Bytes/s", "Flow Packets/s", "Flow IAT Mean", "Flow IAT Std",
    "Packet Length Mean", "Packet Length Std",
    "SYN Flag Count", "ACK Flag Count", "Down/Up Ratio",
    "Idle Mean", "Active Max", "Idle Max"
]

NORMALIZED_FEATURES = [normalize_feature(f) for f in FEATURES]

# 2. Load all Datasets
print("Loading all datasets from Google Drive (NetGuardDataset folder)...")
# Exclude any file with "subset" in the name to prevent data leakage during testing!
csv_files = [f for f in glob.glob("/content/drive/MyDrive/NetGuardDataset/*.csv") if 'subset' not in f.lower()]
parquet_files = [f for f in glob.glob("/content/drive/MyDrive/NetGuardDataset/*.parquet") if 'subset' not in f.lower()]

dataframes = []
for f in csv_files: 
    print(f"Loading {f}...")
    dataframes.append(pd.read_csv(f))
for f in parquet_files: 
    print(f"Loading {f}...")
    dataframes.append(pd.read_parquet(f))

if not dataframes:
    print("ERROR: No files found in /content/drive/MyDrive/NetGuardDataset/")
    exit()

df = pd.concat(dataframes, ignore_index=True)
print(f"Loaded {len(df)} total rows from {len(csv_files) + len(parquet_files)} files.")

# 3. Data Cleaning
print("Cleaning data...")
# Normalize features, but keep 'label' capitalized as 'Label' for the script
df.columns = [normalize_feature(c) if normalize_feature(c) != 'label' else 'Label' for c in df.columns]

# If multiple datasets had slightly different spellings of 'Label', they are now duplicate columns.
# We must coalesce (merge) them so we have exactly one 'Label' column.
if type(df.get('Label')) == pd.DataFrame:
    df['Label'] = df['Label'].bfill(axis=1).iloc[:, 0]

# Remove any remaining duplicate columns (e.g. overlapping features)
df = df.loc[:,~df.columns.duplicated()].copy()

for f in NORMALIZED_FEATURES:
    if f not in df.columns:
        df[f] = 0.0

df = df[NORMALIZED_FEATURES + ['Label']]
df.replace([np.inf, -np.inf], np.nan, inplace=True)
df.fillna(0, inplace=True)

if len(df) > 500000:
    print("Dataset is massive! Sampling down to 500k rows to prevent memory crashes...")
    df_filtered = df.sample(n=500000, random_state=42)
else:
    df_filtered = df

print("Filtering rare classes to prevent SMOTE crashes...")
class_counts = df_filtered['Label'].value_counts()
valid_classes = class_counts[class_counts >= 6].index
df_filtered = df_filtered[df_filtered['Label'].isin(valid_classes)]

# =======================================================
# STAGE 1: THE BINARY SNIPER MODEL (Benign vs Attack)
# =======================================================
print("\n" + "="*50)
print("PHASE 1: Training Binary Classifier (Benign vs Attack)")
print("="*50)

X_stage1 = df_filtered[NORMALIZED_FEATURES]
y_stage1_raw = df_filtered['Label'].apply(lambda x: 'Benign' if str(x).upper().strip() == 'BENIGN' else 'Attack')

le_binary = LabelEncoder()
y_stage1 = le_binary.fit_transform(y_stage1_raw)
joblib.dump(le_binary, "/content/le_binary.pkl")

print("Applying SMOTE ('auto' strategy) for Binary Model...")
smote_bin = SMOTE(sampling_strategy='auto', random_state=42)
X_res_bin, y_res_bin = smote_bin.fit_resample(X_stage1, y_stage1)

X_train_b, X_test_b, y_train_b, y_test_b = train_test_split(X_res_bin, y_res_bin, test_size=0.2, random_state=42)

model_binary = xgb.XGBClassifier(
    n_estimators=300, max_depth=8, learning_rate=0.1,
    tree_method='hist', device='cuda', n_jobs=-1,
    early_stopping_rounds=20, eval_metric='logloss'
)

model_binary.fit(X_train_b, y_train_b, eval_set=[(X_test_b, y_test_b)], verbose=False)

print("Binary Model Performance:")
preds_bin = model_binary.predict(X_test_b)
print(f"Accuracy: {accuracy_score(y_test_b, preds_bin) * 100:.2f}%")
print(classification_report(y_test_b, preds_bin, target_names=le_binary.classes_))
joblib.dump(model_binary, "/content/xgb_binary.pkl")

# =======================================================
# STAGE 2: THE MULTI-CLASS ANALYST MODEL (Attacks Only)
# =======================================================
print("\n" + "="*50)
print("PHASE 2: Training Multi-Class Classifier (Attacks Only)")
print("="*50)

# Filter dataset to ONLY include attacks
df_attacks = df_filtered[df_filtered['Label'].astype(str).str.upper().str.strip() != 'BENIGN']

X_stage2 = df_attacks[NORMALIZED_FEATURES]
y_stage2_raw = df_attacks['Label']

le_multi = LabelEncoder()
y_stage2 = le_multi.fit_transform(y_stage2_raw)
joblib.dump(le_multi, "/content/le_multiclass.pkl")

# Since this is only attacks, we balance all attacks equally using 'auto'
print("Applying SMOTE ('auto') for Multi-Class Attack Analyst...")
smote_multi = SMOTE(sampling_strategy='auto', random_state=42)
X_res_multi, y_res_multi = smote_multi.fit_resample(X_stage2, y_stage2)

X_train_m, X_test_m, y_train_m, y_test_m = train_test_split(X_res_multi, y_res_multi, test_size=0.2, random_state=42)

model_multiclass = xgb.XGBClassifier(
    n_estimators=300, max_depth=8, learning_rate=0.1,
    tree_method='hist', device='cuda', n_jobs=-1,
    early_stopping_rounds=20, eval_metric='mlogloss'
)

model_multiclass.fit(X_train_m, y_train_m, eval_set=[(X_test_m, y_test_m)], verbose=False)

print("Multi-Class Attack Analyst Performance:")
preds_multi = model_multiclass.predict(X_test_m)
print(f"Accuracy: {accuracy_score(y_test_m, preds_multi) * 100:.2f}%")
print(classification_report(y_test_m, preds_multi, target_names=le_multi.classes_))
joblib.dump(model_multiclass, "/content/xgb_multiclass.pkl")

print("\n" + "="*50)
print("ALL DONE STAGE 1 & 2! Downloading XGBoost models...")
print("="*50)

# =======================================================
# STAGE 3: THE ZERO-DAY SAFETY NET (Autoencoder)
# =======================================================
print("\n" + "="*50)
print("PHASE 3: Training PyTorch Autoencoder (Benign Traffic Only)")
print("="*50)

import torch
import torch.nn as nn
from torch.utils.data import DataLoader, TensorDataset
from sklearn.preprocessing import MinMaxScaler
from sklearn.model_selection import train_test_split

# 1. Isolate only normal traffic using case-insensitive check
df_benign = df[df['Label'].astype(str).str.upper().str.strip() == 'BENIGN'].copy()

# Sample 500k to prevent RAM crash during PyTorch conversion
if len(df_benign) > 500000:
    df_benign = df_benign.sample(n=500000, random_state=42)

X_benign = df_benign[NORMALIZED_FEATURES].values

print("Fitting MinMaxScaler on modern normal traffic...")
scaler = MinMaxScaler()
X_benign_scaled = scaler.fit_transform(X_benign)
joblib.dump(scaler, "/content/scaler.pkl")

X_train_auto, X_test_auto = train_test_split(X_benign_scaled, test_size=0.2, random_state=42)

# Convert to PyTorch Tensors
X_tensor = torch.FloatTensor(X_train_auto)
dataset = TensorDataset(X_tensor, X_tensor)
dataloader = DataLoader(dataset, batch_size=2048, shuffle=True)

# 2. Define Ultra-Fast Architecture (Matches your backend)
LATENT_DIM = 8

class Autoencoder(nn.Module):
    def __init__(self, input_dim):
        super().__init__()
        self.encoder = nn.Sequential(
            nn.Linear(input_dim, 64),
            nn.ReLU(),
            nn.Linear(64, 32),
            nn.ReLU(),
            nn.Linear(32, LATENT_DIM)
        )
        self.decoder = nn.Sequential(
            nn.Linear(LATENT_DIM, 32),
            nn.ReLU(),
            nn.Linear(32, 64),
            nn.ReLU(),
            nn.Linear(64, input_dim),
            nn.Sigmoid()
        )

    def forward(self, x):
        z = self.encoder(x)
        return self.decoder(z)

model_ae = Autoencoder(len(FEATURES))
device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
model_ae.to(device)

criterion = nn.MSELoss()
optimizer = torch.optim.Adam(model_ae.parameters(), lr=0.001)

print(f"Training Autoencoder on {device} (This is fast!)...")
epochs = 10
model_ae.train()
for epoch in range(epochs):
    total_loss = 0
    for batch_x, _ in dataloader:
        batch_x = batch_x.to(device)
        
        optimizer.zero_grad()
        reconstructed = model_ae(batch_x)
        loss = criterion(reconstructed, batch_x)
        loss.backward()
        optimizer.step()
        
        total_loss += loss.item()
        
    print(f"Epoch {epoch+1}/{epochs} | Loss: {total_loss/len(dataloader):.6f}")

print("Saving Autoencoder model...")
torch.save(model_ae.state_dict(), "/content/autoencoder.pt")

print("\n" + "="*50)
print("PHASE 4: Deriving the Optimal Anomaly Threshold")
print("="*50)
model_ae.eval()
with torch.no_grad():
    X_val_tensor = torch.FloatTensor(X_test_auto).to(device)
    reconstructed_val = model_ae(X_val_tensor)
    mse_val = torch.mean((X_val_tensor - reconstructed_val) ** 2, dim=1).cpu().numpy()

mean_mse = np.mean(mse_val)
std_mse = np.std(mse_val)

# Common statistical approach: Mean + 3 * Standard Deviations (covers 99.7% of normal traffic)
optimal_threshold = mean_mse + (3 * std_mse)
print(f"Validation Mean MSE: {mean_mse:.6f}")
print(f"Validation Std  MSE: {std_mse:.6f}")
print(f"Calculated Optimal Threshold (Mean + 3*Std): {optimal_threshold:.6f}")
print("\n--> Update the THRESHOLD variable in your backend's anomaly_detector.py with this value!")

print("\n" + "="*50)
print("PIPELINE COMPLETE! Download ALL 6 files from the sidebar:")
print("1. xgb_binary.pkl")
print("2. le_binary.pkl")
print("3. xgb_multiclass.pkl")
print("4. le_multiclass.pkl")
print("5. autoencoder.pt")
print("6. scaler.pkl")
print("="*50)
