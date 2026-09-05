import pandas as pd
import numpy as np
import torch
import torch.nn as nn
import joblib

from pathlib import Path
from sklearn.preprocessing import MinMaxScaler
from feature_config import FEATURES

# -------------------------------
# CONFIG
# -------------------------------

DATA_PATH = "../data/cicids2017/monday_subset.csv"

MODEL_PATH = "../models/autoencoder.pt"
SCALER_PATH = "../models/scaler.pkl"

LATENT_DIM = 8
EPOCHS = 15
BATCH_SIZE = 512

# -------------------------------
# LOAD DATA
# -------------------------------

print("Loading dataset...")

df = pd.read_csv(DATA_PATH)

print("Rows:", len(df))
print(df.memory_usage(deep=True).sum() / 1024**2, "MB")
# Keep only selected features
df = df[FEATURES]

# Replace infinities
df.replace([np.inf, -np.inf], np.nan, inplace=True)

# Fill missing values
df.fillna(0, inplace=True)

# Sample for faster training
if len(df) > 100000:
    df = df.sample(100000, random_state=42)

print("Training rows:", len(df))

# -------------------------------
# SCALE
# -------------------------------

scaler = MinMaxScaler()

X = scaler.fit_transform(df)

joblib.dump(scaler, SCALER_PATH)

print("Scaler saved.")

X_tensor = torch.FloatTensor(X)

# -------------------------------
# MODEL
# -------------------------------

input_dim = X.shape[1]

class Autoencoder(nn.Module):

    def __init__(self):
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

model = Autoencoder()

criterion = nn.MSELoss()
optimizer = torch.optim.Adam(model.parameters(), lr=0.001)

# -------------------------------
# TRAIN
# -------------------------------

print("\nTraining started...\n")

dataset = torch.utils.data.TensorDataset(X_tensor)
loader = torch.utils.data.DataLoader(
    dataset,
    batch_size=BATCH_SIZE,
    shuffle=True
)

for epoch in range(EPOCHS):

    total_loss = 0

    for batch in loader:

        batch_x = batch[0]

        reconstructed = model(batch_x)

        loss = criterion(reconstructed, batch_x)

        optimizer.zero_grad()
        loss.backward()
        optimizer.step()

        total_loss += loss.item()

    avg_loss = total_loss / len(loader)

    print(
        f"Epoch {epoch+1}/{EPOCHS} | Loss = {avg_loss:.6f}"
    )

# -------------------------------
# SAVE
# -------------------------------

Path("../models").mkdir(exist_ok=True)

torch.save(
    model.state_dict(),
    MODEL_PATH
)

print("\nModel saved:")
print(MODEL_PATH)

print("\nTraining complete.")