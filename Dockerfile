# Stage 1: Build the React frontend
FROM node:18 AS frontend-builder
WORKDIR /app/frontend
COPY frontend/package*.json ./
RUN npm install
COPY frontend/ .
RUN npm run build

# Stage 2: Build the FastAPI backend and serve everything
FROM python:3.11-slim AS backend
WORKDIR /app

# Install system dependencies required for ML packages (gcc, g++ for XGBoost)
RUN apt-get update && apt-get install -y \
    gcc \
    g++ \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY backend/requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# Copy the backend code
COPY backend/ ./backend/

# Copy the compiled React build from Stage 1 into the location expected by main.py
COPY --from=frontend-builder /app/frontend/build /app/frontend/build

# Expose Hugging Face Space port
EXPOSE 7860

# Run Uvicorn directly from the backend folder
WORKDIR /app/backend
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "7860"]
