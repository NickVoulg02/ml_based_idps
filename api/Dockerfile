FROM python:3.11-slim AS builder

WORKDIR /build

COPY requirements.txt .
RUN pip install --user --no-cache-dir -r requirements.txt

COPY . .
# This generates your model.json artifact
RUN python xgb_model.py 

FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /app

# Copy only the installed Python packages from the builder stage
COPY --from=builder /root/.local /root/.local
ENV PATH=/root/.local/bin:$PATH

# Copy only the necessary API files and the trained model artifact
# This leaves behind the training scripts, Kaggle data, and cache
COPY main.py .
COPY --from=builder /build/xgb_model_reduced.json .
COPY --from=builder /build/scaler.joblib .
COPY --from=builder /build/feature_names.json .
EXPOSE 8000

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]