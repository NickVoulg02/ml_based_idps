from contextlib import asynccontextmanager
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field
import xgboost as xgb
import pandas as pd
import json
import joblib

# Global dictionary to persist state across requests
ml_state = {}

@asynccontextmanager
async def lifespan(app: FastAPI):
    with open("feature_names.json", "r") as f:
        ml_state["feature_names"] = json.load(f)
        
    ml_state["scaler"] = joblib.load("scaler.joblib")
        
    model = xgb.XGBClassifier()
    model.load_model("xgb_model_reduced.json")
    ml_state["model"] = model
    
    yield
    ml_state.clear()

app = FastAPI(lifespan=lifespan, title="XGBoost IDS Inference API")

# Explicit schema using aliases to match the exact spacing of the model's expected columns
class FlowFeatures(BaseModel):
    dst_port: float = Field(alias="Dst Port")
    fwd_pkt_len_std: float = Field(alias="Fwd Pkt Len Std")
    bwd_pkt_len_min: float = Field(alias="Bwd Pkt Len Min")
    flow_byts_s: float = Field(alias="Flow Byts/s")
    fwd_iat_tot: float = Field(alias="Fwd IAT Tot")
    fwd_iat_mean: float = Field(alias="Fwd IAT Mean")
    fwd_iat_max: float = Field(alias="Fwd IAT Max")
    fwd_iat_min: float = Field(alias="Fwd IAT Min")
    bwd_iat_std: float = Field(alias="Bwd IAT Std")
    bwd_iat_min: float = Field(alias="Bwd IAT Min")
    fwd_pkts_s: float = Field(alias="Fwd Pkts/s")
    bwd_pkts_s: float = Field(alias="Bwd Pkts/s")
    pkt_len_min: float = Field(alias="Pkt Len Min")
    pkt_len_std: float = Field(alias="Pkt Len Std")
    fin_flag_cnt: float = Field(alias="FIN Flag Cnt")
    psh_flag_cnt: float = Field(alias="PSH Flag Cnt")
    ack_flag_cnt: float = Field(alias="ACK Flag Cnt")
    ece_flag_cnt: float = Field(alias="ECE Flag Cnt")
    fwd_seg_size_avg: float = Field(alias="Fwd Seg Size Avg")
    bwd_seg_size_avg: float = Field(alias="Bwd Seg Size Avg")
    subflow_fwd_byts: float = Field(alias="Subflow Fwd Byts")
    subflow_bwd_pkts: float = Field(alias="Subflow Bwd Pkts")
    init_fwd_win_byts: float = Field(alias="Init Fwd Win Byts")
    init_bwd_win_byts: float = Field(alias="Init Bwd Win Byts")
    fwd_seg_size_min: float = Field(alias="Fwd Seg Size Min")
    active_max: float = Field(alias="Active Max")
    active_min: float = Field(alias="Active Min")
    idle_max: float = Field(alias="Idle Max")
    idle_min: float = Field(alias="Idle Min")

class BatchFlowRequest(BaseModel):
    flows: list[FlowFeatures]

@app.post("/predict")
async def predict_flows(request: BatchFlowRequest):
    try:
        data = [flow.model_dump(by_alias=True) for flow in request.flows]
        df = pd.DataFrame(data)
        
        # Dynamically pad any missing features required by the scaler with 0.0
        expected_scaler_cols = ml_state["scaler"].feature_names_in_
        for col in expected_scaler_cols:
            if col not in df.columns:
                df[col] = 0.0
                
        # Enforce column ordering for the scaler and apply transformation
        df_for_scaler = df[expected_scaler_cols]
        scaled_data = ml_state["scaler"].transform(df_for_scaler)
        scaled_df = pd.DataFrame(scaled_data, columns=expected_scaler_cols)
        
        final_df = scaled_df[ml_state["feature_names"]]
        
        predictions = ml_state["model"].predict(final_df)
        probabilities = ml_state["model"].predict_proba(final_df)[:, 1]
        
        return {
            "predictions": predictions.tolist(),
            "probabilities": probabilities.tolist()
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.get("/health")
async def health_check():
    """Production health check endpoint."""
    if "model" not in ml_state or "scaler" not in ml_state:
        raise HTTPException(status_code=503, detail="Model artifacts not loaded")
    return {"status": "healthy", "model_version": "1.0-reduced"}