import time
import json
import kagglehub
import numpy as np
import pandas as pd
import xgboost as xgb
import joblib

from sklearn.model_selection import train_test_split
from sklearn.preprocessing import MinMaxScaler
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, roc_auc_score, classification_report, log_loss

# 1. Download and Load Data
path = kagglehub.dataset_download("ekkykharismadhany/csecicids2018-cleaned")
print("Dataset downloaded successfully.")

df = pd.read_csv(f"{path}/cleaned_ids2018_sampled.csv")

# 2. Prepare Features and Binary Target
X = df.drop(columns=['Label', 'Unnamed: 0'])
y = df['Label'].apply(lambda x: 0 if x == 1 else 1) 

# 3. Drop Highly Correlated Features
corr_matrix = X.corr(numeric_only=True)
high_corr = corr_matrix.abs() > 0.9
to_drop = set()

for i in range(len(high_corr.columns)):
    for j in range(i):
        if high_corr.iloc[i, j]:
            colName_i = high_corr.columns[i]
            colName_j = high_corr.columns[j]
            if colName_i not in to_drop and colName_j not in to_drop:
                to_drop.add(colName_j)

X_reduced = X.drop(columns=to_drop)

# 4. Normalize Data
scaler = MinMaxScaler()
X_normalized = pd.DataFrame(scaler.fit_transform(X_reduced), columns=X_reduced.columns)

joblib.dump(scaler, "scaler.joblib")

# 5. Train-Test Split
X_train, X_test, y_train, y_test = train_test_split(X_normalized, y, test_size=0.25, stratify=y, random_state=42)

# 6. Drop Least Significant Features (Hardcoded from SHAP Analysis)
least_significant = [
    'Bwd IAT Mean', 'Subflow Bwd Byts', 'Fwd Act Data Pkts', 'Active Std', 
    'Protocol', 'URG Flag Cnt', 'Bwd IAT Tot', 'Bwd IAT Max', 'SYN Flag Cnt', 
    'Bwd URG Flags', 'Bwd PSH Flags', 'Fwd URG Flags', 'Fwd Pkts/b Avg', 
    'Fwd Byts/b Avg', 'CWE Flag Count', 'Pkt Len Var', 'Fwd Blk Rate Avg', 
    'Bwd Byts/b Avg', 'Bwd Pkts/b Avg', 'Bwd Blk Rate Avg'
]

X_train_final = X_train.drop(columns=least_significant)
X_test_final = X_test.drop(columns=least_significant)

# 7. Train XGBoost Model
xgb_model_reduced = xgb.XGBClassifier(
    learning_rate=np.float64(0.05286004537658223),
    max_depth=4,
    n_estimators=1382,
    subsample=np.float64(0.8259278817295955),
    device='cpu' 
)

start_time = time.perf_counter()
xgb_model_reduced.fit(X_train_final, y_train)
print(f"\nTraining time: {time.perf_counter() - start_time:.2f} seconds")

# 8. Evaluate Model
y_pred = xgb_model_reduced.predict(X_test_final)
y_pred_proba = xgb_model_reduced.predict_proba(X_test_final)[:, 1]

print(f"Accuracy: {accuracy_score(y_test, y_pred)}")
print(f"Recall: {recall_score(y_test, y_pred)}")
print(f"Precision: {precision_score(y_test, y_pred)}")
print(f"F1 Score: {f1_score(y_test, y_pred)}")
print(f"ROC AUC: {roc_auc_score(y_test, y_pred_proba)}")
print(f"Log Loss: {log_loss(y_test, y_pred_proba)}")
print("\nClassification Report:\n", classification_report(y_test, y_pred))

# 9. Export Artifacts for API
with open("feature_names.json", "w") as f:
    json.dump(X_train_final.columns.tolist(), f)

xgb_model_reduced.save_model("xgb_model_reduced.json")
print("Deployment artifacts saved successfully.")