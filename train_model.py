import pandas as pd
import numpy as np
import pickle
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import classification_report

# Load dataset
df = pd.read_csv("C:\\Users\\Ash\\Desktop\\new_training\\Synthetic_Financial_datasets_log.csv")

# Rename for consistency
df = df.rename(columns={
    'oldbalanceOrg': 'old_balance',
    'newbalanceOrig': 'new_balance'
})

# Select relevant features
df = df[['amount', 'old_balance', 'new_balance', 'type', 'isFraud']]

# Encode categorical features
label_encoders = {}
le = LabelEncoder()
df['type'] = le.fit_transform(df['type'])
label_encoders['type'] = le

# Features and target
X = df.drop('isFraud', axis=1)
y = df['isFraud']

# Split dataset
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# Train model
model = RandomForestClassifier(n_estimators=100, random_state=42)
model.fit(X_train, y_train)

# Evaluate
y_pred = model.predict(X_test)
print(classification_report(y_test, y_pred))

# Save model and encoders
with open("model/fraud_model.pkl", "wb") as f:
    pickle.dump(model, f)

with open("model/encoders.pkl", "wb") as f:
    pickle.dump(label_encoders, f)

print("Model and encoders saved successfully.")


