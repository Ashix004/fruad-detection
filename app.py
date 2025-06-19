import pickle
import pandas as pd
import joblib
import os
import sqlite3
import bcrypt
from flask import Flask, request, jsonify, render_template, send_from_directory, Blueprint
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
from flask_jwt_extended import JWTManager, create_access_token, jwt_required

app = Flask(__name__)
CORS(app)
app.config['JWT_SECRET_KEY'] = 'super-secret-key'
jwt = JWTManager(app)

# Blueprint for prediction routes
predict_bp = Blueprint('predict', __name__)

# Blueprint for authentication routes
auth_bp = Blueprint('auth', __name__)

# Load model and encoders
try:
    model = joblib.load("model/fraud_model.pkl")
except FileNotFoundError:
    print("Error: fraud_model.pkl not found. Ensure the file exists in the 'model' directory.")
    model = None

try:
    with open("model/encoders.pkl", "rb") as f:
        encoders = pickle.load(f)
except FileNotFoundError:
    print("Error: encoders.pkl not found. Ensure the file exists in the 'model' directory.")
    encoders = None

# In-memory user store (replace with database in production)
users = {}

def create_user_table():
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        password TEXT
    )''')
    conn.commit()
    conn.close()

create_user_table()

@auth_bp.route('/register', methods=['POST'])
def register():
    data = request.json
    username = data['username']
    password = data['password'].encode('utf-8')
    hashed = bcrypt.hashpw(password, bcrypt.gensalt())

    try:
        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, hashed))
        conn.commit()
        return jsonify(message="User registered"), 201
    except sqlite3.IntegrityError:
        return jsonify(message="User already exists"), 409
    finally:
        conn.close()

@auth_bp.route('/login', methods=['POST'])
def login():
    data = request.json
    username = data['username']
    password = data['password'].encode('utf-8')

    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute("SELECT password FROM users WHERE username = ?", (username,))
    result = cursor.fetchone()
    conn.close()

    if result and bcrypt.checkpw(password, result[0]):
        access_token = create_access_token(identity=username)
        return jsonify(access_token=access_token, username=username), 200  # Include username here
    else:
        return jsonify(message="Invalid credentials"), 401

@predict_bp.route('/predict', methods=['POST'])
@jwt_required()
def predict():
    if model is None or encoders is None:
        return jsonify(error="Model or encoders not loaded properly."), 500

    data = request.json
    try:
        # Prepare input DataFrame
        df = pd.DataFrame([{
            'amount': data['amount'],
            'old_balance': data['old_balance'],
            'new_balance': data['new_balance'],
            'type': encoders['type'].transform([data['type']])[0]
        }])

        pred = model.predict(df)[0]
        return jsonify(result="Fraudulent Transaction" if pred else "Legitimate Transaction"), 200
    except Exception as e:
        return jsonify(error=str(e)), 500

@app.route('/')
def home():
    return render_template('index.html')

# Serve favicon if needed
@app.route('/favicon.ico')
def favicon():
    return send_from_directory(os.path.join(app.root_path, 'static'),
                               'favicon.ico', mimetype='image/vnd.microsoft.icon')

@app.route('/register_in_memory', methods=['POST'])
def register_in_memory():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    if username in users:
        return jsonify({"message": "User already exists"}), 400

    users[username] = generate_password_hash(password)
    return jsonify({"message": "User registered successfully"}), 201

@app.route('/login_in_memory', methods=['POST'])
def login_in_memory():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    if username not in users or not check_password_hash(users[username], password):
        return jsonify({"message": "Invalid credentials"}), 401

    access_token = create_access_token(identity=username)
    return jsonify(access_token=access_token)

@predict_bp.route('/predict_v2', methods=['POST'])
@jwt_required()
def predict_v2():
    if model is None or encoders is None:
        return jsonify({'error': 'Model or encoders not loaded properly'}), 500

    data = request.get_json()
    print("Received data:", data)  # Log received data
    amount = data.get('amount')
    old_balance = data.get('old_balance')
    new_balance = data.get('new_balance')
    tx_type = data.get('type')

    if None in [amount, old_balance, new_balance, tx_type]:
        return jsonify({'error': 'Missing input fields'}), 400

    input_df = pd.DataFrame([{
        'amount': amount,
        'old_balance': old_balance,
        'new_balance': new_balance,
        'type': tx_type
    }])

    try:
        print("Before encoding, input_df:", input_df)
        input_df['type'] = encoders['type'].transform(input_df['type'])
        print("After encoding, input_df:", input_df)

        expected_columns = ['amount', 'old_balance', 'new_balance', 'type']
        input_df = input_df[expected_columns]
        print("Final input_df for prediction:", input_df)

        prediction = model.predict(input_df)[0]
        print("Raw prediction:", prediction)  # Log the raw prediction

        result = 'Fraudulent Transaction' if prediction == 1 else 'Legitimate Transaction'
        print("Prediction result:", result)  # Log the final result
        return jsonify({'result': result})
    except Exception as e:
        print("Prediction error:", str(e))  # Log any errors
        return jsonify({'error': f'Error during prediction: {str(e)}'}), 500
# Register the blueprints
app.register_blueprint(predict_bp)
app.register_blueprint(auth_bp)

if __name__ == '__main__':
    app.run(debug=True)