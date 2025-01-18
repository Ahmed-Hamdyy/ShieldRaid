from flask import Flask, request, render_template, jsonify
import os
from werkzeug.utils import secure_filename
import pandas as pd
from model_integrations.mod import predict
from network_analysis.packets_from import parse_packet_file

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size

# Ensure upload directory exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return jsonify({'error': 'No file part'}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No selected file'}), 400
    
    if not (file.filename.endswith('.txt') or file.filename.endswith('.csv')):
        return jsonify({'error': 'Please upload either a .txt or .csv file'}), 400
    
    try:
        filename = secure_filename(file.filename)
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(file_path)
        
        if file.filename.endswith('.txt'):
            # Convert txt to CSV using packets_from.py
            csv_filename = filename.rsplit('.', 1)[0] + '_flow_features.csv'
            csv_path = os.path.join(app.config['UPLOAD_FOLDER'], csv_filename)
            parse_packet_file(file_path, csv_path)
            data = pd.read_csv(csv_path)
            # Clean up temporary files after reading
            os.remove(file_path)
            os.remove(csv_path)
        else:
            # Directly read the CSV file
            data = pd.read_csv(file_path)
            # Clean up the temporary file
            os.remove(file_path)
        
        predictions = predict(data)
        
        return jsonify({
            'success': True,
            'predictions': predictions
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True) 