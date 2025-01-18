import os
from werkzeug.utils import secure_filename
import pandas as pd
from AI_GUI.model_integrations.mod import predict
from AI_GUI.network_analysis.packets_from import parse_packet_file

class ChatBot:
    def __init__(self):
        # Set upload folder relative to project root
        self.upload_folder = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'uploads')
        self.max_content_length = 16 * 1024 * 1024  # 16MB max file size
        
        # Ensure upload directory exists
        os.makedirs(self.upload_folder, exist_ok=True)

    def handle_upload(self, file):
        if not file:
            return {'error': 'No file part'}, 400
        
        if file.filename == '':
            return {'error': 'No selected file'}, 400
        
        if not (file.filename.endswith('.txt') or file.filename.endswith('.csv')):
            return {'error': 'Please upload either a .txt or .csv file'}, 400
        
        try:
            filename = secure_filename(file.filename)
            file_path = os.path.join(self.upload_folder, filename)
            file.save(file_path)
            
            if file.filename.endswith('.txt'):
                # Convert txt to CSV using packets_from.py
                csv_filename = filename.rsplit('.', 1)[0] + '_flow_features.csv'
                csv_path = os.path.join(self.upload_folder, csv_filename)
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
            
            # Get predictions from the model
            predictions = predict(data)
            
            return {
                'success': True,
                'predictions': predictions
            }
            
        except Exception as e:
            return {'error': str(e)}, 500 