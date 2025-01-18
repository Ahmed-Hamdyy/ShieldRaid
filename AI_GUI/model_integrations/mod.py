import torch
import torch.nn as nn
import torch.nn.functional as F
import pandas as pd
import os
import sys

# Add the current directory to Python path
current_dir = os.path.dirname(os.path.abspath(__file__))
if current_dir not in sys.path:
    sys.path.append(current_dir)

def save_model(model, path):
    """Save only the model's state dict"""
    torch.save(model.state_dict(), path)

class ResidualEnhancedNeuralNet(nn.Module):
    def __init__(self, input_size=53, hidden_size=256, output_size=10, dropout_prob=0.5):
        super().__init__()
        self.input_size = input_size
        self.hidden_size = hidden_size
        self.output_size = output_size
        self.dropout_prob = dropout_prob
        
        self.input_layer = nn.Linear(input_size, hidden_size)
        self.bn1 = nn.BatchNorm1d(hidden_size)
        self.hidden_layer1 = nn.Linear(hidden_size, hidden_size)
        self.hidden_layer2 = nn.Linear(hidden_size, hidden_size)
        self.output_layer = nn.Linear(hidden_size, output_size)
        self.dropout = nn.Dropout(dropout_prob)
        self.activation = nn.ReLU()

    def forward(self, x):
        # Input to first layer
        x = self.activation(self.bn1(self.input_layer(x)))

        # Residual connection 1
        residual = x
        x = self.activation(self.hidden_layer1(x))
        x = self.dropout(x)
        x += residual  # Add residual connection

        # Residual connection 2
        residual = x
        x = self.activation(self.hidden_layer2(x))
        x = self.dropout(x)
        x += residual  # Add residual connection

        # Output layer
        x = self.output_layer(x)
        return x

    @staticmethod
    def load_from_checkpoint(checkpoint_path):
        """Load model from checkpoint"""
        checkpoint = torch.load(checkpoint_path, map_location=torch.device('cpu'))
        
        # If it's a state dict
        if isinstance(checkpoint, dict) and 'state_dict' not in checkpoint:
            state_dict = checkpoint
        # If it's a checkpoint with metadata
        elif isinstance(checkpoint, dict) and 'state_dict' in checkpoint:
            state_dict = checkpoint['state_dict']
        # If it's the whole model
        else:
            state_dict = checkpoint.state_dict()
        
        # Create a new model instance
        model = ResidualEnhancedNeuralNet()
        model.load_state_dict(state_dict)
        return model

def predict(data):
    classes = ['Benign', 'backdoor', 'ddos', 'dos', 'injection', 'mitm',
       'password', 'ransomware', 'scanning', 'xss']

    # Get the directory where this file is located
    current_dir = os.path.dirname(os.path.abspath(__file__))
    model_path = os.path.join(current_dir, 'model.pt')
    
    # Load the model using the static method
    model = ResidualEnhancedNeuralNet.load_from_checkpoint(model_path)
    model.eval()
    
    # Convert input data to tensor
    data = torch.tensor(data.values, dtype=torch.float32)
    
    # Make predictions
    with torch.no_grad():
        out = model(data)
        _, predicted = torch.max(out, 1)
    
    # Convert numeric predictions to class names
    attack_types = []
    for pred in predicted:
        pred_idx = pred.item()
        if pred_idx == 0:
            attack_types.append("Your packets are benign (no attack detected)")
        else:
            attack_name = classes[pred_idx]
            attack_types.append(f"Warning: Your packets contain a {attack_name} attack!")
    
    return attack_types