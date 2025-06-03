import torch
import torch.nn as nn
import torch.optim as optim
from torch.utils.data import Dataset, DataLoader
import numpy as np
import os
import matplotlib.pyplot as plt
from Simon import SIMON32 
from Speck import SPECK32

class CipherWrapper:
    def __init__(self, cipher_name, key, wordsize, rounds):
        if cipher_name == 'SIMON32':
          
            self.cipher = SIMON32(key, wordsize, rounds)
        elif cipher_name == 'Speck32':
    
            self.cipher = SPECK32(key, wordsize, rounds)
        else:
            raise ValueError(f"Unsupported cipher: {cipher_name}")

    def encrypt(self, plaintext):
        return self.cipher.encrypt(plaintext)

def generate_data(cipher_name='SIMON32', n_samples=100000, rounds=8, input_diff=0x00000200):
    key = int(np.random.randint(0, 2**64, dtype=np.uint64))
    wordsize = 16
    cipher = CipherWrapper(cipher_name, key, wordsize, rounds)

    data = np.zeros((2 * n_samples, 2), dtype=np.uint32)
    labels = np.zeros(2 * n_samples, dtype=np.uint8)

    for i in range(n_samples):
        p1 = np.random.randint(0, 2**32, dtype=np.uint32)
        p2 = p1 ^ input_diff

        c1 = cipher.encrypt(p1)
        c2 = cipher.encrypt(p2)

        data[2 * i] = [c1, c2]
        labels[2 * i] = 1

        r1 = np.random.randint(0, 2**32, dtype=np.uint32)
        r2 = np.random.randint(0, 2**32, dtype=np.uint32)

        data[2 * i + 1] = [r1, r2]
        labels[2 * i + 1] = 0

    return data, labels

class CipherDataset(Dataset):
    def __init__(self, X, y):
        self.X = torch.tensor(X, dtype=torch.float32)
        self.y = torch.tensor(y, dtype=torch.float32)

    def __len__(self):
        return len(self.y)

    def __getitem__(self, idx):
        return self.X[idx], self.y[idx]

class ResidualBlock(nn.Module):
    def __init__(self, in_channels, out_channels):
        super(ResidualBlock, self).__init__()
        self.conv1 = nn.Conv1d(in_channels, out_channels, kernel_size=3, padding=1)
        self.bn1 = nn.BatchNorm1d(out_channels)
        self.conv2 = nn.Conv1d(out_channels, out_channels, kernel_size=3, padding=1)
        self.bn2 = nn.BatchNorm1d(out_channels)
        self.relu = nn.ReLU()

    def forward(self, x):
        residual = x
        out = self.conv1(x)
        out = self.bn1(out)
        out = self.relu(out)
        out = self.conv2(out)
        out = self.bn2(out)
        out += residual
        out = self.relu(out)
        return out

class ResNetDistinguisher(nn.Module):
    def __init__(self):
        super(ResNetDistinguisher, self).__init__()
        self.conv1 = nn.Conv1d(1, 32, kernel_size=3, padding=1)
        self.bn1 = nn.BatchNorm1d(32)
        self.relu = nn.ReLU()
        self.res_blocks = nn.Sequential(*[ResidualBlock(32, 32) for _ in range(5)])
        self.fc1 = nn.Linear(32 * 2, 128)
        self.fc2 = nn.Linear(128, 128)
        self.fc3 = nn.Linear(128, 1)
        self.dropout = nn.Dropout(0.2)
        self.sigmoid = nn.Sigmoid()

    def forward(self, x):
        x = x.unsqueeze(1)
        x = self.relu(self.bn1(self.conv1(x)))
        x = self.res_blocks(x)
        x = x.view(x.size(0), -1)
        x = self.relu(self.fc1(x))
        x = self.dropout(x)
        x = self.relu(self.fc2(x))
        x = self.sigmoid(self.fc3(x))
        return x.squeeze()

def train_model(model, train_loader, val_loader, cipher_name, epochs=20, lr=0.001):
    device = torch.device("cuda:0" if torch.cuda.is_available() else "cpu")
    model.to(device)
    criterion = nn.BCELoss()
    optimizer = optim.Adam(model.parameters(), lr=lr)

    train_losses, val_losses, train_accs, val_accs = [], [], [], []

    for epoch in range(epochs):
        model.train()
        correct_train, total_train, epoch_train_loss = 0, 0, 0

        for X_batch, y_batch in train_loader:
            X_batch, y_batch = X_batch.to(device), y_batch.to(device)
            optimizer.zero_grad()
            outputs = model(X_batch).squeeze()
            loss = criterion(outputs, y_batch)
            loss.backward()
            optimizer.step()

            epoch_train_loss += loss.item()
            predicted = (outputs > 0.5).float()
            correct_train += (predicted == y_batch).sum().item()
            total_train += y_batch.size(0)

        train_acc = correct_train / total_train
        train_losses.append(epoch_train_loss / len(train_loader))
        train_accs.append(train_acc)

        model.eval()
        correct_val, total_val, epoch_val_loss = 0, 0, 0
        with torch.no_grad():
            for X_batch, y_batch in val_loader:
                X_batch, y_batch = X_batch.to(device), y_batch.to(device)
                outputs = model(X_batch).squeeze()
                loss = criterion(outputs, y_batch)
                epoch_val_loss += loss.item()
                predicted = (outputs > 0.5).float()
                correct_val += (predicted == y_batch).sum().item()
                total_val += y_batch.size(0)

        val_acc = correct_val / total_val
        val_losses.append(epoch_val_loss / len(val_loader))
        val_accs.append(val_acc)

        print(f"Epoch [{epoch+1}/{epochs}] | Train Loss: {train_losses[-1]:.4f} | Train Acc: {train_acc:.4f} | Val Loss: {val_losses[-1]:.4f} | Val Acc: {val_acc:.4f}")

    os.makedirs('./plots', exist_ok=True)
    plt.figure(figsize=(12, 5))
    plt.subplot(1, 2, 1)
    plt.plot(train_losses, label="Train Loss")
    plt.plot(val_losses, label="Val Loss")
    plt.title(f"{cipher_name}: Loss")
    plt.legend()
    plt.subplot(1, 2, 2)
    plt.plot(train_accs, label="Train Acc")
    plt.plot(val_accs, label="Val Acc")
    plt.title(f"{cipher_name}: Accuracy")
    plt.legend()
    plt.savefig(f"./plots/{cipher_name}_training.png")
    plt.show()

def key_recovery_attack(model, cipher_name='SIMON32', num_samples=10000, rounds=8, input_diff=0x00000200):
    correct_guesses = 0
    device = torch.device("cuda:0" if torch.cuda.is_available() else "cpu")
    wordsize = 16
    for _ in range(num_samples):
        key = np.random.randint(0, 2**64, dtype=np.uint64)
        cipher = CipherWrapper(cipher_name, key, wordsize, rounds)
        p1 = np.random.randint(0, 2**32, dtype=np.uint32)
        p2 = p1 ^ input_diff
        c1 = cipher.encrypt(p1)
        c2 = cipher.encrypt(p2)
        prediction = model(torch.tensor([[c1, c2]], dtype=torch.float32).to(device)).item()
        if prediction > 0.5:
            correct_guesses += 1
    accuracy = correct_guesses / num_samples
    print(f"Key recovery accuracy on {cipher_name}: {accuracy:.2%}")

if __name__ == '__main__':
    cipher_name = 'SIMON32'  
    X, y = generate_data(cipher_name=cipher_name, n_samples=10000, rounds=4)
    x_val, y_val = generate_data(cipher_name=cipher_name, n_samples=1300, rounds=4)

    train_dataset = CipherDataset(X, y)
    val_dataset = CipherDataset(x_val, y_val)

    train_loader = DataLoader(train_dataset, batch_size=64, shuffle=True)
    val_loader = DataLoader(val_dataset, batch_size=64, shuffle=False)

    model = ResNetDistinguisher()
    train_model(model, train_loader, val_loader, cipher_name=cipher_name, epochs=10, lr=0.0001)
    key_recovery_attack(model, cipher_name=cipher_name)
