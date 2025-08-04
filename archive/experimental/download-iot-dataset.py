import kagglehub

# Download latest version
path = kagglehub.dataset_download("programmer3/ton-iot-network-intrusion-dataset")
print("Path to dataset files:", path)