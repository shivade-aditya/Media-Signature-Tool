import os
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import rsa
import tkinter as tk
from tkinter import filedialog
from tkinter import messagebox
from tkinter.ttk import Progressbar, Combobox
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature
import time

# Create a Tkinter window
window = tk.Tk()
window.title("Media Signature Tool")
window.geometry("500x400")

# Generate RSA private and public keys
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
)
public_key = private_key.public_key()

signature = None

# Create a frame with a stylish background
frame = tk.Frame(window, bg="#333")
frame.place(relwidth=1, relheight=1)

# Stylish font
stylish_font = ("Verdana", 14, "bold")

# Sign a file (video, audio, or image)
def sign_file(private_key, file_path):
    with open(file_path, "rb") as file:
        file_data = file.read()

    total_size = len(file_data)
    chunk_size = 1024  # Adjust as needed
    chunks_processed = 0

    signature = private_key.sign(
        file_data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    return signature

# Verify the signature of a file (video, audio, or image)
def verify_file(public_key, file_path, signature):
    if signature is None:
        return False

    with open(file_path, "rb") as file:
        file_data = file.read()

    try:
        public_key.verify(
            signature,
            file_data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except InvalidSignature:
        return False

# Function to update the progress bar
def update_progress(progress_bar, progress_label):
    for i in range(101):
        progress_bar['value'] = i
        progress_label.config(text=f"Processing: {i}%")
        window.update_idletasks()
        time.sleep(0.02)  # Adjust to control the speed of the progress bar
    progress_label.config(text="Operation Complete", fg="green")

# Create a common function to handle file selection, signing, and verification
def process_media(file_type, operation, window):
    file_types = [("All Files", "*.*")]
    if file_type == "Video":
        file_types = [("Video Files", "*.mp4"), ("All Files", "*.*")]
    elif file_type == "Audio":
        file_types = [("Audio Files", "*.mp3"), ("All Files", "*.*")]
    elif file_type == "Image":
        file_types = [("Image Files", "*.png *.jpg *.jpeg"), ("All Files", "*.*")]

    file_path = filedialog.askopenfilename(title=f"Select {file_type} File", filetypes=file_types)
    if not file_path:
        return

    global signature

    if operation == "Sign":
        # Sign media
        progress_label.config(text=f"Signing {file_type} file in progress...", fg="white")
        window.after(100, update_progress, progress_bar, progress_label)
        signature = sign_file(private_key, file_path)
        messagebox.showinfo("File Signed", f"{file_type} file has been signed successfully!")
    else:
        # Verify media
        is_valid = verify_file(public_key, file_path, signature)
        if is_valid:
            messagebox.showinfo("Verification Result", f"{file_type} file is authentic and unaltered.")
        else:
            messagebox.showwarning("Verification Result", f"{file_type} file has been altered or is not authentic.")

# Create a Combobox to select media type
media_type_label = tk.Label(frame, text="Select Media Type:", font=("Helvetica", 12), bg="#333", fg="white")
media_types = ["Video", "Audio", "Image"]
media_type_combobox = Combobox(frame, values=media_types)
media_type_combobox.set("Video")  # Default selection

media_type_label.pack(pady=10)
media_type_combobox.pack(pady=10)

# Create media buttons for signing and verifying
sign_button = tk.Button(frame, text="Sign", command=lambda: process_media(media_type_combobox.get(), "Sign", window), bg="green", font=stylish_font)
verify_button = tk.Button(frame, text="Verify", command=lambda: process_media(media_type_combobox.get(), "Verify", window), bg="red", font=stylish_font)

sign_button.pack(pady=10, padx=20)
verify_button.pack(pady=10, padx=20)

# Create a progress bar
progress_bar = Progressbar(window, orient=tk.HORIZONTAL, length=300, mode='determinate', style="TProgressbar")
progress_label = tk.Label(window, text="Ready", font=("Helvetica", 12), bg="#333", fg="white")

# Start the Tkinter event loop
window.mainloop()