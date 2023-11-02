import os
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import rsa
import tkinter as tk
from tkinter import filedialog
from tkinter import messagebox
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature

# Global variables
private_key = None
public_key = None
signature = None


# Generate or load RSA key pair
def generate_key_pair(private_key_file, public_key_file):
    private_key_exists = os.path.exists(private_key_file)
    public_key_exists = os.path.exists(public_key_file)

    if private_key_exists:
        with open(private_key_file, "rb") as private_key_file:
            private_key = serialization.load_pem_private_key(private_key_file.read(), password=None)
    else:
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        with open(private_key_file, "wb") as private_key_file:
            private_key_file.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ))

    if public_key_exists:
        with open(public_key_file, "rb") as public_key_file:
            public_key = serialization.load_pem_public_key(public_key_file.read())
    else:
        public_key = private_key.public_key()
        with open(public_key_file, "wb") as public_key_file:
            public_key_file.write(public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ))

    return private_key, public_key


# Sign a video file
def sign_video(private_key, video_file):
    with open(video_file, "rb") as video_file:
        video_data = video_file.read()

    signature = private_key.sign(
        video_data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    return signature


# Verify the signature of a video file
def verify_video(public_key, video_file, signature):
    if signature is None:
        return False

    with open(video_file, "rb") as video_file:
        video_data = video_file.read()

    try:
        public_key.verify(
            signature,
            video_data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except InvalidSignature:
        return False


def sign_video_file():
    global signature
    video_file = filedialog.askopenfilename(title="Select Video to Sign")
    if not video_file:
        return
    signature = sign_video(private_key, video_file)
    messagebox.showinfo("Video Signed", "Video has been signed successfully!")


def verify_video_file():
    video_file = filedialog.askopenfilename(title="Select Video to Verify")
    if not video_file:
        return
    is_valid = verify_video(public_key, video_file, signature)
    if is_valid:
        messagebox.showinfo("Verification Result", "Video is authentic and unaltered.")
    else:
        messagebox.showwarning("Verification Result", "Video has been altered or is not authentic.")


# Create the main window
window = tk.Tk()
window.title("Video Authentication and Verification")

# Set window size
window.geometry("400x200")

# Generate or load RSA key pair
private_key_file = "private_key.pem"
public_key_file = "public_key.pem"
private_key, public_key = generate_key_pair(private_key_file, public_key_file)

# Create and configure GUI elements
sign_button = tk.Button(window, text="Sign Video", command=sign_video_file)
verify_button = tk.Button(window, text="Verify Video", command=verify_video_file)

# Create labels
label1 = tk.Label(window, text="Video Authentication and Verification", font=("Helvetica", 16))
label2 = tk.Label(window, text="Step 1: Sign a video file", font=("Helvetica", 12))
label3 = tk.Label(window, text="Step 2: Verify the signed video", font=("Helvetica", 12))

# Place GUI elements on the window
label1.pack(pady=10)
label2.pack()
sign_button.pack(pady=10)
label3.pack()
verify_button.pack()

# Start the Tkinter event loop
window.mainloop()