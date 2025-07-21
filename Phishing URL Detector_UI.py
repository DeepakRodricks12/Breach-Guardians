"""
Phishing URL Detector Application

This application analyzes URLs to detect potential phishing attempts using various heuristic checks.
It provides a graphical interface with detailed analysis results and visual indicators.
"""

import tkinter as tk
from tkinter import messagebox, ttk
from PIL import Image, ImageTk, ImageDraw, ImageFont
import re
import whois
from urllib.parse import urlparse
import itertools
import threading
from datetime import datetime

# --- Feature Extraction ---
def extract_features(url):
    """
    Extracts various features from a URL that are useful for phishing detection.
    
    Args:
        url (str): The URL to analyze
        
    Returns:
        dict: Dictionary containing extracted features with their values
    """
    parsed = urlparse(url)
    features = {
        'url_length': len(url),
        'has_ip': 1 if re.match(r'https?://\d+\.\d+\.\d+\.\d+', url) else 0,
        'has_at': 1 if '@' in url else 0,
        'has_hyphen': 1 if '-' in parsed.netloc else 0,
        'num_dots': url.count('.'),
        'is_https': 1 if parsed.scheme == 'https' else 0,
        'has_suspicious_words': 1 if any(word in url.lower() for word in ['login', 'verify', 'update', 'bank', 'secure', 'account', 'paypal']) else 0
    }
    return features

# --- Domain Age ---
def get_domain_age(url):
    """
    Attempts to determine the age of a domain by querying WHOIS information.
    
    Args:
        url (str): The URL to check
        
    Returns:
        int: Age of domain in days (capped at 5 years), or 0 if unknown
    """
    try:
        domain = urlparse(url).netloc
        info = whois.whois(domain)
        if info.creation_date:
            if isinstance(info.creation_date, list):
                creation_date = info.creation_date[0]
            else:
                creation_date = info.creation_date
            
            age = (datetime.now() - creation_date).days
            return max(1, min(age, 365*5))
    except:
        pass
    return 0

# --- Phishing Detection Logic ---
def is_suspicious_url(url):
    """
    Determines if a URL is suspicious based on extracted features and domain age.
    
    Args:
        url (str): The URL to analyze
        
    Returns:
        tuple: (is_suspicious, features, domain_age, score) where:
            is_suspicious (bool): True if URL is suspicious
            features (dict): Extracted features
            domain_age (int): Domain age in days
            score (float): Calculated phishing score
    """
    features = extract_features(url)
    domain_age = get_domain_age(url)
    
    domain_age_factor = min(1.0, domain_age / 365)

    score = 0
    score += features['has_ip'] * 2
    score += features['has_at'] * 1.5
    score += features['has_hyphen'] * 1
    score += features['has_suspicious_words'] * 2
    score += 1.5 if features['url_length'] > 75 else 0
    score += 1.5 if features['num_dots'] > 3 else 0
    score += (1 - domain_age_factor) * 3

    return score >= 4, features, domain_age, score

# --- Animated Status ---
def animate_status():
    """
    Animates the status label during URL analysis by cycling through loading frames.
    """
    frame = next(loading_cycle)
    status_label.config(text=frame)
    if checking_url:
        root.after(200, animate_status)

# --- Create Perfect Themed Images ---
def create_phishing_image():
    """
    Creates a warning image for detected phishing URLs.
    
    Returns:
        ImageTk.PhotoImage: The generated phishing warning image
    """
    # Create image with professional laptop and fishing hook
    width, height = 500, 250
    img = Image.new('RGB', (width, height), "#000000")
    draw = ImageDraw.Draw(img)
    
    # Draw modern laptop
    # Screen
    screen_rect = [100, 30, 400, 160]
    draw.rectangle(screen_rect, fill="#111111", outline="#39ff14", width=2)
    
    # Screen content - suspicious website
    draw.rectangle([110, 40, 390, 150], fill="#222222")
    draw.line([(120, 95), (380, 95)], fill="#ff5555", width=2)
    draw.text((250, 70), "suspicious-site.com/login", fill="#39ff14", font=font_small, anchor="mt")
    
    # Warning symbol (triangle with exclamation)
    warning_size = 30
    warning_x, warning_y = 450, 50
    draw.polygon([
        (warning_x, warning_y - warning_size//2),
        (warning_x - warning_size//2, warning_y + warning_size//2),
        (warning_x + warning_size//2, warning_y + warning_size//2)
    ], fill="#ff5555")
    draw.text((warning_x, warning_y), "!", fill="black", font=font_large, anchor="mm")
    
    # Laptop base
    base_rect = [130, 160, 370, 190]
    draw.rectangle(base_rect, fill="#222222", outline="#39ff14", width=2)
    
    # Keyboard
    draw.rectangle([140, 170, 360, 185], fill="#333333")
    
    # Add title text
    draw.text((width//2, 220), "Phishing Alert - Suspicious Link Detected", 
             fill="#ff5555", font=font_medium, anchor="mt")
    
    return ImageTk.PhotoImage(img)

def create_secure_image():
    """
    Creates a secure connection image for legitimate URLs.
    
    Returns:
        ImageTk.PhotoImage: The generated secure connection image
    """
    # Create professional security shield
    width, height = 500, 250
    img = Image.new('RGB', (width, height), "#000000")
    draw = ImageDraw.Draw(img)
    
    # Draw shield
    shield_x, shield_y = width//2, height//2 - 20
    shield_width, shield_height = 120, 150
    
    # Shield outline
    draw.rounded_rectangle(
        [shield_x - shield_width//2, shield_y - shield_height//2, 
         shield_x + shield_width//2, shield_y + shield_height//2],
        radius=20, outline="#39ff14", width=4, fill="#111111"
    )
    
    # PERFECT Check mark
    check_size = 30
    draw.line([
        (shield_x - 15, shield_y),
        (shield_x - 5, shield_y + 10),
        (shield_x + 15, shield_y - 15)
    ], fill="#39ff14", width=6)
    
    
    # Add title text
    draw.text((width//2, 220), "Secure Connection - Verified Site", 
             fill="#39ff14", font=font_medium, anchor="mt")
    
    return ImageTk.PhotoImage(img)

# --- URL Check ---
def check_url():
    """
    Initiates the URL checking process, validating input and starting analysis.
    """
    global checking_url
    url = entry.get().strip()
    
    if not url:
        messagebox.showerror("Error", "Please enter a URL")
        return
    
    # Add http:// if missing
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url
        entry.delete(0, tk.END)
        entry.insert(0, url)
    
    # Clear previous results
    result_text.config(state=tk.NORMAL)
    result_text.delete(1.0, tk.END)
    result_text.config(state=tk.DISABLED)
    image_status_label.config(text="")
    status_image_label.config(image="")
    
    checking_url = True
    status_label.config(text="Analyzing URL...")
    progress_bar.start(10)
    
    # Use threading to prevent UI freezing
    threading.Thread(target=perform_url_check, args=(url,), daemon=True).start()

def perform_url_check(url):
    """
    Performs the actual URL analysis in a background thread.
    
    Args:
        url (str): The URL to analyze
    """
    try:
        suspicious, features, domain_age, score = is_suspicious_url(url)
        
        # Update UI in main thread
        root.after(0, lambda: finish_check(url, suspicious, features, domain_age, score))
    except Exception as e:
        root.after(0, lambda: show_error(str(e)))

def show_error(error_msg):
    """
    Displays an error message in the UI when URL analysis fails.
    
    Args:
        error_msg (str): The error message to display
    """
    global checking_url
    checking_url = False
    progress_bar.stop()
    status_label.config(text="Error occurred")
    result_text.config(state=tk.NORMAL)
    result_text.delete(1.0, tk.END)
    result_text.insert(tk.END, f"Error: {error_msg}", "error")
    result_text.config(state=tk.DISABLED)

def finish_check(url, suspicious, features, domain_age, score):
    """
    Completes the URL check process by updating the UI with results.
    
    Args:
        url (str): The analyzed URL
        suspicious (bool): Whether the URL was flagged as suspicious
        features (dict): Extracted URL features
        domain_age (int): Domain age in days
        score (float): Calculated phishing score
    """
    global checking_url
    checking_url = False
    progress_bar.stop()
    status_label.config(text="Analysis complete")
    
    # Update images and status
    if suspicious:
        image_status_label.config(text="⚠️ PHISHING URL DETECTED!", fg="#ff5555", 
                                font=("PixelFont", 14, "bold"), bg="#000000")
        status_image_label.config(image=phishing_img, bg="#000000")
    else:
        image_status_label.config(text="✅ LEGITIMATE URL", fg="#39ff14", 
                                font=("PixelFont", 14, "bold"), bg="#000000")
        status_image_label.config(image=legit_img, bg="#000000")
    
    # Display detailed results
    result_text.config(state=tk.NORMAL)
    result_text.delete(1.0, tk.END)
    
    result_text.insert(tk.END, "Detailed Analysis Results\n", "header")
    result_text.insert(tk.END, "-" * 70 + "\n", "divider")
    
    # Create a perfectly aligned table
    result_text.insert(tk.END, "Feature".ljust(25) + "Value".ljust(20) + "Status".ljust(20) + "Points\n", "subheader")
    result_text.insert(tk.END, "-" * 70 + "\n", "divider")
    
    # Add feature details with proper alignment
    features_list = [
        ("URL Length", f"{features['url_length']} chars", 
         "High risk" if features['url_length'] > 75 else "OK", 
         1.5 if features['url_length'] > 75 else 0),
        
        ("Contains IP", "Yes" if features['has_ip'] else "No", 
         "High risk" if features['has_ip'] else "OK", 
         features['has_ip'] * 2),
        
        ("Contains '@'", "Yes" if features['has_at'] else "No", 
         "Risk" if features['has_at'] else "OK", 
         features['has_at'] * 1.5),
        
        ("Hyphen in Domain", "Yes" if features['has_hyphen'] else "No", 
         "Risk" if features['has_hyphen'] else "OK", 
         features['has_hyphen']),
        
        ("Number of Dots", str(features['num_dots']), 
         "High risk" if features['num_dots'] > 3 else "OK", 
         1.5 if features['num_dots'] > 3 else 0),
        
        ("Uses HTTPS", "Yes" if features['is_https'] else "No", 
         "Good" if features['is_https'] else "Risk", 
         0),
        
        ("Suspicious Words", "Yes" if features['has_suspicious_words'] else "No", 
         "High risk" if features['has_suspicious_words'] else "OK", 
         features['has_suspicious_words'] * 2),
        
        ("Domain Age", f"{domain_age} days" if domain_age > 0 else "Unknown", 
         "New/Unknown" if domain_age == 0 else ("Established" if domain_age > 365 else "Recent"), 
         (1 - min(1.0, domain_age/365)) * 3)
    ]
    
    for feature, value, status, points in features_list:
        # Format points display
        points_display = f"+{points:.1f}" if points > 0 else "0.0"
        
        # Insert with perfect alignment
        result_text.insert(tk.END, feature.ljust(25), "normal")
        result_text.insert(tk.END, value.ljust(20), "normal")
        
        # Apply appropriate tag based on risk level
        if "risk" in status.lower():
            result_text.insert(tk.END, status.ljust(20), "risk")
            result_text.insert(tk.END, points_display.rjust(5) + "\n", "risk")
        elif "established" in status.lower():
            result_text.insert(tk.END, status.ljust(20), "safe")
            result_text.insert(tk.END, points_display.rjust(5) + "\n", "safe")
        else:
            result_text.insert(tk.END, status.ljust(20), "normal")
            result_text.insert(tk.END, points_display.rjust(5) + "\n", "normal")
    
    result_text.insert(tk.END, "-" * 70 + "\n", "divider")
    result_text.insert(tk.END, "TOTAL SCORE".ljust(45) + f"{score:.1f}/10.0\n", "total")
    result_text.insert(tk.END, "Threshold for phishing: 4.0\n", "normal")
    result_text.insert(tk.END, "\n")
    
    # Add final recommendation
    if suspicious:
        result_text.insert(tk.END, "SECURITY WARNING:\n", "warning")
        result_text.insert(tk.END, "This URL has characteristics commonly found in phishing websites. ", "risk")
        result_text.insert(tk.END, "We strongly recommend against visiting this site or entering any personal information.\n\n", "risk")
    else:
        result_text.insert(tk.END, "SECURITY ASSESSMENT:\n", "safe_header")
        result_text.insert(tk.END, "This URL appears to be legitimate based on our analysis. ", "safe")
        result_text.insert(tk.END, "You may proceed with caution, but always verify the site's authenticity before entering sensitive information.\n\n", "safe")
    
    result_text.config(state=tk.DISABLED)

# --- GUI Setup ---
root = tk.Tk()
root.title("Phishing URL Detector")
root.geometry("900x800")
root.minsize(800, 750)
root.configure(bg="#000000")

# Define pixel font
try:
    # Try to load a pixel font if available
    pixel_font = ("Terminal", 10)
    header_font = ("Terminal", 20, "bold")
    subheader_font = ("Terminal", 12)
except:
    # Fallback to default monospace fonts
    pixel_font = ("Courier", 10)
    header_font = ("Courier", 20, "bold")
    subheader_font = ("Courier", 12)

# Style Configuration
style = ttk.Style()
style.theme_use('clam')  # Use a theme that allows customization

# Configure styles
style.configure("TFrame", background="#000000")
style.configure("TButton", 
                font=pixel_font, 
                padding=8,
                background="#111111",
                foreground="#39ff14",
                bordercolor="#39ff14",
                borderwidth=1,
                relief="solid")
style.configure("TLabel", background="#000000", foreground="#39ff14", font=pixel_font)
style.configure("TEntry", 
                fieldbackground="#000000", 
                foreground="#39ff14",
                insertbackground="#39ff14",
                bordercolor="#39ff14")
style.configure("TProgressbar", 
                background="#39ff14", 
                troughcolor="#111111",
                bordercolor="#000000")
style.configure("TLabelframe", 
                background="#000000", 
                foreground="#39ff14",
                bordercolor="#39ff14")
style.configure("TLabelframe.Label", 
                background="#000000", 
                foreground="#39ff14",
                font=subheader_font)

# Map button states
style.map("TButton", 
          background=[("active", "#222222")],
          foreground=[("active", "#39ff14")])

# Initialize image variables
phishing_img = None
legit_img = None

# Create fonts for images
try:
    # Try to load specific fonts
    font_small = ImageFont.truetype("arial.ttf", 14)
    font_medium = ImageFont.truetype("arialbd.ttf", 16)
    font_large = ImageFont.truetype("arialbd.ttf", 24)
except:
    # Fallback to default fonts
    font_small = ImageFont.load_default()
    font_medium = ImageFont.load_default()
    font_large = ImageFont.load_default()

# Create initial images
phishing_img = create_phishing_image()
legit_img = create_secure_image()

# Main frame
main_frame = ttk.Frame(root, padding=20)
main_frame.pack(fill="both", expand=True)

# Header
header_frame = ttk.Frame(main_frame)
header_frame.pack(fill="x", pady=(0, 15))

title_label = tk.Label(header_frame, text="🔒 Phishing URL Detector", 
                      font=header_font, fg="#39ff14", bg="#000000")
title_label.pack(side="left")

subtitle_label = tk.Label(header_frame, text="Stay Safe Online", 
                         font=subheader_font, fg="#39ff14", bg="#000000")
subtitle_label.pack(side="left", padx=10)

# Input Section
input_frame = ttk.Frame(main_frame)
input_frame.pack(fill="x", pady=10)

input_label = ttk.Label(input_frame, text="Enter URL to analyze:", 
                       font=subheader_font)
input_label.pack(anchor="w", pady=(0, 5))

entry_frame = ttk.Frame(input_frame)
entry_frame.pack(fill="x")

entry = ttk.Entry(entry_frame, font=pixel_font)
entry.pack(side="left", fill="x", expand=True, padx=(0, 10))
entry.insert(0, "https://")

check_button = ttk.Button(entry_frame, text="Analyze URL", 
                         command=check_url)
check_button.pack(side="right")

# Status Area
status_frame = ttk.Frame(main_frame)
status_frame.pack(fill="x", pady=10)

progress_bar = ttk.Progressbar(status_frame, mode="indeterminate", length=300)
progress_bar.pack(side="left", padx=(0, 10))

status_label = ttk.Label(status_frame, text="Ready to analyze", 
                        font=pixel_font, foreground="#39ff14")
status_label.pack(side="left")

# Result Images
image_frame = ttk.Frame(main_frame)
image_frame.pack(fill="x", pady=10)

image_status_label = tk.Label(image_frame, text="", font=("PixelFont", 14, "bold"), 
                            padx=10, pady=5, relief="groove", bd=1,
                            bg="#000000", fg="#39ff14")
image_status_label.pack(pady=5, fill="x")

status_image_label = tk.Label(image_frame, bg="#000000", bd=0, relief="flat")
status_image_label.pack(pady=10)

# Detailed Results
results_frame = ttk.LabelFrame(main_frame, text="Detailed Analysis Results", padding=10)
results_frame.pack(fill="both", expand=True, pady=10)

# Create a scrollable text area for results with monospace font
scrollbar = ttk.Scrollbar(results_frame)
scrollbar.pack(side="right", fill="y")

result_text = tk.Text(results_frame, wrap="none", height=15, 
                     padx=15, pady=15, font=pixel_font,
                     bg="#000000", fg="#39ff14", 
                     insertbackground="#39ff14",
                     yscrollcommand=scrollbar.set)
result_text.pack(fill="both", expand=True)

scrollbar.config(command=result_text.yview)

# Configure text tags for perfect alignment
result_text.tag_configure("header", font=header_font, 
                         foreground="#39ff14", justify="center")
result_text.tag_configure("divider", foreground="#39ff14")
result_text.tag_configure("subheader", font=subheader_font, 
                         foreground="#39ff14")
result_text.tag_configure("normal", font=pixel_font, foreground="#39ff14")
result_text.tag_configure("risk", font=pixel_font, foreground="#ff5555")
result_text.tag_configure("safe", font=pixel_font, foreground="#00ff00")
result_text.tag_configure("total", font=("PixelFont", 11, "bold"), foreground="#00ffff")
result_text.tag_configure("error", foreground="#ff5555")
result_text.tag_configure("warning", font=("PixelFont", 12, "bold"), foreground="#ff5555")
result_text.tag_configure("safe_header", font=("PixelFont", 12, "bold"), foreground="#00ff00")

# Add placeholder text
result_text.insert(tk.END, "Analysis results will appear here\n", "normal")
result_text.insert(tk.END, "Enter a URL and click 'Analyze URL' to begin\n\n", "normal")
result_text.insert(tk.END, "Example URLs to try:\n", "subheader")
result_text.insert(tk.END, "• https://www.paypal-login.com/verify\n", "risk")
result_text.insert(tk.END, "• https://www.google.com\n", "safe")
result_text.config(state=tk.DISABLED)

# Footer
footer_frame = ttk.Frame(main_frame)
footer_frame.pack(fill="x", pady=(10, 0))

footer_label = ttk.Label(footer_frame, 
                        text="Phishing Detector v2.0 • Always verify before entering personal information", 
                        font=pixel_font, foreground="#39ff14")
footer_label.pack(side="right")

# Animation setup
loading_cycle = itertools.cycle([
    "Analyzing URL security", 
    "Analyzing URL security.", 
    "Analyzing URL security..", 
    "Analyzing URL security..."
])
checking_url = False

# Set initial UI state
image_status_label.config(text="No URL analyzed yet", fg="#39ff14", bg="#000000")
status_image_label.config(image="")

root.mainloop()