import tkinter as tk
from tkinter import ttk, messagebox
import re
import random
import webbrowser
from datetime import datetime, timedelta

class PasswordStrengthChecker:
    def __init__(self, root):
        self.root = root
        self.root.title("Password Strength Checker - Breach Guardians Initiative")
        self.root.configure(bg='#000000')
        self.root.geometry('800x700')
        
        # Configure styles
        self.style = ttk.Style()
        self.style.theme_use('clam')
        
        # Configure styles for dark theme
        self.style.configure('TFrame', background='#000000')
        self.style.configure('TLabel', background='#000000', foreground='#39FF14', font=('Courier', 10))
        self.style.configure('TButton', background='#111111', foreground='#39FF14', font=('Courier', 10, 'bold'))
        self.style.map('TButton', background=[('active', '#222222')])
        self.style.configure('TEntry', fieldbackground='#111111', foreground='#39FF14', font=('Courier', 10))
        self.style.configure('Horizontal.TProgressbar', background='#39FF14', troughcolor='#111111')
        self.style.configure('Title.TLabel', font=('Courier', 16, 'bold'))
        self.style.configure('Subtitle.TLabel', font=('Courier', 12, 'bold'))
        
        # Initialize breach data (simulated)
        self.known_breaches = [
            "2023-12: MegaCorp Data Breach (142M accounts)",
            "2023-09: SocialMediaSite Hack (87M accounts)",
            "2023-06: CloudService Provider Incident (53M accounts)",
            "2023-03: E-Commerce Platform Leak (31M accounts)",
            "2022-11: Gaming Network Compromise (67M accounts)",
            "2022-08: Financial Institution Attack (45M accounts)",
            "2022-05: Healthcare Provider Breach (38M records)",
            "2022-02: Government Database Exposure (29M records)"
        ]
        
        self.setup_gui()
        
    def setup_gui(self):
        # Create notebook for tabs
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill='both', expand=True, padx=10, pady=10)
        
        # Password Checker Tab
        self.checker_frame = ttk.Frame(self.notebook, padding="10")
        self.notebook.add(self.checker_frame, text="Password Checker")
        
        # Breach Guardians Tab
        self.guardians_frame = ttk.Frame(self.notebook, padding="10")
        self.notebook.add(self.guardians_frame, text="Breach Guardians")
        
        # Setup both tabs
        self.setup_checker_tab()
        self.setup_guardians_tab()
        
    def setup_checker_tab(self):
        # Title
        title_label = ttk.Label(self.checker_frame, text="PASSWORD STRENGTH CHECKER", style='Title.TLabel')
        title_label.grid(row=0, column=0, columnspan=2, pady=10)
        
        # Password entry
        ttk.Label(self.checker_frame, text="Enter Password:", style='Subtitle.TLabel').grid(row=1, column=0, sticky='w', pady=10)
        
        self.password_var = tk.StringVar()
        self.password_entry = ttk.Entry(self.checker_frame, textvariable=self.password_var, show='•', font=('Courier', 12), width=40)
        self.password_entry.grid(row=2, column=0, sticky='ew', pady=5)
        self.password_entry.bind('<KeyRelease>', self.check_password_strength)
        
        # Show password checkbox
        self.show_password_var = tk.IntVar()
        show_password_cb = ttk.Checkbutton(self.checker_frame, text="Show Password", variable=self.show_password_var, 
                                          command=self.toggle_password_visibility)
        show_password_cb.grid(row=3, column=0, sticky='w', pady=5)
        
        # Strength meter
        ttk.Label(self.checker_frame, text="Strength Meter:", style='Subtitle.TLabel').grid(row=4, column=0, sticky='w', pady=(20, 5))
        
        self.strength_meter = ttk.Progressbar(self.checker_frame, orient='horizontal', length=400, mode='determinate')
        self.strength_meter.grid(row=5, column=0, sticky='ew', pady=5)
        
        # Strength label
        self.strength_label = ttk.Label(self.checker_frame, text="", font=('Courier', 12, 'bold'))
        self.strength_label.grid(row=6, column=0, pady=5)
        
        # Score breakdown
        ttk.Label(self.checker_frame, text="Score Breakdown:", style='Subtitle.TLabel').grid(row=7, column=0, sticky='w', pady=(20, 5))
        
        # Create a frame for the score breakdown
        breakdown_frame = ttk.Frame(self.checker_frame)
        breakdown_frame.grid(row=8, column=0, sticky='ew', pady=5)
        
        # Criteria labels
        self.length_label = ttk.Label(breakdown_frame, text="✗ Length (12+ characters)", font=('Courier', 10))
        self.length_label.grid(row=0, column=0, sticky='w', pady=2)
        
        self.upper_label = ttk.Label(breakdown_frame, text="✗ Uppercase letter", font=('Courier', 10))
        self.upper_label.grid(row=1, column=0, sticky='w', pady=2)
        
        self.lower_label = ttk.Label(breakdown_frame, text="✗ Lowercase letter", font=('Courier', 10))
        self.lower_label.grid(row=2, column=0, sticky='w', pady=2)
        
        self.digit_label = ttk.Label(breakdown_frame, text="✗ Digit", font=('Courier', 10))
        self.digit_label.grid(row=3, column=0, sticky='w', pady=2)
        
        self.special_label = ttk.Label(breakdown_frame, text="✗ Special character", font=('Courier', 10))
        self.special_label.grid(row=4, column=0, sticky='w', pady=2)
        
        # Time to crack
        self.crack_time_label = ttk.Label(self.checker_frame, text="Time to crack: ", font=('Courier', 10))
        self.crack_time_label.grid(row=9, column=0, sticky='w', pady=(20, 5))
        
        # Breach check
        self.breach_status_label = ttk.Label(self.checker_frame, text="Breach check: Not performed", font=('Courier', 10))
        self.breach_status_label.grid(row=10, column=0, sticky='w', pady=(20, 5))
        
        ttk.Button(self.checker_frame, text="Check Against Known Breaches", 
                  command=self.check_against_breaches).grid(row=11, column=0, sticky='w', pady=5)
        
        # Suggestions
        ttk.Label(self.checker_frame, text="Suggestions:", style='Subtitle.TLabel').grid(row=12, column=0, sticky='w', pady=(20, 5))
        
        self.suggestions_text = tk.Text(self.checker_frame, height=4, width=60, bg='#111111', fg='#39FF14', 
                                       font=('Courier', 9), relief='flat', wrap='word')
        self.suggestions_text.grid(row=13, column=0, sticky='ew', pady=5)
        
        # Configure grid weights
        self.checker_frame.columnconfigure(0, weight=1)
        
    def setup_guardians_tab(self):
        # Title
        title_label = ttk.Label(self.guardians_frame, text="BREACH GUARDIANS INITIATIVE", style='Title.TLabel')
        title_label.grid(row=0, column=0, columnspan=2, pady=10)
        
        # Mission statement
        mission_text = """The Breach Guardians Initiative is a global cybersecurity awareness program 
dedicated to protecting digital identities through education, tools, and community action."""
        
        mission_label = ttk.Label(self.guardians_frame, text=mission_text, font=('Courier', 11), justify='center')
        mission_label.grid(row=1, column=0, pady=10, padx=20)
        
        # Pillars of the initiative
        ttk.Label(self.guardians_frame, text="Our Pillars:", style='Subtitle.TLabel').grid(row=2, column=0, sticky='w', pady=(20, 10))
        
        pillars = [
            "1. Education: Cybersecurity awareness training for all ages",
            "2. Tools: Free resources for password management and protection",
            "3. Monitoring: Dark web surveillance for compromised credentials",
            "4. Response: Rapid action protocols when breaches occur",
            "5. Community: Building a network of digital safety advocates"
        ]
        
        for i, pillar in enumerate(pillars):
            ttk.Label(self.guardians_frame, text=pillar, font=('Courier', 10)).grid(row=3+i, column=0, sticky='w', pady=2)
        
        # Recent breaches frame
        ttk.Label(self.guardians_frame, text="Recent Major Breaches:", style='Subtitle.TLabel').grid(row=8, column=0, sticky='w', pady=(20, 10))
        
        breach_frame = ttk.Frame(self.guardians_frame)
        breach_frame.grid(row=9, column=0, sticky='ew', pady=5)
        
        # Create a canvas with scrollbar for breaches
        canvas = tk.Canvas(breach_frame, bg='#111111', height=150, highlightthickness=0)
        scrollbar = ttk.Scrollbar(breach_frame, orient="vertical", command=canvas.yview)
        self.scrollable_frame = ttk.Frame(canvas)
        
        self.scrollable_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
        )
        
        canvas.create_window((0, 0), window=self.scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)
        
        for i, breach in enumerate(self.known_breaches):
            ttk.Label(self.scrollable_frame, text=f"• {breach}", font=('Courier', 9), 
                     foreground='#FF5555' if 'M' in breach else '#FFAA00').grid(row=i, column=0, sticky='w', pady=2)
        
        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        
        # Protection tips
        ttk.Label(self.guardians_frame, text="Essential Protection Tips:", style='Subtitle.TLabel').grid(row=10, column=0, sticky='w', pady=(20, 10))
        
        tips = [
            "• Use unique passwords for every account",
            "• Enable two-factor authentication (2FA) wherever possible",
            "• Regularly update your software and apps",
            "• Be cautious of phishing emails and suspicious links",
            "• Use a password manager to generate and store strong passwords",
            "• Monitor your accounts for unusual activity",
            "• Consider using a VPN on public Wi-Fi networks"
        ]
        
        for i, tip in enumerate(tips):
            ttk.Label(self.guardians_frame, text=tip, font=('Courier', 9)).grid(row=11+i, column=0, sticky='w', pady=1)
        
        # Action buttons
        button_frame = ttk.Frame(self.guardians_frame)
        button_frame.grid(row=18, column=0, pady=20)
        
        ttk.Button(button_frame, text="Join the Initiative", command=self.join_initiative).grid(row=0, column=0, padx=5)
        ttk.Button(button_frame, text="Request Security Audit", command=self.request_audit).grid(row=0, column=1, padx=5)
        ttk.Button(button_frame, text="Educational Resources", command=self.open_resources).grid(row=0, column=2, padx=5)
        
        # Configure grid weights
        self.guardians_frame.columnconfigure(0, weight=1)
            
    def toggle_password_visibility(self):
        if self.show_password_var.get() == 1:
            self.password_entry.config(show='')
        else:
            self.password_entry.config(show='•')
            
    def check_password_strength(self, event=None):
        password = self.password_var.get()
        
        if not password:
            self.strength_meter['value'] = 0
            self.strength_label.config(text="")
            self.crack_time_label.config(text="Time to crack: ")
            self.breach_status_label.config(text="Breach check: Not performed")
            self.suggestions_text.delete(1.0, tk.END)
            return
            
        # Calculate password strength
        score = self.calculate_password_strength(password)
        self.strength_meter['value'] = score * 25  # Convert 0-4 score to 0-100
        
        strength_texts = ["Very Weak", "Weak", "Fair", "Strong", "Very Strong"]
        strength_colors = ["#FF0000", "#FF5500", "#FFAA00", "#55FF00", "#00FF00"]
        
        self.strength_label.config(text=strength_texts[min(score, 4)], foreground=strength_colors[min(score, 4)])
        
        # Estimate crack time
        crack_time = self.estimate_crack_time(password, score)
        self.crack_time_label.config(text=f"Time to crack: {crack_time}")
        
        # Provide suggestions
        self.suggestions_text.delete(1.0, tk.END)
        suggestions = self.generate_suggestions(password, score)
        for suggestion in suggestions:
            self.suggestions_text.insert(tk.END, f"• {suggestion}\n")
        
        # Update criteria labels
        self.update_criteria_labels(password)
        
    def calculate_password_strength(self, password):
        """Calculate password strength score (0-4)"""
        strength = 0
        
        # Length check
        if len(password) >= 8:
            strength += 1
        if len(password) >= 12:
            strength += 1
            
        # Character variety checks
        if re.search(r'[A-Z]', password):
            strength += 0.5
        if re.search(r'[a-z]', password):
            strength += 0.5
        if re.search(r'[0-9]', password):
            strength += 0.5
        if re.search(r'[^A-Za-z0-9]', password):
            strength += 0.5
            
        # Entropy calculation (simple version)
        char_set = 0
        if re.search(r'[a-z]', password):
            char_set += 26
        if re.search(r'[A-Z]', password):
            char_set += 26
        if re.search(r'[0-9]', password):
            char_set += 10
        if re.search(r'[^A-Za-z0-9]', password):
            char_set += 32
            
        if char_set > 0:
            entropy = len(password) * (char_set ** 0.5) / 10
            strength = min(strength + entropy / 10, 4)
            
        return min(round(strength), 4)
        
    def estimate_crack_time(self, password, score):
        """Estimate how long it would take to crack the password"""
        if score == 0:
            return "Instantly"
        elif score == 1:
            return "Seconds to minutes"
        elif score == 2:
            return "Hours to days"
        elif score == 3:
            return "Months to years"
        else:
            return "Centuries or more"
            
    def generate_suggestions(self, password, score):
        """Generate suggestions to improve password strength"""
        suggestions = []
        
        if len(password) < 12:
            suggestions.append("Use at least 12 characters")
            
        if not re.search(r'[A-Z]', password):
            suggestions.append("Add uppercase letters")
            
        if not re.search(r'[a-z]', password):
            suggestions.append("Add lowercase letters")
            
        if not re.search(r'[0-9]', password):
            suggestions.append("Add numbers")
            
        if not re.search(r'[^A-Za-z0-9]', password):
            suggestions.append("Add special characters (!, @, #, etc.)")
            
        if score >= 3 and len(suggestions) == 0:
            suggestions.append("Good job! Your password is strong.")
            
        # Add Breach Guardians tip
        suggestions.append("Consider using a passphrase instead of a password")
        suggestions.append("Join the Breach Guardians Initiative for more security tips")
            
        return suggestions
        
    def update_criteria_labels(self, password):
        """Update the criteria labels with checkmarks or crossmarks"""
        # Length check
        if len(password) >= 12:
            self.length_label.config(text="✓ Length (12+ characters)", foreground='#39FF14')
        else:
            self.length_label.config(text="✗ Length (12+ characters)", foreground='#FF5555')
            
        # Uppercase check
        if re.search(r'[A-Z]', password):
            self.upper_label.config(text="✓ Uppercase letter", foreground='#39FF14')
        else:
            self.upper_label.config(text="✗ Uppercase letter", foreground='#FF5555')
            
        # Lowercase check
        if re.search(r'[a-z]', password):
            self.lower_label.config(text="✓ Lowercase letter", foreground='#39FF14')
        else:
            self.lower_label.config(text="✗ Lowercase letter", foreground='#FF5555')
            
        # Digit check
        if re.search(r'[0-9]', password):
            self.digit_label.config(text="✓ Digit", foreground='#39FF14')
        else:
            self.digit_label.config(text="✗ Digit", foreground='#FF5555')
            
        # Special character check
        if re.search(r'[^A-Za-z0-9]', password):
            self.special_label.config(text="✓ Special character", foreground='#39FF14')
        else:
            self.special_label.config(text="✗ Special character", foreground='#FF5555')
            
    def check_against_breaches(self):
        """Simulate checking against known breaches"""
        password = self.password_var.get()
        
        if not password:
            messagebox.showwarning("Warning", "Please enter a password first.")
            return
            
        # Simulate checking against common passwords and known breaches
        common_passwords = ["123456", "password", "123456789", "qwerty", "abc123", "password1", "admin", "letmein"]
        
        if password in common_passwords:
            self.breach_status_label.config(text="Breach check: ❌ Found in multiple breaches!", foreground='#FF5555')
            messagebox.showerror("Security Alert", "This password has been compromised in multiple data breaches. Do not use it!")
        elif len(password) < 8:
            self.breach_status_label.config(text="Breach check: ⚠ Too weak, easily guessable", foreground='#FFAA00')
            messagebox.showwarning("Security Warning", "This password is too short and would be easily compromised in a breach.")
        else:
            # Simulate a random result for demonstration
            if random.random() < 0.2:  # 20% chance of being found in a breach
                self.breach_status_label.config(text="Breach check: ❌ Found in past breaches", foreground='#FF5555')
                messagebox.showerror("Security Alert", "This password has appeared in past data breaches. Consider changing it.")
            else:
                self.breach_status_label.config(text="Breach check: ✅ No known breaches", foreground='#39FF14')
                messagebox.showinfo("Security Check", "No known breaches found for this password. However, always use unique passwords for each account.")
                
    def join_initiative(self):
        """Show information about joining the Breach Guardians"""
        messagebox.showinfo("Join Breach Guardians", 
                          "Thank you for your interest in the Breach Guardians Initiative!\n\n"
                          "As a member, you'll receive:\n"
                          "- Monthly security newsletters\n"
                          "- Access to exclusive webinars\n"
                          "- Early alerts about new threats\n"
                          "- Community support forum access\n\n"
                          "Visit our website to sign up and learn more.")
        
    def request_audit(self):
        """Simulate requesting a security audit"""
        messagebox.showinfo("Security Audit", 
                          "Our security experts will analyze your digital footprint and provide:\n\n"
                          "- Password strength evaluation\n"
                          "- Dark web monitoring report\n"
                          "- Personalized security recommendations\n"
                          "- Ongoing protection strategies\n\n"
                          "A representative will contact you within 48 hours.")
        
    def open_resources(self):
        """Open educational resources (simulated)"""
        resources = [
            "Creating Strong Passwords Guide",
            "Two-Factor Authentication Tutorial",
            "Recognizing Phishing Attempts",
            "Data Breach Response Checklist",
            "Home Network Security Setup"
        ]
        
        resource_list = "\n".join([f"• {resource}" for resource in resources])
        messagebox.showinfo("Educational Resources", 
                          f"Available resources:\n\n{resource_list}\n\n"
                          "These resources are available on our website.")

if __name__ == "__main__":
    root = tk.Tk()
    app = PasswordStrengthChecker(root)
    root.mainloop()