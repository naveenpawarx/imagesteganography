"""
Steganography GUI Application
Advanced Cyber Security Interface with Encryption
# added by naveen on 01-feb_2025
"""

# Standard imports
import os
import tkinter as tk
from tkinter import filedialog, messagebox
from tkinter import ttk

# Custom modules
from steganography_core import AdvancedSteganography
from encryption_module import AdvancedEncryption, RSAEncryption, HybridEncryption
from gui_themes import CyberSecurityTheme, AnimationEffects, StatusIndicator

# added by naveen on 28-feb_2025
class StegApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Image Steganography Pro – CyberSecurity Edition")
        self.root.geometry("900x600")
        self.root.minsize(800, 550)

        # Theme
        self.theme = CyberSecurityTheme()
        self.theme.configure_root(root)

        # Animation Effects
        self.anim = AnimationEffects(root)

        # Core functionality
        self.steg = AdvancedSteganography()
        self.crypto = AdvancedEncryption()
        self.rsa = RSAEncryption()
        self.hybrid = HybridEncryption()

        # Status indicator helpers
        self.indicator_util = StatusIndicator(self.theme)

        # Build UI
        self._build_ui()

    #---------------- GUI Layout ----------------#
    def _build_ui(self):
        # Create notebook tabs
        notebook = ttk.Notebook(self.root, style='Cyber.TNotebook')
        notebook.pack(fill=tk.BOTH, expand=True)

        # Hide text tab
        self.hide_text_tab = self._create_hide_text_tab(notebook)
        notebook.add(self.hide_text_tab, text="Hide Text")

        # Extract text tab
        self.extract_text_tab = self._create_extract_text_tab(notebook)
        notebook.add(self.extract_text_tab, text="Extract Text")

        # Hide image tab
        self.hide_image_tab = self._create_hide_image_tab(notebook)
        notebook.add(self.hide_image_tab, text="Hide Image")

        # Extract image tab
        self.extract_image_tab = self._create_extract_image_tab(notebook)
        notebook.add(self.extract_image_tab, text="Extract Image")

        # Encryption / Key tab
        self.crypto_tab = self._create_crypto_tab(notebook)
        notebook.add(self.crypto_tab, text="Encryption Keys")

        # About / help tab
        self.about_tab = self._create_about_tab(notebook)
        notebook.add(self.about_tab, text="About")

        # Animation start
        self.root.after(1000, lambda: self.anim.matrix_rain(self.matrix_canvas, duration=0))

    #-----------------------------#
    def _create_hide_text_tab(self, notebook):
        frame = tk.Frame(notebook, bg=self.theme.colors['primary_bg'])

        title = self.theme.create_styled_label(frame, "Hide Text in Image", style='title')
        title.pack(pady=10)

        # File selector for image
        img_frame = self.theme.create_styled_frame(frame, 'card')
        img_frame.pack(pady=10, fill=tk.X, padx=20)
        img_label = self.theme.create_styled_label(img_frame, "Cover Image:")
        img_label.pack(side=tk.LEFT, padx=10, pady=10)
        self.cover_path_var = tk.StringVar()
        img_entry = self.theme.create_styled_entry(img_frame, width=50)
        img_entry.pack(side=tk.LEFT, padx=10, pady=10)
        img_entry.configure(textvariable=self.cover_path_var)
        img_button = self.theme.create_styled_button(img_frame, "Browse", command=self._select_cover_image)
        img_button.pack(side=tk.RIGHT, padx=10, pady=10)

        # Text input
        text_label = self.theme.create_styled_label(frame, "Secret Message:")
        text_label.pack(anchor=tk.W, padx=30, pady=(10, 0))
        self.secret_text = self.theme.create_styled_text(frame, width=80, height=8)
        self.secret_text.pack(padx=30, pady=10)

        # Encryption password
        pass_frame = self.theme.create_styled_frame(frame, 'card')
        pass_frame.pack(pady=10, fill=tk.X, padx=20)
        pass_label = self.theme.create_styled_label(pass_frame, "Password (AES-256):")
        pass_label.pack(side=tk.LEFT, padx=10, pady=10)
        self.password_var = tk.StringVar()
        pass_entry = self.theme.create_styled_entry(pass_frame, width=30, show="*")
        pass_entry.pack(side=tk.LEFT, padx=10, pady=10)
        pass_entry.configure(textvariable=self.password_var)

        # Output path
        output_frame = self.theme.create_styled_frame(frame, 'card')
        output_frame.pack(pady=10, fill=tk.X, padx=20)
        output_label = self.theme.create_styled_label(output_frame, "Save As:")
        output_label.pack(side=tk.LEFT, padx=10, pady=10)
        self.output_path_var = tk.StringVar()
        output_entry = self.theme.create_styled_entry(output_frame, width=50)
        output_entry.pack(side=tk.LEFT, padx=10, pady=10)
        output_entry.configure(textvariable=self.output_path_var)
        output_button = self.theme.create_styled_button(output_frame, "Browse", command=self._select_output_image)
        output_button.pack(side=tk.RIGHT, padx=10, pady=10)

        # Status & progress
        status_frame = self.theme.create_styled_frame(frame, 'panel')
        status_frame.pack(fill=tk.X, pady=5, padx=20)
        self.status_led = self.indicator_util.create_led_indicator(status_frame, 'off')
        self.status_led.pack(side=tk.LEFT, padx=10, pady=5)
        self.status_label = self.theme.create_styled_label(status_frame, "Idle", style='secondary')
        self.status_label.pack(side=tk.LEFT, padx=10)
        self.progress_bar = self.indicator_util.create_progress_bar(status_frame, length=200)
        self.progress_bar.pack(side=tk.RIGHT, padx=10, pady=5)

        # Action button
        action_button = self.theme.create_styled_button(frame, "Embed & Encrypt", command=self._embed_text_action, style='primary')
        action_button.pack(pady=20)

        return frame

    #---------------- helper UI creators for other tabs ----------------#
    def _create_extract_text_tab(self, notebook):
        frame = tk.Frame(notebook, bg=self.theme.colors['primary_bg'])
        title = self.theme.create_styled_label(frame, "Extract Hidden Text", style='title')
        title.pack(pady=10)

        # Stego image path
        path_frame = self.theme.create_styled_frame(frame, 'card')
        path_frame.pack(pady=10, fill=tk.X, padx=20)
        path_label = self.theme.create_styled_label(path_frame, "Stego Image:")
        path_label.pack(side=tk.LEFT, padx=10, pady=10)
        self.stego_extract_path = tk.StringVar()
        path_entry = self.theme.create_styled_entry(path_frame, width=50)
        path_entry.configure(textvariable=self.stego_extract_path)
        path_entry.pack(side=tk.LEFT, padx=10, pady=10)
        path_button = self.theme.create_styled_button(path_frame, "Browse", command=self._select_stego_image)
        path_button.pack(side=tk.RIGHT, padx=10, pady=10)

        # Password
        pass_frame = self.theme.create_styled_frame(frame, 'card')
        pass_frame.pack(pady=10, fill=tk.X, padx=20)
        pass_label = self.theme.create_styled_label(pass_frame, "Password (optional):")
        pass_label.pack(side=tk.LEFT, padx=10, pady=10)
        self.extract_password_var = tk.StringVar()
        pass_entry = self.theme.create_styled_entry(pass_frame, width=30, show="*")
        pass_entry.pack(side=tk.LEFT, padx=10, pady=10)
        pass_entry.configure(textvariable=self.extract_password_var)

        # Output text
        out_label = self.theme.create_styled_label(frame, "Extracted Message:")
        out_label.pack(anchor=tk.W, padx=30, pady=(10, 0))
        self.output_text = self.theme.create_styled_text(frame, width=80, height=8)
        self.output_text.pack(padx=30, pady=10)

        # Status
        status_frame = self.theme.create_styled_frame(frame, 'panel')
        status_frame.pack(fill=tk.X, pady=5, padx=20)
        self.extract_status_led = self.indicator_util.create_led_indicator(status_frame, 'off')
        self.extract_status_led.pack(side=tk.LEFT, padx=10, pady=5)
        self.extract_status_label = self.theme.create_styled_label(status_frame, "Idle", style='secondary')
        self.extract_status_label.pack(side=tk.LEFT, padx=10)

        # Action button
        action_button = self.theme.create_styled_button(frame, "Extract", command=self._extract_text_action, style='primary')
        action_button.pack(pady=20)

        return frame

    def _create_hide_image_tab(self, notebook):
        frame = tk.Frame(notebook, bg=self.theme.colors['primary_bg'])
        title = self.theme.create_styled_label(frame, "Hide Image in Image", style='title')
        title.pack(pady=10)
        # Implementation simplified for brevity
        placeholder = self.theme.create_styled_label(frame, "Coming soon...", style='info')
        placeholder.pack(pady=100)
        return frame

    def _create_extract_image_tab(self, notebook):
        frame = tk.Frame(notebook, bg=self.theme.colors['primary_bg'])
        title = self.theme.create_styled_label(frame, "Extract Hidden Image", style='title')
        title.pack(pady=10)
        placeholder = self.theme.create_styled_label(frame, "Coming soon...", style='info')
        placeholder.pack(pady=100)
        return frame

    def _create_crypto_tab(self, notebook):
        frame = tk.Frame(notebook, bg=self.theme.colors['primary_bg'])
        title = self.theme.create_styled_label(frame, "Encryption Keys & Utilities", style='title')
        title.pack(pady=10)
        placeholder = self.theme.create_styled_label(frame, "Key management features coming soon...", style='info')
        placeholder.pack(pady=100)
        return frame

    def _create_about_tab(self, notebook):
        frame = tk.Frame(notebook, bg=self.theme.colors['primary_bg'])
        title = self.theme.create_styled_label(frame, "About / Help", style='title')
        title.pack(pady=10)
        # Matrix Canvas
        self.matrix_canvas = tk.Canvas(frame, bg='black', highlightthickness=0)
        self.matrix_canvas.pack(fill=tk.BOTH, expand=True)
        about_text = """
Image Steganography Pro – CyberSecurity Edition
Version 1.0 (2025)

Developed by Naveen (01-feb_2025 to 15-jun_2025).

Features:
• LSB & DCT steganography
• AES-256 / RSA-2048 encryption
• Hybrid encryption & PBKDF2 KDF
• Professional dark GUI with Matrix effects

Use responsibly. Unauthorized data hiding may violate laws.
"""
        text_widget = self.theme.create_styled_text(frame, width=80, height=15)
        text_widget.insert(tk.END, about_text)
        text_widget.configure(state=tk.DISABLED)
        text_widget.place(relx=0.5, rely=0.5, anchor=tk.CENTER)
        return frame

    #---------------- File dialogs ----------------#
    def _select_cover_image(self):
        path = filedialog.askopenfilename(title="Select Cover Image", filetypes=[("Image Files", "*.png *.bmp *.tiff")])
        if path:
            self.cover_path_var.set(path)

    def _select_output_image(self):
        path = filedialog.asksaveasfilename(defaultextension=".png", title="Save Stego Image")
        if path:
            self.output_path_var.set(path)

    def _select_stego_image(self):
        path = filedialog.askopenfilename(title="Select Stego Image", filetypes=[("Image Files", "*.png *.bmp *.tiff")])
        if path:
            self.stego_extract_path.set(path)

    #---------------- Actions ----------------#
    def _embed_text_action(self):
        cover = self.cover_path_var.get()
        message = self.secret_text.get(1.0, tk.END).strip()
        output = self.output_path_var.get()
        password = self.password_var.get()

        if not cover or not os.path.exists(cover):
            messagebox.showerror("Error", "Cover image not selected or invalid")
            return
        if not message:
            messagebox.showerror("Error", "Secret message is empty")
            return
        if not output:
            messagebox.showerror("Error", "Output path not specified")
            return

        # Encrypt message if password provided
        if password:
            self._update_status("Encrypting message...", 'info')
            try:
                message = self.crypto.aes_encrypt(message, password, mode='CBC')
            except Exception as e:
                self._update_status(f"Encryption failed: {str(e)}", 'error')
                return

        # Embed text
        try:
            self._update_status("Embedding data...", 'info')
            self.progress_bar.start(10)
            self.steg.embed_text_lsb(cover, message, output)
            self.progress_bar.stop()
            self._update_status("Success! Data embedded.", 'success')
            messagebox.showinfo("Success", "Secret message embedded successfully!")
        except Exception as e:
            self.progress_bar.stop()
            self._update_status(f"Embedding failed: {str(e)}", 'error')
            messagebox.showerror("Error", f"Embedding failed: {str(e)}")

    def _extract_text_action(self):
        stego = self.stego_extract_path.get()
        password = self.extract_password_var.get()
        if not stego or not os.path.exists(stego):
            messagebox.showerror("Error", "Stego image not selected or invalid")
            return

        try:
            self._update_status("Extracting data...", 'info', extract=True)
            data = self.steg.extract_text_lsb(stego)
            # If password provided – decrypt
            if password:
                data = self.crypto.aes_decrypt(data, password, mode='CBC')
            self.output_text.configure(state=tk.NORMAL)
            self.output_text.delete(1.0, tk.END)
            self.output_text.insert(tk.END, data)
            self.output_text.configure(state=tk.DISABLED)
            self._update_status("Success! Data extracted.", 'success', extract=True)
            messagebox.showinfo("Success", "Hidden message extracted successfully!")
        except Exception as e:
            self._update_status(f"Extraction failed: {str(e)}", 'error', extract=True)
            messagebox.showerror("Error", f"Extraction failed: {str(e)}")

    #---------------- Status updates ----------------#
    def _update_status(self, text, status='info', extract=False):
        if extract:
            led = self.extract_status_led
            label = self.extract_status_label
        else:
            led = self.status_led
            label = self.status_label

        if status == 'success':
            led.configure(fg=self.theme.colors['success_text'])
        elif status == 'error':
            led.configure(fg=self.theme.colors['warning_text'])
        elif status == 'info':
            led.configure(fg=self.theme.colors['info_text'])
        else:
            led.configure(fg=self.theme.colors['secondary_text'])
        label.configure(text=text)

# ---------------- Main ----------------#
if __name__ == '__main__':
    root = tk.Tk()
    app = StegApp(root)
    root.mainloop()
