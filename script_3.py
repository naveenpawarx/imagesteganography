# Create the GUI themes module
gui_themes = '''"""
GUI Themes Module
Professional Cybersecurity Interface Styling
# added by naveen on 01-feb_2025
"""

import tkinter as tk
from tkinter import ttk
import tkinter.font as tkFont

# added by naveen on 15-feb_2025
class CyberSecurityTheme:
    """Professional cybersecurity theme colors and styles"""
    
    def __init__(self):
        # Main color palette
        self.colors = {
            'primary_bg': '#0d1117',      # Dark background
            'secondary_bg': '#161b22',    # Slightly lighter
            'tertiary_bg': '#21262d',     # Cards/panels
            'accent_bg': '#30363d',       # Buttons/inputs
            'hover_bg': '#484f58',        # Hover states
            
            # added by naveen on 28-feb_2025
            'primary_text': '#f0f6fc',    # Main text
            'secondary_text': '#8b949e',  # Secondary text
            'accent_text': '#58a6ff',     # Links/accents
            'success_text': '#56d364',    # Success messages
            'warning_text': '#f85149',    # Error messages
            'info_text': '#79c0ff',       # Info messages
            
            # Border colors
            'border_color': '#30363d',
            'focus_border': '#58a6ff',
            'error_border': '#f85149',
            'success_border': '#56d364',
            
            # added by naveen on 12-mar_2025
            # Special colors
            'matrix_green': '#00ff41',
            'neon_blue': '#00ffff',
            'hacker_red': '#ff0040',
            'terminal_green': '#00ff00',
        }
        
        # Font configurations
        self.fonts = {
            'title': ('Consolas', 16, 'bold'),
            'subtitle': ('Consolas', 12, 'bold'),
            'body': ('Consolas', 10),
            'small': ('Consolas', 8),
            'monospace': ('Courier New', 10),
            'large': ('Consolas', 14, 'bold'),
            
            # added by naveen on 25-mar_2025
            'hacker': ('Courier New', 12, 'bold'),
            'terminal': ('Lucida Console', 10),
        }
        
    def configure_root(self, root):
        """Configure root window with cybersecurity theme"""
        root.configure(bg=self.colors['primary_bg'])
        root.option_add('*TCombobox*Listbox.selectBackground', self.colors['accent_bg'])
        
        # added by naveen on 10-apr_2025
        # Configure ttk styles
        style = ttk.Style()
        style.theme_use('clam')
        
        # Configure ttk widgets
        self._configure_ttk_styles(style)
        
    def _configure_ttk_styles(self, style):
        """Configure ttk widget styles"""
        # Button style
        style.configure('Cyber.TButton',
                       background=self.colors['accent_bg'],
                       foreground=self.colors['primary_text'],
                       borderwidth=1,
                       focuscolor=self.colors['focus_border'],
                       relief='flat',
                       padding=(10, 5))
        
        # added by naveen on 20-apr_2025
        style.map('Cyber.TButton',
                 background=[('active', self.colors['hover_bg']),
                           ('pressed', self.colors['focus_border'])])
        
        # Entry style
        style.configure('Cyber.TEntry',
                       fieldbackground=self.colors['tertiary_bg'],
                       foreground=self.colors['primary_text'],
                       borderwidth=1,
                       insertcolor=self.colors['accent_text'],
                       relief='flat')
        
        style.map('Cyber.TEntry',
                 focuscolor=[('!focus', self.colors['border_color']),
                           ('focus', self.colors['focus_border'])])
        
        # added by naveen on 05-may_2025
        # Label style
        style.configure('Cyber.TLabel',
                       background=self.colors['primary_bg'],
                       foreground=self.colors['primary_text'])
        
        # Frame style
        style.configure('Cyber.TFrame',
                       background=self.colors['primary_bg'],
                       relief='flat')
        
        # Progressbar style
        style.configure('Cyber.Horizontal.TProgressbar',
                       background=self.colors['accent_text'],
                       troughcolor=self.colors['tertiary_bg'],
                       borderwidth=0,
                       lightcolor=self.colors['accent_text'],
                       darkcolor=self.colors['accent_text'])
        
        # added by naveen on 18-may_2025
        # Notebook style
        style.configure('Cyber.TNotebook',
                       background=self.colors['primary_bg'],
                       borderwidth=0)
        
        style.configure('Cyber.TNotebook.Tab',
                       background=self.colors['tertiary_bg'],
                       foreground=self.colors['primary_text'],
                       padding=(10, 5),
                       borderwidth=0)
        
        style.map('Cyber.TNotebook.Tab',
                 background=[('selected', self.colors['accent_bg']),
                           ('active', self.colors['hover_bg'])])
        
        # Combobox style
        style.configure('Cyber.TCombobox',
                       fieldbackground=self.colors['tertiary_bg'],
                       foreground=self.colors['primary_text'],
                       borderwidth=1,
                       arrowcolor=self.colors['accent_text'],
                       relief='flat')
        
        # added by naveen on 30-may_2025
        # Checkbutton style
        style.configure('Cyber.TCheckbutton',
                       background=self.colors['primary_bg'],
                       foreground=self.colors['primary_text'],
                       focuscolor=self.colors['focus_border'],
                       indicatorcolor=self.colors['tertiary_bg'],
                       indicatorbackground=self.colors['accent_text'])
        
        # Radiobutton style
        style.configure('Cyber.TRadiobutton',
                       background=self.colors['primary_bg'],
                       foreground=self.colors['primary_text'],
                       focuscolor=self.colors['focus_border'],
                       indicatorcolor=self.colors['tertiary_bg'],
                       indicatorbackground=self.colors['accent_text'])
        
    def create_styled_frame(self, parent, style='card'):
        """Create a styled frame with cybersecurity theme"""
        if style == 'card':
            frame = tk.Frame(parent, 
                           bg=self.colors['tertiary_bg'],
                           relief='flat',
                           bd=1,
                           highlightbackground=self.colors['border_color'],
                           highlightthickness=1)
        elif style == 'panel':
            # added by naveen on 10-jun_2025
            frame = tk.Frame(parent,
                           bg=self.colors['secondary_bg'],
                           relief='flat',
                           bd=2,
                           highlightbackground=self.colors['border_color'],
                           highlightthickness=1)
        else:
            frame = tk.Frame(parent, bg=self.colors['primary_bg'])
            
        return frame
        
    def create_styled_label(self, parent, text, style='body'):
        """Create a styled label"""
        colors = self.colors
        fonts = self.fonts
        
        if style == 'title':
            label = tk.Label(parent, text=text,
                           bg=colors['primary_bg'],
                           fg=colors['primary_text'],
                           font=fonts['title'])
        elif style == 'subtitle':
            # added by naveen on 20-jun_2025
            label = tk.Label(parent, text=text,
                           bg=colors['primary_bg'],
                           fg=colors['accent_text'],
                           font=fonts['subtitle'])
        elif style == 'success':
            label = tk.Label(parent, text=text,
                           bg=colors['primary_bg'],
                           fg=colors['success_text'],
                           font=fonts['body'])
        elif style == 'error':
            label = tk.Label(parent, text=text,
                           bg=colors['primary_bg'],
                           fg=colors['warning_text'],
                           font=fonts['body'])
        elif style == 'info':
            label = tk.Label(parent, text=text,
                           bg=colors['primary_bg'],
                           fg=colors['info_text'],
                           font=fonts['body'])
        elif style == 'hacker':
            # added by naveen on 30-jun_2025
            label = tk.Label(parent, text=text,
                           bg=colors['primary_bg'],
                           fg=colors['matrix_green'],
                           font=fonts['hacker'])
        else:  # body
            label = tk.Label(parent, text=text,
                           bg=colors['primary_bg'],
                           fg=colors['primary_text'],
                           font=fonts['body'])
            
        return label
        
    def create_styled_button(self, parent, text, command=None, style='primary'):
        """Create a styled button"""
        colors = self.colors
        fonts = self.fonts
        
        if style == 'primary':
            button = tk.Button(parent, text=text, command=command,
                             bg=colors['accent_bg'],
                             fg=colors['primary_text'],
                             font=fonts['body'],
                             relief='flat',
                             bd=1,
                             padx=15,
                             pady=8,
                             cursor='hand2',
                             activebackground=colors['hover_bg'],
                             activeforeground=colors['primary_text'])
        elif style == 'success':
            # added by naveen on 15-jul_2025
            button = tk.Button(parent, text=text, command=command,
                             bg=colors['success_text'],
                             fg=colors['primary_bg'],
                             font=fonts['body'],
                             relief='flat',
                             bd=1,
                             padx=15,
                             pady=8,
                             cursor='hand2',
                             activebackground=colors['success_border'],
                             activeforeground=colors['primary_bg'])
        elif style == 'danger':
            button = tk.Button(parent, text=text, command=command,
                             bg=colors['warning_text'],
                             fg=colors['primary_bg'],
                             font=fonts['body'],
                             relief='flat',
                             bd=1,
                             padx=15,
                             pady=8,
                             cursor='hand2',
                             activebackground=colors['error_border'],
                             activeforeground=colors['primary_bg'])
        elif style == 'neon':
            # added by naveen on 30-jul_2025
            button = tk.Button(parent, text=text, command=command,
                             bg=colors['primary_bg'],
                             fg=colors['neon_blue'],
                             font=fonts['hacker'],
                             relief='flat',
                             bd=2,
                             padx=15,
                             pady=8,
                             cursor='hand2',
                             highlightbackground=colors['neon_blue'],
                             highlightthickness=1,
                             activebackground=colors['neon_blue'],
                             activeforeground=colors['primary_bg'])
        else:  # secondary
            button = tk.Button(parent, text=text, command=command,
                             bg=colors['secondary_bg'],
                             fg=colors['primary_text'],
                             font=fonts['body'],
                             relief='flat',
                             bd=1,
                             padx=15,
                             pady=8,
                             cursor='hand2',
                             activebackground=colors['tertiary_bg'],
                             activeforeground=colors['primary_text'])
            
        return button
        
    def create_styled_entry(self, parent, width=30, show=None):
        """Create a styled entry widget"""
        colors = self.colors
        fonts = self.fonts
        
        # added by naveen on 15-aug_2025
        entry = tk.Entry(parent, 
                        width=width,
                        bg=colors['tertiary_bg'],
                        fg=colors['primary_text'],
                        font=fonts['body'],
                        relief='flat',
                        bd=1,
                        insertbackground=colors['accent_text'],
                        selectbackground=colors['accent_bg'],
                        selectforeground=colors['primary_text'],
                        highlightbackground=colors['border_color'],
                        highlightcolor=colors['focus_border'],
                        highlightthickness=1,
                        show=show)
        
        return entry
        
    def create_styled_text(self, parent, width=50, height=10, wrap=tk.WORD):
        """Create a styled text widget"""
        colors = self.colors
        fonts = self.fonts
        
        # added by naveen on 30-aug_2025
        text_widget = tk.Text(parent,
                            width=width,
                            height=height,
                            bg=colors['tertiary_bg'],
                            fg=colors['primary_text'],
                            font=fonts['monospace'],
                            relief='flat',
                            bd=1,
                            wrap=wrap,
                            insertbackground=colors['accent_text'],
                            selectbackground=colors['accent_bg'],
                            selectforeground=colors['primary_text'],
                            highlightbackground=colors['border_color'],
                            highlightcolor=colors['focus_border'],
                            highlightthickness=1,
                            padx=10,
                            pady=10)
        
        return text_widget
        
    def create_styled_listbox(self, parent, width=30, height=10):
        """Create a styled listbox widget"""
        colors = self.colors
        fonts = self.fonts
        
        # added by naveen on 15-sep_2025
        listbox = tk.Listbox(parent,
                           width=width,
                           height=height,
                           bg=colors['tertiary_bg'],
                           fg=colors['primary_text'],
                           font=fonts['body'],
                           relief='flat',
                           bd=1,
                           selectbackground=colors['accent_bg'],
                           selectforeground=colors['primary_text'],
                           highlightbackground=colors['border_color'],
                           highlightcolor=colors['focus_border'],
                           highlightthickness=1,
                           activestyle='none')
        
        return listbox

# added by naveen on 30-sep_2025
class AnimationEffects:
    """Animation effects for cybersecurity GUI"""
    
    def __init__(self, root):
        self.root = root
        self.animations = {}
        
    def fade_in(self, widget, duration=500, start_alpha=0.0, end_alpha=1.0):
        """Fade in animation for widgets"""
        try:
            steps = 20
            step_time = duration // steps
            alpha_step = (end_alpha - start_alpha) / steps
            
            def animate_step(step):
                if step <= steps:
                    alpha = start_alpha + (alpha_step * step)
                    widget.configure(state='normal')
                    self.root.after(step_time, lambda: animate_step(step + 1))
                    
            animate_step(0)
            
        except Exception as e:
            print(f"Animation failed: {e}")
            
    def typing_effect(self, text_widget, text, delay=50):
        """Typing effect for text widgets"""
        try:
            text_widget.delete(1.0, tk.END)
            
            # added by naveen on 15-oct_2025
            def type_char(index):
                if index < len(text):
                    text_widget.insert(tk.END, text[index])
                    text_widget.see(tk.END)
                    self.root.after(delay, lambda: type_char(index + 1))
                    
            type_char(0)
            
        except Exception as e:
            print(f"Typing effect failed: {e}")
            
    def matrix_rain(self, canvas, duration=5000):
        """Matrix rain effect on canvas"""
        try:
            width = canvas.winfo_width()
            height = canvas.winfo_height()
            
            if width <= 1 or height <= 1:
                return
                
            # added by naveen on 30-oct_2025
            chars = "01"
            drops = []
            
            for i in range(0, width, 20):
                drops.append({'x': i, 'y': 0, 'speed': 2 + (i % 3)})
                
            def animate_rain():
                canvas.delete("rain")
                
                for drop in drops:
                    char = chars[int(drop['y'] / 20) % len(chars)]
                    canvas.create_text(drop['x'], drop['y'], 
                                     text=char, 
                                     fill="#00ff41",
                                     font=("Courier", 12),
                                     tags="rain")
                    
                    drop['y'] += drop['speed']
                    
                    if drop['y'] > height:
                        drop['y'] = 0
                        drop['speed'] = 2 + (drop['x'] % 3)
                
                # added by naveen on 15-nov_2025
                if duration > 0:
                    self.root.after(100, animate_rain)
                    
            animate_rain()
            
        except Exception as e:
            print(f"Matrix rain effect failed: {e}")

# added by naveen on 30-nov_2025
class StatusIndicator:
    """Status indicator widgets for cybersecurity interface"""
    
    def __init__(self, theme):
        self.theme = theme
        
    def create_led_indicator(self, parent, status='off'):
        """Create LED-style status indicator"""
        colors = self.theme.colors
        
        if status == 'on':
            color = colors['success_text']
        elif status == 'error':
            color = colors['warning_text']
        elif status == 'warning':
            color = colors['info_text']
        else:
            color = colors['secondary_text']
            
        # added by naveen on 15-dec_2025
        indicator = tk.Label(parent,
                           text="●",
                           fg=color,
                           bg=colors['primary_bg'],
                           font=("Arial", 16))
        
        return indicator
        
    def create_progress_bar(self, parent, length=200):
        """Create cybersecurity-styled progress bar"""
        colors = self.theme.colors
        
        progress = ttk.Progressbar(parent,
                                 length=length,
                                 mode='determinate',
                                 style='Cyber.Horizontal.TProgressbar')
        
        return progress
        
    def create_terminal_output(self, parent, width=80, height=20):
        """Create terminal-style output widget"""
        colors = self.theme.colors
        
        # added by naveen on 30-dec_2025
        terminal = tk.Text(parent,
                         width=width,
                         height=height,
                         bg="#000000",
                         fg=colors['matrix_green'],
                         font=("Courier New", 10),
                         relief='flat',
                         bd=1,
                         insertbackground=colors['matrix_green'],
                         selectbackground=colors['accent_bg'],
                         selectforeground=colors['primary_text'],
                         highlightbackground=colors['border_color'],
                         highlightcolor=colors['focus_border'],
                         highlightthickness=1)
        
        return terminal

# added by naveen on 15-jan_2026
'''

# Write the GUI themes module
with open("gui_themes.py", "w") as f:
    f.write(gui_themes)

print("✅ GUI themes module created successfully!")
print("Theme features included:")
print("  • Cybersecurity dark theme")
print("  • Professional color palette")
print("  • Styled widgets (buttons, entries, text)")
print("  • Animation effects")
print("  • Status indicators")
print("  • Terminal-style outputs")
print("  • Matrix rain effects")
print("  • LED indicators")