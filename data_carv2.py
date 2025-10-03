import os
import re
import json
import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext
from tkinter import ttk
import threading
from datetime import datetime
import hashlib

# --------------------- Enhanced File Signatures ---------------------
FILE_TYPES = {
    "JPEG": {"header": b'\xff\xd8\xff', "footer": b'\xff\xd9', "ext": ".jpg"},
    "PNG": {"header": b'\x89PNG\r\n\x1a\n', "footer": b'IEND\xaeB`\x82', "ext": ".png"},
    "PDF": {"header": b'%PDF-', "footer": b'%%EOF', "ext": ".pdf"},
    "ZIP": {"header": b'PK\x03\x04', "footer": b'PK\x05\x06', "ext": ".zip"},
    "GIF": {"header": b'GIF87a', "footer": b'\x00\x3b', "ext": ".gif"},
    "MP3": {"header": b'\xff\xfb', "footer": None, "ext": ".mp3"}  # MP3 has no fixed footer
}

# --------------------- Enhanced Carving Function ---------------------
def calculate_file_hash(file_path):
    """Calculate MD5 hash of a file"""
    hash_md5 = hashlib.md5()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_md5.update(chunk)
    return hash_md5.hexdigest()

def carve_file(file_path, output_dir, progress_callback=None, file_types=None):
    recovered_files = []
    file_count = {ftype: 1 for ftype in FILE_TYPES.keys()}
    try:
        file_size = os.path.getsize(file_path)
        with open(file_path, 'rb') as f:
            data = f.read()
        types_to_process = file_types if file_types else FILE_TYPES.keys()
        total_types = len(types_to_process)
        for i, ftype in enumerate(types_to_process):
            sig = FILE_TYPES[ftype]
            header = sig['header']
            footer = sig['footer']
            
            if ftype == 'ZIP':
                # Improved ZIP carving: from header to last footer after header
                start = 0
                while True:
                    header_idx = data.find(header, start)
                    if header_idx == -1:
                        break
                    # Find the last footer after this header
                    search_from = header_idx + len(header)
                    last_footer_idx = -1
                    next_header_idx = data.find(header, search_from)
                    search_to = next_header_idx if next_header_idx != -1 else len(data)
                    idx = search_from
                    while True:
                        idx = data.find(footer, idx, search_to)
                        if idx == -1:
                            break
                        last_footer_idx = idx
                        idx += 1
                    if last_footer_idx != -1:
                        end_idx = last_footer_idx + len(footer)
                        carved_data = data[header_idx:end_idx]
                        output_name = f"{ftype}_{file_count[ftype]:03d}{sig['ext']}"
                        output_path = os.path.join(output_dir, output_name)
                        with open(output_path, 'wb') as out_file:
                            out_file.write(carved_data)
                        file_hash = calculate_file_hash(output_path)
                        recovered_files.append({
                            "file_name": output_name,
                            "file_type": ftype,
                            "start_offset": header_idx,
                            "end_offset": end_idx,
                            "size": end_idx - header_idx,
                            "md5_hash": file_hash,
                            "recovery_time": datetime.now().isoformat(),
                            "source_file": os.path.basename(file_path)
                        })
                        file_count[ftype] += 1
                        start = end_idx
                    else:
                        # No footer found, skip to next header
                        start = search_from
            else:
                # Handle files without fixed footers (like MP3)
                if footer:
                    pattern = re.compile(re.escape(header) + b'.*?' + re.escape(footer), re.DOTALL)
                else:
                    # For files without footers, look for next header or end of data or next header of any other selected type
                    other_headers = b'|'.join([re.escape(FILE_TYPES[t]['header']) for t in types_to_process if t != ftype])
                    if other_headers:
                        pattern = re.compile(re.escape(header) + b'.*?(?=' + other_headers + b'|$)', re.DOTALL)
                    else:
                        pattern = re.compile(re.escape(header) + b'.*?$', re.DOTALL)
                
                matches = pattern.finditer(data)
                
                for match in matches:
                    output_name = f"{ftype}_{file_count[ftype]:03d}{sig['ext']}"
                    output_path = os.path.join(output_dir, output_name)
                    
                    with open(output_path, 'wb') as out_file:
                        out_file.write(match.group())
                    
                    # Calculate file hash
                    file_hash = calculate_file_hash(output_path)
                    
                    recovered_files.append({
                        "file_name": output_name,
                        "file_type": ftype,
                        "start_offset": match.start(),
                        "end_offset": match.end(),
                        "size": match.end() - match.start(),
                        "md5_hash": file_hash,
                        "recovery_time": datetime.now().isoformat(),
                        "source_file": os.path.basename(file_path)
                    })
                    file_count[ftype] += 1
            
            if progress_callback:
                progress_callback((i + 1) / total_types * 50)  # 50% for file type processing
                
    except Exception as e:
        return recovered_files, str(e)
    
    return recovered_files, None

# --------------------- Enhanced Batch Processing ---------------------
def carve_batch(input_paths, output_dir, progress_callback=None, status_callback=None, file_types=None):
    all_recovered = []
    errors = []
    
    for idx, path in enumerate(input_paths):
        if status_callback:
            status_callback(f"Processing: {os.path.basename(path)}")
            
        if os.path.isfile(path):
            recovered, error = carve_file(path, output_dir, 
                                        lambda p: progress_callback(p * 0.5 + idx/len(input_paths)*50) 
                                        if progress_callback else None,
                                        file_types)
            all_recovered.extend(recovered)
            if error:
                errors.append(f"{os.path.basename(path)}: {error}")
        
        if progress_callback:
            progress_callback((idx + 1) / len(input_paths) * 100)
    
    # Save enhanced log with metadata
    log_data = {
        "recovery_session": {
            "timestamp": datetime.now().isoformat(),
            "total_files_recovered": len(all_recovered),
            "input_files_processed": len(input_paths),
            "errors_encountered": errors
        },
        "recovered_files": all_recovered
    }
    
    log_path = os.path.join(output_dir, f'recovery_log_{datetime.now().strftime("%Y%m%d_%H%M%S")}.json')
    with open(log_path, 'w') as log_file:
        json.dump(log_data, log_file, indent=4)
    
    return all_recovered, errors

# --------------------- Enhanced GUI ---------------------
class AdvancedDataCarverGUI:
    def get_selected_file_types(self):
        """Return a list of file types selected by the user."""
        return [ftype for ftype, var in self.file_type_vars.items() if var.get()]
    def __init__(self, root):
        self.root = root
        self.root.title("🔍 Advanced Data Carving Tool - Digital Forensics")
        self.root.geometry("900x700")
        self.root.configure(bg='#f0f0f0')
        
        # Style configuration
        self.style = ttk.Style()
        self.style.configure('TFrame', background='#f0f0f0')
        self.style.configure('TLabel', background='#f0f0f0', font=('Arial', 10))
        self.style.configure('Title.TLabel', background='#f0f0f0', font=('Arial', 14, 'bold'))
        self.style.configure('Action.TButton', font=('Arial', 10, 'bold'))
        
        # Main container
        main_frame = ttk.Frame(root, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Title
        title_label = ttk.Label(main_frame, text="Advanced Data Carving Tool", style='Title.TLabel')
        title_label.pack(pady=(0, 20))
        
        # Create notebook for tabs
        self.notebook = ttk.Notebook(main_frame)
        self.notebook.pack(fill=tk.BOTH, expand=True)
        
        # Carving Tab
        self.carving_frame = ttk.Frame(self.notebook, padding="10")
        self.notebook.add(self.carving_frame, text="📁 File Carving")
        
        # Settings Tab
        self.settings_frame = ttk.Frame(self.notebook, padding="10")
        self.notebook.add(self.settings_frame, text="⚙️ Settings")
        
        self.setup_carving_tab()
        self.setup_settings_tab()
        
        # Initialize variables
        self.input_paths = []
        self.output_dir = ""
        self.is_processing = False

    def setup_carving_tab(self):
        # File selection section
        selection_frame = ttk.LabelFrame(self.carving_frame, text="Input Selection", padding="10")
        selection_frame.pack(fill=tk.X, pady=(0, 10))
        
        ttk.Button(selection_frame, text="📂 Select Files", 
                  command=self.browse_files, style='Action.TButton').pack(side=tk.LEFT, padx=(0, 10))
        ttk.Button(selection_frame, text="📁 Select Folder", 
                  command=self.browse_folder, style='Action.TButton').pack(side=tk.LEFT, padx=(0, 10))
        ttk.Button(selection_frame, text="🗂️ Select Output", 
                  command=self.browse_output, style='Action.TButton').pack(side=tk.LEFT)
        
        self.selected_files_label = ttk.Label(selection_frame, text="No files selected")
        self.selected_files_label.pack(side=tk.RIGHT)
        
        # File type selection
        type_frame = ttk.LabelFrame(self.carving_frame, text="File Types to Recover", padding="10")
        type_frame.pack(fill=tk.X, pady=(0, 10))
        
        self.file_type_vars = {}
        for ftype in FILE_TYPES.keys():
            var = tk.BooleanVar(value=True)
            self.file_type_vars[ftype] = var
            cb = ttk.Checkbutton(type_frame, text=ftype, variable=var)
            cb.pack(side=tk.LEFT, padx=(0, 15))
        
        # Progress section
        progress_frame = ttk.LabelFrame(self.carving_frame, text="Recovery Progress", padding="10")
        progress_frame.pack(fill=tk.X, pady=(0, 10))
        
        self.progress = ttk.Progressbar(progress_frame, length=500, mode='determinate')
        self.progress.pack(fill=tk.X, pady=5)
        
        self.status_label = ttk.Label(progress_frame, text="Ready to start recovery")
        self.status_label.pack()
        
        # Action buttons
        button_frame = ttk.Frame(self.carving_frame)
        button_frame.pack(fill=tk.X, pady=10)
        
        self.start_btn = ttk.Button(button_frame, text="🚀 Start Recovery", 
                                   command=self.start_recovery, style='Action.TButton')
        self.start_btn.pack(side=tk.LEFT, padx=(0, 10))
        
        ttk.Button(button_frame, text="🗑️ Clear Results", 
                  command=self.clear_results).pack(side=tk.LEFT)
        
        # Results section
        results_frame = ttk.LabelFrame(self.carving_frame, text="Recovery Results", padding="10")
        results_frame.pack(fill=tk.BOTH, expand=True)
        
        # Treeview for results
        columns = ("File Name", "Type", "Size", "MD5 Hash", "Status")
        self.results_tree = ttk.Treeview(results_frame, columns=columns, show="headings", height=15)
        
        for col in columns:
            self.results_tree.heading(col, text=col)
            self.results_tree.column(col, width=120)
        
        self.results_tree.column("File Name", width=200)
        self.results_tree.column("MD5 Hash", width=250)
        
        # Scrollbar for treeview
        scrollbar = ttk.Scrollbar(results_frame, orient=tk.VERTICAL, command=self.results_tree.yview)
        self.results_tree.configure(yscrollcommand=scrollbar.set)
        self.results_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Double-click to open file location
        self.results_tree.bind("<Double-1>", self.open_file_location)

    def setup_settings_tab(self):
        # Settings content
        ttk.Label(self.settings_frame, text="Recovery Settings", font=('Arial', 12, 'bold')).pack(anchor=tk.W)
        
        # Chunk size setting
        chunk_frame = ttk.Frame(self.settings_frame)
        chunk_frame.pack(fill=tk.X, pady=10)
        ttk.Label(chunk_frame, text="Processing chunk size (MB):").pack(side=tk.LEFT)
        self.chunk_size = ttk.Combobox(chunk_frame, values=["1", "5", "10", "50"], state="readonly")
        self.chunk_size.set("1")
        self.chunk_size.pack(side=tk.LEFT, padx=(10, 0))
        
        # About section
        about_frame = ttk.LabelFrame(self.settings_frame, text="About", padding="10")
        about_frame.pack(fill=tk.X, pady=20)
        
        about_text = """Advanced Data Carving Tool v2.0
       
Features:
- Multiple file type support (JPEG, PNG, PDF, ZIP, GIF, MP3)
- Batch processing capabilities
- MD5 hash verification
- Detailed recovery logging
- Professional GUI interface
- Error handling and reporting

Designed for Digital Forensics and Cybersecurity education."""
        
        about_label = ttk.Label(about_frame, text=about_text, justify=tk.LEFT)
        about_label.pack(anchor=tk.W)

    def browse_files(self):
        files = filedialog.askopenfilenames(title="Select Files for Carving")
        if files:
            self.input_paths = list(files)
            self.selected_files_label.config(text=f"{len(self.input_paths)} files selected")

    def browse_folder(self):
        folder = filedialog.askdirectory(title="Select Folder for Batch Processing")
        if folder:
            self.input_paths = [os.path.join(folder, f) for f in os.listdir(folder) 
                              if os.path.isfile(os.path.join(folder, f))]
            self.selected_files_label.config(text=f"Folder: {os.path.basename(folder)} ({len(self.input_paths)} files)")

    def browse_output(self):
        self.output_dir = filedialog.askdirectory(title="Select Output Directory")
        if self.output_dir:
            messagebox.showinfo("Output Folder", f"Output directory set to:\n{self.output_dir}")

    def start_recovery(self):
        if not self.input_paths or not self.output_dir:
            messagebox.showerror("Error", "Please select input files/folder and output directory")
            return
        if self.is_processing:
            return
        self.is_processing = True
        self.start_btn.config(state="disabled")
        self.clear_results()
        self.selected_types = self.get_selected_file_types()
        if not self.selected_types:
            messagebox.showerror("Error", "Please select at least one file type to recover.")
            self.is_processing = False
            self.start_btn.config(state="normal")
            return
        # Start processing in separate thread
        thread = threading.Thread(target=self.process_files)
        thread.daemon = True
        thread.start()

    def process_files(self):
        try:
            def update_progress(value):
                self.progress['value'] = value
                self.root.update_idletasks()
            
            def update_status(text):
                self.status_label.config(text=text)
                self.root.update_idletasks()
            
            recovered_files, errors = carve_batch(
                self.input_paths, 
                self.output_dir, 
                update_progress, 
                update_status,
                self.selected_types
            )
            
            # Update results
            for file_info in recovered_files:
                self.results_tree.insert("", "end", values=(
                    file_info["file_name"],
                    file_info["file_type"],
                    f"{file_info['size']:,} bytes",
                    file_info["md5_hash"],
                    "✅ Recovered"
                ))
            
            # Show completion message
            messagebox.showinfo("Recovery Completed", 
                              f"Successfully recovered {len(recovered_files)} files!\n"
                              f"Errors: {len(errors)}")
            
            if errors:
                update_status(f"Completed with {len(errors)} errors")
            else:
                update_status("Recovery completed successfully!")
                
        except Exception as e:
            messagebox.showerror("Error", f"An error occurred during processing:\n{str(e)}")
            self.status_label.config(text="Recovery failed")
        finally:
            self.is_processing = False
            self.start_btn.config(state="normal")
            self.progress['value'] = 0

    def clear_results(self):
        for item in self.results_tree.get_children():
            self.results_tree.delete(item)

    def open_file_location(self, event):
        selection = self.results_tree.selection()
        if selection:
            item = self.results_tree.item(selection[0])
            filename = item['values'][0]
            filepath = os.path.join(self.output_dir, filename)
            if os.path.exists(filepath):
                os.startfile(self.output_dir)  # Opens folder in Windows
            else:
                messagebox.showwarning("File Not Found", "The recovered file is not available.")
    

# --------------------- Run Enhanced GUI ---------------------
if __name__ == "__main__":
    root = tk.Tk()
    app = AdvancedDataCarverGUI(root)
    root.mainloop()