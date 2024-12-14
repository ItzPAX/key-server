import sqlite3
import threading
import time
import tkinter as tk
from tkinter import ttk, messagebox

# Database file path
DATABASE_FILE = "keys.db"

# Initialize the database
def initialize_database():
    """Create the database table if it doesn't exist."""
    with sqlite3.connect(DATABASE_FILE) as conn:
        cursor = conn.cursor()
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS keys (
            key TEXT PRIMARY KEY,
            value INTEGER,
            hwid TEXT
        )
        """)
        conn.commit()

# Load all keys from the database
def load_key_data():
    with sqlite3.connect(DATABASE_FILE) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT key, duration, hwid FROM keys")
        return cursor.fetchall()

# Save a key-value-hwid triple to the database
def save_key(key, value, hwid):
    with sqlite3.connect(DATABASE_FILE) as conn:
        cursor = conn.cursor()
        cursor.execute("""
        INSERT INTO keys (key, duration, hwid)
        VALUES (?, ?, ?)
        ON CONFLICT(key) DO UPDATE SET duration = excluded.duration, hwid = excluded.hwid
        """, (key, value, hwid))
        conn.commit()

# Remove a key from the database
def remove_key(key):
    with sqlite3.connect(DATABASE_FILE) as conn:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM keys WHERE key = ?", (key,))
        conn.commit()

# wrapper to run the background functions
def run_periodically(interval, func):
    def wrapper():
        while True:
            func()
            time.sleep(interval)
    
    thread = threading.Thread(target=wrapper, daemon=True)
    thread.start()

# GUI Application
class KeyManagerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Key Manager")
        
        # Key-Value-HWID Entry Frame
        self.entry_frame = ttk.Frame(root)
        self.entry_frame.pack(pady=10)
        
        # Key Entry
        ttk.Label(self.entry_frame, text="Key:").grid(row=0, column=0, padx=5, pady=5, sticky=tk.E)
        self.key_entry = ttk.Entry(self.entry_frame, width=25)
        self.key_entry.grid(row=0, column=1, padx=5, pady=5)
        
        # Value Entry (e.g., Expiry Date or Duration)
        ttk.Label(self.entry_frame, text="Expiry Date:").grid(row=1, column=0, padx=5, pady=5, sticky=tk.E)
        self.value_entry = ttk.Entry(self.entry_frame, width=25)
        self.value_entry.grid(row=1, column=1, padx=5, pady=5)
        
        # HWID Entry
        ttk.Label(self.entry_frame, text="HWID:").grid(row=2, column=0, padx=5, pady=5, sticky=tk.E)
        self.hwid_entry = ttk.Entry(self.entry_frame, width=25)
        self.hwid_entry.grid(row=2, column=1, padx=5, pady=5)
        
        # Buttons
        self.add_button = ttk.Button(self.entry_frame, text="Add/Update", command=self.add_update_key)
        self.add_button.grid(row=3, column=0, columnspan=2, pady=10)
        
        self.delete_button = ttk.Button(self.entry_frame, text="Delete", command=self.delete_key)
        self.delete_button.grid(row=4, column=0, columnspan=2, pady=10)
        
        # Data Display Frame
        self.data_frame = ttk.Frame(root)
        self.data_frame.pack(pady=10, fill=tk.BOTH, expand=True)
        
        # Configure Treeview
        self.tree = ttk.Treeview(self.data_frame, columns=("key", "duration", "hwid"), show="headings")
        self.tree.heading("key", text="Key")
        self.tree.heading("duration", text="Expiry Date")
        self.tree.heading("hwid", text="HWID")
        self.tree.column("key", width=150)
        self.tree.column("duration", width=150)
        self.tree.column("hwid", width=200)
        self.tree.pack(fill=tk.BOTH, expand=True)
        
        # Add vertical scrollbar to the Treeview
        self.scrollbar = ttk.Scrollbar(self.data_frame, orient=tk.VERTICAL, command=self.tree.yview)
        self.tree.configure(yscroll=self.scrollbar.set)
        self.scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Populate data
        self.refresh_tree()

    def refresh_tree(self):
        """Refresh the data displayed in the tree view."""
        for row in self.tree.get_children():
            self.tree.delete(row)
        for key, value, hwid in load_key_data():
            self.tree.insert("", tk.END, values=(key, value, hwid))
    
    def add_update_key(self):
        """Add or update a key-value-hwid triple in the database."""
        key = self.key_entry.get().strip()
        value = self.value_entry.get().strip()
        hwid = self.hwid_entry.get().strip()
        
        if not key or not value:
            messagebox.showwarning("Input Error", "Key, Expiry Date, and HWID must not be empty.")
            return
        
        try:
            value = int(value)
        except ValueError:
            messagebox.showwarning("Input Error", "Expiry Date must be an integer (e.g., duration in seconds).")
            return
        
        save_key(key, value, hwid)
        self.refresh_tree()
        messagebox.showinfo("Success", f"Key '{key}' updated successfully.")
        
        # Clear input fields after successful addition/update
        self.key_entry.delete(0, tk.END)
        self.value_entry.delete(0, tk.END)
        self.hwid_entry.delete(0, tk.END)
    
    def delete_key(self):
        """Delete the selected key from the database."""
        selected_item = self.tree.selection()
        if not selected_item:
            messagebox.showwarning("Selection Error", "No item selected.")
            return
        
        key = self.tree.item(selected_item, "values")[0]
        
        confirm = messagebox.askyesno("Confirm Deletion", f"Are you sure you want to delete key '{key}'?")
        if not confirm:
            return
        
        remove_key(key)
        self.refresh_tree()
        messagebox.showinfo("Success", f"Key '{key}' deleted successfully.")

# Main Function
if __name__ == "__main__":
    initialize_database()
    root = tk.Tk()
    app = KeyManagerApp(root)
    root.mainloop()

    run_periodically(1, app.refresh_tree)
