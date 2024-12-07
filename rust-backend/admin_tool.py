import sqlite3
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
            value INTEGER
        )
        """)
        conn.commit()

# Load all keys from the database
def load_key_data():
    with sqlite3.connect(DATABASE_FILE) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT key, value FROM keys")
        return cursor.fetchall()

# Save a key-value pair to the database
def save_key(key, value):
    with sqlite3.connect(DATABASE_FILE) as conn:
        cursor = conn.cursor()
        cursor.execute("""
        INSERT INTO keys (key, value)
        VALUES (?, ?)
        ON CONFLICT(key) DO UPDATE SET value = excluded.value
        """, (key, value))
        conn.commit()

# Remove a key from the database
def remove_key(key):
    with sqlite3.connect(DATABASE_FILE) as conn:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM keys WHERE key = ?", (key,))
        conn.commit()

# GUI Application
class KeyManagerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Key Manager")
        
        # Key-Value Entry Frame
        self.entry_frame = ttk.Frame(root)
        self.entry_frame.pack(pady=10)
        
        ttk.Label(self.entry_frame, text="Key:").grid(row=0, column=0, padx=5, pady=5)
        self.key_entry = ttk.Entry(self.entry_frame, width=20)
        self.key_entry.grid(row=0, column=1, padx=5, pady=5)
        
        ttk.Label(self.entry_frame, text="Expiry Date:").grid(row=1, column=0, padx=5, pady=5)
        self.value_entry = ttk.Entry(self.entry_frame, width=20)
        self.value_entry.grid(row=1, column=1, padx=5, pady=5)
        
        # Buttons
        self.add_button = ttk.Button(self.entry_frame, text="Add/Update", command=self.add_update_key)
        self.add_button.grid(row=2, column=0, columnspan=2, pady=10)
        
        self.delete_button = ttk.Button(self.entry_frame, text="Delete", command=self.delete_key)
        self.delete_button.grid(row=3, column=0, columnspan=2, pady=10)
        
        # Data Display Frame
        self.data_frame = ttk.Frame(root)
        self.data_frame.pack(pady=10, fill=tk.BOTH, expand=True)
        
        self.tree = ttk.Treeview(self.data_frame, columns=("key", "value"), show="headings")
        self.tree.heading("key", text="Key")
        self.tree.heading("value", text="Expiry Date")
        self.tree.pack(fill=tk.BOTH, expand=True)
        
        # Populate data
        self.refresh_tree()

    def refresh_tree(self):
        """Refresh the data displayed in the tree view."""
        for row in self.tree.get_children():
            self.tree.delete(row)
        for key, value in load_key_data():
            self.tree.insert("", tk.END, values=(key, value))
    
    def add_update_key(self):
        """Add or update a key-value pair in the database."""
        key = self.key_entry.get().strip()
        value = self.value_entry.get().strip()
        
        if not key or not value:
            messagebox.showwarning("Input Error", "Key and Value must not be empty.")
            return
        
        try:
            value = int(value)
        except ValueError:
            messagebox.showwarning("Input Error", "Value must be an integer.")
            return
        
        save_key(key, value)
        self.refresh_tree()
        messagebox.showinfo("Success", f"Key '{key}' updated successfully.")
    
    def delete_key(self):
        """Delete the selected key from the database."""
        selected_item = self.tree.selection()
        if not selected_item:
            messagebox.showwarning("Selection Error", "No item selected.")
            return
        
        key = self.tree.item(selected_item, "values")[0]
        remove_key(key)
        self.refresh_tree()
        messagebox.showinfo("Success", f"Key '{key}' deleted successfully.")

# Main Function
if __name__ == "__main__":
    initialize_database()
    root = tk.Tk()
    app = KeyManagerApp(root)
    root.mainloop()
