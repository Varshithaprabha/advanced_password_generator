import tkinter as tk
from tkinter import messagebox
import random
import string

class PasswordGenerator:
    def __init__(self, master):
        self.master = master
        master.title("Random Password Generator")

        self.length_label = tk.Label(master, text="Password Length:")
        self.length_label.pack()

        self.length_entry = tk.Entry(master)
        self.length_entry.pack()

        self.include_lowercase = tk.BooleanVar(value=True)
        self.include_uppercase = tk.BooleanVar(value=True)
        self.include_digits = tk.BooleanVar(value=True)
        self.include_special = tk.BooleanVar(value=True)

        self.lowercase_checkbox = tk.Checkbutton(master, text="Include Lowercase Letters", variable=self.include_lowercase)
        self.lowercase_checkbox.pack()

        self.uppercase_checkbox = tk.Checkbutton(master, text="Include Uppercase Letters", variable=self.include_uppercase)
        self.uppercase_checkbox.pack()

        self.digits_checkbox = tk.Checkbutton(master, text="Include Digits", variable=self.include_digits)
        self.digits_checkbox.pack()

        self.special_checkbox = tk.Checkbutton(master, text="Include Special Characters", variable=self.include_special)
        self.special_checkbox.pack()

        self.generate_button = tk.Button(master, text="Generate Password", command=self.generate_password)
        self.generate_button.pack()

        self.password_label = tk.Label(master, text="")
        self.password_label.pack()

        self.copy_button = tk.Button(master, text="Copy to Clipboard", command=self.copy_to_clipboard)
        self.copy_button.pack()

    def generate_password(self):
        length = self.length_entry.get()
        if not length.isdigit() or int(length) <= 0:
            messagebox.showerror("Input Error", "Please enter a valid password length greater than 0.")
            return

        length = int(length)
        characters = ""

        if self.include_lowercase.get():
            characters += string.ascii_lowercase
        if self.include_uppercase.get():
            characters += string.ascii_uppercase
        if self.include_digits.get():
            characters += string.digits
        if self.include_special.get():
            characters += string.punctuation

        if not characters:
            messagebox.showerror("Input Error", "Please select at least one character set.")
            return

        password = ''.join(random.choice(characters) for _ in range(length))
        self.password_label.config(text=f"Generated Password: {password}")

    def copy_to_clipboard(self):
        password = self.password_label.cget("text").replace("Generated Password: ", "")
        if password:
            self.master.clipboard_clear()
            self.master.clipboard_append(password)
            messagebox.showinfo("Copied", "Password copied to clipboard!")

# Run the application
if __name__ == "__main__":
    root = tk.Tk()
    password_generator = PasswordGenerator(root)
    root.mainloop()
