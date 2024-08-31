import tkinter as tk
from tkinter import ttk, messagebox

# Kategorien und NSE-Skripte
nse_scripts = {
    "Standard Scripts": ["http-vuln-cve2017-5638", "smb-vuln-ms17-010", "ssl-heartbleed", "smb-vuln-ms08-067", "smb-vuln-ms10-061", "SCRIPT"],
    "Vulnerability Detection": ["http-vuln-cve2013-7091", "http-vuln-cve2014-3704", "http-vuln-cve2014-0160", "ssl-poodle", "rdp-vuln-ms12-020", "ssl-known-key"],
    "Enumeration": ["smb-enum-shares", "smb-enum-users", "dns-brute", "http-enum", "http-title", "snmp-info"],
    "Brute Force": ["smb-brute", "ssh-brute", "http-brute", "ftp-brute", "snmp-brute", "telnet-brute", "smtp-brute"],
    "Authentication and Credentials": ["ftp-anon", "ssh-auth-methods", "smb-security-mode", "mysql-empty-password"],
    "Web Exploitation": ["http-sql-injection", "http-xssed", "http-phpmyadmin-dir-traversal", "http-open-proxy", "http-backup-finder"],
    "Service Detection": ["ssl-cert", "nbstat", "smb-os-discovery", "snmp-info", "ssh-hostkey"],
    "Miscellaneous": ["vulners", "vulscan", "firewalk", "dns-recursion"]
}

def update_nse_scripts(event):
    category = nse_category_combobox.get()
    scripts = nse_scripts.get(category, [])
    nse_script_combobox['values'] = scripts
    if scripts:
        nse_script_combobox.set(scripts[0])

def update_port_entry(event):
    selected_option = port_option_combobox.get()
    if selected_option == "Manuelle Eingabe":
        port_entry.config(state='normal')
    elif selected_option == "Top 1000 Ports":
        port_entry.config(state='disabled')
        port_entry.delete(0, tk.END)
        port_entry.insert(0, "Top 1000 Ports")
    elif selected_option == "Alle Ports":
        port_entry.config(state='disabled')
        port_entry.delete(0, tk.END)
        port_entry.insert(0, "1-65535")

def update_timeout_label(value):
    timeout_label.config(text=f"Timeout (Sekunden): {int(float(value))}")

def generate_command():
    ip = ip_entry.get()
    selected_port_option = port_option_combobox.get()
    ports = port_entry.get() if selected_port_option == "Manuelle Eingabe" else ("-F" if selected_port_option == "Top 1000 Ports" else "-p 1-65535")
    selected_nse_script = nse_script_combobox.get()
    timeout = timeout_scale.get()

    # Weitere Optionen
    scan_os = os_var.get()
    service_detection = service_var.get()

    # Beispielhafter Nmap-Befehl
    command = f"nmap {ports} --script {selected_nse_script} --host-timeout {int(timeout)}s {ip}"

    # Zusätzliche Optionen hinzufügen
    if scan_os:
        command += " -O"
    if service_detection:
        command += " -sV"
    
    # Berechnung der Stärke (vereinfachtes Beispiel)
    strength = len(command) + 20 * scan_os + 20 * service_detection
    if strength < 100:
        strength_label.config(background="green", text="Stärke: Grün (Niedrig)")
    elif strength < 150:
        strength_label.config(background="orange", text="Stärke: Orange (Mittel)")
    else:
        strength_label.config(background="red", text="Stärke: Rot (Hoch)")

    command_output.config(state='normal')
    command_output.delete(1.0, tk.END)
    command_output.insert(tk.END, command)
    command_output.config(state='disabled')

def copy_to_clipboard():
    # Holen Sie sich den Befehl aus dem Textfeld
    command = command_output.get(1.0, tk.END).strip()
    
    # Kopieren Sie den Befehl in die Zwischenablage
    root.clipboard_clear()  # Löschen Sie den aktuellen Inhalt der Zwischenablage
    root.clipboard_append(command)  # Fügen Sie den neuen Inhalt hinzu
    root.update()  # Aktualisieren Sie das Fenster, um sicherzustellen, dass die Zwischenablage aktualisiert wird

    messagebox.showinfo("Kopiert", "Der Befehl wurde in die Zwischenablage kopiert.")

# Hauptfenster
root = tk.Tk()
root.title("Nmap GUI Tool")
root.geometry("600x500")
root.resizable(True, True)

# Styling
style = ttk.Style()
style.theme_use('clam')
style.configure('TLabel', font=('Helvetica', 11), background="#f0f0f0")
style.configure('TButton', font=('Helvetica', 11), padding=6)
style.configure('TCombobox', font=('Helvetica', 11))
style.configure('TCheckbutton', font=('Helvetica', 11))

main_frame = ttk.Frame(root, padding=(10, 10, 10, 10))
main_frame.grid(row=0, column=0, sticky="nsew")

root.columnconfigure(0, weight=1)
root.rowconfigure(0, weight=1)

# Widgets
ttk.Label(main_frame, text="Target IP:").grid(row=0, column=0, padx=10, pady=5, sticky='w')
ip_entry = ttk.Entry(main_frame)
ip_entry.grid(row=0, column=1, padx=10, pady=5, sticky='ew')

ttk.Label(main_frame, text="Ports:").grid(row=1, column=0, padx=10, pady=5, sticky='w')
port_option_combobox = ttk.Combobox(main_frame, values=["Manuelle Eingabe", "Top 1000 Ports", "Alle Ports"], state='readonly')
port_option_combobox.grid(row=1, column=1, padx=10, pady=5, sticky='ew')
port_option_combobox.bind("<<ComboboxSelected>>", update_port_entry)

port_entry = ttk.Entry(main_frame)
port_entry.grid(row=2, column=1, padx=10, pady=5, sticky='ew')

ttk.Label(main_frame, text="NSE Script Kategorie:").grid(row=3, column=0, padx=10, pady=5, sticky='w')
nse_category_combobox = ttk.Combobox(main_frame, values=list(nse_scripts.keys()), state='readonly')
nse_category_combobox.grid(row=3, column=1, padx=10, pady=5, sticky='ew')
nse_category_combobox.bind("<<ComboboxSelected>>", update_nse_scripts)

ttk.Label(main_frame, text="NSE Script:").grid(row=4, column=0, padx=10, pady=5, sticky='w')
nse_script_combobox = ttk.Combobox(main_frame, state='readonly')
nse_script_combobox.grid(row=4, column=1, padx=10, pady=5, sticky='ew')

timeout_label = ttk.Label(main_frame, text="Timeout (Sekunden): 10")
timeout_label.grid(row=5, column=0, padx=10, pady=5, sticky='w')
timeout_scale = ttk.Scale(main_frame, from_=10, to=1000, orient=tk.HORIZONTAL, command=update_timeout_label)
timeout_scale.set(10)
timeout_scale.grid(row=5, column=1, padx=10, pady=5, sticky='ew')

# Weitere Optionen
os_var = tk.IntVar()
ttk.Checkbutton(main_frame, text="OS-Scan (-O)", variable=os_var).grid(row=6, column=0, columnspan=2, sticky='w', padx=10, pady=5)

service_var = tk.IntVar()
ttk.Checkbutton(main_frame, text="Service-Erkennung (-sV)", variable=service_var).grid(row=7, column=0, columnspan=2, sticky='w', padx=10, pady=5)

generate_button = ttk.Button(main_frame, text="Befehl Generieren", command=generate_command)
generate_button.grid(row=8, column=0, columnspan=2, pady=10, sticky='ew')

command_output = tk.Text(main_frame, height=4, width=50, state='disabled', font=('Helvetica', 10))
command_output.grid(row=9, column=0, columnspan=2, padx=10, pady=5, sticky='ew')

copy_button = ttk.Button(main_frame, text="In Zwischenablage kopieren", command=copy_to_clipboard)
copy_button.grid(row=10, column=0, columnspan=2, pady=10, sticky='ew')

strength_label = ttk.Label(main_frame, text="Stärke: ", background="white")
strength_label.grid(row=11, column=0, columnspan=2, pady=5, sticky='ew')

# Grid column configuration for responsiveness
for i in range(2):
    main_frame.columnconfigure(i, weight=1)

root.mainloop()
