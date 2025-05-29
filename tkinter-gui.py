import tkinter as tk
from tkinter import scrolledtext, messagebox
import subprocess
import threading
import json

class C2ScannerGUI:
    def __init__(self, master):
        self.master = master
        master.title("Scanner de Menaces C2 - Zgrab2")

        # Entrées utilisateur
        tk.Label(master, text="Cible (IP ou Domaine):").grid(row=0, column=0, sticky='w')
        self.target_entry = tk.Entry(master, width=40)
        self.target_entry.grid(row=0, column=1)

        tk.Label(master, text="Port (ex: 80, 443):").grid(row=1, column=0, sticky='w')
        self.port_entry = tk.Entry(master, width=10)
        self.port_entry.grid(row=1, column=1, sticky='w')

        # Bouton de scan
        self.scan_button = tk.Button(master, text="Lancer le scan", command=self.start_scan_thread)
        self.scan_button.grid(row=2, column=0, columnspan=2, pady=10)

        # Zone de résultats
        tk.Label(master, text="Résultats:").grid(row=3, column=0, sticky='nw')
        self.result_box = scrolledtext.ScrolledText(master, height=20, width=80)
        self.result_box.grid(row=4, column=0, columnspan=2)

    def start_scan_thread(self):
        threading.Thread(target=self.run_scan, daemon=True).start()

    def run_scan(self):
        target = self.target_entry.get().strip()
        port = self.port_entry.get().strip()

        if not target or not port:
            messagebox.showerror("Erreur", "Veuillez entrer une cible et un port.")
            return

        self.result_box.insert(tk.END, f"⏳ Scan en cours sur {target}:{port}...\n")
        self.result_box.see(tk.END)

        # Préparer la commande zgrab2 (HTTP ici comme exemple)
        cmd = [
            "zgrab2",
            "--senders=1",
            "--timeout=5",
            "--port", port,
            "http",
            "--endpoint", "/",
            "--method", "GET",
            "--domain", target
        ]

        try:
            proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            output = proc.stdout.strip()
            errors = proc.stderr.strip()

            if output:
                for line in output.splitlines():
                    try:
                        data = json.loads(line)
                        result = json.dumps(data, indent=2)
                        self.result_box.insert(tk.END, f"{result}\n")

                        # Détection simple de bannière C2
                        banner = data.get("data", {}).get("http", {}).get("response", {}).get("body", "")
                        if "c2" in banner.lower() or "rat" in banner.lower() or "implant" in banner.lower():
                            self.result_box.insert(tk.END, "⚠️  Menace potentielle C2 détectée dans la bannière HTTP !\n", "alert")

                    except json.JSONDecodeError:
                        self.result_box.insert(tk.END, f"🔧 Erreur de décodage JSON :\n{line}\n")
            else:
                self.result_box.insert(tk.END, f"Aucun résultat ou erreur : {errors}\n")
        except FileNotFoundError:
            self.result_box.insert(tk.END, "❌ zgrab2 n'est pas installé ou introuvable dans le PATH.\n")

        self.result_box.insert(tk.END, "-"*80 + "\n")
        self.result_box.see(tk.END)

# Lancement de l'application
if __name__ == "__main__":
    root = tk.Tk()
    app = C2ScannerGUI(root)
    root.mainloop()