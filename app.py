import json
import hashlib
import secrets
from dataclasses import dataclass, asdict
from pathlib import Path
from array import array
from typing import Optional, List, Dict

import tkinter as tk
from tkinter import ttk, messagebox, filedialog



# Data Models (Classes)


@dataclass
class Pet:
    pet_id: int
    name: str
    species: str
    age: int
    breed: str
    adoption_fee: float
    status: str
    notes: str = ""
    photo_path: str = ""

    def to_dict(self) -> dict:
        d = asdict(self)  
        d["display_label"] = f"#{self.pet_id} - {self.name} ({self.species})"
        return d


@dataclass
class User:
    username: str
    salt: str
    password_hash: str
    role: str  # "Admin" or "Staff"

    def to_dict(self) -> dict:
        return asdict(self)



# Business Logic 


class PetInventory:
    SPECIES_OPTIONS = ("Dog", "Cat", "Rabbit", "Bird", "Reptile", "Other")  
    STATUS_OPTIONS = ("Available", "Pending", "Adopted")  

    def __init__(self):
        self.pets: List[Pet] = []            
        self.by_id: Dict[int, Pet] = {}      
        self.id_pool = array("I")            
        self.next_id = 1

    def add_pet(self, name: str, species: str, age: int, breed: str,
                fee: float, status: str, notes: str = "", photo_path: str = "") -> Pet:
        pet = Pet(
            pet_id=self.next_id,
            name=name.strip(),
            species=species,
            age=age,
            breed=breed.strip(),
            adoption_fee=fee,
            status=status,
            notes=notes.strip(),
            photo_path=photo_path.strip()
        )
        self.next_id += 1
        self.pets.append(pet)
        self.by_id[pet.pet_id] = pet
        self.id_pool.append(pet.pet_id)
        return pet

    def update_pet(self, pet_id: int, **updates):
        pet = self.by_id.get(pet_id)
        if not pet:
            raise ValueError("Pet not found.")
        for k, v in updates.items():
            if hasattr(pet, k):
                setattr(pet, k, v)

    def delete_pet(self, pet_id: int):
        if pet_id not in self.by_id:
            return
        self.by_id.pop(pet_id)
        self.pets = [p for p in self.pets if p.pet_id != pet_id]

    def search(self, keyword: str) -> List[Pet]:
        kw = keyword.strip().lower()
        if not kw:
            return list(self.pets)
        out = []
        for p in self.pets:
            hay = f"{p.pet_id} {p.name} {p.species} {p.breed} {p.status} {p.notes}".lower()
            if kw in hay:
                out.append(p)
        return out

    def to_payload(self) -> dict:
        return {
            "total_pets": len(self.pets),
            "pets": [p.to_dict() for p in self.pets],
        }

    def load_payload(self, payload: dict):
        self.pets.clear()
        self.by_id.clear()
        self.id_pool = array("I")
        self.next_id = 1

        max_id = 0
        for item in payload.get("pets", []):
            pet = Pet(
                pet_id=int(item["pet_id"]),
                name=item["name"],
                species=item["species"],
                age=int(item["age"]),
                breed=item["breed"],
                adoption_fee=float(item["adoption_fee"]),
                status=item["status"],
                notes=item.get("notes", ""),
                photo_path=item.get("photo_path", ""),
            )
            self.pets.append(pet)
            self.by_id[pet.pet_id] = pet
            self.id_pool.append(pet.pet_id)
            max_id = max(max_id, pet.pet_id)

        self.next_id = max_id + 1


class UserManager:
    ROLES = ("Admin", "Staff")  

    def __init__(self):
        self.users: Dict[str, User] = {}  

    @staticmethod
    def _hash(password: str, salt: str) -> str:
        return hashlib.sha256((salt + password).encode("utf-8")).hexdigest()

    def add_user(self, username: str, password: str, role: str):
        u = username.strip().lower()
        if not u:
            raise ValueError("Username is required.")
        if u in self.users:
            raise ValueError("Username already exists.")
        if len(password) < 4:
            raise ValueError("Password must be at least 4 characters.")
        if role not in self.ROLES:
            raise ValueError("Invalid role.")

        salt = secrets.token_hex(8)
        pw_hash = self._hash(password, salt)
        self.users[u] = User(username=u, salt=salt, password_hash=pw_hash, role=role)

    def delete_user(self, username: str):
        u = username.strip().lower()
        if u in self.users:
            self.users.pop(u)

    def verify_login(self, username: str, password: str) -> bool:
        u = username.strip().lower()
        user = self.users.get(u)
        if not user:
            return False
        return self._hash(password, user.salt) == user.password_hash

    def get_user(self, username: str) -> Optional[User]:
        return self.users.get(username.strip().lower())

    def count_admins(self) -> int:
        return sum(1 for u in self.users.values() if u.role == "Admin")

    def to_payload(self) -> dict:
        return {"users": [u.to_dict() for u in self.users.values()]}

    def load_payload(self, payload: dict):
        self.users.clear()
        for item in payload.get("users", []):
            u = User(
                username=item["username"],
                salt=item["salt"],
                password_hash=item["password_hash"],
                role=item["role"],
            )
            self.users[u.username] = u


class JsonFile:
    def __init__(self, path: Path):
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def read(self) -> Optional[dict]:
        if not self.path.exists():
            return None
        return json.loads(self.path.read_text(encoding="utf-8"))

    def write(self, data: dict):
        self.path.write_text(json.dumps(data, indent=2), encoding="utf-8")


class WebsiteUploader:
    def __init__(self, upload_dir: Path):
        self.upload_dir = upload_dir
        self.upload_dir.mkdir(parents=True, exist_ok=True)

    def upload(self, payload: dict) -> Path:
        out = self.upload_dir / "pets.json"
        out.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        return out


# GUI App

class IvyAnimalShelterApp(tk.Tk):
    DEFAULT_ADMIN_USER = "admin"
    DEFAULT_ADMIN_PASS = "admin123"

    def __init__(self):
        super().__init__()
        self.title("IVY Animal Shelter - Inventory Manager")
        self.geometry("1000x650")
        self.minsize(920, 580)

        # Show errors as popups
        self.report_callback_exception = self._report_callback_exception

        # Style
        style = ttk.Style()
        style.theme_use("clam")
        self.configure(bg="#f6f7fb")
        style.configure("TFrame", background="#f6f7fb")
        style.configure("TLabel", background="#f6f7fb", foreground="#1a1a1a")
        style.configure("Header.TLabel", font=("Segoe UI", 16, "bold"))
        style.configure("Card.TFrame", background="#ffffff", relief="raised")
        style.configure("TButton", padding=[10, 6])
        style.configure("Treeview", rowheight=28)

        # Data
        self.inventory = PetInventory()
        self.users = UserManager()

        self.pets_file = JsonFile(Path("data") / "pets.json")
        self.users_file = JsonFile(Path("data") / "users.json")
        self.uploader = WebsiteUploader(Path("website_upload"))

        self.current_user: Optional[User] = None
        self.selected_pet_id: Optional[int] = None
        self._admin_tab_added = False

        # Load files
        self._load_all()
        self._ensure_default_admin()

        # Root
        self.root = ttk.Frame(self, padding=12)
        self.root.pack(fill="both", expand=True)

        # Screens
        self.login_frame = ttk.Frame(self.root, style="Card.TFrame", padding=18)
        self.main_frame = ttk.Frame(self.root)

        self._build_login()
        self._build_main()

        self._show_login()

    #error popup 
    def _report_callback_exception(self, exc, val, tb):
        import traceback
        msg = "".join(traceback.format_exception(exc, val, tb))
        messagebox.showerror("Unexpected Error", msg)

    #load/save
    def _load_all(self):
        pets_data = self.pets_file.read()
        if pets_data:
            self.inventory.load_payload(pets_data)

        users_data = self.users_file.read()
        if users_data:
            self.users.load_payload(users_data)

    def _save_pets(self):
        self.pets_file.write(self.inventory.to_payload())

    def _save_users(self):
        self.users_file.write(self.users.to_payload())

    def _ensure_default_admin(self):
        # If users file is empty/missing, create default admin/admin123
        if len(self.users.users) == 0:
            self.users.add_user(self.DEFAULT_ADMIN_USER, self.DEFAULT_ADMIN_PASS, "Admin")
            self._save_users()
            return

        # If no admins exist, add default admin
        if self.users.count_admins() == 0 and self.DEFAULT_ADMIN_USER not in self.users.users:
            self.users.add_user(self.DEFAULT_ADMIN_USER, self.DEFAULT_ADMIN_PASS, "Admin")
            self._save_users()


    # LOGIN SCREEN

    def _build_login(self):
        top = ttk.Frame(self.login_frame)
        top.pack(fill="x", pady=(0, 10))
        ttk.Label(top, text="IVY Animal Shelter", style="Header.TLabel").pack(anchor="w")
        ttk.Label(top, text="Log in to manage pet listings.").pack(anchor="w", pady=(4, 0))

        form = ttk.Frame(self.login_frame)
        form.pack(fill="x", pady=10)

        self.login_user = tk.StringVar()
        self.login_pass = tk.StringVar()

        ttk.Label(form, text="Username").grid(row=0, column=0, sticky="w", padx=(0, 10), pady=8)
        ttk.Entry(form, textvariable=self.login_user).grid(row=0, column=1, sticky="ew", pady=8)

        ttk.Label(form, text="Password").grid(row=1, column=0, sticky="w", padx=(0, 10), pady=8)
        ttk.Entry(form, textvariable=self.login_pass, show="•").grid(row=1, column=1, sticky="ew", pady=8)

        form.columnconfigure(1, weight=1)

        buttons = ttk.Frame(self.login_frame)
        buttons.pack(fill="x", pady=(10, 0))
        ttk.Button(buttons, text="Login 🔐", command=self._do_login).pack(side="left")
        ttk.Button(buttons, text="Quit", command=self.destroy).pack(side="left", padx=8)

        ttk.Label(self.login_frame, text="Default Admin: admin / admin123").pack(anchor="w", pady=(14, 0))
        self.login_msg = tk.StringVar(value="")
        ttk.Label(self.login_frame, textvariable=self.login_msg).pack(anchor="w", pady=(8, 0))

        self.bind("<Return>", lambda e: self._do_login())

    def _show_login(self):
        self.main_frame.pack_forget()
        self.login_frame.pack(fill="both", expand=True)
        self.current_user = None
        self.login_pass.set("")
        self.login_msg.set("")

    def _do_login(self):
        u = self.login_user.get().strip().lower()
        p = self.login_pass.get()

        if not u or not p:
            self.login_msg.set("Enter both username and password.")
            return

        if not self.users.verify_login(u, p):
            self.login_msg.set("Invalid username or password.")
            return

        self.current_user = self.users.get_user(u)
        self.login_msg.set("")
        self._show_main()


    # MAIN SCREEN

    def _build_main(self):
        header = ttk.Frame(self.main_frame)
        header.pack(fill="x", pady=(0, 10))

        ttk.Label(header, text="IVY Animal Shelter", style="Header.TLabel").pack(side="left")
        self.whoami = tk.StringVar(value="")
        ttk.Label(header, textvariable=self.whoami).pack(side="left", padx=12)

        ttk.Button(header, text="Logout 🚪", command=self._show_login).pack(side="right")

        self.notebook = ttk.Notebook(self.main_frame)
        self.notebook.pack(fill="both", expand=True)

        self.tab_form = ttk.Frame(self.notebook, padding=12)
        self.tab_inventory = ttk.Frame(self.notebook, padding=12)
        self.tab_upload = ttk.Frame(self.notebook, padding=12)
        self.tab_admin = ttk.Frame(self.notebook, padding=12)

        self.notebook.add(self.tab_form, text="➕ Add / Edit Pet")
        self.notebook.add(self.tab_inventory, text="📋 Inventory")
        self.notebook.add(self.tab_upload, text="🚀 Export / Upload")

        self._build_pet_form_tab()
        self._build_inventory_tab()
        self._build_upload_tab()
        self._build_admin_tab()

        self.status = tk.StringVar(value="Ready.")
        ttk.Label(self.main_frame, textvariable=self.status, anchor="w").pack(fill="x", pady=(10, 0))

    def _show_main(self):
        self.login_frame.pack_forget()
        self.main_frame.pack(fill="both", expand=True)

        self.whoami.set(f"Logged in as {self.current_user.username} ({self.current_user.role})")
        self._refresh_pet_table()
        self._refresh_preview()
        self._refresh_users_table()

        # Admin tab visibility
        if self.current_user.role == "Admin":
            if not self._admin_tab_added:
                self.notebook.add(self.tab_admin, text="🛡️ Admin (Users)")
                self._admin_tab_added = True
        else:
            if self._admin_tab_added:
                try:
                    idx = self.notebook.index(self.tab_admin)
                    self.notebook.forget(idx)
                except tk.TclError:
                    pass
                self._admin_tab_added = False


    # PET FORM TAB

    def _build_pet_form_tab(self):
        card = ttk.Frame(self.tab_form, style="Card.TFrame", padding=12)
        card.pack(fill="both", expand=True)

        form = ttk.Frame(card)
        form.pack(fill="x")

        self.v_name = tk.StringVar()
        self.v_species = tk.StringVar(value=PetInventory.SPECIES_OPTIONS[0])
        self.v_age = tk.StringVar()
        self.v_breed = tk.StringVar()
        self.v_fee = tk.StringVar()
        self.v_status = tk.StringVar(value=PetInventory.STATUS_OPTIONS[0])
        self.v_photo = tk.StringVar()

        def row(r, label, widget):
            ttk.Label(form, text=label).grid(row=r, column=0, sticky="w", padx=(0, 10), pady=6)
            widget.grid(row=r, column=1, sticky="ew", pady=6)

        form.columnconfigure(1, weight=1)

        row(0, "Pet Name", ttk.Entry(form, textvariable=self.v_name))
        row(1, "Species", ttk.Combobox(form, textvariable=self.v_species,
                                       values=PetInventory.SPECIES_OPTIONS, state="readonly"))
        row(2, "Age (years)", ttk.Entry(form, textvariable=self.v_age))
        row(3, "Breed", ttk.Entry(form, textvariable=self.v_breed))
        row(4, "Adoption Fee ($)", ttk.Entry(form, textvariable=self.v_fee))
        row(5, "Status", ttk.Combobox(form, textvariable=self.v_status,
                                      values=PetInventory.STATUS_OPTIONS, state="readonly"))

        photo_row = ttk.Frame(form)
        ttk.Entry(photo_row, textvariable=self.v_photo).pack(side="left", fill="x", expand=True)
        ttk.Button(photo_row, text="Browse…", command=self._pick_photo).pack(side="left", padx=8)
        row(6, "Photo Path", photo_row)

        ttk.Label(form, text="Notes").grid(row=7, column=0, sticky="nw", padx=(0, 10), pady=6)
        self.notes = tk.Text(form, height=6, wrap="word")
        self.notes.grid(row=7, column=1, sticky="ew", pady=6)

        btns = ttk.Frame(card)
        btns.pack(fill="x", pady=(10, 0))

        self.btn_save = ttk.Button(btns, text="Save Pet ✅", command=self._save_pet)
        self.btn_save.pack(side="left")

        ttk.Button(btns, text="Clear 🧼", command=self._clear_pet_form).pack(side="left", padx=8)

        self.btn_cancel = ttk.Button(btns, text="Cancel Edit", command=self._cancel_edit, state="disabled")
        self.btn_cancel.pack(side="left", padx=8)

    def _pick_photo(self):
        path = filedialog.askopenfilename(
            title="Choose a pet photo",
            filetypes=[("Images", "*.png *.jpg *.jpeg *.gif *.webp"), ("All files", "*.*")]
        )
        if path:
            self.v_photo.set(path)

    def _clear_pet_form(self):
        self.selected_pet_id = None
        self.v_name.set("")
        self.v_species.set(PetInventory.SPECIES_OPTIONS[0])
        self.v_age.set("")
        self.v_breed.set("")
        self.v_fee.set("")
        self.v_status.set(PetInventory.STATUS_OPTIONS[0])
        self.v_photo.set("")
        self.notes.delete("1.0", "end")
        self.btn_save.configure(text="Save Pet ✅")
        self.btn_cancel.configure(state="disabled")

    def _cancel_edit(self):
        self._clear_pet_form()
        self.status.set("Edit cancelled.")

    def _validate_pet_form(self):
        name = self.v_name.get().strip()
        species = self.v_species.get().strip()
        breed = self.v_breed.get().strip()
        status = self.v_status.get().strip()
        notes = self.notes.get("1.0", "end").strip()
        photo = self.v_photo.get().strip()

        if not name:
            return None, "Pet name is required."

        try:
            age = int(self.v_age.get().strip())
            if age < 0:
                return None, "Age must be 0 or more."
        except ValueError:
            return None, "Age must be a whole number (example: 2)."

        try:
            fee = float(self.v_fee.get().strip())
            if fee < 0:
                return None, "Adoption fee must be 0 or more."
        except ValueError:
            return None, "Adoption fee must be a number (example: 75 or 75.00)."

        return {
            "name": name,
            "species": species,
            "age": age,
            "breed": breed,
            "fee": fee,
            "status": status,
            "notes": notes,
            "photo_path": photo,
        }, None

    def _save_pet(self):
        data, err = self._validate_pet_form()
        if err:
            messagebox.showerror("Fix this first", err)
            return

        if self.selected_pet_id is None:
            pet = self.inventory.add_pet(
                name=data["name"],
                species=data["species"],
                age=data["age"],
                breed=data["breed"],
                fee=data["fee"],
                status=data["status"],
                notes=data["notes"],
                photo_path=data["photo_path"]
            )
            self.status.set(f"Saved: {pet.name} (ID {pet.pet_id})")
        else:
            self.inventory.update_pet(
                self.selected_pet_id,
                name=data["name"],
                species=data["species"],
                age=data["age"],
                breed=data["breed"],
                adoption_fee=data["fee"],
                status=data["status"],
                notes=data["notes"],
                photo_path=data["photo_path"]
            )
            self.status.set(f"Updated pet ID {self.selected_pet_id}")

        self._save_pets()
        self._refresh_pet_table()
        self._refresh_preview()
        self._clear_pet_form()


    # INVENTORY TAB

    def _build_inventory_tab(self):
        top = ttk.Frame(self.tab_inventory)
        top.pack(fill="x")

        ttk.Label(top, text="Search").pack(side="left")
        self.v_search = tk.StringVar()
        entry = ttk.Entry(top, textvariable=self.v_search)
        entry.pack(side="left", padx=8, fill="x", expand=True)
        entry.bind("<KeyRelease>", lambda e: self._refresh_pet_table())

        ttk.Button(top, text="Edit ✏️", command=self._edit_selected_pet).pack(side="left", padx=6)
        ttk.Button(top, text="Delete 🗑️", command=self._delete_selected_pet).pack(side="left", padx=6)

        cols = ("id", "name", "species", "age", "breed", "fee", "status")
        self.pet_tree = ttk.Treeview(self.tab_inventory, columns=cols, show="headings")
        self.pet_tree.pack(fill="both", expand=True, pady=(10, 0))

        for c, title, w in [
            ("id", "ID", 60),
            ("name", "Name", 170),
            ("species", "Species", 110),
            ("age", "Age", 60),
            ("breed", "Breed", 170),
            ("fee", "Fee", 80),
            ("status", "Status", 110),
        ]:
            self.pet_tree.heading(c, text=title)
            self.pet_tree.column(c, width=w, anchor="w")

        self.pet_tree.bind("<Double-1>", lambda e: self._edit_selected_pet())

    def _refresh_pet_table(self):
        kw = self.v_search.get() if hasattr(self, "v_search") else ""
        rows = self.inventory.search(kw)

        for item in self.pet_tree.get_children():
            self.pet_tree.delete(item)

        for p in rows:
            self.pet_tree.insert("", "end", values=(
                p.pet_id, p.name, p.species, p.age, p.breed, f"{p.adoption_fee:.2f}", p.status
            ))

    def _selected_pet_id_from_table(self) -> Optional[int]:
        sel = self.pet_tree.selection()
        if not sel:
            return None
        values = self.pet_tree.item(sel[0], "values")
        return int(values[0])

    def _edit_selected_pet(self):
        pet_id = self._selected_pet_id_from_table()
        if pet_id is None:
            messagebox.showinfo("Select a pet", "Click a pet row first.")
            return

        pet = self.inventory.by_id.get(pet_id)
        if not pet:
            return

        self.selected_pet_id = pet.pet_id
        self.v_name.set(pet.name)
        self.v_species.set(pet.species)
        self.v_age.set(str(pet.age))
        self.v_breed.set(pet.breed)
        self.v_fee.set(f"{pet.adoption_fee:.2f}")
        self.v_status.set(pet.status)
        self.v_photo.set(pet.photo_path)

        self.notes.delete("1.0", "end")
        self.notes.insert("1.0", pet.notes)

        self.btn_save.configure(text="Save Changes 💾")
        self.btn_cancel.configure(state="normal")
        self.notebook.select(self.tab_form)
        self.status.set(f"Editing pet ID {pet.pet_id}")

    def _delete_selected_pet(self):
        pet_id = self._selected_pet_id_from_table()
        if pet_id is None:
            messagebox.showinfo("Select a pet", "Click a pet row first.")
            return

        pet = self.inventory.by_id.get(pet_id)
        if not pet:
            return

        if not messagebox.askyesno("Confirm delete", f"Delete {pet.name} (ID {pet.pet_id})?"):
            return

        self.inventory.delete_pet(pet_id)
        self._save_pets()
        self._refresh_pet_table()
        self._refresh_preview()
        self.status.set(f"Deleted pet ID {pet_id}")


    # UPLOAD TAB

    def _build_upload_tab(self):
        card = ttk.Frame(self.tab_upload, style="Card.TFrame", padding=12)
        card.pack(fill="both", expand=True)

        ttk.Label(card, text="Website JSON Preview").pack(anchor="w")
        self.preview = tk.Text(card, height=16, wrap="none")
        self.preview.pack(fill="both", expand=True, pady=(8, 10))

        controls = ttk.Frame(card)
        controls.pack(fill="x")

        ttk.Button(controls, text="Refresh Preview 🔄", command=self._refresh_preview).pack(side="left")
        ttk.Button(controls, text="Export JSON 📦", command=self._export_json).pack(side="left", padx=8)
        ttk.Button(controls, text="Upload to Website 🚀", command=self._upload_json).pack(side="left", padx=8)

        self.progress = ttk.Progressbar(controls, mode="determinate", maximum=100)
        self.progress.pack(side="right", fill="x", expand=True, padx=(12, 0))

        self._refresh_preview()

    def _refresh_preview(self):
        payload = self.inventory.to_payload()
        self.preview.delete("1.0", "end")
        self.preview.insert("1.0", json.dumps(payload, indent=2))

    def _export_json(self):
        out_dir = Path("exports")
        out_dir.mkdir(exist_ok=True)
        out_path = out_dir / "pets_export.json"
        out_path.write_text(json.dumps(self.inventory.to_payload(), indent=2), encoding="utf-8")
        messagebox.showinfo("Export complete", f"Saved:\n{out_path}")
        self.status.set(f"Exported: {out_path}")

    def _upload_json(self):
        self.progress["value"] = 0
        self.update_idletasks()

        payload = self.inventory.to_payload()
        for v in (25, 55, 80, 100):
            self.progress["value"] = v
            self.update_idletasks()
            self.after(80)

        out_path = self.uploader.upload(payload)
        messagebox.showinfo("Upload complete", f"Website data written to:\n{out_path}")
        self.status.set(f"Uploaded: {out_path}")


    # ADMIN TAB (USERS)

    def _build_admin_tab(self):
        card = ttk.Frame(self.tab_admin, style="Card.TFrame", padding=12)
        card.pack(fill="both", expand=True)

        ttk.Label(card, text="User Management (Admins Only)").pack(anchor="w")

        form = ttk.Frame(card)
        form.pack(fill="x", pady=(10, 10))

        self.v_new_user = tk.StringVar()
        self.v_new_pass = tk.StringVar()
        self.v_new_role = tk.StringVar(value="Staff")

        ttk.Label(form, text="New Username").grid(row=0, column=0, sticky="w", padx=(0, 10), pady=6)
        ttk.Entry(form, textvariable=self.v_new_user).grid(row=0, column=1, sticky="ew", pady=6)

        ttk.Label(form, text="New Password").grid(row=1, column=0, sticky="w", padx=(0, 10), pady=6)
        ttk.Entry(form, textvariable=self.v_new_pass, show="•").grid(row=1, column=1, sticky="ew", pady=6)

        ttk.Label(form, text="Role").grid(row=2, column=0, sticky="w", padx=(0, 10), pady=6)
        ttk.Combobox(form, textvariable=self.v_new_role, values=UserManager.ROLES, state="readonly") \
            .grid(row=2, column=1, sticky="ew", pady=6)

        form.columnconfigure(1, weight=1)

        actions = ttk.Frame(card)
        actions.pack(fill="x", pady=(0, 10))
        ttk.Button(actions, text="Add User ➕", command=self._admin_add_user).pack(side="left")
        ttk.Button(actions, text="Delete Selected 🗑️", command=self._admin_delete_user).pack(side="left", padx=8)
        ttk.Button(actions, text="Refresh 🔄", command=self._refresh_users_table).pack(side="left", padx=8)

        self.user_tree = ttk.Treeview(card, columns=("username", "role"), show="headings", height=10)
        self.user_tree.pack(fill="both", expand=True)

        self.user_tree.heading("username", text="Username")
        self.user_tree.heading("role", text="Role")
        self.user_tree.column("username", width=220, anchor="w")
        self.user_tree.column("role", width=120, anchor="w")

    def _refresh_users_table(self):
        if not hasattr(self, "user_tree"):
            return
        for item in self.user_tree.get_children():
            self.user_tree.delete(item)

        for username in sorted(self.users.users.keys()):
            u = self.users.users[username]
            self.user_tree.insert("", "end", values=(u.username, u.role))

    def _admin_add_user(self):
        if not self.current_user or self.current_user.role != "Admin":
            messagebox.showerror("Not allowed", "Only Admins can add users.")
            return
        try:
            self.users.add_user(self.v_new_user.get(), self.v_new_pass.get(), self.v_new_role.get())
            self._save_users()
            self._refresh_users_table()
            self.v_new_user.set("")
            self.v_new_pass.set("")
            self.v_new_role.set("Staff")
            self.status.set("User added.")
            messagebox.showinfo("Success", "User added successfully.")
        except Exception as e:
            messagebox.showerror("Could not add user", str(e))

    def _admin_delete_user(self):
        if not self.current_user or self.current_user.role != "Admin":
            messagebox.showerror("Not allowed", "Only Admins can delete users.")
            return

        sel = self.user_tree.selection()
        if not sel:
            messagebox.showinfo("Select a user", "Click a user row first.")
            return

        username, role = self.user_tree.item(sel[0], "values")
        username = (username or "").strip().lower()

        if username == self.current_user.username:
            messagebox.showerror("Not allowed", "You cannot delete the account you are logged into.")
            return

        if role == "Admin" and self.users.count_admins() <= 1:
            messagebox.showerror("Not allowed", "You must keep at least one Admin account.")
            return

        if not messagebox.askyesno("Confirm", f"Delete user '{username}'?"):
            return

        self.users.delete_user(username)
        self._save_users()
        self._refresh_users_table()
        self.status.set(f"Deleted user: {username}")


if __name__ == "__main__":
    IvyAnimalShelterApp().mainloop()

import json
import hashlib
import secrets
from dataclasses import dataclass, asdict
from pathlib import Path
from array import array
from typing import Optional, List, Dict

import tkinter as tk
from tkinter import ttk, messagebox, filedialog



# Data Models (Classes)


@dataclass
class Pet:
    pet_id: int
    name: str
    species: str
    age: int
    breed: str
    adoption_fee: float
    status: str
    notes: str = ""
    photo_path: str = ""

    def to_dict(self) -> dict:
        d = asdict(self)  
        d["display_label"] = f"#{self.pet_id} - {self.name} ({self.species})"
        return d


@dataclass
class User:
    username: str
    salt: str
    password_hash: str
    role: str  # "Admin" or "Staff"

    def to_dict(self) -> dict:
        return asdict(self)



# Business Logic 


class PetInventory:
    SPECIES_OPTIONS = ("Dog", "Cat", "Rabbit", "Bird", "Reptile", "Other")  
    STATUS_OPTIONS = ("Available", "Pending", "Adopted")  

    def __init__(self):
        self.pets: List[Pet] = []            
        self.by_id: Dict[int, Pet] = {}      
        self.id_pool = array("I")            
        self.next_id = 1

    def add_pet(self, name: str, species: str, age: int, breed: str,
                fee: float, status: str, notes: str = "", photo_path: str = "") -> Pet:
        pet = Pet(
            pet_id=self.next_id,
            name=name.strip(),
            species=species,
            age=age,
            breed=breed.strip(),
            adoption_fee=fee,
            status=status,
            notes=notes.strip(),
            photo_path=photo_path.strip()
        )
        self.next_id += 1
        self.pets.append(pet)
        self.by_id[pet.pet_id] = pet
        self.id_pool.append(pet.pet_id)
        return pet

    def update_pet(self, pet_id: int, **updates):
        pet = self.by_id.get(pet_id)
        if not pet:
            raise ValueError("Pet not found.")
        for k, v in updates.items():
            if hasattr(pet, k):
                setattr(pet, k, v)

    def delete_pet(self, pet_id: int):
        if pet_id not in self.by_id:
            return
        self.by_id.pop(pet_id)
        self.pets = [p for p in self.pets if p.pet_id != pet_id]

    def search(self, keyword: str) -> List[Pet]:
        kw = keyword.strip().lower()
        if not kw:
            return list(self.pets)
        out = []
        for p in self.pets:
            hay = f"{p.pet_id} {p.name} {p.species} {p.breed} {p.status} {p.notes}".lower()
            if kw in hay:
                out.append(p)
        return out

    def to_payload(self) -> dict:
        return {
            "total_pets": len(self.pets),
            "pets": [p.to_dict() for p in self.pets],
        }

    def load_payload(self, payload: dict):
        self.pets.clear()
        self.by_id.clear()
        self.id_pool = array("I")
        self.next_id = 1

        max_id = 0
        for item in payload.get("pets", []):
            pet = Pet(
                pet_id=int(item["pet_id"]),
                name=item["name"],
                species=item["species"],
                age=int(item["age"]),
                breed=item["breed"],
                adoption_fee=float(item["adoption_fee"]),
                status=item["status"],
                notes=item.get("notes", ""),
                photo_path=item.get("photo_path", ""),
            )
            self.pets.append(pet)
            self.by_id[pet.pet_id] = pet
            self.id_pool.append(pet.pet_id)
            max_id = max(max_id, pet.pet_id)

        self.next_id = max_id + 1


class UserManager:
    ROLES = ("Admin", "Staff")  

    def __init__(self):
        self.users: Dict[str, User] = {}  

    @staticmethod
    def _hash(password: str, salt: str) -> str:
        return hashlib.sha256((salt + password).encode("utf-8")).hexdigest()

    def add_user(self, username: str, password: str, role: str):
        u = username.strip().lower()
        if not u:
            raise ValueError("Username is required.")
        if u in self.users:
            raise ValueError("Username already exists.")
        if len(password) < 4:
            raise ValueError("Password must be at least 4 characters.")
        if role not in self.ROLES:
            raise ValueError("Invalid role.")

        salt = secrets.token_hex(8)
        pw_hash = self._hash(password, salt)
        self.users[u] = User(username=u, salt=salt, password_hash=pw_hash, role=role)

    def delete_user(self, username: str):
        u = username.strip().lower()
        if u in self.users:
            self.users.pop(u)

    def verify_login(self, username: str, password: str) -> bool:
        u = username.strip().lower()
        user = self.users.get(u)
        if not user:
            return False
        return self._hash(password, user.salt) == user.password_hash

    def get_user(self, username: str) -> Optional[User]:
        return self.users.get(username.strip().lower())

    def count_admins(self) -> int:
        return sum(1 for u in self.users.values() if u.role == "Admin")

    def to_payload(self) -> dict:
        return {"users": [u.to_dict() for u in self.users.values()]}

    def load_payload(self, payload: dict):
        self.users.clear()
        for item in payload.get("users", []):
            u = User(
                username=item["username"],
                salt=item["salt"],
                password_hash=item["password_hash"],
                role=item["role"],
            )
            self.users[u.username] = u


class JsonFile:
    def __init__(self, path: Path):
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def read(self) -> Optional[dict]:
        if not self.path.exists():
            return None
        return json.loads(self.path.read_text(encoding="utf-8"))

    def write(self, data: dict):
        self.path.write_text(json.dumps(data, indent=2), encoding="utf-8")


class WebsiteUploader:
    def __init__(self, upload_dir: Path):
        self.upload_dir = upload_dir
        self.upload_dir.mkdir(parents=True, exist_ok=True)

    def upload(self, payload: dict) -> Path:
        out = self.upload_dir / "pets.json"
        out.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        return out


# GUI App

class IvyAnimalShelterApp(tk.Tk):
    DEFAULT_ADMIN_USER = "admin"
    DEFAULT_ADMIN_PASS = "admin123"

    def __init__(self):
        super().__init__()
        self.title("IVY Animal Shelter - Inventory Manager")
        self.geometry("1000x650")
        self.minsize(920, 580)

        # Show errors as popups
        self.report_callback_exception = self._report_callback_exception

        # Style
        style = ttk.Style()
        style.theme_use("clam")
        self.configure(bg="#f6f7fb")
        style.configure("TFrame", background="#f6f7fb")
        style.configure("TLabel", background="#f6f7fb", foreground="#1a1a1a")
        style.configure("Header.TLabel", font=("Segoe UI", 16, "bold"))
        style.configure("Card.TFrame", background="#ffffff", relief="raised")
        style.configure("TButton", padding=[10, 6])
        style.configure("Treeview", rowheight=28)

        # Data
        self.inventory = PetInventory()
        self.users = UserManager()

        self.pets_file = JsonFile(Path("data") / "pets.json")
        self.users_file = JsonFile(Path("data") / "users.json")
        self.uploader = WebsiteUploader(Path("website_upload"))

        self.current_user: Optional[User] = None
        self.selected_pet_id: Optional[int] = None
        self._admin_tab_added = False

        # Load files
        self._load_all()
        self._ensure_default_admin()

        # Root
        self.root = ttk.Frame(self, padding=12)
        self.root.pack(fill="both", expand=True)

        # Screens
        self.login_frame = ttk.Frame(self.root, style="Card.TFrame", padding=18)
        self.main_frame = ttk.Frame(self.root)

        self._build_login()
        self._build_main()

        self._show_login()

    #error popup 
    def _report_callback_exception(self, exc, val, tb):
        import traceback
        msg = "".join(traceback.format_exception(exc, val, tb))
        messagebox.showerror("Unexpected Error", msg)

    #load/save
    def _load_all(self):
        pets_data = self.pets_file.read()
        if pets_data:
            self.inventory.load_payload(pets_data)

        users_data = self.users_file.read()
        if users_data:
            self.users.load_payload(users_data)

    def _save_pets(self):
        self.pets_file.write(self.inventory.to_payload())

    def _save_users(self):
        self.users_file.write(self.users.to_payload())

    def _ensure_default_admin(self):
        # If users file is empty/missing, create default admin/admin123
        if len(self.users.users) == 0:
            self.users.add_user(self.DEFAULT_ADMIN_USER, self.DEFAULT_ADMIN_PASS, "Admin")
            self._save_users()
            return

        # If no admins exist, add default admin
        if self.users.count_admins() == 0 and self.DEFAULT_ADMIN_USER not in self.users.users:
            self.users.add_user(self.DEFAULT_ADMIN_USER, self.DEFAULT_ADMIN_PASS, "Admin")
            self._save_users()


    # LOGIN SCREEN

    def _build_login(self):
        top = ttk.Frame(self.login_frame)
        top.pack(fill="x", pady=(0, 10))
        ttk.Label(top, text="IVY Animal Shelter", style="Header.TLabel").pack(anchor="w")
        ttk.Label(top, text="Log in to manage pet listings.").pack(anchor="w", pady=(4, 0))

        form = ttk.Frame(self.login_frame)
        form.pack(fill="x", pady=10)

        self.login_user = tk.StringVar()
        self.login_pass = tk.StringVar()

        ttk.Label(form, text="Username").grid(row=0, column=0, sticky="w", padx=(0, 10), pady=8)
        ttk.Entry(form, textvariable=self.login_user).grid(row=0, column=1, sticky="ew", pady=8)

        ttk.Label(form, text="Password").grid(row=1, column=0, sticky="w", padx=(0, 10), pady=8)
        ttk.Entry(form, textvariable=self.login_pass, show="•").grid(row=1, column=1, sticky="ew", pady=8)

        form.columnconfigure(1, weight=1)

        buttons = ttk.Frame(self.login_frame)
        buttons.pack(fill="x", pady=(10, 0))
        ttk.Button(buttons, text="Login 🔐", command=self._do_login).pack(side="left")
        ttk.Button(buttons, text="Quit", command=self.destroy).pack(side="left", padx=8)

        ttk.Label(self.login_frame, text="Default Admin: admin / admin123").pack(anchor="w", pady=(14, 0))
        self.login_msg = tk.StringVar(value="")
        ttk.Label(self.login_frame, textvariable=self.login_msg).pack(anchor="w", pady=(8, 0))

        self.bind("<Return>", lambda e: self._do_login())

    def _show_login(self):
        self.main_frame.pack_forget()
        self.login_frame.pack(fill="both", expand=True)
        self.current_user = None
        self.login_pass.set("")
        self.login_msg.set("")

    def _do_login(self):
        u = self.login_user.get().strip().lower()
        p = self.login_pass.get()

        if not u or not p:
            self.login_msg.set("Enter both username and password.")
            return

        if not self.users.verify_login(u, p):
            self.login_msg.set("Invalid username or password.")
            return

        self.current_user = self.users.get_user(u)
        self.login_msg.set("")
        self._show_main()


    # MAIN SCREEN

    def _build_main(self):
        header = ttk.Frame(self.main_frame)
        header.pack(fill="x", pady=(0, 10))

        ttk.Label(header, text="IVY Animal Shelter", style="Header.TLabel").pack(side="left")
        self.whoami = tk.StringVar(value="")
        ttk.Label(header, textvariable=self.whoami).pack(side="left", padx=12)

        ttk.Button(header, text="Logout 🚪", command=self._show_login).pack(side="right")

        self.notebook = ttk.Notebook(self.main_frame)
        self.notebook.pack(fill="both", expand=True)

        self.tab_form = ttk.Frame(self.notebook, padding=12)
        self.tab_inventory = ttk.Frame(self.notebook, padding=12)
        self.tab_upload = ttk.Frame(self.notebook, padding=12)
        self.tab_admin = ttk.Frame(self.notebook, padding=12)

        self.notebook.add(self.tab_form, text="➕ Add / Edit Pet")
        self.notebook.add(self.tab_inventory, text="📋 Inventory")
        self.notebook.add(self.tab_upload, text="🚀 Export / Upload")

        self._build_pet_form_tab()
        self._build_inventory_tab()
        self._build_upload_tab()
        self._build_admin_tab()

        self.status = tk.StringVar(value="Ready.")
        ttk.Label(self.main_frame, textvariable=self.status, anchor="w").pack(fill="x", pady=(10, 0))

    def _show_main(self):
        self.login_frame.pack_forget()
        self.main_frame.pack(fill="both", expand=True)

        self.whoami.set(f"Logged in as {self.current_user.username} ({self.current_user.role})")
        self._refresh_pet_table()
        self._refresh_preview()
        self._refresh_users_table()

        # Admin tab visibility
        if self.current_user.role == "Admin":
            if not self._admin_tab_added:
                self.notebook.add(self.tab_admin, text="🛡️ Admin (Users)")
                self._admin_tab_added = True
        else:
            if self._admin_tab_added:
                try:
                    idx = self.notebook.index(self.tab_admin)
                    self.notebook.forget(idx)
                except tk.TclError:
                    pass
                self._admin_tab_added = False


    # PET FORM TAB

    def _build_pet_form_tab(self):
        card = ttk.Frame(self.tab_form, style="Card.TFrame", padding=12)
        card.pack(fill="both", expand=True)

        form = ttk.Frame(card)
        form.pack(fill="x")

        self.v_name = tk.StringVar()
        self.v_species = tk.StringVar(value=PetInventory.SPECIES_OPTIONS[0])
        self.v_age = tk.StringVar()
        self.v_breed = tk.StringVar()
        self.v_fee = tk.StringVar()
        self.v_status = tk.StringVar(value=PetInventory.STATUS_OPTIONS[0])
        self.v_photo = tk.StringVar()

        def row(r, label, widget):
            ttk.Label(form, text=label).grid(row=r, column=0, sticky="w", padx=(0, 10), pady=6)
            widget.grid(row=r, column=1, sticky="ew", pady=6)

        form.columnconfigure(1, weight=1)

        row(0, "Pet Name", ttk.Entry(form, textvariable=self.v_name))
        row(1, "Species", ttk.Combobox(form, textvariable=self.v_species,
                                       values=PetInventory.SPECIES_OPTIONS, state="readonly"))
        row(2, "Age (years)", ttk.Entry(form, textvariable=self.v_age))
        row(3, "Breed", ttk.Entry(form, textvariable=self.v_breed))
        row(4, "Adoption Fee ($)", ttk.Entry(form, textvariable=self.v_fee))
        row(5, "Status", ttk.Combobox(form, textvariable=self.v_status,
                                      values=PetInventory.STATUS_OPTIONS, state="readonly"))

        photo_row = ttk.Frame(form)
        ttk.Entry(photo_row, textvariable=self.v_photo).pack(side="left", fill="x", expand=True)
        ttk.Button(photo_row, text="Browse…", command=self._pick_photo).pack(side="left", padx=8)
        row(6, "Photo Path", photo_row)

        ttk.Label(form, text="Notes").grid(row=7, column=0, sticky="nw", padx=(0, 10), pady=6)
        self.notes = tk.Text(form, height=6, wrap="word")
        self.notes.grid(row=7, column=1, sticky="ew", pady=6)

        btns = ttk.Frame(card)
        btns.pack(fill="x", pady=(10, 0))

        self.btn_save = ttk.Button(btns, text="Save Pet ✅", command=self._save_pet)
        self.btn_save.pack(side="left")

        ttk.Button(btns, text="Clear 🧼", command=self._clear_pet_form).pack(side="left", padx=8)

        self.btn_cancel = ttk.Button(btns, text="Cancel Edit", command=self._cancel_edit, state="disabled")
        self.btn_cancel.pack(side="left", padx=8)

    def _pick_photo(self):
        path = filedialog.askopenfilename(
            title="Choose a pet photo",
            filetypes=[("Images", "*.png *.jpg *.jpeg *.gif *.webp"), ("All files", "*.*")]
        )
        if path:
            self.v_photo.set(path)

    def _clear_pet_form(self):
        self.selected_pet_id = None
        self.v_name.set("")
        self.v_species.set(PetInventory.SPECIES_OPTIONS[0])
        self.v_age.set("")
        self.v_breed.set("")
        self.v_fee.set("")
        self.v_status.set(PetInventory.STATUS_OPTIONS[0])
        self.v_photo.set("")
        self.notes.delete("1.0", "end")
        self.btn_save.configure(text="Save Pet ✅")
        self.btn_cancel.configure(state="disabled")

    def _cancel_edit(self):
        self._clear_pet_form()
        self.status.set("Edit cancelled.")

    def _validate_pet_form(self):
        name = self.v_name.get().strip()
        species = self.v_species.get().strip()
        breed = self.v_breed.get().strip()
        status = self.v_status.get().strip()
        notes = self.notes.get("1.0", "end").strip()
        photo = self.v_photo.get().strip()

        if not name:
            return None, "Pet name is required."

        try:
            age = int(self.v_age.get().strip())
            if age < 0:
                return None, "Age must be 0 or more."
        except ValueError:
            return None, "Age must be a whole number (example: 2)."

        try:
            fee = float(self.v_fee.get().strip())
            if fee < 0:
                return None, "Adoption fee must be 0 or more."
        except ValueError:
            return None, "Adoption fee must be a number (example: 75 or 75.00)."

        return {
            "name": name,
            "species": species,
            "age": age,
            "breed": breed,
            "fee": fee,
            "status": status,
            "notes": notes,
            "photo_path": photo,
        }, None

    def _save_pet(self):
        data, err = self._validate_pet_form()
        if err:
            messagebox.showerror("Fix this first", err)
            return

        if self.selected_pet_id is None:
            pet = self.inventory.add_pet(
                name=data["name"],
                species=data["species"],
                age=data["age"],
                breed=data["breed"],
                fee=data["fee"],
                status=data["status"],
                notes=data["notes"],
                photo_path=data["photo_path"]
            )
            self.status.set(f"Saved: {pet.name} (ID {pet.pet_id})")
        else:
            self.inventory.update_pet(
                self.selected_pet_id,
                name=data["name"],
                species=data["species"],
                age=data["age"],
                breed=data["breed"],
                adoption_fee=data["fee"],
                status=data["status"],
                notes=data["notes"],
                photo_path=data["photo_path"]
            )
            self.status.set(f"Updated pet ID {self.selected_pet_id}")

        self._save_pets()
        self._refresh_pet_table()
        self._refresh_preview()
        self._clear_pet_form()


    # INVENTORY TAB

    def _build_inventory_tab(self):
        top = ttk.Frame(self.tab_inventory)
        top.pack(fill="x")

        ttk.Label(top, text="Search").pack(side="left")
        self.v_search = tk.StringVar()
        entry = ttk.Entry(top, textvariable=self.v_search)
        entry.pack(side="left", padx=8, fill="x", expand=True)
        entry.bind("<KeyRelease>", lambda e: self._refresh_pet_table())

        ttk.Button(top, text="Edit ✏️", command=self._edit_selected_pet).pack(side="left", padx=6)
        ttk.Button(top, text="Delete 🗑️", command=self._delete_selected_pet).pack(side="left", padx=6)

        cols = ("id", "name", "species", "age", "breed", "fee", "status")
        self.pet_tree = ttk.Treeview(self.tab_inventory, columns=cols, show="headings")
        self.pet_tree.pack(fill="both", expand=True, pady=(10, 0))

        for c, title, w in [
            ("id", "ID", 60),
            ("name", "Name", 170),
            ("species", "Species", 110),
            ("age", "Age", 60),
            ("breed", "Breed", 170),
            ("fee", "Fee", 80),
            ("status", "Status", 110),
        ]:
            self.pet_tree.heading(c, text=title)
            self.pet_tree.column(c, width=w, anchor="w")

        self.pet_tree.bind("<Double-1>", lambda e: self._edit_selected_pet())

    def _refresh_pet_table(self):
        kw = self.v_search.get() if hasattr(self, "v_search") else ""
        rows = self.inventory.search(kw)

        for item in self.pet_tree.get_children():
            self.pet_tree.delete(item)

        for p in rows:
            self.pet_tree.insert("", "end", values=(
                p.pet_id, p.name, p.species, p.age, p.breed, f"{p.adoption_fee:.2f}", p.status
            ))

    def _selected_pet_id_from_table(self) -> Optional[int]:
        sel = self.pet_tree.selection()
        if not sel:
            return None
        values = self.pet_tree.item(sel[0], "values")
        return int(values[0])

    def _edit_selected_pet(self):
        pet_id = self._selected_pet_id_from_table()
        if pet_id is None:
            messagebox.showinfo("Select a pet", "Click a pet row first.")
            return

        pet = self.inventory.by_id.get(pet_id)
        if not pet:
            return

        self.selected_pet_id = pet.pet_id
        self.v_name.set(pet.name)
        self.v_species.set(pet.species)
        self.v_age.set(str(pet.age))
        self.v_breed.set(pet.breed)
        self.v_fee.set(f"{pet.adoption_fee:.2f}")
        self.v_status.set(pet.status)
        self.v_photo.set(pet.photo_path)

        self.notes.delete("1.0", "end")
        self.notes.insert("1.0", pet.notes)

        self.btn_save.configure(text="Save Changes 💾")
        self.btn_cancel.configure(state="normal")
        self.notebook.select(self.tab_form)
        self.status.set(f"Editing pet ID {pet.pet_id}")

    def _delete_selected_pet(self):
        pet_id = self._selected_pet_id_from_table()
        if pet_id is None:
            messagebox.showinfo("Select a pet", "Click a pet row first.")
            return

        pet = self.inventory.by_id.get(pet_id)
        if not pet:
            return

        if not messagebox.askyesno("Confirm delete", f"Delete {pet.name} (ID {pet.pet_id})?"):
            return

        self.inventory.delete_pet(pet_id)
        self._save_pets()
        self._refresh_pet_table()
        self._refresh_preview()
        self.status.set(f"Deleted pet ID {pet_id}")


    # UPLOAD TAB

    def _build_upload_tab(self):
        card = ttk.Frame(self.tab_upload, style="Card.TFrame", padding=12)
        card.pack(fill="both", expand=True)

        ttk.Label(card, text="Website JSON Preview").pack(anchor="w")
        self.preview = tk.Text(card, height=16, wrap="none")
        self.preview.pack(fill="both", expand=True, pady=(8, 10))

        controls = ttk.Frame(card)
        controls.pack(fill="x")

        ttk.Button(controls, text="Refresh Preview 🔄", command=self._refresh_preview).pack(side="left")
        ttk.Button(controls, text="Export JSON 📦", command=self._export_json).pack(side="left", padx=8)
        ttk.Button(controls, text="Upload to Website 🚀", command=self._upload_json).pack(side="left", padx=8)

        self.progress = ttk.Progressbar(controls, mode="determinate", maximum=100)
        self.progress.pack(side="right", fill="x", expand=True, padx=(12, 0))

        self._refresh_preview()

    def _refresh_preview(self):
        payload = self.inventory.to_payload()
        self.preview.delete("1.0", "end")
        self.preview.insert("1.0", json.dumps(payload, indent=2))

    def _export_json(self):
        out_dir = Path("exports")
        out_dir.mkdir(exist_ok=True)
        out_path = out_dir / "pets_export.json"
        out_path.write_text(json.dumps(self.inventory.to_payload(), indent=2), encoding="utf-8")
        messagebox.showinfo("Export complete", f"Saved:\n{out_path}")
        self.status.set(f"Exported: {out_path}")

    def _upload_json(self):
        self.progress["value"] = 0
        self.update_idletasks()

        payload = self.inventory.to_payload()
        for v in (25, 55, 80, 100):
            self.progress["value"] = v
            self.update_idletasks()
            self.after(80)

        out_path = self.uploader.upload(payload)
        messagebox.showinfo("Upload complete", f"Website data written to:\n{out_path}")
        self.status.set(f"Uploaded: {out_path}")


    # ADMIN TAB (USERS)

    def _build_admin_tab(self):
        card = ttk.Frame(self.tab_admin, style="Card.TFrame", padding=12)
        card.pack(fill="both", expand=True)

        ttk.Label(card, text="User Management (Admins Only)").pack(anchor="w")

        form = ttk.Frame(card)
        form.pack(fill="x", pady=(10, 10))

        self.v_new_user = tk.StringVar()
        self.v_new_pass = tk.StringVar()
        self.v_new_role = tk.StringVar(value="Staff")

        ttk.Label(form, text="New Username").grid(row=0, column=0, sticky="w", padx=(0, 10), pady=6)
        ttk.Entry(form, textvariable=self.v_new_user).grid(row=0, column=1, sticky="ew", pady=6)

        ttk.Label(form, text="New Password").grid(row=1, column=0, sticky="w", padx=(0, 10), pady=6)
        ttk.Entry(form, textvariable=self.v_new_pass, show="•").grid(row=1, column=1, sticky="ew", pady=6)

        ttk.Label(form, text="Role").grid(row=2, column=0, sticky="w", padx=(0, 10), pady=6)
        ttk.Combobox(form, textvariable=self.v_new_role, values=UserManager.ROLES, state="readonly") \
            .grid(row=2, column=1, sticky="ew", pady=6)

        form.columnconfigure(1, weight=1)

        actions = ttk.Frame(card)
        actions.pack(fill="x", pady=(0, 10))
        ttk.Button(actions, text="Add User ➕", command=self._admin_add_user).pack(side="left")
        ttk.Button(actions, text="Delete Selected 🗑️", command=self._admin_delete_user).pack(side="left", padx=8)
        ttk.Button(actions, text="Refresh 🔄", command=self._refresh_users_table).pack(side="left", padx=8)

        self.user_tree = ttk.Treeview(card, columns=("username", "role"), show="headings", height=10)
        self.user_tree.pack(fill="both", expand=True)

        self.user_tree.heading("username", text="Username")
        self.user_tree.heading("role", text="Role")
        self.user_tree.column("username", width=220, anchor="w")
        self.user_tree.column("role", width=120, anchor="w")

    def _refresh_users_table(self):
        if not hasattr(self, "user_tree"):
            return
        for item in self.user_tree.get_children():
            self.user_tree.delete(item)

        for username in sorted(self.users.users.keys()):
            u = self.users.users[username]
            self.user_tree.insert("", "end", values=(u.username, u.role))

    def _admin_add_user(self):
        if not self.current_user or self.current_user.role != "Admin":
            messagebox.showerror("Not allowed", "Only Admins can add users.")
            return
        try:
            self.users.add_user(self.v_new_user.get(), self.v_new_pass.get(), self.v_new_role.get())
            self._save_users()
            self._refresh_users_table()
            self.v_new_user.set("")
            self.v_new_pass.set("")
            self.v_new_role.set("Staff")
            self.status.set("User added.")
            messagebox.showinfo("Success", "User added successfully.")
        except Exception as e:
            messagebox.showerror("Could not add user", str(e))

    def _admin_delete_user(self):
        if not self.current_user or self.current_user.role != "Admin":
            messagebox.showerror("Not allowed", "Only Admins can delete users.")
            return

        sel = self.user_tree.selection()
        if not sel:
            messagebox.showinfo("Select a user", "Click a user row first.")
            return

        username, role = self.user_tree.item(sel[0], "values")
        username = (username or "").strip().lower()

        if username == self.current_user.username:
            messagebox.showerror("Not allowed", "You cannot delete the account you are logged into.")
            return

        if role == "Admin" and self.users.count_admins() <= 1:
            messagebox.showerror("Not allowed", "You must keep at least one Admin account.")
            return

        if not messagebox.askyesno("Confirm", f"Delete user '{username}'?"):
            return

        self.users.delete_user(username)
        self._save_users()
        self._refresh_users_table()
        self.status.set(f"Deleted user: {username}")


if __name__ == "__main__":
    IvyAnimalShelterApp().mainloop()

