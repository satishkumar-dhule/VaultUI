import tkinter
import tkinter.messagebox
import customtkinter
import os,json
from tkinter import ttk
import traceback

from vaultlib import *

customtkinter.set_appearance_mode("System")  # Modes: "System" (standard), "Dark", "Light"
customtkinter.set_default_color_theme("blue")  # Themes: "blue" (standard), "green", "dark-blue"
vault_client=None
paths_dict=None


class TempFrame(customtkinter.CTkFrame):
    def __init__(self, master, message, **kwargs):
        super().__init__(master, **kwargs)
        self.pack_propagate(0)
        self.label = customtkinter.CTkLabel(self, text=message, width=800, font=customtkinter.CTkFont(size=20), wraplength=780, anchor='center')
        self.label.pack(fill='both', expand=True)
        self.place(in_=master.message_frame, rely=0.5, relx=0.5, anchor='center')
        self.master.after(5000, self.destroy)



class App(customtkinter.CTk):
    global paths_dict

    def add_key_value_pair_to_path(self,path=None):

        global paths_dict
        print("add_key_value_pair_to_path")
        
        if path is None:
            path=self.combobox_paths.get()
            print(f" in add_key_value_pair_to_path path={path}")
        else:
            print(path)
        
        if path=="":
            tkinter.messagebox.showerror('Error', f'Error adding key-value pair to Vault as path is ""')


        try:
            # Get the path, key, and value from the user using dialog boxes
            key = customtkinter.CTkInputDialog(title='Vault Key', text='Enter the key for the Vault secret:').get_input()

            value = customtkinter.CTkInputDialog(title='Vault Value', text='Enter the value for the Vault secret:').get_input()
            if key == "" or value == "" or key is None or value is None:
                return

            # Get the existing secrets at the path, if any
            existing_secrets = paths_dict[path]

            if key in existing_secrets:
                tkinter.messagebox.showinfo("Fail", f"Key -->{key}<-- already exists, please use update feature for existing keys.")
                return

            # Add the new key-value pair to the existing secrets
            existing_secrets[key] = value
            paths_dict[path]=existing_secrets

            # Write the updated secrets back to the Vault path
            vault_client.secrets.kv.v2.create_or_update_secret(
                path=trim_vault_path(path),mount_point="kv",
                secret=existing_secrets
            )
            # show_secrets(comboboxes['secrets_path'][0].get())
            # tkinter.messagebox.showinfo("Success", f"The Vault path '{path}'has been added.")
            # self.show_message(f"Success: The Vault path '{path}'has been added.")
            self.show_message(f"Success: path added.")
            self.draw_key_value_list(path, paths_dict)
        except Exception as e:
            # If there was an error, display an error message in a dialog box
            tkinter.messagebox.showerror('Error', f'Error adding key-value pair to Vault: {e}')
            traceback.print_exc()


    def remove_key_value_pair_to_path(self,path,key):
        
        try:
            if key == "" or key is None:
                return

            # Get the existing secrets at the path, if any
            existing_secrets = vault_client.secrets.kv.v2.read_secret_version(
                path=trim_vault_path(path),mount_point="kv"
            ).get('data', {}).get('data', {})

            if key not in existing_secrets:
                tkinter.messagebox.showinfo("Fail", f"Key -->{key}<-- does not exists.")
                return

            # Remove the new key-value pair to the existing secrets
            del existing_secrets[key]

            # Write the updated secrets back to the Vault path
            vault_client.secrets.kv.v2.create_or_update_secret(
                path=trim_vault_path(path),mount_point="kv",
                secret=existing_secrets
            )
            # show_secrets(comboboxes['secrets_path'][0].get())
            tkinter.messagebox.showinfo("Success", f"The key'{key}'has been removed.")
            # paths_dict=get_secrets_from_vault(vault_client=vault_client, path=path, results=None)
            print(f"paths_dict {paths_dict}")
            paths_dict[path]=existing_secrets
            print(f"paths_dict {paths_dict}")
            print(f"existing_secrets {existing_secrets}")
            # self.draw_secret_path_details(paths_dict)
            self.draw_key_value_list(path, paths_dict)
        except Exception as e:
            # If there was an error, display an error message in a dialog box
            tkinter.messagebox.showerror('Error', f'Error removing key-value pair to Vault: {e}')

    def update_secret_value(self,path, key, value, button,vault_client=vault_client):
        print(path, key, value, button)
        try:
            update_secret(vault_client, path, key, value, mount_point="kv")
            button.configure(text='\u2714', state="disabled")
        except Exception as e:
            print(f"{e}")
            button.configure(text="Fail", state="disabled")

    
    def open_input_dialog_event(self):
        dialog = customtkinter.CTkInputDialog(text="Type in a number:", title="CTkInputDialog")
        print("CTkInputDialog:", dialog.get_input())

    config_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), "config.json")
    
    def show_message(self, message):
        temp_frame = TempFrame(self, message, width=500, height=100)
    # def show_message(self, message):
    #     temp_frame = TempFrame(self, message, width=800, height=100)
    #     temp_frame.pack(fill='both', expand=True, padx=10, pady=10)


    def make_add_kv(self,path):
        def inner():
            return self.add_key_value_pair_to_path(path)
        return inner
    
    
# Create a function to add the Vault path
    def add_vault_path(self,path,paths_dict=paths_dict):        
        try:
            if path in paths_dict:
                tkinter.messagebox.showerror("Error", f"Error : '{path}' already exists, duplicates are not supported.")
                return
            # Add the Vault path
            vault_client.secrets.kv.v2.create_or_update_secret(
            path=trim_vault_path(path),mount_point="kv", secret=dict({}))
            # tkinter.messagebox.showinfo("Success", f"The Vault path '{path}'has been added.")
            self.show_message(f"Success: Path added.")
            paths_dict[path]=dict({})


        except Exception as e:
            # Display an error message if the path could not be added
            error_message = "An error occurred while adding the Vault path:\n\n{}".format(str(e))
            tkinter.messagebox.showerror("Error", error_message)
            traceback.print_exc()
    
    def get_and_add_subpath(self):
        dialog = customtkinter.CTkInputDialog(text="Enter the path you want to add:", title="Add New Path")
        path=dialog.get_input()
        print(paths_dict)
        self.add_vault_path(path,paths_dict=paths_dict)
        self.draw_secret_path_details(paths_dict)
    

    def del_vault_path(self,path,paths_dict=paths_dict):        
        confirmed = tkinter.messagebox.askyesno("Confirmation", f"Are you sure you want to delete '{path}' path?")
        try:
            if confirmed:
                deleted = vault_client.secrets.kv.v2.delete_metadata_and_all_versions(path=trim_vault_path(path),mount_point="kv")
                if deleted:
                    tkinter.messagebox.showinfo("Success", "The Vault path has been deleted.")
                    del paths_dict[path]
                    self.draw_secret_path_details(paths_dict)
                else:
                    tkinter.messagebox.showerror("Error", "Error : There was an error deleting the Vault path.")
        except Exception as e:
            # Display an error message if the path could not be added
            error_message = "An error occurred while deleting the Vault path:\n\n{}".format(str(e))
            tkinter.messagebox.showerror("Error", error_message)
            traceback.print_exc()




    def draw_secret_path_details(self,paths_dict):
        self.pack_propagate(1)
        self.label = customtkinter.CTkLabel(self.right_frame, text="Path Details View", font=customtkinter.CTkFont(size=20, weight="bold"))
        self.label.grid(row=1, column=0,columnspan=4, padx=10, pady=10)
        self.combobox_paths = ttk.Combobox(self.right_frame,values=[k for k in paths_dict], width=400) 
        self.combobox_paths.grid(row=2, column=0,columnspan=4, padx=10, pady=10)
        self.combobox_paths.bind("<<ComboboxSelected>>", lambda event: self.draw_key_value_list(self.combobox_paths.get(), paths_dict))
        self.button_add_path = customtkinter.CTkButton(self.right_frame, text="Add New Path",
                                                           command=self.get_and_add_subpath)
        self.button_add_path.grid(row=3, column=2, padx=10, pady=10)
        self.button_remove_path = customtkinter.CTkButton(self.right_frame, text="Delete This Path",
                                                           command=lambda: self.del_vault_path(self.combobox_paths.get(), paths_dict))
        self.button_remove_path.grid(row=3, column=3, padx=10, pady=10)
        self.button_add_kv = customtkinter.CTkButton(self.right_frame, text="Add New KV",
                                                           command=self.add_key_value_pair_to_path)
        self.button_add_kv.grid(row=3, column=1, padx=10, pady=10)
        



    def draw_key_value_list(self,path, paths_dict=paths_dict):

        print(f"Selected Path: {path} in {paths_dict}")

        def make_update_function(button, path, key, entry, vault_client):
            def update():
                button.configure(state="disabled")
                self.update_secret_value(path, key, entry.get(), button, vault_client=vault_client)
                paths_dict[path][key]=entry.get()
                print(paths_dict)
                # self.draw_key_value_list(self,path, paths_dict=paths_dict)
            return update

        def on_entry_change(event, entry, button):
            if entry.get():
                button.configure(state="normal", text='Update ?')
            else:
                button.configure(state="disabled")


        def make_on_entry_change_function(entry, button):
            def on_entry_change(event):
                if entry.get():
                    button.configure(state="normal", text="Update")
                else:
                    button.configure(state="disabled")

            return on_entry_change

        def make_del_function(path, key):
            def del_kv_from_path_inner():
                confirmed = tkinter.messagebox.askyesno("Confirmation", f"Are you sure you want to delete key-value '{key}' from '{path}' path?")
                if not confirmed:
                    print("Aborted.")
                    return
                self.remove_key_value_pair_to_path(path=path,key=key)
            return del_kv_from_path_inner

        try:
            self.frame.destroy()
        except:
            pass
        finally:
            self.frame = customtkinter.CTkScrollableFrame(self.right_frame,label_text=path)
            self.frame.grid(row=4, column=0, columnspan=4, padx=10, pady=10,sticky="nsew")

        print(paths_dict)

        kv_pairs = paths_dict[path]
        if not kv_pairs:
            self.label = customtkinter.CTkLabel(self.frame, text=f"No key-value pairs found at '{path}'")
            self.label.grid(row=1, column=0, padx=10, pady=10)
            return

        row=1
        for k, v in kv_pairs.items():
            print(f"{k} --> {v}")


            self.label_key = customtkinter.CTkLabel(self.frame, text=k,  width=40)
            self.label_key.grid(row=row, column=1, padx=10, pady=10)

            self.entry = customtkinter.CTkEntry(self.frame,  width=250)
            self.entry.insert(0, v)
            self.entry.grid(row=row, column=2, padx=10, pady=10)

            self.update_kv_button = customtkinter.CTkButton(self.frame, text="Update",  width=1)
            self.update_kv_button.grid(row=row, column=3, padx=10, pady=10)
            self.del_kv_button = customtkinter.CTkButton(self.frame, text="X",  width=1)
            self.del_kv_button.grid(row=row, column=4, padx=10, pady=10)
            update_func = make_update_function(self.update_kv_button, path, k, self.entry, vault_client=vault_client)
            del_func = make_del_function(path, k)
            self.update_kv_button.configure(command=update_func)
            # self.update_kv_button.configure()

            self.del_kv_button.configure(command=del_func)

            # on_entry_change_function = make_on_entry_change_function(self.update_kv_button)
            self.entry.bind("<KeyRelease>", make_on_entry_change_function(self.entry, self.update_kv_button))

            row=row+1



    def generate_vault_token(self,aws_creds_cmd,fi,vault_role,path):
        global vault_client

        if not all([fi, aws_creds_cmd, vault_role]):
            print("Warning", "Please select FI, AWS credentials, and Vault role!")
            return
        try:
            # Set environment variables for Vault
            os.environ['FI'] = fi
            os.environ['AWS_CREDENTIALS_COMMAND'] = aws_creds_cmd
            alt=aws_creds_cmd.split('export ')[1]
            os.environ['AWS_ACCESS_KEY_ID']="=".join(alt.split(" ")[0].split("=")[1:])
            os.environ['AWS_SECRET_ACCESS_KEY']="=".join(alt.split(" ")[1].split("=")[1:])
            os.environ['AWS_SESSION_TOKEN']="=".join(alt.split(" ")[2].split("=")[1:])
            os.environ['VAULT_ROLE'] = vault_role
            os.environ['CFG_ADDR'] = f"https://api.vault-config.top.secrets.{fi}.aws.sfdc.cl:443"
            os.environ['AWS_LOGIN_HEADER'] = f"api.vault.secrets.{fi}.aws.sfdc.cl"
            os.environ['VAULT_ADDR'] = f"https://{os.environ['AWS_LOGIN_HEADER']}"
            vault_client=get_falcon_vault_client(vault_role,f"https://{os.environ['AWS_LOGIN_HEADER']}","")
        except Exception as e:
            print("Error", f"{e}")
            self.show_message(f"Fail: Token generation Failed!, {e}")

        if vault_client is not None:
            print("Success", 'Token generated Successfully!')
            # show_secrets(comboboxes['secrets_path'][0].get())
            self.show_message("Success: Token generated Successfully!")
            global paths_dict
            paths_dict=get_secrets_from_vault(vault_client=vault_client, path=path, results=None)
            self.draw_secret_path_details(paths_dict)
        else:
            print("Error", f"Token generation Failed!")
            self.show_message("Fail: Token generation Failed!")
            # hide the sidebar frame after 5 seconds





    def hide_sidebar(self):
        if hasattr(self, 'sidebar_frame'):
            self.sidebar_frame.grid_forget()

    def add_option(self, past_values, key, new_value, combo,button_add):
        current_set_for_key = past_values.get(key, None)
        if current_set_for_key is None:
            current_set_for_key = [new_value]
        elif new_value not in current_set_for_key:
            current_set_for_key.append(new_value)
        past_values[key] = current_set_for_key[:]
        combo['values'] = past_values[key]
        # combo.update()

        with open(self.config_file, 'w') as f:
            json.dump(past_values, f)
    
    def remove_option(self, past_values, key, new_value, combo,button_remove):
        current_set_for_key = past_values.get(key, None)
        if new_value in current_set_for_key:
            current_set_for_key.remove(new_value)
        past_values[key] = current_set_for_key[:]
        combo['values'] = past_values[key]
        # combo.update()

        with open(self.config_file, 'w') as f:
            json.dump(past_values, f)



    def __init__(self):
        super().__init__()
        with open(self.config_file) as f:
            past_values = json.load(f)
        default_keys = ['aws_cred', 'FI', 'vault_role','secrets_path']
        for key in default_keys:
            past_values.setdefault(key, [])

        # configure window
        self.title("Simple Vault UI")
        self.geometry(f"{1100}x{580}")

        # configure grid layout (4x4)
        self.grid_columnconfigure(1, weight=1)
        self.grid_columnconfigure((2, 3), weight=0)
        self.grid_rowconfigure((0, 1, 2), weight=1)



        def get_add_item_funcation(past_values,key,combobox_item,button_add):
            def inner_fun():
                self.add_option(past_values,key, combobox_item.get(),combobox_item,button_add)
                sidebar()
            return inner_fun
        
        def get_remove_item_funcation(past_values,key,combobox_item,button_remove):
            def inner_fun():
                self.remove_option(past_values,key, combobox_item.get(),combobox_item,button_remove)
                sidebar()
            return inner_fun

        # create sidebar frame with widgets
        def sidebar():
            if hasattr(self, 'sidebar_frame'):
                    self.sidebar_frame.destroy()
            self.sidebar_frame = customtkinter.CTkFrame(self, width=240, corner_radius=0)
            self.sidebar_frame.grid(row=0, column=0, rowspan=7, sticky="nsew")
            self.sidebar_frame.grid_rowconfigure(7, weight=1)
            self.logo_label = customtkinter.CTkLabel(self.sidebar_frame, text="Configure Vault Parameters", font=customtkinter.CTkFont(size=20, weight="bold"))
            self.logo_label.grid(row=0, column=0, padx=20, pady=(20, 10))
            self.vault_config_items=dict([(k,dict({})) for k in ('aws_cred', 'FI', 'vault_role', 'secrets_path')])
            for i, key in enumerate(('aws_cred', 'FI', 'vault_role', 'secrets_path')):

                self.combobox_item = customtkinter.CTkComboBox(self.sidebar_frame,
                                                            values=past_values.get(key,[]), width=400,corner_radius=20,) 
                self.combobox_item.grid(row=1+i, column=0, padx=10, pady=10)

                self.sidebar_button_add = customtkinter.CTkButton(self.sidebar_frame,text='+', width=0,corner_radius=20, hover_color="green")
                self.sidebar_button_add.grid(row=1+i, column=2, padx=1, pady=10)
                self.sidebar_button_del = customtkinter.CTkButton(self.sidebar_frame,text='-', width=1,corner_radius=20, hover_color="red")
                self.sidebar_button_del.grid(row=1+i, column=3, padx=1, pady=10)
                add_func = get_add_item_funcation(past_values,key, self.combobox_item,self.sidebar_button_add )
                del_func = get_remove_item_funcation(past_values,key, self.combobox_item,self.sidebar_button_del)
                self.vault_config_items[key]['combobox_item']=self.combobox_item
                self.vault_config_items[key]['sidebar_button_add']=self.sidebar_button_add
                self.vault_config_items[key]['sidebar_button_del']=self.sidebar_button_del
                self.sidebar_button_add.configure(command=add_func)
                self.sidebar_button_del.configure(command=del_func)
            aws_creds=self.vault_config_items['aws_cred']['combobox_item'].get()
            FI=self.vault_config_items['FI']['combobox_item'].get()
            vault_role=self.vault_config_items['vault_role']['combobox_item'].get()
            path=self.vault_config_items['secrets_path']['combobox_item'].get()
                                                
            self.button_generate_token = customtkinter.CTkButton(self.sidebar_frame, 
            command=lambda: self.generate_vault_token(aws_creds,FI,vault_role,path), text="Generate Token",corner_radius=20)
            self.button_generate_token.grid(row=6, column=0, padx=10, pady=10)

            self.message_frame = customtkinter.CTkFrame(self, width=240, corner_radius=0)
            self.message_frame.grid(row=7, column=0, rowspan=7, sticky="nsew")
            self.message_frame.grid_rowconfigure(7, weight=1)

        sidebar()

        self.right_frame = customtkinter.CTkFrame(self, corner_radius=0)
        self.right_frame.grid(row=0, column=1,rowspan=15,sticky="nsew")
        self.right_frame.grid_columnconfigure(0, weight=1)
        self.right_frame.grid_rowconfigure(4, weight=1)
        # self.seg_button_1 = customtkinter.CTkSegmentedButton(self.right_frame)
        # self.seg_button_1.grid(row=0, column=0, padx=(20, 10), pady=(10, 10), sticky="ew")


    def open_input_dialog_event(self):
        dialog = customtkinter.CTkInputDialog(text="Type in a number:", title="CTkInputDialog")
        print("CTkInputDialog:", dialog.get_input())

    def change_appearance_mode_event(self, new_appearance_mode: str):
        customtkinter.set_appearance_mode(new_appearance_mode)

    def change_scaling_event(self, new_scaling: str):
        new_scaling_float = int(new_scaling.replace("%", "")) / 100
        customtkinter.set_widget_scaling(new_scaling_float)

    def sidebar_button_event(self):
        print("sidebar_button click")


if __name__ == "__main__":
    app = App()
    app.mainloop()
