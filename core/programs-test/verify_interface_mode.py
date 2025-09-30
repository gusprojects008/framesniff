import subprocess

def identify_interfaces_mode(interface):
    try:
       informations_iface = subprocess.run(['iwconfig', interface], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=False)
       stdout_info = informations_iface.stdout.decode('utf-8')
      
       if "Mode:Monitor" in informations_iface.stdout.decode('utf-8'):
          print(f"Interface: {interface} is in Monitor Mode (:")
       else:
           print(f"The {interface} it is not Monitor mode ):")
       
    except Exception as error:
           print(f"Error ): it was not possible identify interface mode... {str(error)}")

iface = input("Type it interface: ")

identify_interfaces_mode(iface)
