import json

mac_address1 = '5c:62:8b:80:83:8a'
mac_address2 = '00:0c:43'

def map_vendors(mac_oui):
    with open('../mac-vendors-export.json', 'r', encoding='utf-8') as file:
         data = json.load(file)
         vendors_name = {}
         for line in data:
             vendors_name[line['macPrefix']] = line['vendorName']
         return vendors_name.get(mac_oui.upper()[:8], 'Unknown Type')

print(map_vendors(mac_address1))
