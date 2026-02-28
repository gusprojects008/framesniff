MGMT = 0
CTRL = 1
DATA = 2

FRAME_TYPES = {
    MGMT: "Management",
    CTRL: "Control",
    DATA: "Data",
}

MGMT_ASSOCIATION_REQUEST = 0
MGMT_ASSOCIATION_RESPONSE = 1
MGMT_REASSOCIATION_REQUEST = 2
MGMT_REASSOCIATION_RESPONSE = 3
MGMT_PROBE_REQUEST = 4
MGMT_PROBE_RESPONSE = 5
MGMT_TIMING_ADVERTISEMENT = 6
MGMT_BEACON = 8
MGMT_ATIM = 9
MGMT_DISASSOCIATION = 10
MGMT_AUTHENTICATION = 11
MGMT_DEAUTHENTICATION = 12
MGMT_ACTION = 13
MGMT_ACTION_NO_ACK = 14

CTRL_BLOCK_ACK_REQUEST = 8
CTRL_BLOCK_ACK = 9
CTRL_PS_POLL = 10
CTRL_RTS = 11
CTRL_CTS = 12
CTRL_ACK = 13
CTRL_CF_END = 14
CTRL_CF_END_ACK = 15

DATA_DATA = 0
DATA_DATA_CF_ACK = 1
DATA_DATA_CF_POLL = 2
DATA_DATA_CF_ACK_CF_POLL = 3
DATA_NULL = 4
DATA_CF_ACK = 5
DATA_CF_POLL = 6
DATA_CF_ACK_CF_POLL = 7
DATA_QOS_DATA = 8
DATA_QOS_DATA_CF_ACK = 9
DATA_QOS_DATA_CF_POLL = 10
DATA_QOS_DATA_CF_ACK_CF_POLL = 11
DATA_QOS_NULL = 12
DATA_RESERVED = 13
DATA_QOS_CF_POLL = 14
DATA_QOS_CF_ACK_CF_POLL = 15

FRAME_SUBTYPES = {
    MGMT: {
        MGMT_ASSOCIATION_REQUEST: "Association Request",
        MGMT_ASSOCIATION_RESPONSE: "Association Response",
        MGMT_REASSOCIATION_REQUEST: "Reassociation Request",
        MGMT_REASSOCIATION_RESPONSE: "Reassociation Response",
        MGMT_PROBE_REQUEST: "Probe Request",
        MGMT_PROBE_RESPONSE: "Probe Response",
        MGMT_TIMING_ADVERTISEMENT: "Timing Advertisement",
        MGMT_BEACON: "Beacon",
        MGMT_ATIM: "ATIM",
        MGMT_DISASSOCIATION: "Disassociation",
        MGMT_AUTHENTICATION: "Authentication",
        MGMT_DEAUTHENTICATION: "Deauthentication",
        MGMT_ACTION: "Action",
        MGMT_ACTION_NO_ACK: "Action No Ack",
    },
    CTRL: {
        CTRL_BLOCK_ACK_REQUEST: "Block Ack Request",
        CTRL_BLOCK_ACK: "Block Ack",
        CTRL_PS_POLL: "PS-Poll",
        CTRL_RTS: "RTS",
        CTRL_CTS: "CTS",
        CTRL_ACK: "ACK",
        CTRL_CF_END: "CF-End",
        CTRL_CF_END_ACK: "CF-End+CF-Ack",
    },
    DATA: {
        DATA_DATA: "Data",
        DATA_DATA_CF_ACK: "Data+CF-Ack",
        DATA_DATA_CF_POLL: "Data+CF-Poll",
        DATA_DATA_CF_ACK_CF_POLL: "Data+CF-Ack+CF-Poll",
        DATA_NULL: "Null",
        DATA_CF_ACK: "CF-Ack",
        DATA_CF_POLL: "CF-Poll",
        DATA_CF_ACK_CF_POLL: "CF-Ack+CF-Poll",
        DATA_QOS_DATA: "QoS Data",
        DATA_QOS_DATA_CF_ACK: "QoS Data+CF-Ack",
        DATA_QOS_DATA_CF_POLL: "QoS Data+CF-Poll",
        DATA_QOS_DATA_CF_ACK_CF_POLL: "QoS Data+CF-Ack+CF-Poll",
        DATA_QOS_NULL: "QoS Null",
        DATA_RESERVED: "Reserved",
        DATA_QOS_CF_POLL: "QoS CF-Poll",
        DATA_QOS_CF_ACK_CF_POLL: "QoS CF-Ack+CF-Poll",
    },
}

TAG_SSID = 0
TAG_SUPPORTED_RATES = 1
TAG_CURRENT_CHANNEL = 3
TAG_TIM = 5
TAG_COUNTRY = 7
TAG_QBSS_LOAD = 11
TAG_POWER_CONSTRAINT = 32
TAG_TPC_REPORT = 35
TAG_ERP = 42
TAG_HT_CAPABILITIES = 45
TAG_RM_ENABLED_CAPABILITIES = 70
TAG_RSN_INFORMATION = 48
TAG_EXTENDED_SUPPORTED_RATES = 50
TAG_EXTENDED_CAPABILITIES = 127
TAG_VENDOR_SPECIFIC = 221

RSN_CIPHER_WEP40 = 1
RSN_CIPHER_TKIP = 2
RSN_CIPHER_CCMP = 4
RSN_CIPHER_WEP104 = 5
RSN_CIPHER_GCMP = 8
RSN_AKM_8021X = 1
RSN_AKM_PSK = 2
RSN_AKM_FT_8021X = 3
RSN_AKM_FT_PSK = 4
RSN_AKM_SAE = 8

EAPOL_REPLAY_COUNTER_LENGTH = 8
EAPOL_NONCE_LENGTH = 32
EAPOL_KEY_IV_LENGTH = 16
EAPOL_KEY_RSC_LENGTH = 8
EAPOL_KEY_ID_LENGTH = 8
EAPOL_MIC_LENGTH = 16
EAPOL_KEY_DATA_LENGTH_FIELD = 2
EAPOL_PMKID_LENGTH = 16

OUI_MICROSOFT = "00:50:f2"
MS_VENDOR_WPA = 1
MS_VENDOR_WPS = 4
MS_VENDOR_WMM_WME = 2
MS_VENDOR_WMM_PARAM = 2
MS_VENDOR_WMM_INFO = 2
MS_VENDOR_WMM_P2P = 4

OUI_IEEE_80211 = "00:0f:ac"
RSN_VENDOR_RSN_IE = 1
RSN_VENDOR_RSN_IE_ALT = 2
RSN_VENDOR_PMKID = 4

OUI_WFA = "50:6f:9a"
WFA_VENDOR_WPS = 4
WFA_VENDOR_P2P = 9
WFA_VENDOR_HS20 = 16
WFA_VENDOR_OSEN = 18

OUI_MEDIATEK = "00:0c:43"
OUI_BROADCOM = "00:10:18"
OUI_ATHEROS = "00:03:7f"

VENDOR_DESCRIPTION = {
    OUI_MICROSOFT: {
        MS_VENDOR_WPS: "Wi-Fi Alliance WPS",
        MS_VENDOR_WPA: "Microsoft WPA",
        MS_VENDOR_WMM_WME: "Microsoft WMM",
    },
    OUI_IEEE_80211: {
        RSN_VENDOR_RSN_IE: "RSN Information",
        RSN_VENDOR_RSN_IE_ALT: "RSN Information",
        RSN_VENDOR_PMKID: "PMKID",
    },
    OUI_WFA: {
        WFA_VENDOR_WPS: "Wi-Fi Alliance WPS",
        WFA_VENDOR_P2P: "Wi-Fi Alliance P2P",
        WFA_VENDOR_HS20: "Wi-Fi Alliance Hotspot 2.0",
        WFA_VENDOR_OSEN: "Wi-Fi Alliance OSEN",
    },
    OUI_MEDIATEK: "MediaTek Inc",
    OUI_BROADCOM: "Broadcom",
    OUI_ATHEROS: "Atheros"
}

WPS_ATTRIBUTE_IDS = {
    "version": 0x104A,
    "device_name": 0x1012,
    "device_password_id": 0x1011,
    "config_methods": 0x1008,
    "manufacturer": 0x1021,
    "model_name": 0x1023,
    "model_number": 0x1024,
    "wps_state": 0x1044,
    "uuid_e": 0x1047,
    "rf_bands": 0x103C,
    "vendor_extension": 0x1049,
    "primary_device_type": 0x1054,
    "selected_registrar": 0x1057,
    "selected_registrar_config_methods": 0x1053,
    "public_key": 0x100d,
    "network_key": 0x1042,
    "network_key_index": 0x1041,
    "ap_setup_locked": 0x1057,
    "message_type": 0x101a,
    "mac_address": 0x1020,
    "response_type": 0x103B,
    "registrar_config_methods": 0x103e,
    "version2": 0x1010,
    "ssid": 0x1045,
    "serial_number": 0x1022,
    "os_version": 0x103b,
    "association_state": 0x1033,
}

WPS_CONFIGURATION_STATES = {
    "not_configured": 0x01,
    "configured": 0x02,
}

WPS_MESSAGE_TYPES = {
    "m4_message": 0x04,
    "m5_message": 0x05,
    "m6_message": 0x06,
    "m7_message": 0x07,
    "m8_message": 0x08,
    "wsc_ack": 0x0b,
    "wsc_nack": 0x0c,
    "wsc_done": 0x0d,
}

WPS_RESPONSE_TYPES = {
    "enrollee_info": 0x00,
    "enrollee": 0x01,
    "registrar": 0x02,
    "ap": 0x03,
}

WPS_RF_BANDS = {
    "2.4ghz": 0x01,
    "5ghz": 0x02,
    "2.4ghz_and_5ghz": 0x03,
}

WPS_CONFIG_METHODS = {
    "usb": 0x0001,
    "ethernet": 0x0002,
    "label": 0x0004,
    "display": 0x0008,
    "external_nfc_token": 0x0010,
    "integrated_nfc_token": 0x0020,
    "nfc_interface": 0x0040,
    "push_button": 0x0080,
    "keypad": 0x0100,
}

WPS_DEVICE_PASSWORD_IDS = {
    "default": 0x0000,
    "user_specified": 0x0001,
    "machine_specified": 0x0002,
    "rekey": 0x0003,
    "push_button": 0x0004,
    "registrar_specified": 0x0005,
}

WPS_DEVICE_CATEGORIES = {
    "computer": 0x0001,
    "input_device": 0x0002,
    "print_scan_fax_copy": 0x0003,
    "camera": 0x0004,
    "storage": 0x0005,
    "network_infrastructure": 0x0006,
    "display": 0x0007,
    "multimedia": 0x0008,
    "gaming": 0x0009,
    "telephone": 0x000a,
    "audio": 0x000b,
    "other": 0x000f,
}
