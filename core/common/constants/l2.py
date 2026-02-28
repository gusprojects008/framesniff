EUI48_LENGTH = 6
OUI_LENGTH = 3

LLC_EAPOL = "0x888e"
LLC_IPV4 = "0x0800"
LLC_ARP = "0x0806"
LLC_IPV6 = "0x86dd"
LLC_MESH_CTRL = "0x888f"
LLC_TDLS = "0x890d"
LLC_WAPI = "0x88b4"
LLC_FAST_BSS_TRANSITION = "0x88b5"
LLC_DLS = "0x88b6"
LLC_RAS = "0x8902"
LLC_WMM = "0x88c0"
LLC_QOS_NULL = "0x8903"

LLC_BODY_NAME = {
    LLC_MESH_CTRL: "mesh_ctrl",
    LLC_TDLS: "tdls",
    LLC_WAPI: "wapi",
    LLC_FAST_BSS_TRANSITION: "fast_bss_transition",
    LLC_DLS: "dls",
    LLC_RAS: "robust_av_streaming",
    LLC_WMM: "wmm",
    LLC_QOS_NULL: "qos_null",
}
