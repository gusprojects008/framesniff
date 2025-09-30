#include <iostream>
#include <linux/nl80211.h>
#include <fstream>
#include <vector>

int main() {
    std::cout << "NL80211_CMD_SET_BEACON: " << NL80211_CMD_SET_BEACON << std::endl;
    std::cout << "NL80211_CMD_START_AP: " << NL80211_CMD_START_AP << std::endl;
    std::cout << "NL80211_CMD_NEW_BEACON: " << NL80211_CMD_NEW_BEACON << std::endl;
    std::cout << "NL80211_CMD_STOP_AP: " << NL80211_CMD_STOP_AP << std::endl;
    std::cout << "NL80211_CMD_DEL_BEACON: " << NL80211_CMD_DEL_BEACON << std::endl;
    return 0;
}


