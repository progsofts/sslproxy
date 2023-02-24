#include <stdio.h>
#include <string.h>

#define LOG_THREAD(format, args...) do { printf("thread:%d, ", sum); printf(format, ##args); } while (0);
#define LOG(format, args...) do { printf(format, ##args); } while (0);

#define IP_KEY   "ip_key.dat"
#define OLD_PCAP "capture.pcap"
#define NEW_PCAP "captures.pcap"

#define MAX_IP_KEY_RULE     (5000)
#define MAX_PCAP_DATA_FILE  (500 * 1024 * 1024)
#define SINGLE_IP_KEY_LEN   (12)
#define DOUBLE_IP_KEY_LEN   (SINGLE_IP_KEY_LEN * 2)

unsigned char g_KeyRule[MAX_IP_KEY_RULE][DOUBLE_IP_KEY_LEN] = { 0 };
int g_KeyRuleNum = 0;

unsigned char g_FileData[MAX_PCAP_DATA_FILE] = { 0 };
int g_FileDataLen = 0;

struct single_rule {
    unsigned char o[SINGLE_IP_KEY_LEN];
    unsigned char d[SINGLE_IP_KEY_LEN];
};

void read_rule_file(const char* path) {
    FILE *fp;
    g_KeyRuleNum = 0;
    fp = fopen(path, "rb");
    if (fp == NULL)
        return;
    g_KeyRuleNum = fread(g_KeyRule, sizeof(unsigned char), sizeof(g_KeyRule), fp) / DOUBLE_IP_KEY_LEN;
    for (int i = 0; i < g_KeyRuleNum; i++) {
        for (int j = 0; j < DOUBLE_IP_KEY_LEN; j++)
            LOG("%02x ", g_KeyRule[i][j]);
        LOG("\r\n");
    }
    fclose(fp);
    return;
}

void read_data_file(const char* path) {
    FILE* fp;
    g_FileDataLen = 0;
    fp = fopen(path, "rb");
    if (fp == NULL)
        return;
    g_FileDataLen = fread(g_FileData, sizeof(unsigned char), sizeof(g_FileData), fp);
    LOG("Read Data file len: %d\r\n", g_FileDataLen);
    fclose(fp);
    return;
}

void write_data_file(const char* path) {
    FILE* fp;
    fp = fopen(path, "wb");
    if (fp == NULL) {
        g_FileDataLen = 0;
        return;
    }
    g_FileDataLen = fwrite(g_FileData, sizeof(unsigned char), g_FileDataLen, fp);
    LOG("Write Data file len: %d\r\n", g_FileDataLen);
    fclose(fp);
    return;
}

void covert_file(struct single_rule* rule) {
    int pos = 0;
    int covert = 0;
    // TOBE FIX，在文件结束可能越界多读了一点数据，只要文件总长度不超过预置长度，就没问题
    while (pos + SINGLE_IP_KEY_LEN <= g_FileDataLen) {
        while (pos + SINGLE_IP_KEY_LEN <= g_FileDataLen) {
            if (g_FileData[pos] == rule->o[0]) break;
            pos++;
        }
        if (memcmp(&g_FileData[pos], &rule->o[0], SINGLE_IP_KEY_LEN) == 0) {
            memcpy(&g_FileData[pos], &rule->d[0], SINGLE_IP_KEY_LEN);
            covert++;
        }
        pos++;
    };

    LOG("Covert Data time: %d\r\n", covert);
}
 
int main(int argc, char* argv[]) {
    LOG("sslproxy Covert Tools (Version %s %s)\r\n", __DATE__, __TIME__);
    LOG("[L Dest] 127.0.0.1:8888 -> 10.10.10.10:443\r\n");
    LOG("[R Source] ServerIP:443 -> 10.10.10.10:443\r\n");

    LOG("\r\n****** Step 1 Read File: %s ******\r\n", IP_KEY);
    read_rule_file(IP_KEY);

    LOG("\r\n****** Step 2 Read PCAP File: %s ******\r\n", OLD_PCAP);
    read_data_file(OLD_PCAP);

    LOG("\r\n****** Step 3 Covert File Start, Rule Num: %d ******\r\n", g_KeyRuleNum);
    for (int k = 0; k < g_KeyRuleNum; k++)
        covert_file((struct single_rule*)&g_KeyRule[k]);

    LOG("\r\n****** Step 4 Write PCAP File: %s ******\r\n", NEW_PCAP);
    write_data_file(NEW_PCAP);

    LOG("\r\n****** Step 5 Success Store Length: %d ******\r\n", g_FileDataLen);
    return 0;
}