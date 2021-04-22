#include <bits/stdc++.h>
#include <WinSock2.h>
#define ull unsigned long long
#define INFU 18446744073709551615
#define rightrotate(w, n) ((w >> n) | (w) << (32 - (n)))
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define copy_uint32(p, val) *((uint32_t *)p) = __builtin_bswap32((val))
#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#define copy_uint32(p, val) *((uint32_t *)p) = (val)
#else
#error "Unsupported target architecture endianess!"
#endif
#pragma comment(lib, "ws2_32.lib") //加载 ws2_32.dll
using namespace std;
struct Transaction
{
    unsigned char From_addr[32];
    unsigned char To_addr[32];
    ull Amount;
    unsigned char Signature[32];
};
struct Blockdata
{
    Blockdata *ptr;
    ull chain_version;
    unsigned char pre_hash[32];
    unsigned char conbase[32];
    ull nonce1, nonce2;
    ull amount;
    Transaction t[105];
} test;
unsigned char tmp_hash[32];
unsigned char in[16];
unsigned char out[64];
static const uint32_t k[64] =
    {
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};
void sha256(const unsigned char *data, size_t len, unsigned char *out)
{
    uint32_t h0 = 0x6a09e667;
    uint32_t h1 = 0xbb67ae85;
    uint32_t h2 = 0x3c6ef372;
    uint32_t h3 = 0xa54ff53a;
    uint32_t h4 = 0x510e527f;
    uint32_t h5 = 0x9b05688c;
    uint32_t h6 = 0x1f83d9ab;
    uint32_t h7 = 0x5be0cd19;
    int r = (int)(len * 8 % 512);
    int append = ((r < 448) ? (448 - r) : (448 + 512 - r)) / 8;
    size_t new_len = len + append + 8;
    unsigned char buf[new_len];
    for (int i = 0; i < append; i++)
        (buf + len)[i] = 0;
    if (len > 0)
    {
        memcpy(buf, data, len);
    }
    buf[len] = (unsigned char)0x80;
    uint64_t bits_len = len * 8;
    for (int i = 0; i < 8; i++)
    {
        buf[len + append + i] = (bits_len >> ((7 - i) * 8)) & 0xff;
    }
    uint32_t w[64];
    for (int i = 0; i < 64; i++)
        w[i] = 0;
    size_t chunk_len = new_len / 64;
    for (int idx = 0; idx < chunk_len; idx++)
    {
        uint32_t val = 0;
        for (int i = 0; i < 64; i++)
        {
            val = val | (*(buf + idx * 64 + i) << (8 * (3 - i)));
            if (i % 4 == 3)
            {
                w[i / 4] = val;
                val = 0;
            }
        }
        for (int i = 16; i < 64; i++)
        {
            uint32_t s0 = rightrotate(w[i - 15], 7) ^ rightrotate(w[i - 15], 18) ^ (w[i - 15] >> 3);
            uint32_t s1 = rightrotate(w[i - 2], 17) ^ rightrotate(w[i - 2], 19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16] + s0 + w[i - 7] + s1;
        }
        uint32_t a = h0;
        uint32_t b = h1;
        uint32_t c = h2;
        uint32_t d = h3;
        uint32_t e = h4;
        uint32_t f = h5;
        uint32_t g = h6;
        uint32_t h = h7;
        for (int i = 0; i < 64; i++)
        {
            uint32_t s_1 = rightrotate(e, 6) ^ rightrotate(e, 11) ^ rightrotate(e, 25);
            uint32_t ch = (e & f) ^ (~e & g);
            uint32_t temp1 = h + s_1 + ch + k[i] + w[i];
            uint32_t s_0 = rightrotate(a, 2) ^ rightrotate(a, 13) ^ rightrotate(a, 22);
            uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
            uint32_t temp2 = s_0 + maj;
            h = g;
            g = f;
            f = e;
            e = d + temp1;
            d = c;
            c = b;
            b = a;
            a = temp1 + temp2;
        }
        h0 += a;
        h1 += b;
        h2 += c;
        h3 += d;
        h4 += e;
        h5 += f;
        h6 += g;
        h7 += h;
    }
    copy_uint32(out, h0);
    copy_uint32(out + 4, h1);
    copy_uint32(out + 8, h2);
    copy_uint32(out + 12, h3);
    copy_uint32(out + 16, h4);
    copy_uint32(out + 20, h5);
    copy_uint32(out + 24, h6);
    copy_uint32(out + 28, h7);
    for (int i = 4; i <= 7; i++)
        out[i] = out[i + 12];
}
bool check(int p) //p表示4bit的个数
{
    bool ok = 1;
    if (p % 2 == 0)
    {
        for (int i = 0; i < p / 2; i++)
            if (out[i] != 0)
                ok = 0;
    }
    else
    {
        for (int i = 0; i < p / 2; i++)
            if (out[i] != 0)
                ok = 0;
        if (out[p / 2] >= 16)
            ok = 0;
    }
    return ok;
}
int main()
{
    //初始化DLL
    WSADATA wsaData;
    WSAStartup(MAKEWORD(2, 2), &wsaData);
    //创建套接字
    SOCKET sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
    //向服务器发起请求
    sockaddr_in sockAddr;
    memset(&sockAddr, 0, sizeof(sockAddr)); //每个字节都用0填充
    sockAddr.sin_family = PF_INET;
    sockAddr.sin_addr.s_addr = inet_addr("127.0.0.1");
    sockAddr.sin_port = htons(1234);
    connect(sock, (SOCKADDR *)&sockAddr, sizeof(SOCKADDR));
    //接收服务器传回的数据
    char szBuffer[MAXBYTE] = {0};
    recv(sock, szBuffer, MAXBYTE, NULL);
    int len = strlen(szBuffer);
    int p = 0;
    for (int i = 0; i < len; i++)
    {
        p += szBuffer[i] - '0';
        if (i != len - 1)
            p *= 10;
    }
    printf("p=%d\n", p);
    Blockdata *head = 0;
    Blockdata *pre = 0;
    int cnt = 0;
    for (ull a = 0; a <= INFU; a++)
    {
        for (ull b = 0; b <= INFU; b++)
        {
            ull tmpa = a, tmpb = b;
            for (int i = 0; i < 8; i++)
            {
                in[i] = tmpa % 256;
                tmpa /= 256;
            }
            for (int i = 8; i < 16; i++)
            {
                in[i] = tmpb % 256;
                tmpb /= 256;
            }
            sha256(in, 16, out);
            if (check(p))
            {
                cnt++;
                if (head == 0)
                {
                    Blockdata *tmp = new Blockdata();
                    tmp->nonce1 = a;
                    tmp->nonce2 = b;
                    head = tmp;
                    memset(tmp->pre_hash, sizeof(tmp->pre_hash), 0);
                    for (int k = 0; k < 16; k++)
                        tmp_hash[k] = out[k];
                    pre = tmp;
                }
                else
                {
                    Blockdata *tmp = new Blockdata();
                    pre->ptr = tmp;
                    tmp->nonce1 = a;
                    tmp->nonce2 = b;
                    for (int k = 0; k < 16; k++)
                        (tmp->pre_hash)[k] = tmp_hash[k];
                    for (int k = 0; k < 16; k++)
                        tmp_hash[k] = out[k];
                    pre = tmp;
                }
            }
            memset(in, sizeof(in), 0);
            memset(out, sizeof(out), 0);
            if (cnt == 10)
                goto label;
        }
    }
label:;
    Blockdata *tmp = 0;
    for (int i = 0; i < 10; i++)
    {
        if (tmp == 0)
            tmp = head;
        else
            tmp = tmp->ptr;
        cout << "nonce1=" << tmp->nonce1 << endl;
        cout << "nonce2=" << tmp->nonce2 << endl;
        printf("hash=");
        for (int j = 0; j < 8; j++)
        {
            if ((tmp->pre_hash)[j] < 16)
                printf("0");
            printf("%x ", (tmp->pre_hash)[j]);
        }
        cout << endl;
    }
    //关闭套接字
    closesocket(sock);
    //终止使用 DLL
    WSACleanup();
    system("pause");
    return 0;
}
