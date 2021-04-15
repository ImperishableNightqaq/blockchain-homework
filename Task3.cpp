#include <bits/stdc++.h>
#include "sha.h" //SHA代码在这里面
#include "rsa.h" //RSA代码在这里面
#define ll long long
#define INFL 9223372036854775807
using namespace std;
const int p = 2;          //p表示4bit的个数
const int num_trans = 50; //交易的个数
const int num_users = 10; //用户的个数
struct User
{
    ll pub_key[2]; //公钥
    ll pri_key[2]; //私钥
} user[num_users + 5];
struct Transaction
{
    ll From_addr;
    ll To_addr;
    ll Amount;
    ll Signature[3];
    Transaction(ll a = 0, ll b = 0, ll c = 0) : From_addr(a), To_addr(b), Amount(c){};
} Trans[num_trans + 5];
struct Blockdata
{
    Blockdata *ptr;
    ll cnt_Tran;
    ll chain_version;
    unsigned char pre_hash[32];
    ll conbase[4]; //公钥
    ll nonce1, nonce2;
    Transaction t[105];
};
unsigned char tmp_hash[32];
unsigned char in[16];
unsigned char out[64];
void Init() //生成每个用户的密钥
{
    int cnt = 0;
    ll N = p1 * p2;
    ll phi = (p1 - 1) * (p2 - 1);
    for (ll e = 2; e < phi; e++)
    {
        if (cnt == 10)
            return;
        if (gcd(N, e) == 1)
        {
            ll d = inv(e, phi);
            if (d == -1)
                continue;
            if ((((e % phi) * (d % phi)) % phi) != 1)
                continue;
            else
            {
                user[cnt].pub_key[0] = N;
                user[cnt].pub_key[1] = e;
                user[cnt].pri_key[0] = N;
                user[cnt].pri_key[1] = d;
            }
            cnt++;
        }
    }
}
void Maketran() //随机生成交易记录
{
    default_random_engine e;                     //随机数生成器
    e.seed(unsigned(time(0)));                   //设置随机数生成种子
    uniform_int_distribution<unsigned> u(1, 10); //设置随机数生成范围
    for (int i = 1; i <= num_trans; i++)
    {
        ll from = u(e);
        ll to = u(e);
        ll amount = u(e);
        ll c1 = encrypt(from, user[from - 1].pri_key[0], user[from - 1].pri_key[1]); //用from的私钥加密
        ll c2 = encrypt(to, user[from - 1].pri_key[0], user[from - 1].pri_key[1]);
        ll c3 = encrypt(amount, user[from - 1].pri_key[0], user[from - 1].pri_key[1]);
        ll m1 = decrypt(c1, user[from - 1].pub_key[0], user[from - 1].pub_key[1]); //用from的公钥解密
        ll m2 = decrypt(c2, user[from - 1].pub_key[0], user[from - 1].pub_key[1]);
        ll m3 = decrypt(c3, user[from - 1].pub_key[0], user[from - 1].pub_key[1]);
        if (m1 == from && m2 == to && m3 == amount) //对交易记录进行验证
        {
            Transaction tmpT(from, to, amount);
            tmpT.Signature[0] = c1;
            tmpT.Signature[1] = c2;
            tmpT.Signature[2] = c3;
            Trans[i] = tmpT;
        }
        else
            puts("Wrong!");
    }
}
signed main()
{
    Init();
    Maketran();
    Blockdata *head = 0;
    Blockdata *pre = 0;
    int cnt = 0;
    for (ll a = 0; a <= INFL; a++)
    {
        for (ll b = 0; b <= INFL; b++)
        {
            ll tmpa = a, tmpb = b;
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
            if (check(p, out)) //找到了区块
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
                    tmp->conbase[0] = user[cnt - 1].pub_key[0];
                    tmp->conbase[1] = user[cnt - 1].pub_key[1];
                    tmp->chain_version = cnt;
                    for (int i = 1; i <= num_trans; i++)
                        if (Trans[i].From_addr == cnt || Trans[i].To_addr == cnt)
                            (tmp->t)[++(tmp->cnt_Tran)] = Trans[i];
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
                    tmp->conbase[0] = user[cnt - 1].pub_key[0];
                    tmp->conbase[1] = user[cnt - 1].pub_key[1];
                    tmp->chain_version = cnt;
                    for (int i = 1; i <= num_trans; i++)
                        if (Trans[i].From_addr == cnt || Trans[i].To_addr == cnt)
                            (tmp->t)[++(tmp->cnt_Tran)] = Trans[i];
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
        printf("cnt of Transaction=%lld\n",tmp->cnt_Tran);
    }
    return 0;
}