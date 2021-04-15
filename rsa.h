#define ll long long
const ll p1 = 907, p2 = 541; //两个质数,用于RSA
ll gcd(ll a, ll b) //欧几里得算法,用于RSA
{
    return b == 0 ? a : gcd(b, a % b);
}
void exgcd(ll a, ll b, ll &x, ll &y, ll &d) //扩展欧几里得算法,用于RSA
{
    if (!b)
        d = a, x = 1, y = 0;
    else
    {
        exgcd(b, a % b, y, x, d);
        y -= x * (a / b);
    }
}
ll inv(ll t, ll p) //求逆元,用于RSA
{
    ll d, x, y;
    exgcd(t, p, x, y, d);
    return d == 1 ? (x % p + p) % p : -1;
}
ll fpow(ll a, ll b, ll p) //快速幂,用于RSA
{
    ll res = 1;
    while (b)
    {
        if (b & 1)
            res = (res * a) % p;
        a = (a * a) % p;
        b >>= 1;
    }
    return res;
}
ll encrypt(ll m, ll N, ll e) //RSA加密
{
    return fpow(m, e, N);
}
ll decrypt(ll c, ll N, ll d) //RSA解密
{
    return fpow(c, d, N);
}
