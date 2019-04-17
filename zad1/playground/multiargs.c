
#define I1      0x10111213
#define L1      0x10111413L
#define LL1     0x4044424344454647LL
#define U1      0xf0f1f2f3U
#define UL1     0xe0e1e2e3LU
#define ULL1    0xf0f1f2f3f4f5f6f7LLU
#define I2      0x10111212
#define L2      0x10111412L
#define LL2     0x1011121314151616LL
#define U2      0xf0f1f2f2U
#define UL2     0xe0e1e2e2LU
#define ULL2    0xf0f1f2f3f4f5f6f6LLU
#define LL_RET  0xfeedfacecafebeedLL

static long long validate(int i1, long l1, long long ll1, unsigned int ui1,
                          unsigned long ul1, unsigned long long ull1, int i2, long l2,
                          long long ll2, unsigned int ui2, unsigned long ul2,
                          unsigned long long ull2) {
    if (i1 != I1 || l1 != L1 || ll1 != LL1 || ui1 != U1 || ul1 != UL1 || ull1 != ULL1 || i2 != I2 || l2 != L2 || ll2 != LL2 || ui2 != U2 || ul2 != UL2 || ull2 != ULL2)
        return -1;
    return LL_RET;
}

int main() {
    int a[30];
    a[29] = 5;
    validate(I1, L1, LL1, U1, UL1, ULL1, I2, L2, LL2, U2, UL2, ULL2);
    return 0;
}