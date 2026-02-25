// cipher.cpp  —  LyaphiCrypt (Hardened Version)

#include <iostream>
#include <vector>
#include <sstream>
#include <iomanip>
#include <cstdint>
#include <cstring>
#include <string>
#include <algorithm>
#include <ctime>
#include <numeric>

using namespace std;

//  SECTION 1 — SHA-256 (self-contained, no external library)

static const uint32_t K256[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,
    0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,
    0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,
    0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,
    0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,
    0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,
    0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,
    0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,
    0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

static inline uint32_t rotr32(uint32_t x, int n){ return (x >> n) | (x << (32-n)); }

struct SHA256Ctx {
    uint32_t state[8];
    uint64_t count;
    uint8_t  buf[64];
};

static void sha256_init(SHA256Ctx &c){
    c.state[0]=0x6a09e667; c.state[1]=0xbb67ae85;
    c.state[2]=0x3c6ef372; c.state[3]=0xa54ff53a;
    c.state[4]=0x510e527f; c.state[5]=0x9b05688c;
    c.state[6]=0x1f83d9ab; c.state[7]=0x5be0cd19;
    c.count=0;
}

static void sha256_compress(SHA256Ctx &c, const uint8_t blk[64]){
    uint32_t w[64], a,b,d,e,f,g,h,s0,s1,ch,maj,t1,t2;
    uint32_t cc = c.state[0]; // alias for brevity
    (void)cc;
    for(int i=0;i<16;i++)
        w[i]=((uint32_t)blk[i*4]<<24)|((uint32_t)blk[i*4+1]<<16)|
             ((uint32_t)blk[i*4+2]<<8)|(uint32_t)blk[i*4+3];
    for(int i=16;i<64;i++){
        s0=rotr32(w[i-15],7)^rotr32(w[i-15],18)^(w[i-15]>>3);
        s1=rotr32(w[i-2],17)^rotr32(w[i-2],19)^(w[i-2]>>10);
        w[i]=w[i-16]+s0+w[i-7]+s1;
    }
    a=c.state[0]; b=c.state[1]; uint32_t cx=c.state[2]; d=c.state[3];
    e=c.state[4]; f=c.state[5]; g=c.state[6]; h=c.state[7];
    for(int i=0;i<64;i++){
        s1=rotr32(e,6)^rotr32(e,11)^rotr32(e,25);
        ch=(e&f)^((~e)&g);
        t1=h+s1+ch+K256[i]+w[i];
        s0=rotr32(a,2)^rotr32(a,13)^rotr32(a,22);
        maj=(a&b)^(a&cx)^(b&cx);
        t2=s0+maj;
        h=g; g=f; f=e; e=d+t1;
        d=cx; cx=b; b=a; a=t1+t2;
    }
    c.state[0]+=a; c.state[1]+=b; c.state[2]+=cx; c.state[3]+=d;
    c.state[4]+=e; c.state[5]+=f; c.state[6]+=g; c.state[7]+=h;
}

static void sha256_update(SHA256Ctx &c, const uint8_t *data, size_t len){
    size_t fill = (size_t)(c.count & 63);
    c.count += len;
    if(fill && fill+len >= 64){
        memcpy(c.buf+fill, data, 64-fill);
        sha256_compress(c, c.buf);
        data += 64-fill; len -= 64-fill; fill = 0;
    }
    while(len >= 64){ sha256_compress(c, data); data+=64; len-=64; }
    if(len) memcpy(c.buf+fill, data, len);
}

static void sha256_final(SHA256Ctx &c, uint8_t digest[32]){
    uint64_t bits = c.count * 8;
    uint8_t pad = 0x80;
    sha256_update(c, &pad, 1);
    pad = 0;
    while((c.count & 63) != 56) sha256_update(c, &pad, 1);
    uint8_t lenb[8];
    for(int i=7;i>=0;i--){ lenb[i]=(uint8_t)(bits & 0xFF); bits>>=8; }
    sha256_update(c, lenb, 8);
    for(int i=0;i<8;i++){
        digest[i*4]  =(uint8_t)(c.state[i]>>24);
        digest[i*4+1]=(uint8_t)(c.state[i]>>16);
        digest[i*4+2]=(uint8_t)(c.state[i]>>8);
        digest[i*4+3]=(uint8_t)(c.state[i]);
    }
}

// one-shot SHA-256
static void sha256(const uint8_t *data, size_t len, uint8_t digest[32]){
    SHA256Ctx c; sha256_init(c);
    sha256_update(c, data, len);
    sha256_final(c, digest);
}

// convenience for strings
static void sha256_str(const string &s, uint8_t digest[32]){
    sha256((const uint8_t*)s.data(), s.size(), digest);
}

//  SECTION 2 — HMAC-SHA256

static void hmac_sha256(const uint8_t *key, size_t klen,
                        const uint8_t *msg, size_t mlen,
                        uint8_t mac[32])
{
    uint8_t k[64] = {};
    if(klen > 64){ sha256(key, klen, k); }
    else { memcpy(k, key, klen); }

    uint8_t ipad[64], opad[64];
    for(int i=0;i<64;i++){ ipad[i]=k[i]^0x36; opad[i]=k[i]^0x5c; }

    // inner hash: SHA256(ipad || msg)
    uint8_t inner[32];
    SHA256Ctx c; sha256_init(c);
    sha256_update(c, ipad, 64);
    sha256_update(c, msg, mlen);
    sha256_final(c, inner);

    // outer hash: SHA256(opad || inner)
    sha256_init(c);
    sha256_update(c, opad, 64);
    sha256_update(c, inner, 32);
    sha256_final(c, mac);
}

//  SECTION 3 — Key Stretching  (10 000 rounds of SHA-256)

// Returns a 32-byte stretched key from the user key + iv
static void stretchKey(const string &key, const string &iv, uint8_t out[32]){
    string combined = key + "||" + iv;
    sha256_str(combined, out);
    for(int i = 0; i < 10000; i++){
        // fold iv into each round to bind stretching to nonce
        uint8_t tmp[32];
        SHA256Ctx c; sha256_init(c);
        sha256_update(c, out, 32);
        sha256_update(c, (const uint8_t*)iv.data(), iv.size());
        sha256_final(c, tmp);
        memcpy(out, tmp, 32);
    }
}

//  SECTION 4 — xorshift128 PRNG  (integer-only, cross-platform)

struct XS128 { uint32_t a,b,c,d; };

static uint32_t xs128_next(XS128 &s){
    uint32_t t = s.d;
    uint32_t x = s.a; x ^= x << 11; x ^= x >> 8; s.a = s.b;
    s.b = s.c; s.c = s.d;
    s.d = x ^ t ^ (t >> 19);
    return s.d;
}

// seed the PRNG from the 32-byte stretched key
static XS128 seedFromKey(const uint8_t stretched[32]){
    XS128 s;
    memcpy(&s.a, stretched,    4);
    memcpy(&s.b, stretched+4,  4);
    memcpy(&s.c, stretched+8,  4);
    memcpy(&s.d, stretched+12, 4);
    if(!s.a) s.a=1; if(!s.b) s.b=2;
    if(!s.c) s.c=3; if(!s.d) s.d=4;
    // warm up
    for(int i=0;i<64;i++) xs128_next(s);
    return s;
}

//  SECTION 5 — Keystream Generation  (no periodic cycle)

static vector<uint8_t> generateKeystream(const string &key,
                                          const string &iv,
                                          int length)
{
    uint8_t stretched[32];
    stretchKey(key, iv, stretched);

    XS128 prng = seedFromKey(stretched);
    vector<uint8_t> stream(length);
    for(int i = 0; i < length; i++){
        uint32_t r = xs128_next(prng);
        // use all 4 bytes progressively to maximise entropy per call
        stream[i] = (uint8_t)((r ^ (r >> 8) ^ (r >> 16) ^ (r >> 24)) & 0xFF);
    }
    return stream;
}

//  SECTION 6 — Key-Derived S-Box  (confusion layer)

// Build a 256-byte permutation unique to this key.
// Uses Fisher-Yates shuffle seeded from the stretched key.
static void buildSBox(const uint8_t stretched[32],
                      uint8_t sbox[256], uint8_t isbox[256])
{
    // initialise identity permutation
    for(int i=0;i<256;i++) sbox[i]=(uint8_t)i;

    // derive a second xorshift stream for shuffling
    // (different from encryption stream — we mix in a domain tag)
    uint8_t taggedKey[36];
    memcpy(taggedKey, stretched, 32);
    taggedKey[32]='S'; taggedKey[33]='B'; taggedKey[34]='O'; taggedKey[35]='X';
    uint8_t sboxSeed[32];
    sha256(taggedKey, 36, sboxSeed);

    XS128 rng;
    memcpy(&rng.a, sboxSeed,    4); memcpy(&rng.b, sboxSeed+4,  4);
    memcpy(&rng.c, sboxSeed+8,  4); memcpy(&rng.d, sboxSeed+12, 4);
    if(!rng.a) rng.a=1; if(!rng.b) rng.b=2;
    if(!rng.c) rng.c=3; if(!rng.d) rng.d=4;
    for(int i=0;i<64;i++) xs128_next(rng);

    // Fisher-Yates shuffle
    for(int i=255;i>0;i--){
        uint32_t j = xs128_next(rng) % (uint32_t)(i+1);
        swap(sbox[i], sbox[j]);
    }

    // build inverse S-Box
    for(int i=0;i<256;i++) isbox[sbox[i]]=i;
}

//  SECTION 7 — Encryption  (XOR → S-Box → Diffusion)

// Append HMAC-SHA256 (32 bytes) as authentication tag
vector<uint8_t> encrypt_with_hmac(const string &pt,
                                   const string &key,
                                   const string &iv)
{
    // --- compute S-Box ---
    uint8_t stretched[32];
    stretchKey(key, iv, stretched);
    uint8_t sbox[256], isbox[256];
    buildSBox(stretched, sbox, isbox);

    // --- compute HMAC over plaintext ---
    uint8_t mac[32];
    hmac_sha256((const uint8_t*)key.data(), key.size(),
                (const uint8_t*)pt.data(),  pt.size(), mac);

    // --- assemble: plaintext || HMAC ---
    string ptWithMac = pt;
    for(int i=0;i<32;i++) ptWithMac.push_back((char)mac[i]);

    int n = (int)ptWithMac.size();

    // --- keystream ---
    auto ks = generateKeystream(key, iv, n);

    // --- Encryption: XOR → S-Box → diffusion ---
    vector<uint8_t> ct(n);
    uint8_t prev = 0xA5; // diffusion initialisation vector (fixed, public)
    for(int i = 0; i < n; i++){
        uint8_t step1 = (uint8_t)ptWithMac[i] ^ ks[i];   // 1. XOR with keystream
        uint8_t step2 = sbox[step1];                       // 2. S-Box substitution
        uint8_t step3 = step2 ^ prev;                      // 3. Diffusion: XOR with previous cipher byte
        ct[i] = step3;
        prev  = step3;
    }
    return ct;
}

//  SECTION 8 — Decryption  (reverse: un-diffuse → inv-S-Box → XOR)

string decrypt_with_hmac(const vector<uint8_t> &ct,
                          const string &key,
                          const string &iv)
{
    int n = (int)ct.size();
    if(n < 32) return ""; // too short to contain HMAC

    // --- compute S-Box ---
    uint8_t stretched[32];
    stretchKey(key, iv, stretched);
    uint8_t sbox[256], isbox[256];
    buildSBox(stretched, sbox, isbox);

    // --- keystream ---
    auto ks = generateKeystream(key, iv, n);

    // --- Decryption: un-diffuse → inv-S-Box → XOR ---
    string ptWithMac;
    ptWithMac.resize(n);
    uint8_t prev = 0xA5;
    for(int i = 0; i < n; i++){
        uint8_t step1 = ct[i] ^ prev;                      // 1. Undo diffusion
        uint8_t step2 = isbox[step1];                       // 2. Inverse S-Box
        uint8_t step3 = step2 ^ ks[i];                     // 3. Undo XOR
        ptWithMac[i] = (char)step3;
        prev = ct[i]; // use ciphertext (same as encoder used)
    }

    // --- extract HMAC (last 32 bytes) ---
    if(n < 32) return "";
    string pt = ptWithMac.substr(0, n - 32);
    uint8_t receivedMac[32];
    for(int i=0;i<32;i++) receivedMac[i]=(uint8_t)ptWithMac[n-32+i];

    // --- verify HMAC ---
    uint8_t expectedMac[32];
    hmac_sha256((const uint8_t*)key.data(), key.size(),
                (const uint8_t*)pt.data(),  pt.size(), expectedMac);

    // constant-time compare to prevent timing attacks
    uint8_t diff = 0;
    for(int i=0;i<32;i++) diff |= (receivedMac[i] ^ expectedMac[i]);
    if(diff != 0) return ""; // HMAC mismatch: wrong key or tampered data

    return pt;
}

//  SECTION 9 — IV Generation  (key + timestamp → SHA-256)

string generateIVFromKey(const string &key){
    uint64_t now = (uint64_t)time(NULL);
    string s = key + "::iv::" + to_string(now);
    uint8_t digest[32];
    sha256_str(s, digest);
    // encode as hex string for safe transport
    ostringstream oss;
    for(int i=0;i<16;i++) oss << hex << setw(2) << setfill('0') << (int)digest[i];
    return oss.str();
}

//  SECTION 10 — Argument Helpers

string getArg(int argc, char* argv[], const string &flag){
    for(int i=1;i<argc-1;++i)
        if(flag==argv[i]) return string(argv[i+1]);
    return "";
}

bool hasFlag(int argc, char* argv[], const string &flag){
    for(int i=1;i<argc;++i)
        if(flag==argv[i]) return true;
    return false;
}

// Read everything from stdin into a string (used to bypass OS argument length limits)
string readStdin(){
    string result, line;
    bool first = true;
    while(getline(cin, line)){
        if(!first) result += '\n';
        result += line;
        first = false;
    }
    return result;
}

//  SECTION 11 — main

int main(int argc, char* argv[]){

    // ---- interactive mode ----
    if(argc == 1){
        cout << "==== LyaphiCrypt ====\n";
        string key, mode;
        cout << "Enter key: "; getline(cin, key);
        cout << "Encrypt or Decrypt (E/D): "; cin >> mode; cin.ignore();

        if(mode=="E"||mode=="e"){
            string plaintext;
            cout << "Enter plaintext: "; getline(cin, plaintext);
            string iv = generateIVFromKey(key);
            auto ct = encrypt_with_hmac(plaintext, key, iv);
            cout << iv << "\n";
            for(size_t i=0;i<ct.size();++i){ if(i) cout<<" "; cout<<(int)ct[i]; }
            cout << "\n";

        } else if(mode=="D"||mode=="d"){
            string iv; cout<<"Enter IV: "; getline(cin,iv);
            string line; cout<<"Enter ciphertext bytes: "; getline(cin,line);
            stringstream ss(line); vector<uint8_t> ct; int b;
            while(ss>>b) ct.push_back((uint8_t)b);
            string pt = decrypt_with_hmac(ct, key, iv);
            if(pt.empty()){ cerr<<"Error: Decryption/authentication failed.\n"; return 1; }
            cout << pt << "\n";

        } else { cout<<"Invalid option.\n"; }
        return 0;
    }

    // ---- non-interactive (called by server.py) ----
    string mode   = getArg(argc, argv, "--mode");
    string key    = getArg(argc, argv, "--key");
    string iv     = getArg(argc, argv, "--iv");
    bool useStdin = hasFlag(argc, argv, "--stdin");

    if(mode=="E"||mode=="e"){
        // Read plaintext from stdin (piped) to support large inputs (10 000+ chars)
        string text = useStdin ? readStdin() : getArg(argc, argv, "--text");
        if(text.size() > 10000){
            cerr << "Error: Input exceeds 10000 character limit (got " << text.size() << ").\n";
            return 1;
        }
        if(iv.empty()) iv = generateIVFromKey(key);
        auto ct = encrypt_with_hmac(text, key, iv);
        stringstream ss;
        for(size_t i=0;i<ct.size();++i){ if(i) ss<<' '; ss<<(int)ct[i]; }
        cout << iv << "\n" << ss.str() << "\n";
        return 0;
    }

    if(mode=="D"||mode=="d"){
        // Read ciphertext from stdin (piped) to support large inputs
        string cipher = useStdin ? readStdin() : getArg(argc, argv, "--cipher");
        stringstream ssc(cipher); vector<uint8_t> ct; int b;
        while(ssc>>b) ct.push_back((uint8_t)b);
        string pt = decrypt_with_hmac(ct, key, iv);
        if(pt.empty()){ cerr<<"Error: Decryption/authentication failed.\n"; return 1; }
        cout << pt << "\n";
        return 0;
    }

    cerr<<"Invalid arguments. Use interactive mode or pass --mode, --key, --iv [--stdin | --text/--cipher]\n";
    return 1;
}
