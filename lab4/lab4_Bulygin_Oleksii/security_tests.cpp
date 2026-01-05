/**
 * Lab 4: Security Analysis of Undeniable Digital Signatures
 * Chaum-van Antwerpen Protocol - Attack Demonstrations
 * Author: Bulygin Oleksii
 */

#include "undeniable_sig.h"
#include <iostream>
#include <iomanip>
#include <sstream>
#include <chrono>
#include <cassert>
#include <vector>
#include <cmath>

using namespace std;
using namespace std::chrono;
using namespace CryptoPP;

// ============================================================================
// UTILITIES
// ============================================================================

void printHeader(const string& title) {
    cout << "\n" << string(60, '=') << "\n  " << title << "\n" << string(60, '=') << endl;
}

void printTest(const string& name, bool passed) {
    cout << "  [" << (passed ? "PASS" : "FAIL") << "] " << name << endl;
}

UndeniableSignature::KeyPair generateSmallKeys(size_t bitSize) {
    UndeniableSignature::KeyPair keys;
    AutoSeededRandomPool rng;
    Integer q, p, g;
    
    do {
        q.Randomize(rng, bitSize - 1);
        q.SetBit(bitSize - 2);
        q.SetBit(0);
        if (!IsPrime(q)) continue;
        p = 2 * q + 1;
    } while (!IsPrime(p));
    
    Integer h;
    do {
        h.Randomize(rng, Integer::Two(), p - 1);
        g = a_exp_b_mod_c(h, Integer::Two(), p);
    } while (g == Integer::One());
    
    keys.pub.p = p; keys.pub.q = q; keys.pub.g = g;
    keys.priv.p = p; keys.priv.q = q; keys.priv.g = g;
    keys.priv.x.Randomize(rng, Integer::One(), q - 1);
    keys.pub.y = a_exp_b_mod_c(g, keys.priv.x, p);
    
    return keys;
}

// ATTACK 1: BRUTE-FORCE DLP

struct BruteForceResult {
    bool found;
    Integer x;
    uint64_t attempts;
    double timeMs;
};

BruteForceResult bruteForceDiscreteLog(const Integer& g, const Integer& y, 
                                        const Integer& p, const Integer& maxAttempts) {
    BruteForceResult result{false, Integer::Zero(), 0, 0};
    auto start = high_resolution_clock::now();
    
    Integer current = Integer::One();
    Integer x = Integer::Zero();
    
    while (x < maxAttempts) {
        result.attempts++;
        if (current == y) { result.found = true; result.x = x; break; }
        current = a_times_b_mod_c(current, g, p);
        x++;
    }
    
    result.timeMs = duration_cast<microseconds>(high_resolution_clock::now() - start).count() / 1000.0;
    return result;
}

void test_BruteForceAttack() {
    printHeader("ATTACK 1: Brute-Force DLP");
    
    vector<size_t> keySizes = {20, 24, 26};  // 26-bit is max practical for demo
    double lastTimePerAttempt = 0;
    
    for (auto bits : keySizes) {
        cout << "\n  " << bits << "-bit key:" << endl;
        auto keys = generateSmallKeys(bits);
        
        Integer maxAttempts = Integer::Power2(bits);
        auto result = bruteForceDiscreteLog(keys.pub.g, keys.pub.y, keys.pub.p, maxAttempts);
        
        if (result.found) {
            cout << "    [BROKEN] x found in " << result.attempts << " attempts, " 
                 << fixed << setprecision(1) << result.timeMs << " ms" << endl;
            
            UndeniableSignature us;
            keys.priv.x = result.x;
            auto sig = us.sign("Forged", keys.priv);
            bool canForge = us.interactiveVerify("Forged", sig, keys.pub, keys.priv);
            cout << "    Can forge signatures: " << (canForge ? "YES" : "NO") << endl;
            
            lastTimePerAttempt = result.timeMs / result.attempts;
        }
    }
    
    // Projections
    if (lastTimePerAttempt > 0) {
        cout << "\n  Time projections:" << endl;
        const double AGE_OF_UNIVERSE = 13.8e9 * 365.25 * 24 * 3600;  // seconds
        
        for (size_t bits : {32, 40, 48, 64, 80, 128, 256, 512, 1024, 2048}) {
            double timeSec = lastTimePerAttempt * pow(2.0, bits) / 1000.0;
            string timeStr;
            
            if (timeSec < 60) timeStr = to_string((int)timeSec) + " sec";
            else if (timeSec < 3600) timeStr = to_string((int)(timeSec/60)) + " min";
            else if (timeSec < 86400) timeStr = to_string((int)(timeSec/3600)) + " hours";
            else if (timeSec < 365.25*86400) timeStr = to_string((int)(timeSec/86400)) + " days";
            else if (timeSec < AGE_OF_UNIVERSE) {
                ostringstream oss; oss << scientific << setprecision(1) << timeSec/(365.25*86400*365) << " years";
                timeStr = oss.str();
            } else {
                ostringstream oss; oss << scientific << setprecision(1) << timeSec/AGE_OF_UNIVERSE << "x universe age";
                timeStr = oss.str();
            }
            cout << "    " << setw(4) << bits << "-bit: " << timeStr << endl;
        }
        
        double universeBits = log2(AGE_OF_UNIVERSE * 1000.0 / lastTimePerAttempt);
        cout << "\n  Universe-age threshold: ~" << (int)universeBits << " bits" << endl;
    }
}

// ATTACK 2: TRANSCRIPT FORGERY

void test_TranscriptForgery() {
    printHeader("ATTACK 2: Transcript Forgery (Non-Transferability)");
    
    UndeniableSignature us;
    auto keys = us.generateKeysFast(1536);
    AutoSeededRandomPool rng;
    
    // Create fake signature
    UndeniableSignature::Signature fakeSig;
    fakeSig.s.Randomize(rng, Integer::Two(), keys.pub.p - 1);
    
    // Forge transcript: choose a,b and compute R = s^a * y^b
    Integer a, b;
    a.Randomize(rng, Integer::One(), keys.pub.q - 1);
    b.Randomize(rng, Integer::One(), keys.pub.q - 1);
    Integer R = a_times_b_mod_c(
        a_exp_b_mod_c(fakeSig.s, a, keys.pub.p),
        a_exp_b_mod_c(keys.pub.y, b, keys.pub.p),
        keys.pub.p
    );
    
    // Check: third party verifying R == s^a * y^b
    Integer expected = a_times_b_mod_c(
        a_exp_b_mod_c(fakeSig.s, a, keys.pub.p),
        a_exp_b_mod_c(keys.pub.y, b, keys.pub.p),
        keys.pub.p
    );
    bool transcriptValid = (R == expected);
    
    // Interactive verification fails
    bool interactiveValid = us.interactiveVerify("msg", fakeSig, keys.pub, keys.priv);
    
    printTest("Forged transcript passes static check", transcriptValid);
    printTest("Forged transcript fails interactive verify", !interactiveValid);
    
    // Multiple forged transcripts
    cout << "\n  Creating 5 fake transcripts for same fake signature:" << endl;
    for (int i = 0; i < 5; i++) {
        Integer ai, bi;
        ai.Randomize(rng, Integer::One(), keys.pub.q - 1);
        bi.Randomize(rng, Integer::One(), keys.pub.q - 1);
        Integer Ri = a_times_b_mod_c(
            a_exp_b_mod_c(fakeSig.s, ai, keys.pub.p),
            a_exp_b_mod_c(keys.pub.y, bi, keys.pub.p),
            keys.pub.p
        );
        cout << "    Transcript " << (i+1) << ": looks valid" << endl;
    }
}

// ATTACK 3: SIGNATURE FORGERY

void test_SignatureForgery() {
    printHeader("ATTACK 3: Signature Forgery");
    
    UndeniableSignature us;
    auto keys = us.generateKeysFast(1536);
    AutoSeededRandomPool rng;
    string msg = "Target message";
    
    // 3.1 Random forgery
    int attempts = 100, success = 0;
    for (int i = 0; i < attempts; i++) {
        UndeniableSignature::Signature forgery;
        forgery.s.Randomize(rng, Integer::Two(), keys.pub.p - 1);
        if (us.interactiveVerify(msg, forgery, keys.pub, keys.priv)) success++;
    }
    printTest("Random forgery (" + to_string(attempts) + " attempts)", success == 0);
    
    // 3.2 Algebraic forgery s = y^k
    success = 0;
    for (int i = 0; i < 50; i++) {
        Integer k; k.Randomize(rng, Integer::One(), keys.pub.q - 1);
        UndeniableSignature::Signature forgery;
        forgery.s = a_exp_b_mod_c(keys.pub.y, k, keys.pub.p);
        if (us.interactiveVerify(msg, forgery, keys.pub, keys.priv)) success++;
    }
    printTest("Algebraic forgery s=y^k (50 attempts)", success == 0);
    
    // 3.3 Related message forgery
    auto sig1 = us.sign("Original", keys.priv);
    vector<pair<string, Integer>> manipulations = {
        {"s^2", a_times_b_mod_c(sig1.s, sig1.s, keys.pub.p)},
        {"s*g", a_times_b_mod_c(sig1.s, keys.pub.g, keys.pub.p)},
        {"s*y", a_times_b_mod_c(sig1.s, keys.pub.y, keys.pub.p)},
        {"s^-1", sig1.s.InverseMod(keys.pub.p)}
    };
    success = 0;
    for (auto& [name, s] : manipulations) {
        UndeniableSignature::Signature forgery; forgery.s = s;
        if (us.interactiveVerify("Different", forgery, keys.pub, keys.priv)) success++;
    }
    printTest("Related message forgery (4 variants)", success == 0);
}

// ATTACK 4: CHALLENGE-RESPONSE

void test_ChallengeResponse() {
    printHeader("ATTACK 4: Challenge-Response Attacks");
    
    UndeniableSignature us;
    auto keys = us.generateKeysFast(1536);
    AutoSeededRandomPool rng;
    
    string msg = "Test";
    auto sig = us.sign(msg, keys.priv);
    
    // 4.1 Replay attack
    auto ch1 = us.createChallenge(msg, sig, keys.pub);
    auto resp1 = us.respondToChallenge(ch1, keys.priv);
    auto ch2 = us.createChallenge(msg, sig, keys.pub);
    bool replayWorks = us.verifyResponse(ch2, resp1, sig, keys.pub);
    printTest("Replay attack blocked", !replayWorks);
    
    // 4.2 Response prediction
    auto challenge = us.createChallenge(msg, sig, keys.pub);
    int success = 0;
    for (int i = 0; i < 50; i++) {
        UndeniableSignature::VerificationResponse fake;
        fake.R.Randomize(rng, Integer::Two(), keys.pub.p - 1);
        if (us.verifyResponse(challenge, fake, sig, keys.pub)) success++;
    }
    printTest("Response prediction (50 attempts)", success == 0);
}

// ============================================================================
// ATTACK 6: DENIAL PROTOCOL
// ============================================================================

void test_DenialProtocol() {
    printHeader("ATTACK 6: Denial Protocol");
    
    UndeniableSignature us;
    auto keys = us.generateKeysFast(1536);
    
    string msg = "Test message";
    auto validSig = us.sign(msg, keys.priv);
    
    UndeniableSignature::Signature invalidSig;
    invalidSig.s = validSig.s + Integer::One();
    
    // Soundness: can't deny valid
    bool canDenyValid = us.denySignature(msg, validSig, keys.priv, keys.pub);
    printTest("Soundness: cannot deny valid signature", !canDenyValid);
    
    // Completeness: can deny invalid
    bool canDenyInvalid = us.denySignature(msg, invalidSig, keys.priv, keys.pub);
    printTest("Completeness: can deny invalid signature", canDenyInvalid);
    
    // Statistical test
    int validDenied = 0, invalidDenied = 0;
    for (int i = 0; i < 100; i++) {
        if (us.denySignature(msg, validSig, keys.priv, keys.pub)) validDenied++;
        if (us.denySignature(msg, invalidSig, keys.priv, keys.pub)) invalidDenied++;
    }
    printTest("Soundness 100/100", validDenied == 0);
    printTest("Completeness 100/100", invalidDenied == 100);
}

void test_WeakParameters() {
    printHeader("ATTACK 7: Weak Parameter Attacks");
    
    AutoSeededRandomPool rng;
    
    // 7.1 Small subgroup attack
    cout << "\n  7.1 Small order generator:" << endl;
    {
        // Створюємо групу де g має малий порядок
        Integer p("0xFFFFFFFFFFFFFFFFC90FDAA22168C234..."); // RFC 3526
        Integer small_factor = Integer(7);  // малий дільник p-1, якщо є
        Integer g_weak = a_exp_b_mod_c(Integer(2), (p-1)/small_factor, p);
        
        // Порядок g_weak = small_factor
        Integer order_test = a_exp_b_mod_c(g_weak, small_factor, p);
        bool is_weak = (order_test == Integer::One());
        
        if (is_weak) {
            cout << "    [VULN] Generator has order " << small_factor << endl;
            cout << "    DLP brute-force: " << small_factor << " operations" << endl;
        } else {
            cout << "    [SAFE] No small subgroup found" << endl;
        }
    }
    
    cout << "\n  7.2 Trivial generator check:" << endl;
    {
        UndeniableSignature us;
        auto keys = us.generateKeysFast(1536);
        
        bool g_is_one = (keys.pub.g == Integer::One());
        bool g_is_neg_one = (keys.pub.g == keys.pub.p - 1);
        
        printTest("g != 1", !g_is_one);
        printTest("g != -1", !g_is_neg_one);
    }
    
    // 7.3 Safe prime validation
    cout << "\n  7.4 Safe prime validation:" << endl;
    {
        UndeniableSignature us;
        auto keys = us.generateKeysFast(1536);
        
        // p = 2q + 1?
        bool is_safe = (keys.pub.p == 2 * keys.pub.q + 1);
        bool q_prime = IsPrime(keys.pub.q);
        bool p_prime = IsPrime(keys.pub.p);
        
        printTest("p is prime", p_prime);
        printTest("q is prime", q_prime);
        printTest("p = 2q + 1 (safe prime)", is_safe);
    }
    
    // 7.4 Pohlig-Hellman demo on weak prime
    cout << "\n  7.4 Pohlig-Hellman on weak parameters:" << endl;
    {
        Integer p_weak("30031");  
        
        if (IsPrime(p_weak)) {
            Integer p_minus_1 = p_weak - 1;
            cout << "    p = " << p_weak << ", p-1 = " << p_minus_1 << endl;
            cout << "    p-1 factors: 2 * 3 * 5 * 7 * 11 * 13" << endl;
    
            Integer g_weak = Integer(3);
            Integer x_secret = Integer(12345);  // секрет
            Integer y_weak = a_exp_b_mod_c(g_weak, x_secret, p_weak);
            
            auto start = high_resolution_clock::now();
            
            Integer x_found = Integer::Zero();
            Integer test = Integer::One();
            while (test != y_weak && x_found < p_weak) {
                test = a_times_b_mod_c(test, g_weak, p_weak);
                x_found++;
            }
            
            auto elapsed = duration_cast<microseconds>(
                high_resolution_clock::now() - start).count();
            
            bool cracked = (x_found == x_secret);
            cout << "    Secret x = " << x_secret << endl;
            cout << "    Found x = " << x_found << " in " << elapsed << " μs" << endl;
            printTest("Weak prime cracked", cracked);
        }
    }
}


int main(int argc, char* argv[]) {
    cout << "\n╔══════════════════════════════════════════════════════════╗" << endl;
    cout << "║  Lab 4: Undeniable Signature Security Analysis           ║" << endl;
    cout << "╚══════════════════════════════════════════════════════════╝" << endl;
    
    bool skipBrute = false;
    for (int i = 1; i < argc; i++)
        if (string(argv[i]) == "--skip-bruteforce") skipBrute = true;
    
    try {
        if (!skipBrute) test_BruteForceAttack();
        else cout << "\n[Skipping brute-force]" << endl;
        
        test_TranscriptForgery();
        test_SignatureForgery();
        test_ChallengeResponse();
        test_KeyExtraction();
        test_DenialProtocol();
        
        cout << "\n" << string(60, '=') << endl;
        cout << "  ALL TESTS COMPLETED" << endl;
        cout << string(60, '=') << endl;
        
        return 0;
    } catch (const exception& e) {
        cerr << "\n[ERROR] " << e.what() << endl;
        return 1;
    }
}
