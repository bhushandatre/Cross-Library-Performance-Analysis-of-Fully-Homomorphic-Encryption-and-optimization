#include <helib/helib.h>
#include <iostream>
#include <fstream>
#include <chrono>
#include <vector>
#include <cmath>

using namespace helib;
using namespace std;

struct Timer {
    chrono::high_resolution_clock::time_point start;
    void tic() { start = chrono::high_resolution_clock::now(); }
    double toc() {
        auto end = chrono::high_resolution_clock::now();
        return chrono::duration<double, milli>(end - start).count();
    }
};

void logResult(ofstream& csv, long poly_degree, long vector_size, const string& operation, 
               double enc_time, double op_time, double dec_time, long nslots) {
    csv << poly_degree << ","
        << vector_size << ","
        << operation << ","
        << enc_time << ","
        << op_time << ","
        << dec_time << ","
        << nslots << "\n";
    csv.flush();
}

int main() {
    cout << "=== SAME NUMBER EXPERIMENT ===" << endl;
    
    ofstream csv("same_number_results.csv");
    csv << "poly_degree,vector_size,operation,enc_time_ms,op_time_ms,dec_time_ms,nslots\n";
    
    // Use power-of-2 minus 1 values that work better with HElib
    vector<long> poly_degrees = { 
        4096, 8192, 16384, 32768
    };
    
    vector<long> vector_sizes = {1024, 2048, 4096, 8192, 16384, 32768, 65536};
    
    Timer total_timer;
    total_timer.tic();
    
    for (long m : poly_degrees) {
        cout << "\n=== Testing m = " << m << " ===" << endl;
        
        try {
            Context context = ContextBuilder<BGV>()
                               .m(m)
                               .p(65537)  // Use larger prime that works better
                               .r(1)
                               .bits(300)
                               .c(2)
                               .build();
            
            SecKey secretKey(context);
            secretKey.GenSecKey();
            addSome1DMatrices(secretKey);
            const PubKey& publicKey = secretKey;
            const EncryptedArray& ea = context.getEA();
            
            long nslots = ea.size();
            cout << "Available slots: " << nslots << endl;
            
            if (nslots < 100) {
                cout << "Skipping - too few slots" << endl;
                continue;
            }
            
            // Warm-up using only EncryptedArray methods
            vector<long> warmup_data(nslots, 1);
            Ctxt warmup_ct(publicKey);
            ea.encrypt(warmup_ct, publicKey, warmup_data);
            vector<long> warmup_dec(nslots);
            ea.decrypt(warmup_ct, secretKey, warmup_dec);
            
            for (long vec_size : vector_sizes) {
                long chunks = (vec_size + nslots - 1) / nslots;
                cout << "  Vector size: " << vec_size << " (chunks: " << chunks << ")" << endl;
                
                vector<string> operations = {"cipher_plus_cipher", "cipher_plus_plain", 
                                           "cipher_times_plain", "cipher_times_cipher"};
                
                for (const string& op : operations) {
                    double total_enc = 0.0, total_op = 0.0, total_dec = 0.0;
                    
                    for (long chunk = 0; chunk < chunks; chunk++) {
                        long chunk_size = min(nslots, vec_size - chunk * nslots);
                        
                        // Same number in all slots
                        vector<long> data1(chunk_size, 123);  // All 123
                        vector<long> data2(chunk_size, 456);  // All 456
                        
                        // Pad to full nslots
                        data1.resize(nslots, 0);
                        data2.resize(nslots, 0);
                        
                        Ctxt ct1(publicKey), ct2(publicKey);
                        Ctxt pt1_ct(publicKey), pt2_ct(publicKey); // For plaintext operations
                        
                        Timer timer;
                        
                        // Encryption
                        timer.tic();
                        ea.encrypt(ct1, publicKey, data1);
                        if (op == "cipher_plus_cipher" || op == "cipher_times_cipher") {
                            ea.encrypt(ct2, publicKey, data2);
                        }
                        
                        // For plain operations, we need to encrypt the plaintext data
                        if (op == "cipher_plus_plain" || op == "cipher_times_plain") {
                            ea.encrypt(pt2_ct, publicKey, data2);
                        }
                        total_enc += timer.toc();
                        
                        // Operation
                        timer.tic();
                        Ctxt result_ct(ct1); // Start with ct1
                        
                        if (op == "cipher_plus_cipher") {
                            result_ct += ct2;
                        } else if (op == "cipher_plus_plain") {
                            result_ct += pt2_ct;
                        } else if (op == "cipher_times_plain") {
                            result_ct.multiplyBy(pt2_ct);
                        } else if (op == "cipher_times_cipher") {
                            result_ct.multiplyBy(ct2);
                        }
                        
                        total_op += timer.toc();
                        
                        // Decryption (first chunk only)
                        if (chunk == 0) {
                            vector<long> decrypted(nslots);
                            timer.tic();
                            ea.decrypt(result_ct, secretKey, decrypted);
                            total_dec += timer.toc();
                        }
                    }
                    
                    logResult(csv, m, vec_size, op, total_enc, total_op, total_dec, nslots);
                    cout << "    " << op << " - Enc: " << total_enc << "ms, Op: " << total_op << "ms" << endl;
                }
            }
            
        } catch (const exception& e) {
            cerr << "Error with m=" << m << ": " << e.what() << endl;
            continue;
        }
    }
    
    double total_time = total_timer.toc();
    cout << "\n✅ Same number experiment completed in " << total_time / 1000.0 << " seconds!" << endl;
    return 0;
}
