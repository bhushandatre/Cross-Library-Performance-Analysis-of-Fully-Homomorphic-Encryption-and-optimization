#include <helib/helib.h>
#include <iostream>
#include <fstream>
#include <chrono>
#include <vector>
#include <random>
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

vector<long> generateRandomData(long size, long min_val = 1, long max_val = 100) {
    vector<long> data(size);
    random_device rd;
    mt19937 gen(rd());
    uniform_int_distribution<long> dist(min_val, max_val);
    
    for (long i = 0; i < size; ++i) {
        data[i] = dist(gen);
    }
    return data;
}

int main() {
    cout << "=== DIFFERENT NUMBERS EXPERIMENT ===" << endl;
    
    ofstream csv("different_numbers_results.csv");
    csv << "poly_degree,vector_size,operation,enc_time_ms,op_time_ms,dec_time_ms,nslots\n";
    
    vector<long> poly_degrees = { 
        4096, 8192, 16384, 32768
    };
    
    vector<long> vector_sizes = {1024, 2048, 4096, 8192, 16384, 32768, 65536};
    
    Timer total_timer;
    total_timer.tic();
    random_device rd;
    
    for (long m : poly_degrees) {
        cout << "\n=== Testing m = " << m << " ===" << endl;
        
        try {
            Context context = ContextBuilder<BGV>()
                               .m(m)
                               .p(65537)
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
            
            // Warm-up
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
                    bool validation_passed = true;
                    
                    for (long chunk = 0; chunk < chunks; chunk++) {
                        long chunk_size = min(nslots, vec_size - chunk * nslots);
                        
                        // Different random numbers in all slots
                        vector<long> data1 = generateRandomData(chunk_size, 1, 100);
                        vector<long> data2 = generateRandomData(chunk_size, 1, 100);
                        data1.resize(nslots, 0);
                        data2.resize(nslots, 0);
                        
                        Ctxt ct1(publicKey), ct2(publicKey);
                        Ctxt pt1_ct(publicKey), pt2_ct(publicKey);
                        
                        Timer timer;
                        
                        // Encryption
                        timer.tic();
                        ea.encrypt(ct1, publicKey, data1);
                        if (op == "cipher_plus_cipher" || op == "cipher_times_cipher") {
                            ea.encrypt(ct2, publicKey, data2);
                        }
                        if (op == "cipher_plus_plain" || op == "cipher_times_plain") {
                            ea.encrypt(pt2_ct, publicKey, data2);
                        }
                        total_enc += timer.toc();
                        
                        // Operation
                        timer.tic();
                        Ctxt result_ct(ct1);
                        
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
                        
                        // Decryption and validation (first chunk only)
                        if (chunk == 0) {
                            vector<long> decrypted(nslots);
                            timer.tic();
                            ea.decrypt(result_ct, secretKey, decrypted);
                            total_dec += timer.toc();
                            
                            // Validate first few elements
                            long validation_count = min(3L, chunk_size);
                            for (long i = 0; i < validation_count; i++) {
                                long expected = 0;
                                if (op.find("plus") != string::npos) {
                                    expected = data1[i] + data2[i];
                                } else {
                                    expected = data1[i] * data2[i];
                                }
                                
                                if (decrypted[i] != expected) {
                                    validation_passed = false;
                                    break;
                                }
                            }
                        }
                    }
                    
                    logResult(csv, m, vec_size, op, total_enc, total_op, total_dec, nslots);
                    cout << "    " << op << " - Enc: " << total_enc << "ms, Op: " << total_op 
                         << "ms, Valid: " << (validation_passed ? "YES" : "NO") << endl;
                }
            }
            
        } catch (const exception& e) {
            cerr << "Error with m=" << m << ": " << e.what() << endl;
            continue;
        }
    }
    
    double total_time = total_timer.toc();
    cout << "\n✅ Different numbers experiment completed in " << total_time / 1000.0 << " seconds!" << endl;
    return 0;
}
