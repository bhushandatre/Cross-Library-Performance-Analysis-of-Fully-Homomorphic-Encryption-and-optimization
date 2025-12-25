#include <helib/helib.h>
#include <iostream>
#include <fstream>
#include <vector>

using namespace helib;
using namespace std;

void logResult(ofstream& csv, long poly_degree, long prime, long max_operations, 
               long actual_slots, double security_level) {
    csv << poly_degree << ","
        << prime << ","
        << max_operations << ","
        << actual_slots << ","
        << security_level << "\n";
    csv.flush();
}

bool verifyOperation(const vector<long>& plain_result, const vector<long>& encrypted_result, long vec_size) {
    for (long i = 0; i < vec_size; i++) {
        if (plain_result[i] != encrypted_result[i]) {
            return false;
        }
    }
    return true;
}

int main() {
    cout << "=== FOCUSED PARAMETER SPACE EXPLORATION ===" << endl;
    
    ofstream csv("focused_parameter_analysis.csv");
    csv << "poly_degree,prime,max_operations,actual_slots,security_level\n";
    
    // Focus on key polynomial degrees
    vector<long> poly_degrees = {1024, 2048, 4096, 8192, 16384, 32768};
    
    // Focus on representative primes
    vector<long> primes = {
        2,      // Smallest
        17,     // Small  
        257,    // Medium
        8191,   // Large
        65537   // Largest (common)
    };
    
    long vector_size = 16;
    
    for (long m : poly_degrees) {
        for (long p : primes) {
            cout << "\n=== Testing m=" << m << ", p=" << p << " ===" << endl;
            
            try {
                Context context = ContextBuilder<BGV>()
                                   .m(m)
                                   .p(p)
                                   .r(1)
                                   .bits(500)
                                   .c(2)
                                   .build();
                
                SecKey secretKey(context);
                secretKey.GenSecKey();
                addSome1DMatrices(secretKey);
                const PubKey& publicKey = secretKey;
                const EncryptedArray& ea = context.getEA();
                
                long nslots = ea.size();
                double security_level = context.securityLevel();
                
                cout << "Slots: " << nslots << ", Security: " << security_level << " bits" << endl;
                
                if (vector_size > nslots) {
                    cout << "Skipping - not enough slots" << endl;
                    continue;
                }
                
                vector<long> data1(vector_size, 1);
                vector<long> data2(vector_size, 1);
                data1.resize(nslots, 0);
                data2.resize(nslots, 0);
                
                Ctxt ct1(publicKey), ct2(publicKey);
                ea.encrypt(ct1, publicKey, data1);
                ea.encrypt(ct2, publicKey, data2);
                
                long max_operations = 0;
                Ctxt result_ct = ct1;
                
                for (long op_count = 1; op_count <= 30; op_count++) {
                    result_ct.multiplyBy(ct2);
                    
                    vector<long> decrypted(nslots);
                    ea.decrypt(result_ct, secretKey, decrypted);
                    
                    vector<long> expected(vector_size, 1);
                    
                    if (verifyOperation(expected, decrypted, vector_size)) {
                        max_operations = op_count;
                        cout << "  " << op_count << " ";
                    } else {
                        cout << " FAIL@" << op_count;
                        break;
                    }
                }
                
                logResult(csv, m, p, max_operations, nslots, security_level);
                cout << endl << "Max operations: " << max_operations << endl;
                
            } catch (const exception& e) {
                cerr << "Error: " << e.what() << endl;
            }
        }
    }
    
    cout << "\n✅ Focused analysis completed!" << endl;
    return 0;
}
