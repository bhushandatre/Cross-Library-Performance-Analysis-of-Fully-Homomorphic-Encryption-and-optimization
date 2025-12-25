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

void logResult(ofstream& csv, long poly_degree, long vector_size, const string& rotation_type, 
               double rotation_time, long nslots) {
    csv << poly_degree << ","
        << vector_size << ","
        << rotation_type << ","
        << rotation_time << ","
        << nslots << "\n";
    csv.flush();
}

int main() {
    cout << "=== ROTATION OPERATION EXPERIMENT ===" << endl;
    cout << "Vector sizes: 2^4 to 2^10 (16 to 1024)" << endl;
    
    ofstream csv("rotation_results.csv");
    csv << "poly_degree,vector_size,rotation_type,rotation_time_ms,nslots\n";
    
    vector<long> poly_degrees = {4096, 8192, 16384, 32768};
    vector<long> vector_sizes;
    
    // Generate vector sizes from 2^4 to 2^10
    for (int exp = 4; exp <= 10; exp++) {
        vector_sizes.push_back(pow(2, exp));
    }
    
    cout << "Vector sizes to test: ";
    for (long size : vector_sizes) {
        cout << size << " ";
    }
    cout << endl;
    
    Timer timer;
    
    for (long m : poly_degrees) {
        cout << "\n=== Testing Polynomial Degree: " << m << " ===" << endl;
        
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
            addSome1DMatrices(secretKey);  // Essential for rotation operations
            const PubKey& publicKey = secretKey;
            const EncryptedArray& ea = context.getEA();
            
            long nslots = ea.size();
            cout << "Available slots: " << nslots << endl;
            
            // Check the algebraic structure
            const PAlgebra& palg = context.getEA().getPAlgebra();
            cout << "Dimensions: " << palg.numOfGens() << " [";
            for (long i = 0; i < palg.numOfGens(); i++) {
                cout << palg.OrderOf(i);
                if (i < palg.numOfGens() - 1) cout << " x ";
            }
            cout << "]" << endl;
            
            for (long vec_size : vector_sizes) {
                cout << "  Vector size: " << vec_size;
                
                if (vec_size > nslots) {
                    cout << " - SKIPPING (exceeds " << nslots << " slots)" << endl;
                    continue;
                }
                cout << endl;
                
                // Create test data with unique values
                vector<long> original_data(vec_size);
                for (long i = 0; i < vec_size; ++i) {
                    original_data[i] = i + 1;  // Values: 1, 2, 3, ..., vec_size
                }
                
                // Pad with zeros to fill all slots
                vector<long> padded_data = original_data;
                padded_data.resize(nslots, 0);
                
                // Test 1: Left Rotation (rotate left by 1 position)
                Ctxt ct_left(publicKey);
                ea.encrypt(ct_left, publicKey, padded_data);
                
                timer.tic();
                ea.rotate(ct_left, 1);  // Rotate left by 1
                double left_time = timer.toc();
                
                logResult(csv, m, vec_size, "left_rotation", left_time, nslots);
                cout << "    Left rotation: " << left_time << " ms" << endl;
                
                // Test 2: Right Rotation (rotate right by 1 position)
                Ctxt ct_right(publicKey);
                ea.encrypt(ct_right, publicKey, padded_data);
                
                timer.tic();
                ea.rotate(ct_right, -1);  // Rotate right by 1
                double right_time = timer.toc();
                
                logResult(csv, m, vec_size, "right_rotation", right_time, nslots);
                cout << "    Right rotation: " << right_time << " ms" << endl;
                
                // Test 3: Column Rotation (rotate along first dimension)
                Ctxt ct_col(publicKey);
                ea.encrypt(ct_col, publicKey, padded_data);
                
                timer.tic();
                ea.rotate1D(ct_col, 0, 1);  // Rotate along dimension 0 by 1
                double col_time = timer.toc();
                
                logResult(csv, m, vec_size, "column_rotation", col_time, nslots);
                cout << "    Column rotation: " << col_time << " ms" << endl;
                
                // Verification for first case of smallest polynomial degree
                if (m == 4096 && vec_size == 16) {
                    cout << "    --- Verification ---" << endl;
                    
                    // Verify left rotation
                    vector<long> decrypted_left(nslots);
                    ea.decrypt(ct_left, secretKey, decrypted_left);
                    cout << "    Original: [";
                    for (int i = 0; i < min(5, (int)vec_size); i++) cout << original_data[i] << " ";
                    cout << "...]" << endl;
                    cout << "    After left rotation: [";
                    for (int i = 0; i < min(5, (int)vec_size); i++) cout << decrypted_left[i] << " ";
                    cout << "...]" << endl;
                    
                    // Verify right rotation  
                    vector<long> decrypted_right(nslots);
                    ea.decrypt(ct_right, secretKey, decrypted_right);
                    cout << "    After right rotation: [";
                    for (int i = 0; i < min(5, (int)vec_size); i++) cout << decrypted_right[i] << " ";
                    cout << "...]" << endl;
                    
                    // Verify column rotation
                    vector<long> decrypted_col(nslots);
                    ea.decrypt(ct_col, secretKey, decrypted_col);
                    cout << "    After column rotation: [";
                    for (int i = 0; i < min(5, (int)vec_size); i++) cout << decrypted_col[i] << " ";
                    cout << "...]" << endl;
                }
            }
            
        } catch (const exception& e) {
            cerr << "Error with m=" << m << ": " << e.what() << endl;
            continue;
        }
    }
    
    cout << "\n✅ Rotation experiment completed!" << endl;
    cout << "Results saved to rotation_results.csv" << endl;
    cout << "Vector sizes tested: 16, 32, 64, 128, 256, 512, 1024" << endl;
    
    return 0;
}
