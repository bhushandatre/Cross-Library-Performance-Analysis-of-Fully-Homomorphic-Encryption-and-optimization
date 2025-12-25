#include "seal/seal.h"
#include <iostream>
#include <vector>
#include <fstream>

using namespace std;
using namespace seal;

void experiment_ct_plus_ct_for_degree(size_t poly_modulus_degree) {
    string filename = "ct_plus_ct_results_" + to_string(poly_modulus_degree) + ".csv";
    ofstream output_file(filename);
    
    // Write CSV header
    output_file << "PolynomialDegree,Operations,NoiseBudget" << endl;
    
    // Set up encryption parameters for specific degree
    EncryptionParameters parms(scheme_type::bfv);
    parms.set_poly_modulus_degree(poly_modulus_degree);
    
    try {
        parms.set_coeff_modulus(CoeffModulus::BFVDefault(poly_modulus_degree));
        
        // Set plain modulus
        if (poly_modulus_degree <= 4096) {
            parms.set_plain_modulus(PlainModulus::Batching(poly_modulus_degree, 20));
        } else {
            parms.set_plain_modulus(PlainModulus::Batching(poly_modulus_degree, 18));
        }
    } catch (const exception &e) {
        cout << "Parameters failed for degree " << poly_modulus_degree << ": " << e.what() << endl;
        return;
    }
    
    SEALContext context(parms);
    if (!context.parameters_set()) {
        cout << "Parameters not valid for degree " << poly_modulus_degree << endl;
        return;
    }
    
    KeyGenerator keygen(context);
    SecretKey secret_key = keygen.secret_key();
    PublicKey public_key;
    keygen.create_public_key(public_key);
    
    Encryptor encryptor(context, public_key);
    Evaluator evaluator(context);
    Decryptor decryptor(context, secret_key);
    
    cout << "=== Ciphertext + Ciphertext Operations (Poly Degree: " << poly_modulus_degree << ") ===" << endl;
    cout << "Operations,Noise Budget" << endl;
    
    // Initialize with ciphertexts
    Plaintext plain1("1"), plain2("1");
    Ciphertext ct1, ct2, result;
    encryptor.encrypt(plain1, ct1);
    encryptor.encrypt(plain2, ct2);
    
    // Start with addition
    evaluator.add(ct1, ct2, result);
    
    int operation_count = 1;
    int noise_budget = decryptor.invariant_noise_budget(result);
    cout << operation_count << "," << noise_budget << endl;
    output_file << poly_modulus_degree << "," << operation_count << "," << noise_budget << endl;
    
    // Perform operations in powers of 2
    vector<int> operation_sequence;
    if (poly_modulus_degree <= 4096) {
        operation_sequence = {2, 4, 8, 16, 32, 64, 128, 256, 512, 1024, 2048, 4096};
    } else if (poly_modulus_degree == 8192) {
        operation_sequence = {2, 4, 8, 16, 32, 64, 128, 256, 512, 1024, 2048};
    } else {
        operation_sequence = {2, 4, 8, 16, 32, 64, 128, 256, 512};
    }
    
    for (int target_ops : operation_sequence) {
        while (operation_count < target_ops) {
            evaluator.add_inplace(result, ct2);
            operation_count++;
            
            noise_budget = decryptor.invariant_noise_budget(result);
            if (noise_budget <= 0) {
                cout << operation_count << ",NOISE EXHAUSTED" << endl;
                output_file << poly_modulus_degree << "," << operation_count << ",NOISE EXHAUSTED" << endl;
                output_file.close();
                return;
            }
        }
        noise_budget = decryptor.invariant_noise_budget(result);
        cout << operation_count << "," << noise_budget << endl;
        output_file << poly_modulus_degree << "," << operation_count << "," << noise_budget << endl;
    }
    
    output_file.close();
}

void experiment_ct_plus_ct() {
    vector<size_t> poly_degrees = {1024, 2048, 4096, 8192, 16384, 32768};
    
    // Create master CSV file
    ofstream master_file("ct_plus_ct_master_results.csv");
    master_file << "PolynomialDegree,Operations,NoiseBudget" << endl;
    master_file.close();
    
    for (size_t degree : poly_degrees) {
        try {
            cout << "Testing poly degree: " << degree << "..." << endl;
            experiment_ct_plus_ct_for_degree(degree);
            cout << endl;
        } catch (const exception &e) {
            cout << "Failed for degree " << degree << ": " << e.what() << endl;
        }
    }
}

int main() {
    try {
        cout << "EXPERIMENT 5: Ciphertext + Ciphertext Addition (All Poly Degrees)" << endl;
        cout << "==================================================================" << endl << endl;
        
        experiment_ct_plus_ct();
        
        cout << endl << "Results saved to CSV files for each polynomial degree." << endl;
        
    } catch (const exception &e) {
        cerr << "Error: " << e.what() << endl;
        return -1;
    }
    
    return 0;
}
