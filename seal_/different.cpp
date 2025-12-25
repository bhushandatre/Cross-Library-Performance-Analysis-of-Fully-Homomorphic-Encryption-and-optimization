#include <seal/seal.h>
#include <vector>
#include <iostream>
#include <fstream>
#include <chrono>
#include <cmath>
#include <random>

using namespace std;
using namespace seal;

class SEALExperimentRandomIntegers {
private:
    shared_ptr<SEALContext> context;
    KeyGenerator *keygen;
    SecretKey secret_key;
    PublicKey public_key;
    RelinKeys relin_keys;
    Encryptor *encryptor;
    Evaluator *evaluator;
    Decryptor *decryptor;
    BatchEncoder *batch_encoder;
    
    ofstream log_file;
    mt19937 rng;

public:
    SEALExperimentRandomIntegers() : keygen(nullptr), encryptor(nullptr), evaluator(nullptr), 
                                     decryptor(nullptr), batch_encoder(nullptr), rng(42) {
        log_file.open("seal_experiment_random_integers.csv");
        log_file << "poly_modulus_degree,vector_size,operation_type,encryption_time_ms,operation_time_ms,decryption_time_ms\n";
    }

    ~SEALExperimentRandomIntegers() {
        cleanup();
        if (log_file.is_open()) {
            log_file.close();
        }
    }

    void cleanup() {
        if (batch_encoder) delete batch_encoder;
        if (decryptor) delete decryptor;
        if (evaluator) delete evaluator;
        if (encryptor) delete encryptor;
        if (keygen) delete keygen;
    }

    void setup_context(size_t poly_modulus_degree) {
        cleanup();

        EncryptionParameters params(scheme_type::bfv);
        params.set_poly_modulus_degree(poly_modulus_degree);
        params.set_coeff_modulus(CoeffModulus::BFVDefault(poly_modulus_degree));
        params.set_plain_modulus(PlainModulus::Batching(poly_modulus_degree, 20));

        context = make_shared<SEALContext>(params);

        keygen = new KeyGenerator(*context);
        secret_key = keygen->secret_key();
        keygen->create_public_key(public_key);
        keygen->create_relin_keys(relin_keys);

        encryptor = new Encryptor(*context, public_key);
        evaluator = new Evaluator(*context);
        decryptor = new Decryptor(*context, secret_key);
        batch_encoder = new BatchEncoder(*context);
    }

    vector<uint64_t> generate_random_vector(size_t size, uint64_t max_value = 100) {
        vector<uint64_t> result(size);
        uniform_int_distribution<uint64_t> dist(1, max_value);
        for (size_t i = 0; i < size; i++) {
            result[i] = dist(rng);
        }
        return result;
    }

    void log_operation(size_t poly_modulus_degree, size_t vector_size, const string& operation_type,
                       double encryption_time, double operation_time, double decryption_time) {
        log_file << poly_modulus_degree << "," << vector_size << "," << operation_type << ","
                 << encryption_time << "," << operation_time << "," << decryption_time << endl;
        
        cout << "PolyModulus: " << poly_modulus_degree 
             << ", VectorSize: " << vector_size
             << ", Operation: " << operation_type
             << ", Encrypt: " << encryption_time << " ms"
             << ", Operation: " << operation_time << " ms"
             << ", Decrypt: " << decryption_time << " ms" << endl;
    }

    void test_operation_single(size_t poly_modulus_degree, size_t vector_size, const string& operation_type) {
        size_t slot_count = batch_encoder->slot_count();
        vector<uint64_t> plain_data = generate_random_vector(vector_size);
        
        // Pad to slot_count if necessary
        if (vector_size < slot_count) {
            plain_data.resize(slot_count, 0);
        }

        Plaintext plain;
        batch_encoder->encode(plain_data, plain);

        // Encryption time
        auto start_encrypt = chrono::high_resolution_clock::now();
        Ciphertext cipher;
        encryptor->encrypt(plain, cipher);
        auto end_encrypt = chrono::high_resolution_clock::now();
        double encrypt_time = chrono::duration<double, milli>(end_encrypt - start_encrypt).count();

        // Operation time
        auto start_op = chrono::high_resolution_clock::now();
        Ciphertext result;
        
        if (operation_type == "CIPHER_ADD_CIPHER") {
            evaluator->add(cipher, cipher, result);
        }
        else if (operation_type == "CIPHER_ADD_PLAIN") {
            evaluator->add_plain(cipher, plain, result);
        }
        else if (operation_type == "CIPHER_MUL_PLAIN") {
            evaluator->multiply_plain(cipher, plain, result);
        }
        else if (operation_type == "CIPHER_MUL_CIPHER") {
            evaluator->multiply(cipher, cipher, result);
            evaluator->relinearize_inplace(result, relin_keys);
        }
        
        auto end_op = chrono::high_resolution_clock::now();
        double operation_time = chrono::duration<double, milli>(end_op - start_op).count();

        // Decryption time
        Plaintext decrypted;
        auto start_decrypt = chrono::high_resolution_clock::now();
        decryptor->decrypt(result, decrypted);
        auto end_decrypt = chrono::high_resolution_clock::now();
        double decrypt_time = chrono::duration<double, milli>(end_decrypt - start_decrypt).count();

        log_operation(poly_modulus_degree, vector_size, operation_type, encrypt_time, operation_time, decrypt_time);
    }

    void test_operation_large_vector(size_t poly_modulus_degree, size_t vector_size, const string& operation_type) {
        size_t slot_count = batch_encoder->slot_count();
        size_t num_ciphertexts = (vector_size + slot_count - 1) / slot_count;

        double total_encrypt_time = 0;
        double total_operation_time = 0;
        double total_decrypt_time = 0;

        for (size_t i = 0; i < num_ciphertexts; i++) {
            size_t current_size = min(slot_count, vector_size - i * slot_count);
            vector<uint64_t> plain_data = generate_random_vector(current_size);
            
            // Pad if necessary
            if (current_size < slot_count) {
                plain_data.resize(slot_count, 0);
            }

            Plaintext plain;
            batch_encoder->encode(plain_data, plain);

            // Encryption
            auto start_encrypt = chrono::high_resolution_clock::now();
            Ciphertext cipher;
            encryptor->encrypt(plain, cipher);
            auto end_encrypt = chrono::high_resolution_clock::now();
            total_encrypt_time += chrono::duration<double, milli>(end_encrypt - start_encrypt).count();

            // Operation
            auto start_op = chrono::high_resolution_clock::now();
            Ciphertext result;
            
            if (operation_type == "CIPHER_ADD_CIPHER") {
                evaluator->add(cipher, cipher, result);
            }
            else if (operation_type == "CIPHER_ADD_PLAIN") {
                evaluator->add_plain(cipher, plain, result);
            }
            else if (operation_type == "CIPHER_MUL_PLAIN") {
                evaluator->multiply_plain(cipher, plain, result);
            }
            else if (operation_type == "CIPHER_MUL_CIPHER") {
                evaluator->multiply(cipher, cipher, result);
                evaluator->relinearize_inplace(result, relin_keys);
            }
            
            auto end_op = chrono::high_resolution_clock::now();
            total_operation_time += chrono::duration<double, milli>(end_op - start_op).count();

            // Decryption
            Plaintext decrypted;
            auto start_decrypt = chrono::high_resolution_clock::now();
            decryptor->decrypt(result, decrypted);
            auto end_decrypt = chrono::high_resolution_clock::now();
            total_decrypt_time += chrono::duration<double, milli>(end_decrypt - start_decrypt).count();
        }

        // Average times per ciphertext
        log_operation(poly_modulus_degree, vector_size, operation_type,
                     total_encrypt_time / num_ciphertexts,
                     total_operation_time / num_ciphertexts,
                     total_decrypt_time / num_ciphertexts);
    }

    void run_experiment(size_t poly_modulus_degree, size_t vector_size) {
        setup_context(poly_modulus_degree);
        
        size_t slot_count = batch_encoder->slot_count();
        
        cout << "Testing - PolyModulus: " << poly_modulus_degree 
             << ", VectorSize: " << vector_size 
             << ", SlotCount: " << slot_count 
             << ", CiphertextsNeeded: " << ((vector_size + slot_count - 1) / slot_count) << endl;

        // Test each operation separately
        vector<string> operations = {
            "CIPHER_ADD_CIPHER",
            "CIPHER_ADD_PLAIN", 
            "CIPHER_MUL_PLAIN",
            "CIPHER_MUL_CIPHER"
        };

        for (const auto& operation : operations) {
            if (vector_size <= slot_count) {
                // Single ciphertext case
                test_operation_single(poly_modulus_degree, vector_size, operation);
            } else {
                // Multiple ciphertexts case
                test_operation_large_vector(poly_modulus_degree, vector_size, operation);
            }
        }
    }

    void run_all_experiments() {
        vector<size_t> poly_modulus_degrees = {1024, 2048, 4096, 8192, 16384, 32768};
        vector<size_t> vector_sizes;
        
        // Generate vector sizes from 2^10 to 2^20
        for (int i = 10; i <= 20; i++) {
            vector_sizes.push_back(1 << i);
        }

        for (auto poly_degree : poly_modulus_degrees) {
            for (auto vec_size : vector_sizes) {
                try {
                    run_experiment(poly_degree, vec_size);
                } catch (const exception& e) {
                    cout << "Error with PolyModulus: " << poly_degree 
                         << ", VectorSize: " << vec_size 
                         << " - " << e.what() << endl;
                }
            }
        }
    }
};

int main() {
    SEALExperimentRandomIntegers experiment;
    cout << "Starting Random Integers Experiments..." << endl;
    experiment.run_all_experiments();
    cout << "Random Integers Experiments Completed!" << endl;
    return 0;
}
